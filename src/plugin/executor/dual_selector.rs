// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `prefer_ipv4` / `prefer_ipv6` quick-setup executors.
//!
//! This plugin follows mosdns dual-selector behavior:
//! - For preferred qtype (A for prefer_ipv4 / AAAA for prefer_ipv6): pass query
//!   through and cache positive preferred-type answers.
//! - For non-preferred qtype:
//!   1) block immediately when cache says preferred type exists.
//!   2) otherwise ask `forward` to run an extra preferred-type probe. The final
//!      block/pass decision is applied in continuation post-stage.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::core::ttl_cache::TtlCache;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{Rcode, RecordType};
use crate::{continue_next, register_plugin_factory};

const CLEANUP_INTERVAL_SECS: u64 = 30;
const DEFAULT_CACHE_ENABLED: bool = true;
const DEFAULT_CACHE_TTL_SECS: u64 = 60 * 60;
const DEFAULT_CACHE_TTL_MS: u64 = DEFAULT_CACHE_TTL_SECS * 1000;

/// Probe request passed from `dual_selector` to `forward`.
#[derive(Debug, Clone, Copy)]
pub struct ForwardProbeRequest {
    pub preferred_type: RecordType,
}

/// Probe result passed from `forward` to `dual_selector`.
#[derive(Debug)]
pub struct ForwardProbeResult {
    pub preferred_has_answer: bool,
    pub preferred_error: Option<String>,
    pub original_error: Option<String>,
}

#[derive(Debug)]
struct DualSelector {
    tag: String,
    preferred_type: RecordType,
    cache: TtlCache<String, Arc<CachedPreferredState>>,
    cache_enabled: bool,
    cache_ttl_ms: u64,
    cleanup_started: AtomicBool,
    cleanup_task_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct CachedPreferredState {
    preferred_exists: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PostMode {
    Preferred,
    NonPreferredProbe,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ExecPlan {
    Bypass,
    Stop,
    Continue { domain: String, mode: PostMode },
}

#[derive(Debug, Clone, Deserialize, Default)]
struct DualSelectorConfig {
    /// Enable preferred-result cache for non-preferred query short-circuiting.
    #[serde(default)]
    cache: Option<bool>,
    /// Cache TTL in seconds for preferred-result probe state.
    cache_ttl: Option<u64>,
}

#[async_trait]
impl Plugin for DualSelector {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        if !self.cache_enabled {
            return Ok(());
        }
        if self.cleanup_started.swap(true, Ordering::Relaxed) {
            return Ok(());
        }

        let cache = self.cache.clone();
        self.cleanup_task_id = Some(task_center::spawn_fixed(
            format!("dual_selector:{}:cleanup", self.tag),
            Duration::from_secs(CLEANUP_INTERVAL_SECS),
            move || {
                let cache = cache.clone();
                async move {
                    let now = AppClock::elapsed_millis();
                    while cache.remove_expired_batch(now, 256) > 0 {}
                }
            },
        ));
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(task_id) = self.cleanup_task_id {
            task_center::stop_task(task_id).await;
        }
        self.cleanup_started.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait]
impl Executor for DualSelector {
    fn with_next(&self) -> bool {
        true
    }

    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.execute_with_next(context, None).await
    }

    #[hotpath::measure]
    async fn execute_with_next(
        &self,
        context: &mut DnsContext,
        next: Option<ExecutorNext>,
    ) -> Result<ExecStep> {
        let plan = self.plan(context);

        match plan {
            ExecPlan::Bypass => continue_next!(next, context),
            ExecPlan::Stop => Ok(ExecStep::Stop),
            ExecPlan::Continue {
                domain,
                mode: PostMode::Preferred,
            } => {
                let step = continue_next!(next, context)?;
                let has_preferred_answer = context
                    .response()
                    .is_some_and(|response| response.has_answer_type(self.preferred_type));
                if has_preferred_answer {
                    self.cache_preferred(&domain);
                }
                Ok(step)
            }
            ExecPlan::Continue {
                domain,
                mode: PostMode::NonPreferredProbe,
            } => {
                context.set_attr(
                    DnsContext::ATTR_FORWARD_PROBE_REQUEST,
                    ForwardProbeRequest {
                        preferred_type: self.preferred_type,
                    },
                );
                let step = continue_next!(next, context)?;
                self.apply_probe_result(context, &domain)?;
                Ok(step)
            }
        }
    }
}

impl DualSelector {
    fn plan(&self, context: &mut DnsContext) -> ExecPlan {
        if context.request.question_count() != 1 {
            return ExecPlan::Bypass;
        }

        let Some(qtype) = context.request.first_qtype() else {
            return ExecPlan::Bypass;
        };
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return ExecPlan::Bypass;
        }

        let Some(domain) = context
            .request
            .first_question()
            .map(|question| question.name().normalized().to_string())
        else {
            return ExecPlan::Bypass;
        };

        if qtype == self.preferred_type {
            return ExecPlan::Continue {
                domain,
                mode: PostMode::Preferred,
            };
        }

        if self.cache_enabled
            && let Some(preferred_exists) = self.cache_get_preferred_state(&domain)
        {
            if preferred_exists {
                context.set_response(context.request().response(Rcode::NoError));
                return ExecPlan::Stop;
            }
            return ExecPlan::Bypass;
        }

        ExecPlan::Continue {
            domain,
            mode: PostMode::NonPreferredProbe,
        }
    }

    fn apply_probe_result(&self, context: &mut DnsContext, domain: &str) -> Result<()> {
        let Some(probe) =
            context.remove_attr::<ForwardProbeResult>(DnsContext::ATTR_FORWARD_PROBE_RESULT)
        else {
            return Ok(());
        };

        // Probe errors mean preferred-type availability is unknown.
        // Never cache/block in this case to avoid false positive suppression.
        if probe.preferred_error.is_some() {
            if context.response().is_none()
                && let Some(err) = probe.original_error
            {
                return Err(DnsError::plugin(err));
            }
            return Ok(());
        }

        if probe.preferred_has_answer {
            if self.cache_enabled {
                self.cache_probe_result(domain, true);
            }
            context.set_response(context.request().response(Rcode::NoError));
            return Ok(());
        }

        if self.cache_enabled {
            self.cache_probe_result(domain, false);
        }

        if context.response().is_none()
            && let Some(err) = probe.original_error
        {
            return Err(DnsError::plugin(err));
        }

        Ok(())
    }

    fn cache_preferred(&self, domain: &str) {
        if !self.cache_enabled {
            return;
        }
        self.cache_probe_result(domain, true);
    }

    fn cache_probe_result(&self, domain: &str, preferred_exists: bool) {
        let now = AppClock::elapsed_millis();
        let expire_at = now.saturating_add(self.cache_ttl_ms);
        self.cache.insert_or_update(
            domain.to_string(),
            Arc::new(CachedPreferredState { preferred_exists }),
            now,
            expire_at,
        );
    }

    fn cache_get_preferred_state(&self, domain: &String) -> Option<bool> {
        let now = AppClock::elapsed_millis();
        self.cache
            .get_retained_cloned(domain, now, 1000)
            .map(|entry| entry.value.preferred_exists)
    }
}

#[derive(Debug, Clone)]
pub struct DualSelectorFactory {
    record_type: RecordType,
}

register_plugin_factory!("prefer_ipv4", DualSelectorFactory::new(RecordType::A));
register_plugin_factory!("prefer_ipv6", DualSelectorFactory::new(RecordType::AAAA));

impl DualSelectorFactory {
    fn new(record_type: RecordType) -> Self {
        Self { record_type }
    }
}

fn parse_dual_selector_config(args: Option<Value>) -> Result<(bool, u64)> {
    let cfg = match args {
        Some(args) => serde_yaml_ng::from_value::<DualSelectorConfig>(args).map_err(|e| {
            DnsError::plugin(format!("failed to parse dual_selector config: {}", e))
        })?,
        None => DualSelectorConfig::default(),
    };

    let cache_enabled = cfg.cache.unwrap_or(DEFAULT_CACHE_ENABLED);
    let cache_ttl_secs = cfg.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL_SECS);
    if cache_enabled && cache_ttl_secs == 0 {
        return Err(DnsError::plugin(
            "dual_selector cache_ttl must be greater than 0 seconds",
        ));
    }
    let cache_ttl_ms = if cache_ttl_secs == 0 {
        DEFAULT_CACHE_TTL_MS
    } else {
        cache_ttl_secs.saturating_mul(1000)
    };
    Ok((cache_enabled, cache_ttl_ms))
}

impl PluginFactory for DualSelectorFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let (cache_enabled, cache_ttl_ms) = parse_dual_selector_config(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(DualSelector {
            tag: plugin_config.tag.clone(),
            preferred_type: self.record_type,
            cache: TtlCache::with_capacity(4096),
            cache_enabled,
            cache_ttl_ms,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        _param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(DualSelector {
            tag: tag.to_string(),
            preferred_type: self.record_type,
            cache: TtlCache::with_capacity(4096),
            cache_enabled: DEFAULT_CACHE_ENABLED,
            cache_ttl_ms: DEFAULT_CACHE_TTL_MS,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::proto::rdata::{A, AAAA};
    use crate::proto::{DNSClass, Message, Name, Question, RData, Record};

    fn make_context(qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            qtype,
            DNSClass::IN,
        ));
        DnsContext::new(
            "127.0.0.1:5533".parse().unwrap(),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn make_selector(preferred_type: RecordType) -> DualSelector {
        DualSelector {
            tag: "dual_selector_test".to_string(),
            preferred_type,
            cache: TtlCache::with_capacity(1024),
            cache_enabled: true,
            cache_ttl_ms: DEFAULT_CACHE_TTL_MS,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
        }
    }

    fn set_answer(context: &mut DnsContext, qtype: RecordType) {
        let qname = context
            .request
            .first_question()
            .expect("question must exist")
            .name()
            .clone();
        let mut response = context.request.response(Rcode::NoError);
        match qtype {
            RecordType::A => response.answers_mut().push(Record::from_rdata(
                qname,
                60,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )),
            RecordType::AAAA => response.answers_mut().push(Record::from_rdata(
                qname,
                60,
                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            )),
            _ => {}
        }
        context.set_response(response);
    }

    fn has_answer_of_type(context: &DnsContext, qtype: RecordType) -> bool {
        context.response().is_some_and(|response| {
            response
                .answers()
                .iter()
                .any(|answer| answer.rr_type() == qtype)
        })
    }

    async fn run_selector(selector: &DualSelector, context: &mut DnsContext) -> Result<ExecStep> {
        selector.execute_with_next(context, None).await
    }

    #[tokio::test]
    async fn cache_hit_blocks_non_preferred_immediately() {
        let selector = make_selector(RecordType::A);
        selector.cache_preferred("example.com");

        let mut context = make_context(RecordType::AAAA);
        let step = run_selector(&selector, &mut context).await.unwrap();

        assert!(matches!(step, ExecStep::Stop));
        assert!(!has_answer_of_type(&context, RecordType::AAAA));
    }

    #[tokio::test]
    async fn preferred_post_warms_cache_for_next_non_preferred_request() {
        let selector = make_selector(RecordType::A);
        let mut preferred_context = make_context(RecordType::A);
        set_answer(&mut preferred_context, RecordType::A);
        run_selector(&selector, &mut preferred_context)
            .await
            .unwrap();

        let mut non_preferred_context = make_context(RecordType::AAAA);
        let step2 = run_selector(&selector, &mut non_preferred_context)
            .await
            .unwrap();
        assert!(matches!(step2, ExecStep::Stop));
        assert!(!has_answer_of_type(
            &non_preferred_context,
            RecordType::AAAA
        ));
    }

    #[tokio::test]
    async fn non_preferred_uses_probe_result_and_blocks_when_preferred_exists() {
        let selector = make_selector(RecordType::A);
        let mut context = make_context(RecordType::AAAA);

        let probe = context
            .get_attr::<ForwardProbeRequest>(DnsContext::ATTR_FORWARD_PROBE_REQUEST)
            .copied();
        assert!(probe.is_none());

        set_answer(&mut context, RecordType::AAAA);
        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: true,
                preferred_error: None,
                original_error: None,
            },
        );

        run_selector(&selector, &mut context).await.unwrap();
        assert!(!has_answer_of_type(&context, RecordType::AAAA));

        let mut second = make_context(RecordType::AAAA);
        let step2 = run_selector(&selector, &mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::Stop));
        assert!(!has_answer_of_type(&second, RecordType::AAAA));
    }

    #[tokio::test]
    async fn non_preferred_without_preferred_answer_is_cached_to_skip_next_probe() {
        let selector = make_selector(RecordType::A);
        let mut first = make_context(RecordType::AAAA);
        set_answer(&mut first, RecordType::AAAA);
        first.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: false,
                preferred_error: None,
                original_error: None,
            },
        );
        run_selector(&selector, &mut first).await.unwrap();
        assert!(has_answer_of_type(&first, RecordType::AAAA));

        let mut second = make_context(RecordType::AAAA);
        let step2 = run_selector(&selector, &mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::Next));
        assert!(
            second
                .get_attr::<ForwardProbeRequest>(DnsContext::ATTR_FORWARD_PROBE_REQUEST)
                .is_none()
        );
    }

    #[tokio::test]
    async fn cache_disabled_always_probes_non_preferred() {
        let mut selector = make_selector(RecordType::A);
        selector.cache_enabled = false;

        let mut first = make_context(RecordType::AAAA);
        set_answer(&mut first, RecordType::AAAA);
        first.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: false,
                preferred_error: None,
                original_error: None,
            },
        );
        run_selector(&selector, &mut first).await.unwrap();

        let mut second = make_context(RecordType::AAAA);
        let step2 = run_selector(&selector, &mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::Next));
    }

    #[tokio::test]
    async fn non_preferred_returns_forward_error_when_probe_not_blocking() {
        let selector = make_selector(RecordType::A);
        let mut context = make_context(RecordType::AAAA);

        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: false,
                preferred_error: None,
                original_error: Some("forward original query failed".to_string()),
            },
        );
        context.clear_response();

        let err = run_selector(&selector, &mut context).await.unwrap_err();
        assert!(err.to_string().contains("forward original query failed"));
    }

    #[tokio::test]
    async fn probe_error_does_not_block_or_warm_cache() {
        let selector = make_selector(RecordType::A);
        let mut context = make_context(RecordType::AAAA);

        set_answer(&mut context, RecordType::AAAA);
        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: true,
                preferred_error: Some("probe timeout".to_string()),
                original_error: None,
            },
        );

        run_selector(&selector, &mut context).await.unwrap();
        assert!(has_answer_of_type(&context, RecordType::AAAA));

        let mut second = make_context(RecordType::AAAA);
        let step2 = run_selector(&selector, &mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::Next));
    }
}
