/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `prefer_ipv4` / `prefer_ipv6` quick-setup executors.
//!
//! This plugin follows mosdns dual-selector behavior:
//! - For preferred qtype (A for prefer_ipv4 / AAAA for prefer_ipv6):
//!   pass query through and cache positive preferred-type answers.
//! - For non-preferred qtype:
//!   1) block immediately when cache says preferred type exists.
//!   2) otherwise ask `forward` to run an extra preferred-type probe.
//!      The final block/pass decision is applied in post_execute.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::dns_utils::build_response_from_request;
use crate::core::error::{DnsError, Result};
use crate::core::ttl_cache::TtlCache;
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::watch;

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
    cache: TtlCache<String, CachedPreferredState>,
    cache_enabled: bool,
    cache_ttl_ms: u64,
    cleanup_started: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
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

#[derive(Debug)]
struct PostState {
    domain: String,
    mode: PostMode,
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
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let interval = Duration::from_secs(CLEANUP_INTERVAL_SECS);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                }
                let now = AppClock::elapsed_millis();
                while cache.remove_expired_batch(now, 256) > 0 {}
            }
        });
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        self.cleanup_started.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait]
impl Executor for DualSelector {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if context.request.queries().len() != 1 {
            return Ok(ExecStep::Next);
        }

        let Some(qtype) = context.request.query().map(|q| q.query_type) else {
            return Ok(ExecStep::Next);
        };
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(ExecStep::Next);
        }

        let Some(domain) = context
            .query_view()
            .map(|view| view.normalized_name().to_string())
        else {
            return Ok(ExecStep::Next);
        };

        if qtype == self.preferred_type {
            return Ok(ExecStep::NextWithPost(Some(Box::new(PostState {
                domain,
                mode: PostMode::Preferred,
            }) as ExecState)));
        }

        if self.cache_enabled {
            if let Some(preferred_exists) = self.cache_get_preferred_state(&domain) {
                if preferred_exists {
                    context.response = Some(build_response_from_request(
                        &context.request,
                        ResponseCode::NoError,
                    ));
                    return Ok(ExecStep::Stop);
                }
                return Ok(ExecStep::Next);
            }
        }

        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_REQUEST,
            ForwardProbeRequest {
                preferred_type: self.preferred_type,
            },
        );

        Ok(ExecStep::NextWithPost(Some(Box::new(PostState {
            domain,
            mode: PostMode::NonPreferredProbe,
        }) as ExecState)))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let Some(state) = state
            .and_then(|boxed| boxed.downcast::<PostState>().ok())
            .map(|boxed| *boxed)
        else {
            return Ok(());
        };

        match state.mode {
            PostMode::Preferred => {
                let has_preferred_answer = context.response.as_ref().is_some_and(|resp| {
                    resp.answers()
                        .iter()
                        .any(|rr| rr.record_type() == self.preferred_type)
                });
                if has_preferred_answer {
                    self.cache_preferred(&state.domain);
                }
                Ok(())
            }
            PostMode::NonPreferredProbe => self.apply_probe_result(context, &state.domain),
        }
    }
}

impl DualSelector {
    fn apply_probe_result(&self, context: &mut DnsContext, domain: &str) -> Result<()> {
        let Some(probe) =
            context.remove_attr::<ForwardProbeResult>(DnsContext::ATTR_FORWARD_PROBE_RESULT)
        else {
            return Ok(());
        };

        // Probe errors mean preferred-type availability is unknown.
        // Never cache/block in this case to avoid false positive suppression.
        if probe.preferred_error.is_some() {
            if context.response.is_none() {
                if let Some(err) = probe.original_error {
                    return Err(DnsError::plugin(err));
                }
            }
            return Ok(());
        }

        if probe.preferred_has_answer {
            if self.cache_enabled {
                self.cache_probe_result(domain, true);
            }
            context.response = Some(build_response_from_request(
                &context.request,
                ResponseCode::NoError,
            ));
            return Ok(());
        }

        if self.cache_enabled {
            self.cache_probe_result(domain, false);
        }

        if context.response.is_none() {
            if let Some(err) = probe.original_error {
                return Err(DnsError::plugin(err));
            }
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
            CachedPreferredState { preferred_exists },
            now,
            expire_at,
        );
    }

    fn cache_get_preferred_state(&self, domain: &String) -> Option<bool> {
        let now = AppClock::elapsed_millis();
        self.cache
            .get_fresh_cloned(domain, now, 1000)
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

fn parse_dual_selector_config(args: Option<serde_yml::Value>) -> Result<(bool, u64)> {
    let cfg = match args {
        Some(args) => serde_yml::from_value::<DualSelectorConfig>(args).map_err(|e| {
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
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let _ = parse_dual_selector_config(plugin_config.args.clone())?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let (cache_enabled, cache_ttl_ms) = parse_dual_selector_config(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(DualSelector {
            tag: plugin_config.tag.clone(),
            preferred_type: self.record_type,
            cache: TtlCache::with_capacity(4096),
            cache_enabled,
            cache_ttl_ms,
            cleanup_started: AtomicBool::new(false),
            shutdown_tx: watch::channel(false).0,
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
            shutdown_tx: watch::channel(false).0,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ExecFlowState;
    use ahash::{AHashMap, AHashSet};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_context(qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            qtype,
        ));
        DnsContext {
            src_addr: "127.0.0.1:5533".parse().unwrap(),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: AHashSet::new(),
            attributes: AHashMap::new(),
            query_view: None,
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    fn make_selector(preferred_type: RecordType) -> DualSelector {
        DualSelector {
            tag: "dual_selector_test".to_string(),
            preferred_type,
            cache: TtlCache::with_capacity(1024),
            cache_enabled: true,
            cache_ttl_ms: DEFAULT_CACHE_TTL_MS,
            cleanup_started: AtomicBool::new(false),
            shutdown_tx: watch::channel(false).0,
        }
    }

    fn set_answer(context: &mut DnsContext, qtype: RecordType) {
        let query = context.request.query().expect("query must exist");
        let qname = query.name().clone();
        let mut response = build_response_from_request(&context.request, ResponseCode::NoError);
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
        context.response = Some(response);
    }

    fn has_answer_of_type(context: &DnsContext, qtype: RecordType) -> bool {
        context.response.as_ref().is_some_and(|response| {
            response
                .answers()
                .iter()
                .any(|answer| answer.record_type() == qtype)
        })
    }

    #[tokio::test]
    async fn cache_hit_blocks_non_preferred_immediately() {
        let selector = make_selector(RecordType::A);
        selector.cache_preferred("example.com");

        let mut context = make_context(RecordType::AAAA);
        let step = selector.execute(&mut context).await.unwrap();

        assert!(matches!(step, ExecStep::Stop));
        assert!(!has_answer_of_type(&context, RecordType::AAAA));
    }

    #[tokio::test]
    async fn preferred_post_warms_cache_for_next_non_preferred_request() {
        let selector = make_selector(RecordType::A);
        let mut preferred_context = make_context(RecordType::A);

        let step = selector.execute(&mut preferred_context).await.unwrap();
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        set_answer(&mut preferred_context, RecordType::A);
        selector
            .post_execute(&mut preferred_context, state)
            .await
            .unwrap();

        let mut non_preferred_context = make_context(RecordType::AAAA);
        let step2 = selector.execute(&mut non_preferred_context).await.unwrap();
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

        let step = selector.execute(&mut context).await.unwrap();
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        let probe = context
            .get_attr::<ForwardProbeRequest>(DnsContext::ATTR_FORWARD_PROBE_REQUEST)
            .copied()
            .expect("probe request should be set");
        assert_eq!(probe.preferred_type, RecordType::A);

        set_answer(&mut context, RecordType::AAAA);
        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: true,
                preferred_error: None,
                original_error: None,
            },
        );

        selector.post_execute(&mut context, state).await.unwrap();
        assert!(!has_answer_of_type(&context, RecordType::AAAA));

        let mut second = make_context(RecordType::AAAA);
        let step2 = selector.execute(&mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::Stop));
        assert!(!has_answer_of_type(&second, RecordType::AAAA));
    }

    #[tokio::test]
    async fn non_preferred_without_preferred_answer_is_cached_to_skip_next_probe() {
        let selector = make_selector(RecordType::A);
        let mut first = make_context(RecordType::AAAA);

        let step = selector.execute(&mut first).await.unwrap();
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        set_answer(&mut first, RecordType::AAAA);
        first.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: false,
                preferred_error: None,
                original_error: None,
            },
        );
        selector.post_execute(&mut first, state).await.unwrap();
        assert!(has_answer_of_type(&first, RecordType::AAAA));

        let mut second = make_context(RecordType::AAAA);
        let step2 = selector.execute(&mut second).await.unwrap();
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
        let step1 = selector.execute(&mut first).await.unwrap();
        let state1 = match step1 {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        set_answer(&mut first, RecordType::AAAA);
        first.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: false,
                preferred_error: None,
                original_error: None,
            },
        );
        selector.post_execute(&mut first, state1).await.unwrap();

        let mut second = make_context(RecordType::AAAA);
        let step2 = selector.execute(&mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::NextWithPost(_)));
        assert!(
            second
                .get_attr::<ForwardProbeRequest>(DnsContext::ATTR_FORWARD_PROBE_REQUEST)
                .is_some()
        );
    }

    #[tokio::test]
    async fn non_preferred_returns_forward_error_when_probe_not_blocking() {
        let selector = make_selector(RecordType::A);
        let mut context = make_context(RecordType::AAAA);

        let step = selector.execute(&mut context).await.unwrap();
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: false,
                preferred_error: None,
                original_error: Some("forward original query failed".to_string()),
            },
        );
        context.response = None;

        let err = selector
            .post_execute(&mut context, state)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("forward original query failed"));
    }

    #[tokio::test]
    async fn probe_error_does_not_block_or_warm_cache() {
        let selector = make_selector(RecordType::A);
        let mut context = make_context(RecordType::AAAA);

        let step = selector.execute(&mut context).await.unwrap();
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        set_answer(&mut context, RecordType::AAAA);
        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer: true,
                preferred_error: Some("probe timeout".to_string()),
                original_error: None,
            },
        );

        selector.post_execute(&mut context, state).await.unwrap();
        assert!(has_answer_of_type(&context, RecordType::AAAA));

        let mut second = make_context(RecordType::AAAA);
        let step2 = selector.execute(&mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::NextWithPost(_)));
    }
}
