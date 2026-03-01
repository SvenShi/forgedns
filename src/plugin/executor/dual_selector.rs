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
//!   2) otherwise run original query and preferred-type reference query
//!      concurrently on the remaining chain and decide whether to block.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::dns_utils::build_response_from_request;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::recursive::RecursiveHandle;
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const CACHE_TTL_MS: u64 = 60 * 60 * 1000;
const CLEANUP_INTERVAL: u64 = 2048;
const REFERENCE_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const SUB_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct DualSelector {
    tag: String,
    preferred_type: RecordType,
    cache: Arc<DashMap<String, u64>>,
    ops: AtomicU64,
}

#[derive(Debug)]
struct PostState {
    domain: String,
}

struct OriginalQueryOutcome {
    context: DnsContext,
    error: Option<DnsError>,
}

#[async_trait]
impl Plugin for DualSelector {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for DualSelector {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.execute_inner(context, None).await
    }

    async fn execute_with_handle(
        &self,
        context: &mut DnsContext,
        next: Option<RecursiveHandle>,
    ) -> Result<ExecStep> {
        self.execute_inner(context, next).await
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let Some(state) = state
            .and_then(|boxed| boxed.downcast::<PostState>().ok())
            .map(|boxed| *boxed)
        else {
            return Ok(());
        };

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
}

impl DualSelector {
    async fn execute_inner(
        &self,
        context: &mut DnsContext,
        next: Option<RecursiveHandle>,
    ) -> Result<ExecStep> {
        self.maybe_cleanup();

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
            return Ok(ExecStep::NextWithPost(Some(
                Box::new(PostState { domain }) as ExecState
            )));
        }

        if self.cache_contains_fresh(&domain) {
            context.response = Some(build_response_from_request(
                &context.request,
                ResponseCode::NoError,
            ));
            return Ok(ExecStep::Stop);
        }

        let Some(next) = next else {
            // No recursive runner available (non-sequence invocation), degrade
            // to pass-through behavior.
            return Ok(ExecStep::Next);
        };

        self.run_concurrent_reference(context, next, domain).await
    }

    async fn run_concurrent_reference(
        &self,
        context: &mut DnsContext,
        next: RecursiveHandle,
        domain: String,
    ) -> Result<ExecStep> {
        let mut preferred_ctx = context.clone_for_subquery();
        if !set_first_query_type(&mut preferred_ctx, self.preferred_type) {
            return Ok(ExecStep::Next);
        }
        let original_ctx = context.clone_for_subquery();

        let mut preferred_task = tokio::spawn(run_reference_sub_query(
            next.clone(),
            preferred_ctx,
            self.preferred_type,
            self.cache.clone(),
            domain.clone(),
        ));
        let mut original_task = tokio::spawn(run_original_sub_query(next, original_ctx));

        tokio::select! {
            preferred_joined = &mut preferred_task => {
                let should_block = preferred_joined.unwrap_or(false);
                if should_block {
                    original_task.abort();
                    context.response = Some(build_response_from_request(
                        &context.request,
                        ResponseCode::NoError,
                    ));
                    return Ok(ExecStep::Stop);
                }

                let original_outcome = original_task.await.map_err(|e| {
                    DnsError::plugin(format!("dual_selector original task join failed: {}", e))
                })?;
                return Self::apply_original_outcome(context, original_outcome);
            }
            original_joined = &mut original_task => {
                let original_outcome = original_joined.map_err(|e| {
                    DnsError::plugin(format!("dual_selector original task join failed: {}", e))
                })?;

                let should_block = match tokio::time::timeout(REFERENCE_WAIT_TIMEOUT, &mut preferred_task).await {
                    Ok(Ok(should_block)) => should_block,
                    _ => false,
                };

                if should_block {
                    context.response = Some(build_response_from_request(
                        &context.request,
                        ResponseCode::NoError,
                    ));
                    return Ok(ExecStep::Stop);
                }

                return Self::apply_original_outcome(context, original_outcome);
            }
        }
    }

    fn apply_original_outcome(
        context: &mut DnsContext,
        outcome: OriginalQueryOutcome,
    ) -> Result<ExecStep> {
        context.replace_with_subquery_result(outcome.context);
        if let Some(err) = outcome.error {
            return Err(err);
        }
        Ok(ExecStep::Stop)
    }

    fn cache_preferred(&self, domain: &str) {
        let expire_at = AppClock::elapsed_millis().saturating_add(CACHE_TTL_MS);
        self.cache.insert(domain.to_string(), expire_at);
    }

    fn cache_contains_fresh(&self, domain: &str) -> bool {
        let now = AppClock::elapsed_millis();
        self.cache
            .get(domain)
            .is_some_and(|entry| *entry.value() > now)
    }

    fn maybe_cleanup(&self) {
        let op = self.ops.fetch_add(1, Ordering::Relaxed) + 1;
        if op % CLEANUP_INTERVAL != 0 {
            return;
        }

        let now = AppClock::elapsed_millis();
        self.cache.retain(|_, expire_at| *expire_at > now);
    }
}

async fn run_reference_sub_query(
    next: RecursiveHandle,
    mut context: DnsContext,
    preferred_type: RecordType,
    cache: Arc<DashMap<String, u64>>,
    domain: String,
) -> bool {
    let Ok(Ok(())) = tokio::time::timeout(SUB_QUERY_TIMEOUT, next.exec_next(&mut context)).await
    else {
        return false;
    };

    let has_preferred_answer = context.response.as_ref().is_some_and(|resp| {
        resp.answers()
            .iter()
            .any(|rr| rr.record_type() == preferred_type)
    });
    if has_preferred_answer {
        let expire_at = AppClock::elapsed_millis().saturating_add(CACHE_TTL_MS);
        cache.insert(domain, expire_at);
        return true;
    }
    false
}

async fn run_original_sub_query(
    next: RecursiveHandle,
    mut context: DnsContext,
) -> OriginalQueryOutcome {
    let error = match tokio::time::timeout(SUB_QUERY_TIMEOUT, next.exec_next(&mut context)).await {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(_) => Some(DnsError::plugin(
            "dual_selector original sub-query timed out",
        )),
    };
    OriginalQueryOutcome { context, error }
}

fn set_first_query_type(context: &mut DnsContext, qtype: RecordType) -> bool {
    let Some(query) = context.request.queries_mut().first_mut() else {
        return false;
    };
    query.query_type = qtype;
    true
}

#[derive(Debug, Clone)]
pub struct PreferIpv4Factory;

#[derive(Debug, Clone)]
pub struct PreferIpv6Factory;

register_plugin_factory!("prefer_ipv4", PreferIpv4Factory {});
register_plugin_factory!("prefer_ipv6", PreferIpv6Factory {});

impl PluginFactory for PreferIpv4Factory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(DualSelector {
            tag: plugin_config.tag.clone(),
            preferred_type: RecordType::A,
            cache: Arc::new(DashMap::new()),
            ops: AtomicU64::new(0),
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
            preferred_type: RecordType::A,
            cache: Arc::new(DashMap::new()),
            ops: AtomicU64::new(0),
        })))
    }
}

impl PluginFactory for PreferIpv6Factory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(DualSelector {
            tag: plugin_config.tag.clone(),
            preferred_type: RecordType::AAAA,
            cache: Arc::new(DashMap::new()),
            ops: AtomicU64::new(0),
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
            preferred_type: RecordType::AAAA,
            cache: Arc::new(DashMap::new()),
            ops: AtomicU64::new(0),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ExecFlowState;
    use crate::plugin::executor::recursive::{NextChainRunner, RecursiveHandle};
    use crate::plugin::registry::PluginRegistry;
    use ahash::{AHashMap, AHashSet};
    use async_trait::async_trait;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use tokio::time::sleep;

    #[derive(Debug)]
    struct MockRunner {
        preferred_type: RecordType,
        has_preferred_answer: bool,
        preferred_delay: Duration,
        original_delay: Duration,
    }

    #[async_trait]
    impl NextChainRunner for MockRunner {
        async fn run_from(
            self: Arc<Self>,
            context: &mut DnsContext,
            _start_pc: usize,
        ) -> Result<()> {
            let query = context.request.query().expect("query must exist");
            let qtype = query.query_type;
            let qname = query.name().clone();

            if qtype == self.preferred_type {
                sleep(self.preferred_delay).await;
            } else {
                sleep(self.original_delay).await;
            }

            let mut response = build_response_from_request(&context.request, ResponseCode::NoError);
            let should_answer = if qtype == self.preferred_type {
                self.has_preferred_answer
            } else {
                true
            };
            if should_answer {
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
            }
            context.response = Some(response);
            Ok(())
        }
    }

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
            cache: Arc::new(DashMap::new()),
            ops: AtomicU64::new(0),
        }
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
    async fn blocks_non_preferred_when_reference_has_preferred_answer() {
        let selector = make_selector(RecordType::A);
        let runner = Arc::new(MockRunner {
            preferred_type: RecordType::A,
            has_preferred_answer: true,
            preferred_delay: Duration::from_millis(10),
            original_delay: Duration::from_millis(20),
        });
        let handle = RecursiveHandle::new(runner, 0);
        let mut context = make_context(RecordType::AAAA);

        let step = selector
            .execute_with_handle(&mut context, Some(handle))
            .await
            .unwrap();
        assert!(matches!(step, ExecStep::Stop));
        assert!(!has_answer_of_type(&context, RecordType::AAAA));
    }

    #[tokio::test]
    async fn passes_non_preferred_when_reference_has_no_preferred_answer() {
        let selector = make_selector(RecordType::A);
        let runner = Arc::new(MockRunner {
            preferred_type: RecordType::A,
            has_preferred_answer: false,
            preferred_delay: Duration::from_millis(10),
            original_delay: Duration::from_millis(20),
        });
        let handle = RecursiveHandle::new(runner, 0);
        let mut context = make_context(RecordType::AAAA);

        let step = selector
            .execute_with_handle(&mut context, Some(handle))
            .await
            .unwrap();
        assert!(matches!(step, ExecStep::Stop));
        assert!(has_answer_of_type(&context, RecordType::AAAA));
    }

    #[tokio::test]
    async fn late_reference_still_warms_cache_for_next_request() {
        let selector = make_selector(RecordType::A);
        let runner = Arc::new(MockRunner {
            preferred_type: RecordType::A,
            has_preferred_answer: true,
            preferred_delay: Duration::from_millis(700),
            original_delay: Duration::from_millis(10),
        });
        let handle = RecursiveHandle::new(runner, 0);

        let mut first = make_context(RecordType::AAAA);
        let step = selector
            .execute_with_handle(&mut first, Some(handle))
            .await
            .unwrap();
        assert!(matches!(step, ExecStep::Stop));
        assert!(has_answer_of_type(&first, RecordType::AAAA));

        sleep(Duration::from_millis(900)).await;

        let mut second = make_context(RecordType::AAAA);
        let step2 = selector.execute(&mut second).await.unwrap();
        assert!(matches!(step2, ExecStep::Stop));
        assert!(!has_answer_of_type(&second, RecordType::AAAA));
    }
}
