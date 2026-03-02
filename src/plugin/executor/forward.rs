/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS forwarding plugin
//!
//! Forwards DNS queries to configured upstream resolvers.
//! Currently, supports single-upstream forwarding with timeout handling.
//! Multi-upstream load balancing is planned for future implementation.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::network::upstream::{ConnectionInfo, Upstream, UpstreamBuilder, UpstreamConfig};
use crate::plugin::executor::dual_selector::{ForwardProbeRequest, ForwardProbeResult};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info, warn};

const PROBE_WAIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Single-upstream DNS forwarder
///
/// Forwards DNS queries to a single configured upstream server.
/// Handles timeouts and logs errors appropriately.
#[allow(unused)]
#[derive(Debug)]
pub struct SingleDnsForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Upstream DNS resolver
    pub upstream: Box<dyn Upstream>,
}

#[async_trait]
impl Plugin for SingleDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        info!("DNS SingleDnsForwarder initialized tag: {}", self.tag);
    }

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for SingleDnsForwarder {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if let Some(probe) = context
            .get_attr::<ForwardProbeRequest>(DnsContext::ATTR_FORWARD_PROBE_REQUEST)
            .copied()
        {
            return self.execute_with_probe(context, probe).await;
        }
        self.execute_standard(context).await
    }
}

impl SingleDnsForwarder {
    #[inline]
    async fn execute_standard(&self, context: &mut DnsContext) -> Result<ExecStep> {
        match self.upstream.query(context.request.clone()).await {
            Ok(res) => {
                context.response = Some(res);
            }
            Err(e) => {
                warn!(
                    "DNS query failed - source: {}, queries: {:?}, id: {}, reason: {}",
                    context.src_addr,
                    context.request.queries(),
                    context.request.id(),
                    e
                );
                return Err(DnsError::plugin(format!(
                    "forward plugin '{}' query failed: {}",
                    self.tag, e
                )));
            }
        }
        Ok(ExecStep::Next)
    }

    async fn execute_with_probe(
        &self,
        context: &mut DnsContext,
        probe: ForwardProbeRequest,
    ) -> Result<ExecStep> {
        let mut preferred_request = context.request.clone();
        if !set_message_first_query_type(&mut preferred_request, probe.preferred_type) {
            return self.execute_standard(context).await;
        }
        let original_request = context.request.clone();

        let mut original_fut = std::pin::pin!(self.upstream.query(original_request));
        let mut preferred_fut = std::pin::pin!(self.upstream.query(preferred_request));
        let mut preferred_early: Option<Result<Message>> = None;

        let original_result = loop {
            tokio::select! {
                result = &mut original_fut => break result,
                result = &mut preferred_fut, if preferred_early.is_none() => {
                    preferred_early = Some(result);
                }
            }
        };

        match original_result {
            Ok(response) => {
                context.response = Some(response);
            }
            Err(e) => {
                let original_error = format!("forward plugin '{}' query failed: {}", self.tag, e);
                context.set_attr(
                    DnsContext::ATTR_FORWARD_PROBE_RESULT,
                    ForwardProbeResult {
                        preferred_has_answer: false,
                        preferred_error: Some("probe aborted due to original query failure".into()),
                        original_error: Some(original_error.clone()),
                    },
                );
                warn!(
                    "DNS query failed - source: {}, queries: {:?}, id: {}, reason: {}",
                    context.src_addr,
                    context.request.queries(),
                    context.request.id(),
                    e
                );
                return Err(DnsError::plugin(original_error));
            }
        }

        let preferred_result = if let Some(result) = preferred_early {
            Some(result)
        } else {
            match tokio::time::timeout(PROBE_WAIT_TIMEOUT, &mut preferred_fut).await {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        };

        let (preferred_has_answer, preferred_error) = match preferred_result {
            Some(Ok(response)) => (
                response_has_answer_of_type(&response, probe.preferred_type),
                None,
            ),
            Some(Err(e)) => {
                if event_enabled!(Level::DEBUG) {
                    debug!(
                        "forward plugin '{}' dual probe query failed: {}",
                        self.tag, e
                    );
                }
                (
                    false,
                    Some(format!(
                        "forward plugin '{}' probe query failed: {}",
                        self.tag, e
                    )),
                )
            }
            None => (
                false,
                Some(format!(
                    "forward plugin '{}' probe query timed out after {:?}",
                    self.tag, PROBE_WAIT_TIMEOUT
                )),
            ),
        };

        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer,
                preferred_error,
                original_error: None,
            },
        );
        Ok(ExecStep::Next)
    }
}

#[derive(Debug)]
pub struct ConcurrentForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Fixed active upstream fanout, computed at creation time.
    pub active_concurrent: usize,

    pub upstreams: Vec<Arc<dyn Upstream>>,
}

#[async_trait]
impl Plugin for ConcurrentForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        info!("DNS ConcurrentForwarder initialized tag: {}", self.tag);
    }

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for ConcurrentForwarder {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if let Some(probe) = context
            .get_attr::<ForwardProbeRequest>(DnsContext::ATTR_FORWARD_PROBE_REQUEST)
            .copied()
        {
            return self.execute_with_probe(context, probe).await;
        }
        self.execute_standard(context).await
    }
}

impl ConcurrentForwarder {
    async fn query_any_upstream(&self, request: Message) -> (Option<Message>, Option<String>) {
        let mut join_set = JoinSet::new();
        let mut last_error: Option<String> = None;

        for i in 0..self.active_concurrent {
            let upstream = self.upstreams[i].clone();
            let message = request.clone();
            join_set.spawn(async move {
                let result = upstream.query(message).await;
                if event_enabled!(Level::DEBUG) {
                    debug!(
                        "DNS ConcurrentForwarder received message {}, remote_addr: {}",
                        i,
                        upstream.connection_info().raw_addr
                    );
                }
                result
            });
        }

        while let Some(joined) = join_set.join_next().await {
            match joined {
                Ok(Ok(response)) => {
                    join_set.abort_all();
                    return (Some(response), None);
                }
                Ok(Err(e)) => {
                    warn!("DNS query failed: {}", e);
                    last_error = Some(e.to_string());
                }
                Err(e) => {
                    last_error = Some(format!("forward subtask join failed: {}", e));
                }
            }
        }

        (None, last_error)
    }

    async fn execute_standard(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let (response, last_error) = self.query_any_upstream(context.request.clone()).await;
        if let Some(response) = response {
            context.response = Some(response);
            return Ok(ExecStep::Next);
        }

        let err = last_error.unwrap_or_else(|| "no upstream response".to_string());
        warn!(
            "forward plugin '{}' failed across all concurrent upstreams: {}",
            self.tag, err
        );
        Err(DnsError::plugin(format!(
            "forward plugin '{}' failed across all concurrent upstreams: {}",
            self.tag, err
        )))
    }

    async fn execute_with_probe(
        &self,
        context: &mut DnsContext,
        probe: ForwardProbeRequest,
    ) -> Result<ExecStep> {
        let mut preferred_request = context.request.clone();
        if !set_message_first_query_type(&mut preferred_request, probe.preferred_type) {
            return self.execute_standard(context).await;
        }
        let original_request = context.request.clone();

        let mut original_fut = std::pin::pin!(self.query_any_upstream(original_request));
        let mut preferred_fut = std::pin::pin!(self.query_any_upstream(preferred_request));
        let mut preferred_early: Option<(Option<Message>, Option<String>)> = None;

        let original_outcome = loop {
            tokio::select! {
                result = &mut original_fut => break result,
                result = &mut preferred_fut, if preferred_early.is_none() => {
                    preferred_early = Some(result);
                }
            }
        };

        let (original_response, original_error_raw) = original_outcome;
        let Some(response) = original_response else {
            let err = original_error_raw.unwrap_or_else(|| "no upstream response".to_string());
            context.set_attr(
                DnsContext::ATTR_FORWARD_PROBE_RESULT,
                ForwardProbeResult {
                    preferred_has_answer: false,
                    preferred_error: Some("probe aborted due to original query failure".into()),
                    original_error: Some(format!(
                        "forward plugin '{}' query failed: {}",
                        self.tag, err
                    )),
                },
            );
            return Err(DnsError::plugin(format!(
                "forward plugin '{}' query failed: {}",
                self.tag, err
            )));
        };
        context.response = Some(response);

        let preferred_outcome = if let Some(result) = preferred_early {
            Some(result)
        } else {
            match tokio::time::timeout(PROBE_WAIT_TIMEOUT, &mut preferred_fut).await {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        };

        let (preferred_has_answer, preferred_error) =
            if let Some((Some(response), _)) = preferred_outcome {
                (
                    response_has_answer_of_type(&response, probe.preferred_type),
                    None,
                )
            } else if let Some((None, err)) = preferred_outcome {
                if event_enabled!(Level::DEBUG) {
                    if let Some(err) = err.as_ref() {
                        debug!(
                            "forward plugin '{}' dual probe query failed: {}",
                            self.tag, err
                        );
                    }
                }
                (
                    false,
                    Some(err.unwrap_or_else(|| {
                        format!(
                            "forward plugin '{}' probe query failed: no upstream response",
                            self.tag
                        )
                    })),
                )
            } else {
                (
                    false,
                    Some(format!(
                        "forward plugin '{}' probe query timed out after {:?}",
                        self.tag, PROBE_WAIT_TIMEOUT
                    )),
                )
            };

        context.set_attr(
            DnsContext::ATTR_FORWARD_PROBE_RESULT,
            ForwardProbeResult {
                preferred_has_answer,
                preferred_error,
                original_error: None,
            },
        );

        Ok(ExecStep::Next)
    }
}

#[inline]
fn set_message_first_query_type(message: &mut Message, qtype: RecordType) -> bool {
    let Some(query) = message.queries_mut().first_mut() else {
        return false;
    };
    query.query_type = qtype;
    true
}

#[inline]
fn response_has_answer_of_type(message: &Message, qtype: RecordType) -> bool {
    message
        .answers()
        .iter()
        .any(|answer| answer.record_type() == qtype)
}

fn parse_forward_config(plugin_config: &PluginConfig) -> Result<ForwardConfig> {
    let cfg = plugin_config.args.clone().ok_or_else(|| {
        DnsError::plugin("forward plugin requires 'concurrent' and 'upstreams' configuration")
    })?;
    let cfg = serde_yml::from_value::<ForwardConfig>(cfg)
        .map_err(|e| DnsError::plugin(format!("failed to parse forward plugin config: {}", e)))?;
    validate_forward_config(&cfg)?;
    Ok(cfg)
}

fn validate_forward_config(cfg: &ForwardConfig) -> Result<()> {
    if cfg.upstreams.is_empty() {
        return Err(DnsError::plugin(
            "forward plugin requires at least one upstream",
        ));
    }

    for (idx, upstream) in cfg.upstreams.iter().enumerate() {
        validate_upstream_addr(&upstream.addr).map_err(|e| {
            DnsError::plugin(format!(
                "forward plugin upstream[{}] addr '{}' is invalid: {}",
                idx, upstream.addr, e
            ))
        })?;
    }

    Ok(())
}

fn validate_upstream_addr(addr: &str) -> std::result::Result<(), String> {
    ConnectionInfo::with_addr(addr)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn build_upstream(upstream_config: UpstreamConfig) -> Result<Box<dyn Upstream>> {
    UpstreamBuilder::with_upstream_config(upstream_config)
}

/// Forward plugin configuration
#[derive(Deserialize)]
#[allow(unused)]
pub struct ForwardConfig {
    /// Number of concurrent forwarding threads (not implemented yet)
    pub concurrent: Option<usize>,

    /// List of upstream DNS servers
    pub upstreams: Vec<UpstreamConfig>,
}

/// Factory for creating DNS forwarder plugins
#[derive(Debug)]
pub struct ForwardFactory;

register_plugin_factory!("forward", ForwardFactory {});

impl PluginFactory for ForwardFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let _ = parse_forward_config(plugin_config)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let forward_config = parse_forward_config(plugin_config)?;

        if forward_config.upstreams.len() == 1 {
            // Single upstream configuration
            let upstream_config = &forward_config.upstreams[0];
            info!(
                "Creating single DNS forwarder (tag: {}) with upstream: {}",
                plugin_config.tag, upstream_config.addr
            );

            Ok(UninitializedPlugin::Executor(Box::new(
                SingleDnsForwarder {
                    tag: plugin_config.tag.clone(),
                    upstream: build_upstream(upstream_config.clone())?,
                },
            )))
        } else {
            let active_concurrent = forward_config
                .concurrent
                .unwrap_or(forward_config.upstreams.len())
                .max(1)
                .min(forward_config.upstreams.len());

            let mut upstreams = Vec::with_capacity(forward_config.upstreams.len());

            for upstream_config in forward_config.upstreams {
                upstreams.push(build_upstream(upstream_config)?.into());
            }

            // Multi-upstream configuration (not yet implemented)
            Ok(UninitializedPlugin::Executor(Box::new(
                ConcurrentForwarder {
                    tag: plugin_config.tag.clone(),
                    active_concurrent,
                    upstreams,
                },
            )))
        }
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let param = param.ok_or_else(|| {
            DnsError::plugin("forward quick setup requires non-empty upstream address parameter")
        })?;
        validate_upstream_addr(&param).map_err(|e| {
            DnsError::plugin(format!(
                "forward quick setup upstream '{}' is invalid: {}",
                param, e
            ))
        })?;

        let upstream_config = UpstreamConfig {
            tag: None,
            addr: param,
            dial_addr: None,
            port: None,
            bootstrap: None,
            bootstrap_version: None,
            socks5: None,
            idle_timeout: None,
            max_conns: None,
            insecure_skip_verify: None,
            timeout: None,
            enable_pipeline: None,
            enable_http3: None,
            so_mark: None,
            bind_to_device: None,
        };

        Ok(UninitializedPlugin::Executor(Box::new(
            SingleDnsForwarder {
                tag: tag.to_string(),
                upstream: build_upstream(upstream_config)?,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ExecFlowState;
    use ahash::{AHashMap, AHashSet};
    use hickory_proto::op::{Query, ResponseCode};
    use hickory_proto::rr::Name;

    #[derive(Debug)]
    struct MockUpstream {
        connection_info: crate::network::upstream::ConnectionInfo,
        fail_message: Option<String>,
    }

    impl MockUpstream {
        fn ok() -> Self {
            Self {
                connection_info: crate::network::upstream::ConnectionInfo::with_addr("1.1.1.1")
                    .expect("mock upstream addr must be valid"),
                fail_message: None,
            }
        }

        fn fail(msg: &str) -> Self {
            Self {
                connection_info: crate::network::upstream::ConnectionInfo::with_addr("1.1.1.1")
                    .expect("mock upstream addr must be valid"),
                fail_message: Some(msg.to_string()),
            }
        }
    }

    #[async_trait]
    impl Upstream for MockUpstream {
        async fn inner_query(&self, request: Message) -> Result<Message> {
            if let Some(err) = self.fail_message.as_ref() {
                return Err(DnsError::plugin(err.clone()));
            }
            Ok(crate::core::dns_utils::build_response_from_request(
                &request,
                ResponseCode::NoError,
            ))
        }

        fn connection_info(&self) -> &crate::network::upstream::ConnectionInfo {
            &self.connection_info
        }
    }

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
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

    fn make_plugin_config(args: &str) -> PluginConfig {
        PluginConfig {
            tag: "forward-test".to_string(),
            plugin_type: "forward".to_string(),
            args: Some(serde_yml::from_str(args).unwrap()),
        }
    }

    #[tokio::test]
    async fn concurrent_returns_error_when_all_upstreams_fail() {
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 2,
            upstreams: vec![
                Arc::new(MockUpstream::fail("u1 fail")),
                Arc::new(MockUpstream::fail("u2 fail")),
            ],
        };

        let mut context = make_context();
        let err = forwarder.execute(&mut context).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("failed across all concurrent upstreams")
        );
        assert!(context.response.is_none());
    }

    #[test]
    fn validate_rejects_empty_upstreams() {
        let factory = ForwardFactory;
        let cfg = make_plugin_config("upstreams: []");
        let err = factory.validate_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("at least one upstream"));
    }

    #[test]
    fn validate_rejects_invalid_upstream_addr() {
        let factory = ForwardFactory;
        let cfg = make_plugin_config(
            r#"
upstreams:
  - addr: "udp://"
"#,
        );
        let err = factory.validate_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("is invalid"));
    }

    #[test]
    fn quick_setup_rejects_invalid_upstream_addr() {
        let factory = ForwardFactory;
        let result = factory.quick_setup(
            "forward-test",
            Some("udp://".to_string()),
            Arc::new(PluginRegistry::new()),
        );
        let err = match result {
            Ok(_) => panic!("expected quick_setup to fail for invalid upstream addr"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("is invalid"));
    }

    #[tokio::test]
    async fn concurrent_success_sets_response() {
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 1,
            upstreams: vec![Arc::new(MockUpstream::ok())],
        };

        let mut context = make_context();
        let step = forwarder.execute(&mut context).await.unwrap();
        assert!(matches!(step, ExecStep::Next));
        assert!(context.response.is_some());
    }
}
