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
use crate::network::upstream::{Upstream, UpstreamBuilder, UpstreamConfig};
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
        } else {
            warn!(
                "forward plugin '{}' failed across all concurrent upstreams: {}",
                self.tag,
                last_error.unwrap_or_else(|| "no upstream response".to_string())
            );
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
        // Parse and validate forward-specific configuration
        let _forward_config = match plugin_config.args.clone() {
            Some(args) => serde_yml::from_value::<ForwardConfig>(args).map_err(|e| {
                DnsError::plugin(format!("Failed to parse Forward plugin config: {}", e))
            })?,
            None => {
                return Err(DnsError::plugin(
                    "Forward plugin requires 'concurrent' and 'upstreams' configuration",
                ));
            }
        };

        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        // valid config
        let forward_config =
            serde_yml::from_value::<ForwardConfig>(plugin_config.args.clone().unwrap())?;

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
                    upstream: UpstreamBuilder::with_upstream_config(upstream_config.clone()),
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
                upstreams.push(UpstreamBuilder::with_upstream_config(upstream_config).into());
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
        if param.is_none() {
            return Err(DnsError::plugin(
                "forward quick setup requires non-empty upstream address parameter",
            ));
        }

        let upstream_config = UpstreamConfig {
            tag: None,
            addr: param.unwrap(),
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
                upstream: UpstreamBuilder::with_upstream_config(upstream_config),
            },
        )))
    }
}
