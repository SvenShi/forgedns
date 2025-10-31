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
use crate::plugin::executor::Executor;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info, warn};
use crate::plugin::executor::sequence::chain::ChainNode;

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

    async fn destroy(&mut self) {}
}

#[async_trait]
impl Executor for SingleDnsForwarder {
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<ChainNode>>) {
        match self.upstream.query(context.request.clone()).await {
            Ok(res) => {
                context.response = Some(res);
            }
            Err(e) => {
                // Log error (includes timeouts and other failures)
                warn!(
                    "DNS query failed - source: {}, queries: {:?}, id: {}, reason: {}",
                    context.src_addr,
                    context.request.queries(),
                    context.request.id(),
                    e
                );
            }
        }
        continue_next!(next, context);
    }
}

#[derive(Debug)]
pub struct ConcurrentForwarder {
    /// Plugin identifier
    pub tag: String,

    pub concurrent: usize,

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

    async fn destroy(&mut self) {}
}

#[async_trait]
impl Executor for ConcurrentForwarder {
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<ChainNode>>) {
        let mut join_set = JoinSet::new();

        for i in 0..self.concurrent {
            let upstream = self.upstreams[i].clone();
            let message = context.request.clone();
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

        while let Some(Ok(res)) = join_set.join_next().await {
            match res {
                Ok(response) => {
                    join_set.abort_all();
                    context.response = Some(response);
                    break;
                }
                Err(e) => {
                    warn!("DNS query failed: {}", e);
                }
            }
        }

        continue_next!(next, context);
    }
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
            let concurrent = forward_config
                .concurrent
                .unwrap_or(forward_config.upstreams.len());

            let mut upstreams = Vec::with_capacity(concurrent);

            for upstream_config in forward_config.upstreams {
                upstreams.push(UpstreamBuilder::with_upstream_config(upstream_config).into());
            }

            // Multi-upstream configuration (not yet implemented)
            Ok(UninitializedPlugin::Executor(Box::new(
                ConcurrentForwarder {
                    tag: plugin_config.tag.clone(),
                    concurrent,
                    upstreams,
                },
            )))
        }
    }
}
