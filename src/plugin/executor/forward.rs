/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS forwarding plugin
//!
//! Forwards DNS queries to configured upstream resolvers.
//! Currently supports single-upstream forwarding with timeout handling.
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
use std::time::Duration;
use tracing::{error, info, warn};

/// Single-upstream DNS forwarder
///
/// Forwards DNS queries to a single configured upstream server.
/// Handles timeouts and logs errors appropriately.
#[allow(unused)]
#[derive(Debug)]
pub struct SingleDnsForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Request timeout duration
    pub timeout: Duration,

    /// Upstream DNS resolver
    pub upstream: Box<dyn Upstream>,
}

#[async_trait]
impl Plugin for SingleDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        info!(
            "DNS forwarder initialized (tag: {}, timeout: {:?})",
            self.tag, self.timeout
        );
    }

    async fn destroy(&mut self) {}
}

#[async_trait]
impl Executor for SingleDnsForwarder {
    async fn execute(&self, context: &mut DnsContext) {
        match tokio::time::timeout(self.timeout, self.upstream.query(context.request.clone())).await
        {
            Ok(Ok(res)) => {
                context.response = Some(res);
            }
            Ok(Err(e)) => {
                // Log error only on actual failures (not on timeouts)
                error!(
                    "DNS query failed - source: {}, queries: {:?}, id: {}, reason: {}",
                    context.src_addr,
                    context.request.queries(),
                    context.request.id(),
                    e
                );
            }
            Err(_) => {
                // Timeout - log as warning since this is less critical
                warn!(
                    "DNS query timeout ({:?}) - source: {}, queries: {:?}, id: {}",
                    self.timeout,
                    context.src_addr,
                    context.request.queries(),
                    context.request.id()
                );
            }
        }
    }
}

/// Forward plugin configuration
#[derive(Deserialize)]
#[allow(unused)]
pub struct ForwardConfig {
    /// Number of concurrent forwarding threads (not implemented yet)
    #[allow(unused_variables)]
    pub concurrent: Option<u32>,

    /// List of upstream DNS servers
    pub upstreams: Vec<UpstreamConfig>,
}

/// Factory for creating DNS forwarder plugins
#[derive(Debug)]
pub struct ForwardFactory;

impl PluginFactory for ForwardFactory {
    fn create(
        &self,
        plugin_info: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        // valid config
        let forward_config =
            serde_yml::from_value::<ForwardConfig>(plugin_info.args.clone().ok_or_else(|| {
                DnsError::plugin("Forward plugin requires configuration arguments")
            })?)
            .map_err(|e| {
                DnsError::plugin(format!("Failed to parse Forward plugin config: {}", e))
            })?;

        if forward_config.upstreams.len() == 1 {
            // Single upstream configuration
            let upstream_config = &forward_config.upstreams[0];
            info!(
                "Creating single DNS forwarder (tag: {}) with upstream: {}",
                plugin_info.tag, upstream_config.addr
            );

            Ok(UninitializedPlugin::Executor(Box::new(
                SingleDnsForwarder {
                    tag: plugin_info.tag.clone(),
                    timeout: upstream_config.timeout.unwrap_or(Duration::from_secs(5)),
                    upstream: UpstreamBuilder::with_upstream_config(&upstream_config),
                },
            )))
        } else {
            // Multi-upstream configuration (not yet implemented)
            Err(DnsError::plugin(format!(
                "Multi-upstream forwarding not yet implemented, {} upstreams configured",
                forward_config.upstreams.len()
            )))
        }
    }

    fn validate_config(&self, plugin_info: &PluginConfig) -> Result<()> {
        // Parse and validate forward-specific configuration
        let _forward_config = match plugin_info.args.clone() {
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
}
