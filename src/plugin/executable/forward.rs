/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS forwarding plugin
//!
//! Forwards DNS queries to configured upstream resolvers.
//! Currently supports single-upstream forwarding with timeout handling.
//! Multi-upstream load balancing is planned for future implementation.

use crate::config::config::PluginConfig;
use crate::core::context::DnsContext;
use crate::pkg::upstream::{UpStream, UpStreamBuilder, UpstreamConfig};
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;
use tracing::{error, info, warn};

/// Single-upstream DNS forwarder
///
/// Forwards DNS queries to a single configured upstream server.
/// Handles timeouts and logs errors appropriately.
#[allow(unused)]
pub struct SingleDnsForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Request timeout duration
    pub timeout: Duration,

    /// Upstream DNS resolver
    pub upstream: Box<dyn UpStream>,
}

#[async_trait]
impl Plugin for SingleDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        info!("DNS forwarder initialized (tag: {}, timeout: {:?})", self.tag, self.timeout);
    }

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

    fn main_type(&self) -> PluginMainType {
        PluginMainType::Executor {
            tag: self.tag.to_string(),
            type_name: "SingleDnsForwarder".to_string(),
        }
    }

    async fn destroy(&mut self) {}
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
pub struct ForwardFactory;

impl PluginFactory for ForwardFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let forward_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<ForwardConfig>(args)
                .unwrap_or_else(|e| panic!("Failed to parse Forward plugin config: {}", e)),
            None => {
                panic!("Forward plugin requires 'concurrent' and 'upstreams' configuration")
            }
        };
        
        if forward_config.upstreams.len() == 1 {
            // Single upstream configuration
            let upstream_config = &forward_config.upstreams[0];
            info!(
                "Creating single DNS forwarder (tag: {}) with upstream: {}",
                plugin_info.tag, upstream_config.addr
            );

            Box::new(SingleDnsForwarder {
                tag: plugin_info.tag.clone(),
                timeout: upstream_config.timeout.unwrap_or(Duration::from_secs(5)),
                upstream: UpStreamBuilder::with_upstream_config(&upstream_config),
            })
        } else {
            // Multi-upstream configuration (not yet implemented)
            warn!("Multi-upstream forwarding not yet implemented, {} upstreams configured", forward_config.upstreams.len());
            todo!("Concurrent DNS forwarding with multiple upstreams not implemented yet")
        }
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Executor {
            tag: tag.to_string(),
            type_name: "forward".to_string(),
        }
    }
}
