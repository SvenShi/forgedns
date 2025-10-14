// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::config::config::PluginConfig;
use crate::core::context::DnsContext;
use crate::pkg::upstream::{UpStream, UpStreamBuilder, UpstreamConfig};
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;
use tracing::{error, info, warn};

/// A single-upstream DNS forwarder
/// - Forwards DNS queries to the configured upstream
#[allow(unused)]
pub struct SingleDnsForwarder {
    /// Plugin identifier
    pub tag: String,

    pub timeout: Duration,

    /// Upstream DNS resolver
    pub upstream: Box<dyn UpStream>,
}

#[async_trait]
impl Plugin for SingleDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {}

    async fn execute(&self, context: &mut DnsContext) {
        match tokio::time::timeout(self.timeout, self.upstream.query(context)).await {
            Ok(Ok(res)) => {
                context.response = Some(res);
            }
            Ok(Err(e)) => {
                error!(
                    "DNS request failed source:{}, queries:{:?}, query_id: {} reason: {e}",
                    context.src_addr,
                    context.request.queries(),
                    context.request.id()
                );
            }
            Err(e) => {
                warn!("DNS forward time out {:?}", self.timeout)
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

/// Forwarder configuration
#[derive(Deserialize)]
#[allow(unused)]
pub struct ForwardConfig {
    /// Number of forwarding threads (not used by SingleDnsForwarder)
    #[allow(unused_variables)]
    pub concurrent: Option<u32>,

    /// Upstream DNS server list
    pub upstreams: Vec<UpstreamConfig>,
}

/// Factory for creating forwarder plugins
pub struct ForwardFactory;

impl PluginFactory for ForwardFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let forward_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<ForwardConfig>(args)
                .unwrap_or_else(|e| panic!("Failed to parse Forward config. Error: {}", e)),
            None => {
                panic!("Forward plugin requires 'concurrent' and 'upstreams' configuration")
            }
        };
        if forward_config.upstreams.len() == 1 {
            let upstream_config = &forward_config.upstreams[0];
            info!(
                "Creating SingleDnsForwarder with upstream {:?}",
                upstream_config
            );

            Box::new(SingleDnsForwarder {
                tag: plugin_info.tag.clone(),
                timeout: upstream_config.timeout.unwrap_or(Duration::from_secs(5)),
                upstream: UpStreamBuilder::with_upstream_config(&upstream_config),
            })
        } else {
            todo!("concurrent dns forward not implemented yet")
        }
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Executor {
            tag: tag.to_string(),
            type_name: "forward".to_string(),
        }
    }
}
