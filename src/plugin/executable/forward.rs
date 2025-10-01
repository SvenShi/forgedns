/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use crate::config::config::PluginConfig;
use crate::core::context::DnsContext;
use crate::pkg::upstream::{UpStream, UpStreamBuilder, UpstreamConfig};
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, error, info};

/// A single-upstream DNS forwarder
/// - Forwards DNS queries to the configured upstream
#[allow(unused)]
pub struct SingleDnsForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Upstream DNS resolver
    pub upstream: Box<dyn UpStream>,
}

#[async_trait]
impl Plugin for SingleDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        info!("Initializing SingleDnsForwarder...");
        self.upstream.connect().await;
        info!("SingleDnsForwarder initialized successfully");
    }

    async fn execute(&self, context: &mut DnsContext) {
        match self.upstream.query(context).await {
            Ok(res) => {
                context.response = Some(res);
            }
            Err(e) => {
                error!("DNS request failed: {e}, {:?}", context);
                context.response = None;
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
            info!(
                "Creating SingleDnsForwarder with upstream {:?}",
                forward_config.upstreams[0]
            );

            Box::new(SingleDnsForwarder {
                tag: plugin_info.tag.clone(),
                upstream: UpStreamBuilder::with_upstream_config(&forward_config.upstreams[0]),
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
