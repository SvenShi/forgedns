/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
pub mod chain;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::DnsError;
use crate::plugin::executor::sequence::chain::ChainNode;
use crate::plugin::executor::Executor;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use async_trait::async_trait;
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Deserialize)]
struct Rule {
    #[serde(default)]
    matches: Option<Vec<String>>,
    exec: Option<String>,
}

#[derive(Debug)]
pub struct Sequence {
    head: Arc<ChainNode>,
}

#[async_trait]
impl Plugin for Sequence {
    fn tag(&self) -> &str {
        todo!()
    }

    async fn init(&mut self) {
        todo!()
    }

    async fn destroy(&mut self) {
        todo!()
    }
}

#[async_trait]
impl Executor for Sequence {
    async fn execute(&self, context: &mut DnsContext, _next: Option<&Arc<ChainNode>>) {
        self.head.next(context).await;
    }
}

#[derive(Debug)]
pub struct SequenceFactory {}

impl PluginFactory for SequenceFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> crate::core::error::Result<UninitializedPlugin> {
        let rules = serde_yml::from_value::<Vec<Rule>>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("sequence requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse sequence config: {}", e)))?;

        let mut next_node: Option<Arc<ChainNode>> = None;

        for rule in rules.iter().rev() {
            if rule.exec.is_none() && rule.matches.is_none() {
                panic!("sequence rule cannot be empty");
            }
            if let Some(exec) = &rule.exec {
                if let Some(plugin) = registry.get_plugin(&exec) {
                    let executor = plugin.to_executor();
                    let node = ChainNode::new(executor, next_node.clone());
                    next_node = Some(Arc::new(node));
                } else {
                    panic!("plugin does not exist for {}", exec);
                }
            }
        }

        Ok(UninitializedPlugin::Executor(Box::new(
            Sequence {
                head: next_node.unwrap().clone(),
            },
        )))
    }

    fn validate_config(&self, _plugin_config: &PluginConfig) -> crate::core::error::Result<()> {
        Ok(())
    }

    fn get_dependencies(&self, _plugin_config: &PluginConfig) -> Vec<String> {
        vec![]
    }
}
