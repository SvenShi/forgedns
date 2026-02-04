/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::PluginRegistry;
use crate::plugin::executor::Executor;
use crate::plugin::executor::sequence::Rule;
use crate::plugin::matcher::Matcher;
use async_trait::async_trait;
use tracing::debug;
use std::fmt::Debug;
use std::sync::Arc;

#[async_trait]
pub trait ChainNode: Debug + Send + Sync + 'static {
    async fn next(&self, context: &mut DnsContext);

    fn set_next(&mut self, next: Option<Arc<dyn ChainNode>>);
}

#[derive(Debug)]
pub struct DirectChainNode {
    executor: Arc<dyn Executor>,
    next: Option<Arc<dyn ChainNode>>,
}

#[async_trait]
impl ChainNode for DirectChainNode {
    async fn next(&self, context: &mut DnsContext) {
        // Pass immediate next (if any) to current executor
        self.executor.execute(context, self.next.as_ref()).await;
    }
    
    fn set_next(&mut self, next: Option<Arc<dyn ChainNode>>) {
        self.next = next;
    }
}

#[derive(Debug)]
pub struct MatcherChainNode {
    matchers: Vec<Arc<dyn Matcher>>,
    executor: Arc<dyn Executor>,
    next: Option<Arc<dyn ChainNode>>,
}

#[async_trait]
impl ChainNode for MatcherChainNode {
    async fn next(&self, context: &mut DnsContext) {
        for matcher in &self.matchers {
            if !matcher.is_match(context).await {
                debug!("MatcherChainNode: context did not match, skipping executor, matcher: {}", matcher.tag());
                return;
            }
        }

        // Pass immediate next (if any) to current executor
        self.executor.execute(context, self.next.as_ref()).await;
    }
    fn set_next(&mut self, next: Option<Arc<dyn ChainNode>>) {
        self.next = next;
    }
}
pub struct ChainBuilder {
    nodes: Vec<Box<dyn ChainNode>>,
    registry: Arc<PluginRegistry>,
}
impl ChainBuilder {
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        ChainBuilder {
            nodes: Vec::new(),
            registry,
        }
    }

    pub fn append_node(&mut self, rule: &Rule) -> Result<()> {
        let node = self.create_chain_node(rule)?;
        self.nodes.push(node);
        Ok(())
    }

    pub fn build(self) -> Option<Arc<dyn ChainNode>> {
        let mut next: Option<Arc<dyn ChainNode>> = None;
        for mut node in self.nodes.into_iter().rev() {
            node.set_next(next.clone());
            next = Some(Arc::from(node));
        }
        next
    }

    fn create_chain_node(&self, rule: &Rule) -> Result<Box<dyn ChainNode>> {
        if let Some(exec) = &rule.exec {
            if let Some(plugin) = self.registry.get_plugin(&exec) {
                let executor = plugin.to_executor();
                if let Some(matches) = &rule.matches {
                    let mut matchers = Vec::with_capacity(matches.len());
                    for matcher_tag in matches {
                        let matcher_plugin = self.registry.get_plugin(matcher_tag).ok_or_else(|| {
                            DnsError::plugin(format!(
                                "matcher plugin does not exist for {}",
                                matcher_tag
                            ))
                        })?;
                        matchers.push(matcher_plugin.to_matcher());
                    }
                    let node = MatcherChainNode {
                        matchers,
                        executor,
                        next: None,
                    };
                    Ok(Box::new(node))
                } else {
                    let node = DirectChainNode {
                        executor,
                        next: None,
                    };
                    Ok(Box::new(node))
                }
            } else {
                Err(DnsError::plugin(format!(
                    "plugin does not exist for {}",
                    exec
                )))
            }
        } else {
            Err(DnsError::plugin("rule must have 'exec' field"))
        }
    }
}
