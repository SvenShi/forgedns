/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::UninitializedPlugin;
use crate::plugin::executor::sequence::Rule;
use crate::plugin::executor::sequence::{SequenceRef, parse_sequence_ref};
use crate::plugin::executor::{ExecResult, Executor};
use crate::plugin::matcher::Matcher;
use crate::plugin::{PluginHolder, PluginRegistry};
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::debug;

#[async_trait]
pub trait ChainNode: Debug + Send + Sync + 'static {
    async fn next(&self, context: &mut DnsContext) -> ExecResult;

    fn set_next(&mut self, next: Option<Arc<dyn ChainNode>>);
}

#[derive(Debug)]
pub struct DirectChainNode {
    executor: Arc<dyn Executor>,
    next: Option<Arc<dyn ChainNode>>,
}

#[async_trait]
impl ChainNode for DirectChainNode {
    async fn next(&self, context: &mut DnsContext) -> ExecResult {
        // Pass immediate next (if any) to current executor
        self.executor.execute(context, self.next.as_ref()).await
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
    async fn next(&self, context: &mut DnsContext) -> ExecResult {
        for matcher in &self.matchers {
            if !matcher.is_match(context).await {
                debug!(
                    "MatcherChainNode: context did not match, skipping executor, matcher: {}",
                    matcher.tag()
                );
                return continue_next!(self.next.as_ref(), context);
            }
        }

        // Pass immediate next (if any) to current executor
        self.executor.execute(context, self.next.as_ref()).await
    }
    fn set_next(&mut self, next: Option<Arc<dyn ChainNode>>) {
        self.next = next;
    }
}

pub struct ChainBuilder {
    nodes: Vec<Box<dyn ChainNode>>,
    registry: Arc<PluginRegistry>,
    sequence_tag: String,
    node_index: usize,
    quick_setup_executors: Vec<Arc<dyn Executor>>,
    quick_setup_matchers: Vec<Arc<dyn Matcher>>,
}
impl ChainBuilder {
    pub fn new(registry: Arc<PluginRegistry>, sequence_tag: impl Into<String>) -> Self {
        ChainBuilder {
            nodes: Vec::new(),
            registry,
            sequence_tag: sequence_tag.into(),
            node_index: 0,
            quick_setup_executors: Vec::new(),
            quick_setup_matchers: Vec::new(),
        }
    }

    pub async fn append_node(&mut self, rule: &Rule) -> Result<()> {
        let node_index = self.node_index;
        let node = self.create_chain_node(rule, node_index).await?;
        self.nodes.push(node);
        self.node_index += 1;
        Ok(())
    }

    pub fn build(
        mut self,
    ) -> (
        Option<Arc<dyn ChainNode>>,
        Vec<Arc<dyn Executor>>,
        Vec<Arc<dyn Matcher>>,
    ) {
        let mut next: Option<Arc<dyn ChainNode>> = None;
        for mut node in self.nodes.into_iter().rev() {
            node.set_next(next.clone());
            next = Some(Arc::from(node));
        }
        (
            next,
            std::mem::take(&mut self.quick_setup_executors),
            std::mem::take(&mut self.quick_setup_matchers),
        )
    }

    async fn create_chain_node(
        &mut self,
        rule: &Rule,
        node_index: usize,
    ) -> Result<Box<dyn ChainNode>> {
        if let Some(exec) = &rule.exec {
            let executor = self.resolve_executor_ref(exec, node_index).await?;
            if let Some(matches) = &rule.matches {
                let mut matchers = Vec::with_capacity(matches.len());
                for (match_index, matcher_expr) in matches.iter().enumerate() {
                    matchers.push(
                        self.resolve_matcher_ref(matcher_expr, node_index, match_index)
                            .await?,
                    );
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
            Err(DnsError::plugin("rule must have 'exec' field"))
        }
    }

    async fn resolve_executor_ref(
        &mut self,
        expr: &str,
        node_index: usize,
    ) -> Result<Arc<dyn Executor>> {
        match parse_sequence_ref(expr)? {
            SequenceRef::PluginTag(tag) => {
                let plugin = self.registry.get_plugin(&tag).ok_or_else(|| {
                    DnsError::plugin(format!("plugin does not exist for {}", tag))
                })?;
                Ok(plugin.to_executor())
            }
            SequenceRef::QuickSetup { plugin_type, param } => {
                let quick_tag = format!("@qs:exec:{}:{}", self.sequence_tag, node_index);
                let uninitialized = self.registry.quick_setup(
                    &plugin_type,
                    &quick_tag,
                    param,
                    self.registry.clone(),
                )?;
                let executor = uninitialized.init_and_wrap().await;
                let executor = match executor {
                    PluginHolder::Executor(executor) => executor,
                    _ => panic!("Plugin {} is not executor", plugin_type),
                };
                self.quick_setup_executors.push(executor.clone());
                Ok(executor)
            }
        }
    }

    async fn resolve_matcher_ref(
        &mut self,
        expr: &str,
        node_index: usize,
        match_index: usize,
    ) -> Result<Arc<dyn Matcher>> {
        match parse_sequence_ref(expr)? {
            SequenceRef::PluginTag(tag) => {
                let plugin = self.registry.get_plugin(&tag).ok_or_else(|| {
                    DnsError::plugin(format!("matcher plugin does not exist for {}", tag))
                })?;
                Ok(plugin.to_matcher())
            }
            SequenceRef::QuickSetup { plugin_type, param } => {
                let quick_tag = format!(
                    "@qs:match:{}:{}:{}",
                    self.sequence_tag, node_index, match_index
                );
                let uninitialized: UninitializedPlugin = self.registry.quick_setup(
                    &plugin_type,
                    &quick_tag,
                    param,
                    self.registry.clone(),
                )?;
                let matcher = uninitialized.init_and_wrap().await;
                let matcher = match matcher {
                    PluginHolder::Matcher(matcher) => matcher,
                    _ => panic!("Plugin {} is not matcher", plugin_type),
                };
                self.quick_setup_matchers.push(matcher.clone());
                Ok(matcher)
            }
        }
    }
}
