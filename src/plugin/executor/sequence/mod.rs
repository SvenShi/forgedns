/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
pub mod chain;

use crate::config::types::PluginConfig;
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::executor::sequence::chain::{ChainBuilder, ChainProgram};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::OnceCell;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SequenceRef {
    PluginTag(String),
    QuickSetup {
        plugin_type: String,
        param: Option<String>,
    },
}

pub(super) fn parse_sequence_ref(raw: &str) -> DnsResult<SequenceRef> {
    let raw = raw.trim_start();
    if raw.is_empty() {
        return Err(DnsError::plugin(format!(
            "invalid plugin reference: '{}'",
            raw
        )));
    }
    if let Some(tag) = raw.strip_prefix('$') {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(DnsError::plugin(format!(
                "invalid plugin reference: '{}'",
                raw
            )));
        }
        return Ok(SequenceRef::PluginTag(tag.to_string()));
    }

    let mut split = raw.splitn(2, char::is_whitespace);
    let plugin_type = split
        .next()
        .ok_or_else(|| DnsError::plugin(format!("invalid quick setup syntax: '{}'", raw)))?;
    let param = split.next().map(String::from);
    Ok(SequenceRef::QuickSetup {
        plugin_type: plugin_type.to_string(),
        param,
    })
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    #[serde(default)]
    matches: Option<Vec<String>>,
    exec: Option<String>,
}

#[derive(Debug)]
#[allow(unused)]
pub struct Sequence {
    tag: String,
    program: OnceCell<Arc<ChainProgram>>,
    rules: Vec<Rule>,
    registry: Arc<PluginRegistry>,
    quick_setup_executors: Vec<Arc<dyn Executor>>,
    quick_setup_matchers: Vec<Arc<dyn crate::plugin::matcher::Matcher>>,
}

#[async_trait]
impl Plugin for Sequence {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        let mut builder = ChainBuilder::new(self.registry.clone(), self.tag.clone());
        for rule in &self.rules {
            if let Err(e) = builder.append_node(rule).await {
                panic!(
                    "failed to build sequence quick setup chain, plugin '{}': {}",
                    self.tag, e
                );
            }
        }
        let (program, quick_setup_executors, quick_setup_matchers) = builder.build();
        self.program.set(program).unwrap();
        self.quick_setup_executors = quick_setup_executors;
        self.quick_setup_matchers = quick_setup_matchers;
    }

    async fn destroy(&self) {
        for executor in &self.quick_setup_executors {
            executor.destroy().await;
        }
        for matcher in &self.quick_setup_matchers {
            matcher.destroy().await;
        }
    }
}

#[async_trait]
impl Executor for Sequence {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> DnsResult<ExecStep> {
        self.program.get().unwrap().run(context).await?;
        if context.exec_flow_state == ExecFlowState::Running {
            context.exec_flow_state = ExecFlowState::ReachedTail;
        }
        Ok(ExecStep::Next)
    }
}

fn parse_control_flow_dependency(exec: &str) -> Option<String> {
    let mut split = exec.trim().splitn(2, char::is_whitespace);
    let op = split.next()?;
    let arg = split.next()?.trim();
    if arg.is_empty() {
        return None;
    }
    if op == "jump" || op == "goto" {
        if let Ok(SequenceRef::PluginTag(tag)) = parse_sequence_ref(arg) {
            return Some(tag);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct SequenceFactory {}

register_plugin_factory!("sequence", SequenceFactory {});

impl PluginFactory for SequenceFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        match plugin_config.args.clone() {
            Some(args) => {
                serde_yml::from_value::<Vec<Rule>>(args).map_err(|e| {
                    DnsError::plugin(format!("sequence config parsing failed: {}", e))
                })?;
                Ok(())
            }
            None => Err(DnsError::plugin(
                "sequence must configure 'exec' in config file",
            )),
        }
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        let mut result = Vec::new();

        let rules =
            serde_yml::from_value::<Vec<Rule>>(plugin_config.args.clone().unwrap()).unwrap();
        for rule in rules {
            if let Some(matches) = rule.matches {
                for matcher in matches {
                    if let Ok(SequenceRef::PluginTag(tag)) = parse_sequence_ref(&matcher) {
                        result.push(tag);
                    }
                }
            }
            if let Some(exec) = rule.exec {
                if let Some(tag) = parse_control_flow_dependency(&exec) {
                    result.push(tag);
                } else if let Ok(SequenceRef::PluginTag(tag)) = parse_sequence_ref(&exec) {
                    result.push(tag);
                }
            }
        }
        result
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = serde_yml::from_value::<Vec<Rule>>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("sequence requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse sequence config: {}", e)))?;

        if rules.is_empty() {
            return Err(DnsError::plugin("sequence requires at least one rule"));
        }

        for rule in &rules {
            if rule.exec.is_none() && rule.matches.is_none() {
                return Err(DnsError::plugin("sequence rule cannot be empty"));
            }
        }

        Ok(UninitializedPlugin::Executor(Box::new(Sequence {
            tag: plugin_config.tag.clone(),
            program: OnceCell::new(),
            rules,
            registry,
            quick_setup_executors: Vec::new(),
            quick_setup_matchers: Vec::new(),
        })))
    }
}
