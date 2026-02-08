/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
pub mod chain;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::DnsError;
use crate::plugin::executor::Executor;
use crate::plugin::executor::sequence::chain::{ChainBuilder, ChainNode};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;

pub(super) fn parse_plugin_ref(raw: &str) -> crate::core::error::Result<Option<String>> {
    let raw = raw.trim();
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
        return Ok(Some(tag.to_string()));
    }
    Ok(None)
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
    head: Arc<dyn ChainNode>,
    rules: Vec<Rule>,
}

#[async_trait]
impl Plugin for Sequence {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for Sequence {
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<dyn ChainNode>>) {
        self.head.next(context).await;
        continue_next!(next, context);
    }
}

#[derive(Debug, Clone)]
pub struct SequenceFactory {}

register_plugin_factory!("sequence", SequenceFactory {});

impl PluginFactory for SequenceFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> crate::core::error::Result<()> {
        match plugin_config.args.clone() {
            Some(args) => {
                serde_yml::from_value::<Vec<Rule>>(args).map_err(|e| {
                    DnsError::plugin(format!("sequence config parsing failed: {}", e))
                })?;
                Ok(())
            }
            None => Err(DnsError::plugin(
                "sequence must configure 'listen' and 'entry' in config file",
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
                    if let Ok(Some(tag)) = parse_plugin_ref(&matcher) {
                        result.push(tag);
                    }
                }
            }
            if let Some(exec) = rule.exec {
                if let Ok(Some(tag)) = parse_plugin_ref(&exec) {
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
    ) -> crate::core::error::Result<UninitializedPlugin> {
        let rules = serde_yml::from_value::<Vec<Rule>>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("sequence requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse sequence config: {}", e)))?;

        let mut builder = ChainBuilder::new(registry);

        for rule in rules.iter() {
            if rule.exec.is_none() && rule.matches.is_none() {
                panic!("sequence rule cannot be empty");
            }
            builder
                .append_node(rule)
                .unwrap_or_else(|e| panic!("failed to create chain node: {}", e));
        }

        Ok(UninitializedPlugin::Executor(Box::new(Sequence {
            tag: plugin_config.tag.clone(),
            head: builder
                .build()
                .unwrap_or_else(|| panic!("sequence requires at least one rule")),
            rules,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_plugin_ref;

    #[test]
    fn parse_plain_as_builtin_syntax() {
        assert_eq!(parse_plugin_ref("forward").unwrap(), None);
    }

    #[test]
    fn parse_dollar_plugin_ref() {
        assert_eq!(
            parse_plugin_ref("$forward").unwrap(),
            Some("forward".into())
        );
    }

    #[test]
    fn parse_invalid_plugin_ref() {
        assert!(parse_plugin_ref("$").is_err());
        assert!(parse_plugin_ref("   ").is_err());
    }
}
