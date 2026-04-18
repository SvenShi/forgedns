/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `reload_provider` executor plugin.
//!
//! This executor reloads one or more provider plugins in place using their
//! existing runtime configuration, without rebuilding the full application.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::matcher::matcher_utils::{
    parse_quick_setup_rules, parse_rules_from_value, provider_dependency_specs, split_rule_sources,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde_yaml_ng::Value;
use std::sync::Arc;
use tracing::info;

#[derive(Debug)]
struct ReloadProviderExecutor {
    tag: String,
    provider_tags: Vec<String>,
}

#[async_trait]
impl Plugin for ReloadProviderExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for ReloadProviderExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        for provider_tag in &self.provider_tags {
            info!(
                plugin = %self.tag,
                provider = %provider_tag,
                "reload_provider executor reloading provider"
            );
            context.registry.reload_provider(provider_tag).await?;
        }
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct ReloadProviderFactory;

register_plugin_factory!("reload_provider", ReloadProviderFactory {});

impl PluginFactory for ReloadProviderFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        parse_provider_tags_from_value(plugin_config.args.clone())
            .map(|provider_tags| provider_dependency_specs("args", provider_tags))
            .unwrap_or_default()
    }

    fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
        parse_quick_setup_rules(param.map(str::to_owned))
            .and_then(parse_provider_tags)
            .map(|provider_tags| provider_dependency_specs("provider_tags", provider_tags))
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let provider_tags = parse_provider_tags_from_value(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(
            ReloadProviderExecutor {
                tag: plugin_config.tag.clone(),
                provider_tags,
            },
        )))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let provider_tags = parse_provider_tags(parse_quick_setup_rules(param)?)?;
        Ok(UninitializedPlugin::Executor(Box::new(
            ReloadProviderExecutor {
                tag: tag.to_string(),
                provider_tags,
            },
        )))
    }
}

fn parse_provider_tags_from_value(args: Option<Value>) -> Result<Vec<String>> {
    parse_provider_tags(parse_rules_from_value(args)?)
}

fn parse_provider_tags(raw_rules: Vec<String>) -> Result<Vec<String>> {
    let (inline_rules, provider_tags, files) = split_rule_sources(raw_rules);
    if !inline_rules.is_empty() || !files.is_empty() {
        return Err(DnsError::plugin(
            "reload_provider only accepts provider references like '$provider_tag'",
        ));
    }
    if provider_tags.is_empty() {
        return Err(DnsError::plugin(
            "reload_provider requires at least one provider tag",
        ));
    }
    Ok(provider_tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_provider_tags_rejects_inline_rules() {
        let err = parse_provider_tags(vec!["example.com".to_string()])
            .expect_err("inline rules should be rejected");
        assert!(err.to_string().contains("only accepts provider references"));
    }

    #[test]
    fn parse_provider_tags_requires_at_least_one_provider() {
        let err = parse_provider_tags(vec![]).expect_err("empty provider list should be rejected");
        assert!(
            err.to_string()
                .contains("requires at least one provider tag")
        );
    }
}
