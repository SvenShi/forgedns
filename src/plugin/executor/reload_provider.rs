// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `reload_provider` executor plugin.
//!
//! This executor reloads one or more provider plugins in place using their
//! existing runtime configuration, without rebuilding the full application.
//!
//! Provider reload is resolved through the process-wide runtime manager. During
//! a runtime swap, an in-flight request from an older runtime reloads providers
//! in the current runtime; if no runtime is currently installed, execution
//! fails with the manager-level initialization error.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde_yaml_ng::Value;
use tracing::info;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::metrics::{
    MetricLabel, MetricSample, MetricSink, MetricSource, register_metric_source,
    unregister_metric_source,
};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::matcher::matcher_utils::{
    parse_quick_setup_rules, parse_rules_from_value, provider_dependency_specs, split_rule_sources,
};
use crate::plugin::{self, Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;

#[derive(Debug)]
struct ReloadProviderMetrics {
    tag: String,
    reload_total: AtomicU64,
    reload_error_total: AtomicU64,
}

impl ReloadProviderMetrics {
    fn new(tag: String) -> Self {
        Self {
            tag,
            reload_total: AtomicU64::new(0),
            reload_error_total: AtomicU64::new(0),
        }
    }
}

impl MetricSource for ReloadProviderMetrics {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn plugin_type(&self) -> &'static str {
        "reload_provider"
    }

    fn collect(&self, sink: &mut dyn MetricSink) {
        let labels = [MetricLabel::new("plugin_tag", self.tag.as_str())];
        sink.emit(MetricSample::counter(
            "reload_provider_reload_total",
            "Total provider reload attempts triggered by this executor.",
            &labels,
            self.reload_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "reload_provider_reload_error_total",
            "Total provider reload attempts that failed.",
            &labels,
            self.reload_error_total.load(Ordering::Relaxed),
        ));
    }
}

#[derive(Debug)]
struct ReloadProviderExecutor {
    tag: String,
    provider_tags: Vec<String>,
    metrics: Arc<ReloadProviderMetrics>,
}

#[async_trait]
impl Plugin for ReloadProviderExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        register_metric_source(self.metrics.clone())
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);
        Ok(())
    }
}

#[async_trait]
impl Executor for ReloadProviderExecutor {
    #[hotpath::measure]
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        for provider_tag in &self.provider_tags {
            info!(
                plugin = %self.tag,
                provider = %provider_tag,
                "reload_provider executor reloading provider"
            );
            self.metrics.reload_total.fetch_add(1, Ordering::Relaxed);
            if let Err(err) = plugin::reload_provider(provider_tag).await {
                self.metrics
                    .reload_error_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
        }
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
#[plugin_factory("reload_provider")]
pub struct ReloadProviderFactory;

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
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        let provider_tags = parse_provider_tags_from_value(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(
            ReloadProviderExecutor {
                tag: plugin_config.tag.clone(),
                provider_tags,
                metrics: Arc::new(ReloadProviderMetrics::new(plugin_config.tag.clone())),
            },
        )))
    }

    fn quick_setup(&self, tag: &str, param: Option<String>) -> Result<UninitializedPlugin> {
        let provider_tags = parse_provider_tags(parse_quick_setup_rules(param)?)?;
        Ok(UninitializedPlugin::Executor(Box::new(
            ReloadProviderExecutor {
                tag: tag.to_string(),
                provider_tags,
                metrics: Arc::new(ReloadProviderMetrics::new(tag.to_string())),
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
