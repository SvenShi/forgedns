// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `sleep` executor plugin.
//!
//! Adds an intentional async delay in the sequence pipeline.
//!
//! This plugin is primarily for testing/benchmark experiments (for example,
//! validating fallback thresholds and concurrency behavior). It uses
//! `tokio::time::sleep`, so it does not block worker threads, but it does add
//! end-to-end request latency by design.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::parse_simple_duration;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;

#[derive(Debug, Clone, Deserialize, Default)]
struct SleepConfig {
    /// Duration in milliseconds.
    #[serde(default)]
    duration: u64,
}

#[derive(Debug)]
struct SleepExecutor {
    tag: String,
    duration: Duration,
}

#[async_trait]
impl Plugin for SleepExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for SleepExecutor {
    #[hotpath::measure]
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        if !self.duration.is_zero() {
            tokio::time::sleep(self.duration).await;
        }
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
#[plugin_factory("sleep")]
pub struct SleepFactory;

impl PluginFactory for SleepFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        let cfg = plugin_config
            .args
            .clone()
            .map(serde_yaml_ng::from_value::<SleepConfig>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse sleep config: {}", e)))?
            .unwrap_or_default();

        Ok(UninitializedPlugin::Executor(Box::new(SleepExecutor {
            tag: plugin_config.tag.clone(),
            duration: Duration::from_millis(cfg.duration),
        })))
    }

    fn quick_setup(&self, tag: &str, param: Option<String>) -> Result<UninitializedPlugin> {
        let raw = param.ok_or_else(|| {
            DnsError::plugin("sleep quick setup requires a duration such as '10', '250ms', or '2s'")
        })?;
        let duration = parse_sleep_quick_duration(&raw)?;

        Ok(UninitializedPlugin::Executor(Box::new(SleepExecutor {
            tag: tag.to_string(),
            duration,
        })))
    }
}

fn parse_sleep_quick_duration(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DnsError::plugin(
            "sleep quick setup requires a non-empty duration",
        ));
    }

    if raw.chars().all(|c| c.is_ascii_digit()) {
        let millis = raw.parse::<u64>().map_err(|e| {
            DnsError::plugin(format!("invalid sleep milliseconds '{}': {}", raw, e))
        })?;
        return Ok(Duration::from_millis(millis));
    }
    parse_simple_duration(raw)
        .map_err(|err| DnsError::plugin(format!("invalid sleep duration '{}': {}", raw, err)))
}

#[cfg(test)]
mod tests {
    use serde_yaml_ng::Value;

    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::{plugin_config, test_context};

    #[test]
    fn test_sleep_factory_quick_setup_validation() {
        let factory = SleepFactory;
        assert!(factory.quick_setup("sleep", None).is_err());
        assert!(
            factory
                .quick_setup("sleep", Some("abc".to_string()))
                .is_err()
        );
        assert!(factory.quick_setup("sleep", Some("10".to_string())).is_ok());
        assert!(factory.quick_setup("sleep", Some("2s".to_string())).is_ok());
    }

    #[test]
    fn test_sleep_factory_create_rejects_invalid_config_type() {
        let factory = SleepFactory;
        let cfg = plugin_config("sleep", "sleep", Some(Value::String("bad".into())));
        assert!(crate::plugin::test_utils::create_plugin_for_test(&factory, &cfg).is_err());
    }

    #[tokio::test]
    async fn test_sleep_execute_zero_duration_returns_next() {
        let plugin = SleepExecutor {
            tag: "sleep".to_string(),
            duration: Duration::from_millis(0),
        };
        let mut ctx = test_context();
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("sleep execute should succeed");
        assert!(matches!(step, ExecStep::Next));
    }
}
