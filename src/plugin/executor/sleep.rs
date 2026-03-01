/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `sleep` executor plugin.
//!
//! Adds an intentional delay in the sequence pipeline, mainly for testing.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

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

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for SleepExecutor {
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        if !self.duration.is_zero() {
            tokio::time::sleep(self.duration).await;
        }
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct SleepFactory;

register_plugin_factory!("sleep", SleepFactory {});

impl PluginFactory for SleepFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        if let Some(args) = plugin_config.args.clone() {
            let _: SleepConfig = serde_yml::from_value(args)
                .map_err(|e| DnsError::plugin(format!("failed to parse sleep config: {}", e)))?;
        }
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg = plugin_config
            .args
            .clone()
            .map(serde_yml::from_value::<SleepConfig>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse sleep config: {}", e)))?
            .unwrap_or_default();

        Ok(UninitializedPlugin::Executor(Box::new(SleepExecutor {
            tag: plugin_config.tag.clone(),
            duration: Duration::from_millis(cfg.duration),
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let raw =
            param.ok_or_else(|| DnsError::plugin("sleep quick setup requires milliseconds"))?;
        let millis = raw.trim().parse::<u64>().map_err(|e| {
            DnsError::plugin(format!("invalid sleep milliseconds '{}': {}", raw, e))
        })?;

        Ok(UninitializedPlugin::Executor(Box::new(SleepExecutor {
            tag: tag.to_string(),
            duration: Duration::from_millis(millis),
        })))
    }
}
