/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `reload` executor plugin.
//!
//! This executor reuses the application-level reload path exposed by the
//! control API. Triggering it schedules a full configuration reload instead of
//! rebuilding selected plugin tags in place.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::info;

#[derive(Debug)]
struct ReloadExecutor {
    tag: String,
}

#[async_trait]
impl Plugin for ReloadExecutor {
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
impl Executor for ReloadExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        info!(plugin = %self.tag, "reload executor triggered full application reload");
        context.registry.request_app_reload()?;
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct ReloadFactory;

register_plugin_factory!("reload", ReloadFactory {});

impl PluginFactory for ReloadFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ReloadExecutor {
            tag: plugin_config.tag.clone(),
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        _param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ReloadExecutor {
            tag: tag.to_string(),
        })))
    }
}
