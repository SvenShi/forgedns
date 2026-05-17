// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `reload` executor plugin.
//!
//! This executor reuses the application-level reload path exposed by the
//! control API. Triggering it schedules a full configuration reload instead of
//! rebuilding selected plugin tags in place.

use async_trait::async_trait;
use tracing::info;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{self, Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;

#[derive(Debug)]
struct ReloadExecutor {
    tag: String,
}

#[async_trait]
impl Plugin for ReloadExecutor {
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
impl Executor for ReloadExecutor {
    #[hotpath::measure]
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        info!(plugin = %self.tag, "reload executor triggered full application reload");
        plugin::request_app_reload()?;
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
#[plugin_factory("reload")]
pub struct ReloadFactory;

impl PluginFactory for ReloadFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ReloadExecutor {
            tag: plugin_config.tag.clone(),
        })))
    }

    fn quick_setup(&self, tag: &str, _param: Option<String>) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ReloadExecutor {
            tag: tag.to_string(),
        })))
    }
}
