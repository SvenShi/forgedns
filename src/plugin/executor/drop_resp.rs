/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `drop_resp` executor plugin.
//!
//! Clears the current response from [`DnsContext`].

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug)]
struct DropResp {
    tag: String,
}

#[async_trait]
impl Plugin for DropResp {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for DropResp {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        context.response = None;
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct DropRespFactory;

register_plugin_factory!("drop_resp", DropRespFactory {});

impl PluginFactory for DropRespFactory {
    fn validate_config(&self, _plugin_config: &PluginConfig) -> Result<()> {
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(DropResp {
            tag: plugin_config.tag.clone(),
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        _param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(DropResp {
            tag: tag.to_string(),
        })))
    }
}
