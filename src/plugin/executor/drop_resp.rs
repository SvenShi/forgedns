/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `drop_resp` executor plugin.
//!
//! Clears the current response from [`DnsContext`].
//!
//! This plugin is useful when a previous executor produced a response but a
//! later policy requires re-querying or rebuilding output. It only resets
//! `context.response`/final packet output and keeps request metadata/marks untouched.

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

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for DropResp {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        context.clear_response();
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct DropRespFactory;

register_plugin_factory!("drop_resp", DropRespFactory {});

impl PluginFactory for DropRespFactory {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::test_context;

    #[tokio::test]
    async fn test_execute_clears_response() {
        let plugin = DropResp {
            tag: "drop_resp".to_string(),
        };
        let mut ctx = test_context();
        ctx.set_response(crate::message::Message::new());

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        assert!(ctx.response().is_none());
    }
}
