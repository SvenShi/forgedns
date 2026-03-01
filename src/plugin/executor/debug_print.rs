/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `debug_print` executor plugin.
//!
//! This plugin logs request/response objects at info level for debugging.
//! It mirrors mosdns `debug_print` quick setup semantics while keeping the
//! existing ForgeDNS plugin lifecycle and sequence execution model.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

const DEFAULT_MSG: &str = "debug print";

#[derive(Debug, Clone, Deserialize, Default)]
struct DebugPrintConfig {
    /// Optional log message title.
    msg: Option<String>,
}

#[derive(Debug)]
pub struct DebugPrint {
    tag: String,
    msg: String,
}

#[async_trait]
impl Plugin for DebugPrint {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for DebugPrint {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        info!(
            plugin = %self.tag,
            title = %self.msg,
            query = ?context.request,
            response = ?context.response,
            "debug_print"
        );
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct DebugPrintFactory;

register_plugin_factory!("debug_print", DebugPrintFactory {});

impl PluginFactory for DebugPrintFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        if let Some(args) = plugin_config.args.clone() {
            if args.is_string() {
                return Ok(());
            }
            let _: DebugPrintConfig = serde_yml::from_value(args).map_err(|e| {
                DnsError::plugin(format!("failed to parse debug_print config: {}", e))
            })?;
        }
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let msg = parse_msg_from_value(plugin_config.args.clone())
            .unwrap_or_else(|| DEFAULT_MSG.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(DebugPrint {
            tag: plugin_config.tag.clone(),
            msg,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let msg = param
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_MSG.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(DebugPrint {
            tag: tag.to_string(),
            msg,
        })))
    }
}

fn parse_msg_from_value(args: Option<serde_yml::Value>) -> Option<String> {
    let Some(args) = args else {
        return None;
    };

    if let Some(s) = args.as_str() {
        let s = s.trim();
        return if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
    }

    serde_yml::from_value::<DebugPrintConfig>(args)
        .ok()
        .and_then(|cfg| cfg.msg)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}
