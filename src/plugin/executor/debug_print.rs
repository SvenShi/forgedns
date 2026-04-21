/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `debug_print` executor plugin.
//!
//! This plugin logs request/response objects at info level for debugging.
//! It mirrors mosdns `debug_print` quick setup semantics in ForgeDNS.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
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

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for DebugPrint {
    #[hotpath::measure]
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
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
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

fn parse_msg_from_value(args: Option<Value>) -> Option<String> {
    let args = args?;

    if let Some(s) = args.as_str() {
        let s = s.trim();
        return if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
    }

    serde_yaml_ng::from_value::<DebugPrintConfig>(args)
        .ok()
        .and_then(|cfg| cfg.msg)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_context;
    use Value;

    #[test]
    fn test_parse_msg_from_value_supports_string_and_struct() {
        let msg = parse_msg_from_value(Some(Value::String(" hello ".to_string())));
        assert_eq!(msg.as_deref(), Some("hello"));

        let msg = parse_msg_from_value(Some(serde_yaml_ng::from_str("msg: custom").unwrap()));
        assert_eq!(msg.as_deref(), Some("custom"));

        let msg = parse_msg_from_value(Some(Value::String("   ".to_string())));
        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn test_debug_print_execute_returns_next_without_mutation() {
        let plugin = DebugPrint {
            tag: "debug".to_string(),
            msg: "m".to_string(),
        };
        let mut ctx = test_context();
        let original_request = ctx.request.clone();

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        assert_eq!(ctx.request, original_request);
    }
}
