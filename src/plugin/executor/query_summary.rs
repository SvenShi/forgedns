/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `query_summary` executor plugin.
//!
//! Logs compact query summary after downstream execution.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

const DEFAULT_MSG: &str = "query summary";

#[derive(Debug, Clone, Deserialize, Default)]
struct QuerySummaryConfig {
    msg: Option<String>,
}

#[derive(Debug)]
struct QuerySummary {
    tag: String,
    msg: String,
}

#[derive(Debug)]
struct PostState {
    start_ms: u64,
}

#[async_trait]
impl Plugin for QuerySummary {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for QuerySummary {
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        Ok(ExecStep::NextWithPost(Some(Box::new(PostState {
            start_ms: AppClock::elapsed_millis(),
        }) as ExecState)))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let start_ms = state
            .and_then(|boxed| boxed.downcast::<PostState>().ok())
            .map(|boxed| boxed.start_ms)
            .unwrap_or_else(AppClock::elapsed_millis);

        let elapsed = AppClock::elapsed_millis().saturating_sub(start_ms);
        let (qname, qtype) = match context.request.query() {
            Some(q) => (q.name().to_utf8(), format!("{:?}", q.query_type)),
            None => ("<none>".to_string(), "<none>".to_string()),
        };
        let rcode = context
            .response
            .as_ref()
            .map(|r| format!("{:?}", r.response_code()))
            .unwrap_or_else(|| "<none>".to_string());

        info!(
            plugin = %self.tag,
            title = %self.msg,
            qname = %qname,
            qtype = %qtype,
            src = %context.src_addr,
            rcode = %rcode,
            elapsed_ms = elapsed,
            "query_summary"
        );

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct QuerySummaryFactory;

register_plugin_factory!("query_summary", QuerySummaryFactory {});

impl PluginFactory for QuerySummaryFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        if let Some(args) = plugin_config.args.clone() {
            if args.is_string() {
                return Ok(());
            }
            let _: QuerySummaryConfig = serde_yml::from_value(args).map_err(|e| {
                DnsError::plugin(format!("failed to parse query_summary config: {}", e))
            })?;
        }
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let msg = parse_msg(plugin_config.args.clone()).unwrap_or_else(|| DEFAULT_MSG.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(QuerySummary {
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

        Ok(UninitializedPlugin::Executor(Box::new(QuerySummary {
            tag: tag.to_string(),
            msg,
        })))
    }
}

fn parse_msg(args: Option<serde_yml::Value>) -> Option<String> {
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

    serde_yml::from_value::<QuerySummaryConfig>(args)
        .ok()
        .and_then(|cfg| cfg.msg)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}
