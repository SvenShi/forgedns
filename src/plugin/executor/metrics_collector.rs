/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `metrics_collector` executor plugin.
//!
//! Collects lightweight in-process counters and latency statistics for a
//! sequence section.

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
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

const DEFAULT_NAME: &str = "default";

#[derive(Debug, Clone, Deserialize, Default)]
struct MetricsCollectorConfig {
    name: Option<String>,
}

#[derive(Debug)]
struct MetricsCollector {
    tag: String,
    name: String,
    query_total: AtomicU64,
    err_total: AtomicU64,
    inflight: AtomicU64,
    latency_count: AtomicU64,
    latency_sum_ms: AtomicU64,
}

#[derive(Debug)]
struct PostState {
    start_ms: u64,
}

#[async_trait]
impl Plugin for MetricsCollector {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for MetricsCollector {
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        self.query_total.fetch_add(1, Ordering::Relaxed);
        self.inflight.fetch_add(1, Ordering::Relaxed);

        Ok(ExecStep::NextWithPost(Some(Box::new(PostState {
            start_ms: AppClock::elapsed_millis(),
        }) as ExecState)))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        self.inflight.fetch_sub(1, Ordering::Relaxed);

        let start_ms = state
            .and_then(|boxed| boxed.downcast::<PostState>().ok())
            .map(|boxed| boxed.start_ms)
            .unwrap_or_else(AppClock::elapsed_millis);

        if context.response.is_none() {
            self.err_total.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let elapsed = AppClock::elapsed_millis().saturating_sub(start_ms);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_ms.fetch_add(elapsed, Ordering::Relaxed);

        let total = self.query_total.load(Ordering::Relaxed);
        if total % 1024 == 0 {
            let count = self.latency_count.load(Ordering::Relaxed);
            let sum = self.latency_sum_ms.load(Ordering::Relaxed);
            let avg = if count == 0 { 0 } else { sum / count };
            debug!(
                plugin = %self.tag,
                name = %self.name,
                query_total = total,
                err_total = self.err_total.load(Ordering::Relaxed),
                inflight = self.inflight.load(Ordering::Relaxed),
                avg_latency_ms = avg,
                "metrics_collector snapshot"
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MetricsCollectorFactory;

register_plugin_factory!("metrics_collector", MetricsCollectorFactory {});

impl PluginFactory for MetricsCollectorFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        if let Some(args) = plugin_config.args.clone() {
            if args.is_string() {
                return Ok(());
            }
            let _: MetricsCollectorConfig = serde_yml::from_value(args).map_err(|e| {
                DnsError::plugin(format!("failed to parse metrics_collector config: {}", e))
            })?;
        }
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let name =
            parse_name(plugin_config.args.clone()).unwrap_or_else(|| DEFAULT_NAME.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(MetricsCollector {
            tag: plugin_config.tag.clone(),
            name,
            query_total: AtomicU64::new(0),
            err_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let name = param
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_NAME.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(MetricsCollector {
            tag: tag.to_string(),
            name,
            query_total: AtomicU64::new(0),
            err_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        })))
    }
}

fn parse_name(args: Option<serde_yml::Value>) -> Option<String> {
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

    serde_yml::from_value::<MetricsCollectorConfig>(args)
        .ok()
        .and_then(|cfg| cfg.name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}
