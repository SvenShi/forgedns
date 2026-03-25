/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `metrics_collector` executor plugin.
//!
//! Collects lightweight in-process counters and latency statistics for a
//! sequence section.
//!
//! Like server-side request handling in `plugin/server/mod.rs`, this plugin
//! only observes and annotates request lifecycle without changing resolver
//! routing decisions:
//! - `execute`: increments total/inflight counters and stores start timestamp.
//! - continuation post-stage: decrements inflight, records success/error and latency.
//! - snapshot logging: emits aggregated metrics every 1024 requests.
//!
//! Design goal is low overhead on hot paths: atomics with relaxed ordering and
//! no allocation in steady-state execution.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::{continue_next, register_plugin_factory};
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

const DEFAULT_NAME: &str = "default";

#[derive(Debug, Clone, Deserialize, Default)]
struct MetricsCollectorConfig {
    /// Optional metrics namespace/name label.
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

#[async_trait]
impl Plugin for MetricsCollector {
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
impl Executor for MetricsCollector {
    fn with_next(&self) -> bool {
        true
    }

    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.execute_with_next(context, None).await
    }

    async fn execute_with_next(
        &self,
        context: &mut DnsContext,
        next: Option<ExecutorNext>,
    ) -> Result<ExecStep> {
        self.query_total.fetch_add(1, Ordering::Relaxed);
        self.inflight.fetch_add(1, Ordering::Relaxed);
        let start_ms = AppClock::elapsed_millis();
        let result = continue_next!(next, context);
        self.finalize_metrics(context, start_ms);
        result
    }
}

impl MetricsCollector {
    fn finalize_metrics(&self, context: &DnsContext, start_ms: u64) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);

        if context.response().is_none() {
            self.err_total.fetch_add(1, Ordering::Relaxed);
            return;
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
    }
}

#[derive(Debug, Clone)]
pub struct MetricsCollectorFactory;

register_plugin_factory!("metrics_collector", MetricsCollectorFactory {});

impl PluginFactory for MetricsCollectorFactory {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_context;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_parse_name_trims_and_filters_empty() {
        assert_eq!(parse_name(None), None);
        assert_eq!(
            parse_name(Some(serde_yml::Value::String(" a ".into()))),
            Some("a".into())
        );
        assert_eq!(
            parse_name(Some(serde_yml::Value::String("   ".into()))),
            None
        );
    }

    fn make_collector() -> MetricsCollector {
        MetricsCollector {
            tag: "metrics".to_string(),
            name: "default".to_string(),
            query_total: AtomicU64::new(0),
            err_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        }
    }

    #[tokio::test]
    async fn test_metrics_collector_records_error_path() {
        let plugin = make_collector();
        let mut ctx = test_context();

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should work");

        assert_eq!(plugin.query_total.load(Ordering::Relaxed), 1);
        assert_eq!(plugin.inflight.load(Ordering::Relaxed), 0);
        assert_eq!(plugin.err_total.load(Ordering::Relaxed), 1);
        assert_eq!(plugin.latency_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_metrics_collector_records_success_latency() {
        let plugin = make_collector();
        let mut ctx = test_context();
        ctx.set_response(crate::message::Message::new());

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should work");

        assert_eq!(plugin.err_total.load(Ordering::Relaxed), 0);
        assert_eq!(plugin.latency_count.load(Ordering::Relaxed), 1);
    }
}
