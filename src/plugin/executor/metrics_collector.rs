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

use crate::api::{ApiHandler, ApiRegister, simple_response};
use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::{continue_next, register_plugin_factory};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use serde::Deserialize;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
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
    stats: Arc<MetricsCollectorStats>,
    api_register: Option<ApiRegister>,
}

#[derive(Debug)]
struct MetricsCollectorStats {
    tag: String,
    name: String,
    query_total: AtomicU64,
    err_total: AtomicU64,
    inflight: AtomicU64,
    latency_count: AtomicU64,
    latency_sum_ms: AtomicU64,
}

#[derive(Debug, Default)]
struct MetricsExporter {
    route_registered: AtomicU64,
    collectors: Mutex<Vec<Arc<MetricsCollectorStats>>>,
}

#[async_trait]
impl Plugin for MetricsCollector {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        let exporter = metrics_exporter();
        {
            let mut collectors = exporter
                .collectors
                .lock()
                .expect("metrics collectors poisoned");
            collectors.push(self.stats.clone());
        }
        if exporter.route_registered.load(Ordering::Relaxed) == 0
            && let Some(api_register) = &self.api_register
        {
            api_register.register_get(
                "/metrics",
                Arc::new(MetricsHandler {
                    exporter: metrics_exporter().clone(),
                }),
            )?;
            exporter.route_registered.store(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        let exporter = metrics_exporter();
        let mut collectors = exporter
            .collectors
            .lock()
            .expect("metrics collectors poisoned");
        collectors.retain(|collector| collector.tag != self.stats.tag);
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
        self.stats.query_total.fetch_add(1, Ordering::Relaxed);
        self.stats.inflight.fetch_add(1, Ordering::Relaxed);
        let start_ms = AppClock::elapsed_millis();
        let result = continue_next!(next, context);
        self.finalize_metrics(context, start_ms);
        result
    }
}

impl MetricsCollector {
    fn finalize_metrics(&self, context: &DnsContext, start_ms: u64) {
        self.stats.inflight.fetch_sub(1, Ordering::Relaxed);

        if context.response().is_none() {
            self.stats.err_total.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let elapsed = AppClock::elapsed_millis().saturating_sub(start_ms);
        self.stats.latency_count.fetch_add(1, Ordering::Relaxed);
        self.stats
            .latency_sum_ms
            .fetch_add(elapsed, Ordering::Relaxed);

        let total = self.stats.query_total.load(Ordering::Relaxed);
        if total.is_multiple_of(1024) {
            let count = self.stats.latency_count.load(Ordering::Relaxed);
            let sum = self.stats.latency_sum_ms.load(Ordering::Relaxed);
            let avg = sum.checked_div(count);
            debug!(
                plugin = %self.stats.tag,
                name = %self.stats.name,
                query_total = total,
                err_total = self.stats.err_total.load(Ordering::Relaxed),
                inflight = self.stats.inflight.load(Ordering::Relaxed),
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
        registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let name =
            parse_name(plugin_config.args.clone()).unwrap_or_else(|| DEFAULT_NAME.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(MetricsCollector {
            tag: plugin_config.tag.clone(),
            stats: Arc::new(MetricsCollectorStats::new(plugin_config.tag.clone(), name)),
            api_register: registry.api_register(),
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
            stats: Arc::new(MetricsCollectorStats::new(tag.to_string(), name)),
            api_register: None,
        })))
    }
}

impl MetricsCollectorStats {
    fn new(tag: String, name: String) -> Self {
        Self {
            tag,
            name,
            query_total: AtomicU64::new(0),
            err_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
struct MetricsHandler {
    exporter: Arc<MetricsExporter>,
}

#[async_trait]
impl ApiHandler for MetricsHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        let body = render_prometheus_metrics(&self.exporter);
        let mut response = simple_response(StatusCode::OK, Bytes::from(body));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        response
    }
}

fn metrics_exporter() -> &'static Arc<MetricsExporter> {
    static EXPORTER: OnceLock<Arc<MetricsExporter>> = OnceLock::new();
    EXPORTER.get_or_init(|| Arc::new(MetricsExporter::default()))
}

fn render_prometheus_metrics(exporter: &MetricsExporter) -> String {
    let collectors = exporter
        .collectors
        .lock()
        .expect("metrics collectors poisoned");
    let mut out = String::new();
    out.push_str("# HELP forgedns_query_total Total DNS queries observed by metrics_collector.\n");
    out.push_str("# TYPE forgedns_query_total counter\n");
    out.push_str("# HELP forgedns_query_error_total Total DNS queries without a response.\n");
    out.push_str("# TYPE forgedns_query_error_total counter\n");
    out.push_str("# HELP forgedns_query_inflight Current number of inflight DNS queries.\n");
    out.push_str("# TYPE forgedns_query_inflight gauge\n");
    out.push_str("# HELP forgedns_query_latency_count Total completed queries included in latency statistics.\n");
    out.push_str("# TYPE forgedns_query_latency_count counter\n");
    out.push_str("# HELP forgedns_query_latency_sum_ms Total latency in milliseconds for completed queries.\n");
    out.push_str("# TYPE forgedns_query_latency_sum_ms counter\n");

    for collector in collectors.iter() {
        let labels = format!(
            "plugin_tag=\"{}\",name=\"{}\"",
            escape_label_value(&collector.tag),
            escape_label_value(&collector.name)
        );
        let _ = writeln!(
            out,
            "forgedns_query_total{{{labels}}} {}",
            collector.query_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "forgedns_query_error_total{{{labels}}} {}",
            collector.err_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "forgedns_query_inflight{{{labels}}} {}",
            collector.inflight.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "forgedns_query_latency_count{{{labels}}} {}",
            collector.latency_count.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "forgedns_query_latency_sum_ms{{{labels}}} {}",
            collector.latency_sum_ms.load(Ordering::Relaxed)
        );
    }

    out
}

fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

fn parse_name(args: Option<serde_yml::Value>) -> Option<String> {
    let args = args?;

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
            stats: Arc::new(MetricsCollectorStats::new(
                "metrics".to_string(),
                "default".to_string(),
            )),
            api_register: None,
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

        assert_eq!(plugin.stats.query_total.load(Ordering::Relaxed), 1);
        assert_eq!(plugin.stats.inflight.load(Ordering::Relaxed), 0);
        assert_eq!(plugin.stats.err_total.load(Ordering::Relaxed), 1);
        assert_eq!(plugin.stats.latency_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_metrics_collector_records_success_latency() {
        let plugin = make_collector();
        let mut ctx = test_context();
        ctx.set_response(crate::proto::Message::new());

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should work");

        assert_eq!(plugin.stats.err_total.load(Ordering::Relaxed), 0);
        assert_eq!(plugin.stats.latency_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_render_prometheus_metrics_includes_labels_and_values() {
        let exporter = MetricsExporter::default();
        let stats = Arc::new(MetricsCollectorStats::new(
            "metrics_main".to_string(),
            "default".to_string(),
        ));
        stats.query_total.store(3, Ordering::Relaxed);
        stats.err_total.store(1, Ordering::Relaxed);
        stats.inflight.store(2, Ordering::Relaxed);
        stats.latency_count.store(2, Ordering::Relaxed);
        stats.latency_sum_ms.store(15, Ordering::Relaxed);
        exporter
            .collectors
            .lock()
            .expect("metrics collectors poisoned")
            .push(stats);

        let output = render_prometheus_metrics(&exporter);
        assert!(
            output.contains("forgedns_query_total{plugin_tag=\"metrics_main\",name=\"default\"} 3")
        );
        assert!(output.contains(
            "forgedns_query_error_total{plugin_tag=\"metrics_main\",name=\"default\"} 1"
        ));
        assert!(
            output.contains(
                "forgedns_query_inflight{plugin_tag=\"metrics_main\",name=\"default\"} 2"
            )
        );
    }
}
