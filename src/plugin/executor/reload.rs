// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `reload` executor plugin.
//!
//! This executor reuses the application-level reload path exposed by the
//! control API. Triggering it schedules a full configuration reload instead of
//! rebuilding selected plugin tags in place.
//!
//! The reload request is routed through the process-wide runtime manager. If a
//! query that started on an older runtime triggers this executor during a
//! runtime swap, the request is scheduled against the current application
//! controller rather than an executor-local registry snapshot.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use tracing::info;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::core::metrics::{
    MetricLabel, MetricSample, MetricSink, MetricSource, register_metric_source,
    unregister_metric_source,
};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{self, Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;

#[derive(Debug)]
struct ReloadMetrics {
    tag: String,
    trigger_total: AtomicU64,
    error_total: AtomicU64,
}

impl ReloadMetrics {
    fn new(tag: String) -> Self {
        Self {
            tag,
            trigger_total: AtomicU64::new(0),
            error_total: AtomicU64::new(0),
        }
    }
}

impl MetricSource for ReloadMetrics {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn plugin_type(&self) -> &'static str {
        "reload"
    }

    fn collect(&self, sink: &mut dyn MetricSink) {
        let labels = [MetricLabel::new("plugin_tag", self.tag.as_str())];
        sink.emit(MetricSample::counter(
            "reload_trigger_total",
            "Total times the reload executor requested an application reload.",
            &labels,
            self.trigger_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "reload_error_total",
            "Total reload requests that failed to be scheduled.",
            &labels,
            self.error_total.load(Ordering::Relaxed),
        ));
    }
}

#[derive(Debug)]
struct ReloadExecutor {
    tag: String,
    metrics: Arc<ReloadMetrics>,
}

#[async_trait]
impl Plugin for ReloadExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        register_metric_source(self.metrics.clone())
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);
        Ok(())
    }
}

#[async_trait]
impl Executor for ReloadExecutor {
    #[hotpath::measure]
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        info!(plugin = %self.tag, "reload executor triggered full application reload");
        self.metrics.trigger_total.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = plugin::request_app_reload() {
            self.metrics.error_total.fetch_add(1, Ordering::Relaxed);
            return Err(err);
        }
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
            metrics: Arc::new(ReloadMetrics::new(plugin_config.tag.clone())),
        })))
    }

    fn quick_setup(&self, tag: &str, _param: Option<String>) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ReloadExecutor {
            tag: tag.to_string(),
            metrics: Arc::new(ReloadMetrics::new(tag.to_string())),
        })))
    }
}
