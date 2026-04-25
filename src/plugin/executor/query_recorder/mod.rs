// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `query_recorder` executor plugin.
//!
//! Records structured request/response snapshots plus execution-path events
//! into recorder-scoped SQLite tables.
//!
//! Design constraints:
//! - pure executor observer, no server-path finalization hook;
//! - request snapshot is captured at recorder entry, response snapshot after
//!   `next`;
//! - each recorder owns its own queue, SQLite connection, writer thread, tail
//!   buffer, and SSE broadcaster;
//! - persistence uses one `records` table and one `steps` table per recorder
//!   schema version.

mod api;
mod backend;
mod capture;
mod model;
mod store;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use serde_yaml_ng::Value as YamlValue;
use tracing::warn;

use self::backend::{RecorderBackend, WriterCommand};
use self::model::{PendingRecord, QueryRecorderConfig, ResolvedRecorderConfig};
use crate::api::ApiRegister;
use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::{continue_next, register_plugin_factory};

const DEFAULT_QUEUE_SIZE: usize = 8_192;
const DEFAULT_BATCH_SIZE: usize = 256;
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 200;
const DEFAULT_MEMORY_TAIL: usize = 1_024;
const DEFAULT_RETENTION_DAYS: u64 = 7;
const DEFAULT_CLEANUP_INTERVAL_HOURS: u64 = 1;

#[derive(Debug)]
struct QueryRecorder {
    tag: String,
    config: ResolvedRecorderConfig,
    api_register: Option<ApiRegister>,
    backend: Option<Arc<RecorderBackend>>,
    cleanup_task_id: Option<u64>,
}

#[async_trait]
impl Plugin for QueryRecorder {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        let backend = RecorderBackend::new(self.tag.clone(), self.config.clone())?;
        backend.register_api_routes(self.api_register.as_ref())?;

        let queue_tx = backend.queue_tx.clone();
        let retention_days = self.config.retention_days;
        self.cleanup_task_id = Some(task_center::spawn_fixed(
            format!("query_recorder:{}:cleanup", self.tag),
            Duration::from_secs(self.config.cleanup_interval_hours * 60 * 60),
            move || {
                let queue_tx = queue_tx.clone();
                async move {
                    let retention_ms = retention_days.saturating_mul(24 * 60 * 60 * 1000);
                    let cutoff_ms = AppClock::elapsed_millis().saturating_sub(retention_ms);
                    if let Err(err) = queue_tx.try_send(WriterCommand::Cleanup { cutoff_ms }) {
                        warn!("query_recorder cleanup skipped: {}", err);
                    }
                }
            },
        ));
        self.backend = Some(backend);
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(task_id) = self.cleanup_task_id {
            task_center::stop_task(task_id).await;
        }
        let join_handle = if let Some(backend) = &self.backend {
            backend.stop_requested.store(true, Ordering::Relaxed);
            let mut guard = backend
                .writer_handle
                .lock()
                .map_err(|_| DnsError::runtime("query_recorder writer lock poisoned"))?;
            guard.take()
        } else {
            None
        };
        if let Some(handle) = join_handle {
            let join_result = tokio::task::spawn_blocking(move || handle.join())
                .await
                .map_err(|err| DnsError::runtime(format!("query_recorder join failed: {err}")))?;
            let _ = join_result;
        }
        Ok(())
    }
}

#[async_trait]
impl Executor for QueryRecorder {
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
        let Some(backend) = &self.backend else {
            return Err(DnsError::runtime(
                "query_recorder backend is not initialized",
            ));
        };

        let request = context.request.clone();
        context.enable_execution_path();
        let step_start_index = context.execution_path_len();
        let started_at_ms = AppClock::elapsed_millis();
        let result = continue_next!(next, context);
        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(started_at_ms);
        let pending = PendingRecord::capture(
            request,
            context,
            started_at_ms,
            elapsed_ms,
            step_start_index,
            result.as_ref().err(),
        );
        backend.enqueue(pending);
        result
    }
}

impl QueryRecorder {
    fn new(tag: String, config: ResolvedRecorderConfig, api_register: Option<ApiRegister>) -> Self {
        Self {
            tag,
            config,
            api_register,
            backend: None,
            cleanup_task_id: None,
        }
    }
}

fn resolve_config(args: Option<YamlValue>) -> Result<ResolvedRecorderConfig> {
    let args = args.ok_or_else(|| DnsError::plugin("query_recorder requires structured args"))?;
    let parsed = serde_yaml_ng::from_value::<QueryRecorderConfig>(args)
        .map_err(|err| DnsError::plugin(format!("failed to parse query_recorder config: {err}")))?;

    let path = parsed.path.trim();
    if path.is_empty() {
        return Err(DnsError::plugin("query_recorder path cannot be empty"));
    }

    let queue_size = parsed.queue_size.unwrap_or(DEFAULT_QUEUE_SIZE);
    let batch_size = parsed.batch_size.unwrap_or(DEFAULT_BATCH_SIZE);
    let flush_interval_ms = parsed
        .flush_interval_ms
        .unwrap_or(DEFAULT_FLUSH_INTERVAL_MS);
    let memory_tail = parsed.memory_tail.unwrap_or(DEFAULT_MEMORY_TAIL);
    let retention_days = parsed.retention_days.unwrap_or(DEFAULT_RETENTION_DAYS);
    let cleanup_interval_hours = parsed
        .cleanup_interval_hours
        .unwrap_or(DEFAULT_CLEANUP_INTERVAL_HOURS);

    if queue_size == 0 {
        return Err(DnsError::plugin(
            "query_recorder queue_size must be greater than 0",
        ));
    }
    if batch_size == 0 {
        return Err(DnsError::plugin(
            "query_recorder batch_size must be greater than 0",
        ));
    }
    if flush_interval_ms == 0 {
        return Err(DnsError::plugin(
            "query_recorder flush_interval_ms must be greater than 0",
        ));
    }
    if memory_tail == 0 {
        return Err(DnsError::plugin(
            "query_recorder memory_tail must be greater than 0",
        ));
    }
    if retention_days == 0 {
        return Err(DnsError::plugin(
            "query_recorder retention_days must be at least 1",
        ));
    }
    if cleanup_interval_hours == 0 {
        return Err(DnsError::plugin(
            "query_recorder cleanup_interval_hours must be at least 1",
        ));
    }

    Ok(ResolvedRecorderConfig {
        path: PathBuf::from(path),
        queue_size,
        batch_size,
        flush_interval_ms,
        memory_tail,
        retention_days,
        cleanup_interval_hours,
    })
}

#[derive(Debug, Clone)]
pub struct QueryRecorderFactory;

register_plugin_factory!("query_recorder", QueryRecorderFactory {});

impl PluginFactory for QueryRecorderFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let config = resolve_config(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(QueryRecorder::new(
            plugin_config.tag.clone(),
            config,
            registry.api_register(),
        ))))
    }

    fn quick_setup(
        &self,
        _tag: &str,
        _param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Err(DnsError::plugin(
            "query_recorder does not support quick setup syntax",
        ))
    }
}
