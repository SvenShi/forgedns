/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `query_recorder` executor plugin.
//!
//! Records structured request/response snapshots plus execution-path events into
//! recorder-scoped SQLite tables.
//!
//! Design constraints:
//! - pure executor observer, no server-path finalization hook;
//! - request snapshot is captured at recorder entry, response snapshot after `next`;
//! - each recorder owns its own queue, SQLite connection, writer thread, tail buffer,
//!   and SSE broadcaster;
//! - persistence uses one `records` table and one `steps` table per recorder schema
//!   version.

use crate::api::{
    ApiHandler, ApiRegister, json_error, json_ok, simple_response, streaming_response,
};
use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::{DnsContext, ExecutionPathEvent};
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::rdata::{
    self, CAA, ClientSubnet, DNSKEY, DS, Edns, EdnsCode, EdnsExtendedDnsError, EdnsOption, NSEC,
    NSEC3, NSEC3PARAM, RRSIG, SOA, SSHFP, SVCB, TLSA, TXT, URI,
};
use crate::proto::{DNSClass, Message, Opcode, Question, RData, Rcode, Record, RecordType};
use crate::{continue_next, register_plugin_factory};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Request, StatusCode};
use hyper::body::Frame;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use serde_yaml_ng::Value as YamlValue;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, warn};

const SCHEMA_VERSION: &str = "v1";
const DEFAULT_QUEUE_SIZE: usize = 8_192;
const DEFAULT_BATCH_SIZE: usize = 256;
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 200;
const DEFAULT_MEMORY_TAIL: usize = 1_024;
const DEFAULT_RETENTION_DAYS: u64 = 7;
const DEFAULT_CLEANUP_INTERVAL_HOURS: u64 = 1;
const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;
const CLEANUP_BATCH_SIZE: usize = 1_000;
const SSE_HEARTBEAT_SECS: u64 = 15;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct QueryRecorderConfig {
    path: String,
    queue_size: Option<usize>,
    batch_size: Option<usize>,
    flush_interval_ms: Option<u64>,
    memory_tail: Option<usize>,
    retention_days: Option<u64>,
    cleanup_interval_hours: Option<u64>,
}

#[derive(Debug, Clone)]
struct ResolvedRecorderConfig {
    path: PathBuf,
    queue_size: usize,
    batch_size: usize,
    flush_interval_ms: u64,
    memory_tail: usize,
    retention_days: u64,
    cleanup_interval_hours: u64,
}

#[derive(Debug, Clone)]
struct TableNames {
    records: String,
    steps: String,
}

#[derive(Debug)]
struct QueryRecorder {
    tag: String,
    config: ResolvedRecorderConfig,
    api_register: Option<ApiRegister>,
    runtime: Option<Arc<RecorderRuntime>>,
    cleanup_task_id: Option<u64>,
}

#[derive(Debug)]
struct RecorderRuntime {
    tag: String,
    path: PathBuf,
    tables: TableNames,
    queue_tx: SyncSender<WriterCommand>,
    stop_requested: Arc<AtomicBool>,
    writer_handle: Mutex<Option<JoinHandle<()>>>,
    tail: Arc<Mutex<VecDeque<RecordDetail>>>,
    memory_tail: usize,
    broadcaster: broadcast::Sender<RecordDetail>,
    dropped_total: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
enum WriterCommand {
    Insert(Box<PendingRecord>),
    Cleanup { cutoff_ms: u64 },
}

#[derive(Debug)]
struct WriterThreadContext {
    path: PathBuf,
    tables: TableNames,
    stop_requested: Arc<AtomicBool>,
    tail: Arc<Mutex<VecDeque<RecordDetail>>>,
    memory_tail: usize,
    broadcaster: broadcast::Sender<RecordDetail>,
    batch_size: usize,
    flush_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct QuestionJson {
    name: String,
    qtype: String,
    qclass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RecordJson {
    name: String,
    class: String,
    ttl: u32,
    rr_type: String,
    payload_kind: String,
    payload_text: String,
    payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EdnsOptionJson {
    code: u16,
    name: String,
    payload_kind: String,
    payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EdnsJson {
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    z: u16,
    options: Vec<EdnsOptionJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StepJson {
    event_index: usize,
    sequence_tag: String,
    node_index: Option<usize>,
    kind: String,
    tag: Option<String>,
    outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RecordRow {
    id: i64,
    created_at_ms: u64,
    elapsed_ms: u64,
    request_id: u16,
    client_ip: String,
    questions_json: Vec<QuestionJson>,
    req_rd: bool,
    req_cd: bool,
    req_ad: bool,
    req_opcode: String,
    req_edns_json: Option<EdnsJson>,
    error: Option<String>,
    has_response: bool,
    rcode: Option<String>,
    resp_aa: Option<bool>,
    resp_tc: Option<bool>,
    resp_ra: Option<bool>,
    resp_ad: Option<bool>,
    resp_cd: Option<bool>,
    answer_count: u32,
    authority_count: u32,
    additional_count: u32,
    answers_json: Vec<RecordJson>,
    authorities_json: Vec<RecordJson>,
    additionals_json: Vec<RecordJson>,
    signature_json: Vec<RecordJson>,
    resp_edns_json: Option<EdnsJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RecordDetail {
    #[serde(flatten)]
    record: RecordRow,
    steps: Vec<StepJson>,
}

#[derive(Debug, Clone)]
struct PendingRecord {
    record: RecordRow,
    steps: Vec<StepJson>,
}

#[derive(Debug, Clone, Serialize)]
struct RecordListResponse {
    ok: bool,
    next_cursor: Option<String>,
    records: Vec<RecordRow>,
}

#[derive(Debug, Clone, Serialize)]
struct RecordDetailResponse {
    ok: bool,
    record: RecordDetail,
}

#[derive(Debug, Clone, Serialize)]
struct StatsOverviewResponse {
    ok: bool,
    query_total: u64,
    error_total: u64,
    dropped_total: u64,
    avg_elapsed_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct PluginStatsRow {
    kind: String,
    tag: Option<String>,
    evaluated: u64,
    matched: u64,
    executed: u64,
    query_total: u64,
    query_share: f64,
}

#[derive(Debug, Clone, Serialize)]
struct PluginStatsResponse {
    ok: bool,
    query_total: u64,
    stats: Vec<PluginStatsRow>,
}

#[derive(Debug)]
struct RecordsListHandler {
    runtime: Arc<RecorderRuntime>,
}

#[derive(Debug)]
struct RecordDetailHandler {
    runtime: Arc<RecorderRuntime>,
    path_prefix: String,
}

#[derive(Debug)]
struct StatsOverviewHandler {
    runtime: Arc<RecorderRuntime>,
}

#[derive(Debug)]
struct StatsPluginsHandler {
    runtime: Arc<RecorderRuntime>,
}

#[derive(Debug)]
struct StreamHandler {
    runtime: Arc<RecorderRuntime>,
}

#[derive(Debug, Clone, Copy)]
struct ListQuery {
    cursor: Option<ListCursor>,
    limit: usize,
    since_ms: Option<u64>,
    until_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct StatsQuery {
    since_ms: Option<u64>,
    until_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct PluginsStatsQuery {
    since_ms: Option<u64>,
    until_ms: Option<u64>,
    kind: PluginStatsKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListCursor {
    created_at_ms: u64,
    id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginStatsKind {
    Matcher,
    Executor,
    Builtin,
    All,
}

#[derive(Debug, Clone, Copy)]
struct StatsOverview {
    query_total: u64,
    error_total: u64,
    avg_elapsed_ms: Option<f64>,
}

#[async_trait]
impl Plugin for QueryRecorder {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        let runtime = RecorderRuntime::new(self.tag.clone(), self.config.clone())?;
        runtime.register_api_routes(self.api_register.as_ref())?;

        let queue_tx = runtime.queue_tx.clone();
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
        self.runtime = Some(runtime);
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(task_id) = self.cleanup_task_id {
            task_center::stop_task(task_id).await;
        }
        let join_handle = if let Some(runtime) = &self.runtime {
            runtime.stop_requested.store(true, Ordering::Relaxed);
            let mut guard = runtime
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
        let Some(runtime) = &self.runtime else {
            return Err(DnsError::runtime(
                "query_recorder runtime is not initialized",
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
        runtime.enqueue(pending);
        result
    }
}

impl QueryRecorder {
    fn new(tag: String, config: ResolvedRecorderConfig, api_register: Option<ApiRegister>) -> Self {
        Self {
            tag,
            config,
            api_register,
            runtime: None,
            cleanup_task_id: None,
        }
    }
}

impl RecorderRuntime {
    fn new(tag: String, config: ResolvedRecorderConfig) -> Result<Arc<Self>> {
        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                DnsError::plugin(format!(
                    "failed to create query_recorder directory '{}': {}",
                    parent.display(),
                    err
                ))
            })?;
        }

        let tables = table_names(&tag);
        initialize_database(&config.path, &tables)?;

        let (queue_tx, queue_rx) = sync_channel(config.queue_size);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(
            config.memory_tail.max(1),
        )));
        let (broadcaster, _) = broadcast::channel(config.memory_tail.max(16));
        let dropped_total = Arc::new(AtomicU64::new(0));

        let writer_path = config.path.clone();
        let writer_tables = tables.clone();
        let writer_stop = stop_requested.clone();
        let writer_tail = tail.clone();
        let writer_broadcaster = broadcaster.clone();
        let memory_tail = config.memory_tail.max(1);
        let batch_size = config.batch_size;
        let flush_interval = Duration::from_millis(config.flush_interval_ms);
        let writer_handle = thread::Builder::new()
            .name(format!("query-recorder-{}", tag))
            .spawn(move || {
                if let Err(err) = run_writer_thread(
                    WriterThreadContext {
                        path: writer_path,
                        tables: writer_tables,
                        stop_requested: writer_stop,
                        tail: writer_tail,
                        memory_tail,
                        broadcaster: writer_broadcaster,
                        batch_size,
                        flush_interval,
                    },
                    queue_rx,
                ) {
                    error!("query_recorder writer stopped: {}", err);
                }
            })
            .map_err(|err| {
                DnsError::plugin(format!("failed to spawn query_recorder writer: {err}"))
            })?;

        Ok(Arc::new(Self {
            tag,
            path: config.path,
            tables,
            queue_tx,
            stop_requested,
            writer_handle: Mutex::new(Some(writer_handle)),
            tail,
            memory_tail,
            broadcaster,
            dropped_total,
        }))
    }

    fn enqueue(&self, pending: PendingRecord) {
        if let Err(err) = self
            .queue_tx
            .try_send(WriterCommand::Insert(Box::new(pending)))
        {
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
            warn!("query_recorder dropped record: {}", err);
        }
    }

    fn register_api_routes(&self, api_register: Option<&ApiRegister>) -> Result<()> {
        let Some(api_register) = api_register else {
            return Ok(());
        };

        let runtime = Arc::new(self.clone_shallow());
        api_register.register_plugin_get(
            &self.tag,
            "/records",
            Arc::new(RecordsListHandler {
                runtime: runtime.clone(),
            }),
        )?;

        let detail_prefix = format!("/plugins/{}/records/", self.tag);
        api_register.register_plugin_get_prefix(
            &self.tag,
            "/records/",
            Arc::new(RecordDetailHandler {
                runtime: runtime.clone(),
                path_prefix: detail_prefix,
            }),
        )?;

        api_register.register_plugin_get(
            &self.tag,
            "/stats/overview",
            Arc::new(StatsOverviewHandler {
                runtime: runtime.clone(),
            }),
        )?;

        api_register.register_plugin_get(
            &self.tag,
            "/stats/plugins",
            Arc::new(StatsPluginsHandler {
                runtime: runtime.clone(),
            }),
        )?;

        api_register.register_plugin_get(
            &self.tag,
            "/stream",
            Arc::new(StreamHandler { runtime }),
        )?;

        Ok(())
    }

    fn clone_shallow(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            path: self.path.clone(),
            tables: self.tables.clone(),
            queue_tx: self.queue_tx.clone(),
            stop_requested: self.stop_requested.clone(),
            writer_handle: Mutex::new(None),
            tail: self.tail.clone(),
            memory_tail: self.memory_tail,
            broadcaster: self.broadcaster.clone(),
            dropped_total: self.dropped_total.clone(),
        }
    }
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

#[async_trait]
impl ApiHandler for RecordsListHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let query = match parse_list_query(request.uri().query()) {
            Ok(query) => query,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };

        let runtime = self.runtime.clone();
        match tokio::task::spawn_blocking(move || query_records(runtime, query)).await {
            Ok(Ok((records, next_cursor))) => json_ok(
                StatusCode::OK,
                &RecordListResponse {
                    ok: true,
                    next_cursor,
                    records,
                },
            ),
            Ok(Err(err)) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_records_failed",
                err.to_string(),
            ),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_records_failed",
                format!("blocking task failed: {err}"),
            ),
        }
    }
}

#[async_trait]
impl ApiHandler for RecordDetailHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let Some(raw_id) = request.uri().path().strip_prefix(self.path_prefix.as_str()) else {
            return simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"));
        };
        if raw_id.is_empty() || raw_id.contains('/') {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_record_id",
                "invalid record id",
            );
        }
        let record_id = match raw_id.parse::<i64>() {
            Ok(record_id) if record_id > 0 => record_id,
            _ => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_record_id",
                    "record id must be a positive integer",
                );
            }
        };

        let runtime = self.runtime.clone();
        match tokio::task::spawn_blocking(move || load_record_detail(runtime, record_id)).await {
            Ok(Ok(Some(record))) => {
                json_ok(StatusCode::OK, &RecordDetailResponse { ok: true, record })
            }
            Ok(Ok(None)) => json_error(
                StatusCode::NOT_FOUND,
                "record_not_found",
                format!("record {} does not exist", record_id),
            ),
            Ok(Err(err)) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_record_failed",
                err.to_string(),
            ),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_record_failed",
                format!("blocking task failed: {err}"),
            ),
        }
    }
}

#[async_trait]
impl ApiHandler for StatsOverviewHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let query = match parse_stats_query(request.uri().query()) {
            Ok(query) => query,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };
        let runtime = self.runtime.clone();
        match tokio::task::spawn_blocking(move || load_stats_overview(runtime, query)).await {
            Ok(Ok(overview)) => json_ok(
                StatusCode::OK,
                &StatsOverviewResponse {
                    ok: true,
                    query_total: overview.query_total,
                    error_total: overview.error_total,
                    dropped_total: self.runtime.dropped_total.load(Ordering::Relaxed),
                    avg_elapsed_ms: overview.avg_elapsed_ms,
                },
            ),
            Ok(Err(err)) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_stats_failed",
                err.to_string(),
            ),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_stats_failed",
                format!("blocking task failed: {err}"),
            ),
        }
    }
}

#[async_trait]
impl ApiHandler for StatsPluginsHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let query = match parse_plugins_stats_query(request.uri().query()) {
            Ok(query) => query,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };
        let runtime = self.runtime.clone();
        match tokio::task::spawn_blocking(move || load_plugin_stats(runtime, query)).await {
            Ok(Ok((query_total, stats))) => json_ok(
                StatusCode::OK,
                &PluginStatsResponse {
                    ok: true,
                    query_total,
                    stats,
                },
            ),
            Ok(Err(err)) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_stats_failed",
                err.to_string(),
            ),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_recorder_stats_failed",
                format!("blocking task failed: {err}"),
            ),
        }
    }
}

#[async_trait]
impl ApiHandler for StreamHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let tail_count = match parse_tail_param(request.uri().query(), self.runtime.memory_tail) {
            Ok(tail_count) => tail_count,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };

        let initial = {
            let guard = match self.runtime.tail.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "query_recorder_stream_failed",
                        "tail buffer lock poisoned",
                    );
                }
            };
            let skip = guard.len().saturating_sub(tail_count);
            guard.iter().skip(skip).cloned().collect::<Vec<_>>()
        };

        let pending = initial
            .into_iter()
            .map(|record| sse_record_frame(&record))
            .collect::<VecDeque<_>>();
        let receiver = self.runtime.broadcaster.subscribe();
        let heartbeat = tokio::time::interval(Duration::from_secs(SSE_HEARTBEAT_SECS));
        let stream = futures::stream::unfold(
            SseState {
                pending,
                receiver,
                heartbeat,
            },
            |mut state| async move {
                if let Some(bytes) = state.pending.pop_front() {
                    return Some((Ok(Frame::data(bytes)), state));
                }

                loop {
                    tokio::select! {
                        recv = state.receiver.recv() => {
                            match recv {
                                Ok(record) => return Some((Ok(Frame::data(sse_record_frame(&record))), state)),
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(broadcast::error::RecvError::Closed) => return None,
                            }
                        }
                        _ = state.heartbeat.tick() => {
                            return Some((Ok(Frame::data(Bytes::from_static(b": heartbeat\n\n"))), state));
                        }
                    }
                }
            },
        );

        let mut response = streaming_response(StatusCode::OK, stream);
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-cache"),
        );
        response.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive"),
        );
        response
    }
}

#[derive(Debug)]
struct SseState {
    pending: VecDeque<Bytes>,
    receiver: broadcast::Receiver<RecordDetail>,
    heartbeat: tokio::time::Interval,
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

fn table_names(tag: &str) -> TableNames {
    let safe_tag = sanitize_tag(tag);
    let hash = fnv1a_hex(tag.as_bytes());
    let prefix = format!("qr_{}_{}_{}", safe_tag, hash, SCHEMA_VERSION);
    TableNames {
        records: format!("{prefix}_records"),
        steps: format!("{prefix}_steps"),
    }
}

fn sanitize_tag(tag: &str) -> String {
    let mut out = String::with_capacity(tag.len().max(1));
    for byte in tag.bytes() {
        let lower = byte.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || lower == b'_' {
            out.push(lower as char);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

fn fnv1a_hex(input: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{hash:016x}")
}

fn initialize_database(path: &Path, tables: &TableNames) -> Result<()> {
    let mut conn = open_database(path).map_err(|err| {
        DnsError::plugin(format!("failed to open query_recorder database: {err}"))
    })?;
    create_schema(&mut conn, tables).map_err(|err| {
        DnsError::plugin(format!("failed to initialize query_recorder schema: {err}"))
    })
}

fn open_database(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;
         PRAGMA auto_vacuum=INCREMENTAL;",
    )?;
    Ok(conn)
}

fn create_schema(conn: &mut Connection, tables: &TableNames) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {records} (
            id INTEGER PRIMARY KEY,
            created_at_ms INTEGER NOT NULL,
            elapsed_ms INTEGER NOT NULL,
            request_id INTEGER NOT NULL,
            client_ip TEXT NOT NULL,
            questions_json TEXT NOT NULL,
            req_rd INTEGER NOT NULL,
            req_cd INTEGER NOT NULL,
            req_ad INTEGER NOT NULL,
            req_opcode TEXT NOT NULL,
            req_edns_json TEXT NULL,
            error TEXT NULL,
            has_response INTEGER NOT NULL,
            rcode TEXT NULL,
            resp_aa INTEGER NULL,
            resp_tc INTEGER NULL,
            resp_ra INTEGER NULL,
            resp_ad INTEGER NULL,
            resp_cd INTEGER NULL,
            answer_count INTEGER NOT NULL,
            authority_count INTEGER NOT NULL,
            additional_count INTEGER NOT NULL,
            answers_json TEXT NOT NULL,
            authorities_json TEXT NOT NULL,
            additionals_json TEXT NOT NULL,
            signature_json TEXT NOT NULL,
            resp_edns_json TEXT NULL
        );
        CREATE TABLE IF NOT EXISTS {steps} (
            record_id INTEGER NOT NULL,
            event_index INTEGER NOT NULL,
            sequence_tag TEXT NOT NULL,
            node_index INTEGER NULL,
            kind TEXT NOT NULL,
            tag TEXT NULL,
            outcome TEXT NOT NULL,
            PRIMARY KEY (record_id, event_index),
            FOREIGN KEY(record_id) REFERENCES {records}(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS {records}_created_at_idx ON {records}(created_at_ms DESC);
        CREATE INDEX IF NOT EXISTS {records}_request_id_idx ON {records}(request_id);
        CREATE INDEX IF NOT EXISTS {records}_client_ip_idx ON {records}(client_ip);
        CREATE INDEX IF NOT EXISTS {records}_rcode_idx ON {records}(rcode);
        CREATE INDEX IF NOT EXISTS {steps}_kind_tag_outcome_idx ON {steps}(kind, tag, outcome);
        CREATE INDEX IF NOT EXISTS {steps}_record_id_idx ON {steps}(record_id);",
        records = tables.records,
        steps = tables.steps,
    ))
}

fn run_writer_thread(
    context: WriterThreadContext,
    rx: Receiver<WriterCommand>,
) -> std::result::Result<(), String> {
    let WriterThreadContext {
        path,
        tables,
        stop_requested,
        tail,
        memory_tail,
        broadcaster,
        batch_size,
        flush_interval,
    } = context;

    let mut conn = open_database(&path)
        .map_err(|err| format!("failed to open database '{}': {}", path.display(), err))?;
    create_schema(&mut conn, &tables).map_err(|err| format!("failed to create schema: {err}"))?;

    let mut pending = Vec::with_capacity(batch_size);
    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(WriterCommand::Insert(record)) => {
                pending.push(*record);
                if pending.len() >= batch_size {
                    flush_pending(
                        &mut conn,
                        &tables,
                        &mut pending,
                        &tail,
                        memory_tail,
                        &broadcaster,
                    )?;
                }
            }
            Ok(WriterCommand::Cleanup { cutoff_ms }) => {
                flush_pending(
                    &mut conn,
                    &tables,
                    &mut pending,
                    &tail,
                    memory_tail,
                    &broadcaster,
                )?;
                run_cleanup(&mut conn, &tables, cutoff_ms)
                    .map_err(|err| format!("cleanup failed: {err}"))?;
            }
            Err(RecvTimeoutError::Timeout) => {
                flush_pending(
                    &mut conn,
                    &tables,
                    &mut pending,
                    &tail,
                    memory_tail,
                    &broadcaster,
                )?;
                if stop_requested.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                flush_pending(
                    &mut conn,
                    &tables,
                    &mut pending,
                    &tail,
                    memory_tail,
                    &broadcaster,
                )?;
                break;
            }
        }
    }

    Ok(())
}

fn flush_pending(
    conn: &mut Connection,
    tables: &TableNames,
    pending: &mut Vec<PendingRecord>,
    tail: &Arc<Mutex<VecDeque<RecordDetail>>>,
    memory_tail: usize,
    broadcaster: &broadcast::Sender<RecordDetail>,
) -> std::result::Result<(), String> {
    if pending.is_empty() {
        return Ok(());
    }

    let tx = conn
        .transaction()
        .map_err(|err| format!("failed to begin transaction: {err}"))?;
    let mut committed = Vec::with_capacity(pending.len());
    for pending_record in pending.drain(..) {
        let detail = insert_record(&tx, tables, pending_record)
            .map_err(|err| format!("failed to insert record: {err}"))?;
        committed.push(detail);
    }
    tx.commit()
        .map_err(|err| format!("failed to commit transaction: {err}"))?;

    let mut tail_guard = tail
        .lock()
        .map_err(|_| "query_recorder tail buffer lock poisoned".to_string())?;
    for detail in committed {
        if tail_guard.len() >= memory_tail {
            tail_guard.pop_front();
        }
        tail_guard.push_back(detail.clone());
        let _ = broadcaster.send(detail);
    }
    Ok(())
}

fn insert_record(
    tx: &rusqlite::Transaction<'_>,
    tables: &TableNames,
    pending: PendingRecord,
) -> rusqlite::Result<RecordDetail> {
    let record = pending.record;
    let questions_json = serde_json::to_string(&record.questions_json)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    let req_edns_json = serialize_optional_json(&record.req_edns_json)?;
    let answers_json = serde_json::to_string(&record.answers_json)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    let authorities_json = serde_json::to_string(&record.authorities_json)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    let additionals_json = serde_json::to_string(&record.additionals_json)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    let signature_json = serde_json::to_string(&record.signature_json)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    let resp_edns_json = serialize_optional_json(&record.resp_edns_json)?;

    tx.execute(
        &format!(
            "INSERT INTO {} (
                created_at_ms,
                elapsed_ms,
                request_id,
                client_ip,
                questions_json,
                req_rd,
                req_cd,
                req_ad,
                req_opcode,
                req_edns_json,
                error,
                has_response,
                rcode,
                resp_aa,
                resp_tc,
                resp_ra,
                resp_ad,
                resp_cd,
                answer_count,
                authority_count,
                additional_count,
                answers_json,
                authorities_json,
                additionals_json,
                signature_json,
                resp_edns_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
            tables.records
        ),
        params![
            as_i64(record.created_at_ms)?,
            as_i64(record.elapsed_ms)?,
            i64::from(record.request_id),
            record.client_ip,
            questions_json,
            bool_to_i64(record.req_rd),
            bool_to_i64(record.req_cd),
            bool_to_i64(record.req_ad),
            record.req_opcode,
            req_edns_json,
            record.error,
            bool_to_i64(record.has_response),
            record.rcode,
            record.resp_aa.map(bool_to_i64),
            record.resp_tc.map(bool_to_i64),
            record.resp_ra.map(bool_to_i64),
            record.resp_ad.map(bool_to_i64),
            record.resp_cd.map(bool_to_i64),
            i64::from(record.answer_count),
            i64::from(record.authority_count),
            i64::from(record.additional_count),
            answers_json,
            authorities_json,
            additionals_json,
            signature_json,
            resp_edns_json,
        ],
    )?;
    let record_id = tx.last_insert_rowid();

    for step in &pending.steps {
        tx.execute(
            &format!(
                "INSERT INTO {} (
                    record_id,
                    event_index,
                    sequence_tag,
                    node_index,
                    kind,
                    tag,
                    outcome
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                tables.steps
            ),
            params![
                record_id,
                step.event_index as i64,
                step.sequence_tag,
                step.node_index.map(|value| value as i64),
                step.kind,
                step.tag,
                step.outcome,
            ],
        )?;
    }

    Ok(RecordDetail {
        record: RecordRow {
            id: record_id,
            ..record
        },
        steps: pending.steps,
    })
}

fn serialize_optional_json<T>(value: &Option<T>) -> rusqlite::Result<Option<String>>
where
    T: Serialize,
{
    value
        .as_ref()
        .map(|value| {
            serde_json::to_string(value)
                .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
        })
        .transpose()
}

fn run_cleanup(conn: &mut Connection, tables: &TableNames, cutoff_ms: u64) -> rusqlite::Result<()> {
    let cutoff_ms = as_i64(cutoff_ms)?;
    loop {
        let deleted = conn.execute(
            &format!(
                "DELETE FROM {records}
                 WHERE id IN (
                    SELECT id FROM {records}
                    WHERE created_at_ms < ?1
                    ORDER BY created_at_ms ASC, id ASC
                    LIMIT ?2
                 )",
                records = tables.records
            ),
            params![cutoff_ms, CLEANUP_BATCH_SIZE as i64],
        )?;
        if deleted == 0 {
            break;
        }
    }
    conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE); PRAGMA incremental_vacuum;")
}

impl PendingRecord {
    fn capture(
        request: Message,
        context: &DnsContext,
        created_at_ms: u64,
        elapsed_ms: u64,
        step_start_index: usize,
        error: Option<&DnsError>,
    ) -> Self {
        let questions_json = request
            .questions()
            .iter()
            .map(question_json)
            .collect::<Vec<_>>();
        let req_edns_json = request.edns().as_ref().map(edns_json);
        let steps = context
            .execution_path_events_from(step_start_index)
            .iter()
            .enumerate()
            .map(step_json)
            .collect::<Vec<_>>();

        let mut record = RecordRow {
            id: 0,
            created_at_ms,
            elapsed_ms,
            request_id: request.id(),
            client_ip: context.peer_addr().ip().to_string(),
            questions_json,
            req_rd: request.recursion_desired(),
            req_cd: request.checking_disabled(),
            req_ad: request.authentic_data(),
            req_opcode: opcode_name(request.opcode()),
            req_edns_json,
            error: error.map(ToString::to_string),
            has_response: false,
            rcode: None,
            resp_aa: None,
            resp_tc: None,
            resp_ra: None,
            resp_ad: None,
            resp_cd: None,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            answers_json: Vec::new(),
            authorities_json: Vec::new(),
            additionals_json: Vec::new(),
            signature_json: Vec::new(),
            resp_edns_json: None,
        };

        if error.is_none()
            && let Some(response) = context.response()
        {
            record.has_response = true;
            record.rcode = Some(rcode_name(response.rcode()));
            record.resp_aa = Some(response.authoritative());
            record.resp_tc = Some(response.truncated());
            record.resp_ra = Some(response.recursion_available());
            record.resp_ad = Some(response.authentic_data());
            record.resp_cd = Some(response.checking_disabled());
            record.answer_count = response.answers().len() as u32;
            record.authority_count = response.authorities().len() as u32;
            record.additional_count = response.additionals().len() as u32;
            record.answers_json = response
                .answers()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.authorities_json = response
                .authorities()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.additionals_json = response
                .additionals()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.signature_json = response
                .signature()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.resp_edns_json = response.edns().as_ref().map(edns_json);
        }

        Self { record, steps }
    }
}

fn question_json(question: &Question) -> QuestionJson {
    QuestionJson {
        name: question.name().to_fqdn(),
        qtype: record_type_name(question.qtype()),
        qclass: dns_class_name(question.qclass()),
    }
}

fn step_json((event_index, event): (usize, &ExecutionPathEvent)) -> StepJson {
    StepJson {
        event_index,
        sequence_tag: event.sequence_tag.clone(),
        node_index: event.node_index,
        kind: event.kind.clone(),
        tag: event.tag.clone(),
        outcome: event.outcome.clone(),
    }
}

fn record_json(record: &Record) -> RecordJson {
    let (payload_kind, payload_text, payload) = rdata_payload(record.data());
    RecordJson {
        name: record.name().to_fqdn(),
        class: dns_class_name(record.class()),
        ttl: record.ttl(),
        rr_type: record_type_name(record.rr_type()),
        payload_kind,
        payload_text,
        payload,
    }
}

fn edns_json(edns: &Edns) -> EdnsJson {
    EdnsJson {
        udp_payload_size: edns.udp_payload_size(),
        ext_rcode: edns.ext_rcode(),
        version: edns.version(),
        dnssec_ok: edns.flags().dnssec_ok,
        z: edns.flags().z,
        options: edns.options().iter().map(edns_option_json).collect(),
    }
}

fn edns_option_json(option: &EdnsOption) -> EdnsOptionJson {
    let code = EdnsCode::from(option);
    let (payload_kind, payload) = match option {
        EdnsOption::Llq(value) => (
            "Llq".to_string(),
            json!({
                "version": value.version(),
                "opcode": value.opcode(),
                "error": value.error(),
                "id": value.id(),
                "lease_life": value.lease_life(),
            }),
        ),
        EdnsOption::UpdateLease(value) => (
            "UpdateLease".to_string(),
            json!({
                "lease": value.lease(),
                "key_lease": value.key_lease(),
            }),
        ),
        EdnsOption::Nsid(value) => (
            "Nsid".to_string(),
            json!({ "nsid_base64": STANDARD.encode(value.nsid()) }),
        ),
        EdnsOption::Esu(value) => (
            "Esu".to_string(),
            utf8_or_base64_payload("uri", value.uri()),
        ),
        EdnsOption::Dau(value) => (
            "Dau".to_string(),
            json!({ "algorithms": value.algorithms() }),
        ),
        EdnsOption::Dhu(value) => (
            "Dhu".to_string(),
            json!({ "algorithms": value.algorithms() }),
        ),
        EdnsOption::N3u(value) => (
            "N3u".to_string(),
            json!({ "algorithms": value.algorithms() }),
        ),
        EdnsOption::Subnet(value) => ("Subnet".to_string(), client_subnet_json(value)),
        EdnsOption::Expire(value) => (
            "Expire".to_string(),
            json!({
                "empty": value.is_empty(),
                "expire": (!value.is_empty()).then_some(value.expire()),
            }),
        ),
        EdnsOption::Cookie(value) => (
            "Cookie".to_string(),
            json!({ "cookie_base64": STANDARD.encode(value.cookie()) }),
        ),
        EdnsOption::TcpKeepalive(value) => (
            "TcpKeepalive".to_string(),
            json!({ "timeout": value.timeout() }),
        ),
        EdnsOption::Padding(value) => (
            "Padding".to_string(),
            json!({ "padding_base64": STANDARD.encode(value.padding()) }),
        ),
        EdnsOption::ExtendedDnsError(value) => (
            "ExtendedDnsError".to_string(),
            extended_dns_error_json(value),
        ),
        EdnsOption::ReportChannel(value) => (
            "ReportChannel".to_string(),
            json!({ "agent_domain": value.agent_domain().to_fqdn() }),
        ),
        EdnsOption::ZoneVersion(value) => (
            "ZoneVersion".to_string(),
            json!({
                "label_count": value.label_count(),
                "version_type": value.version_type(),
                "version_base64": STANDARD.encode(value.version()),
            }),
        ),
        EdnsOption::Local(value) => (
            "Local".to_string(),
            json!({
                "code": value.code(),
                "data_base64": STANDARD.encode(value.data()),
            }),
        ),
    };

    EdnsOptionJson {
        code: u16::from(code),
        name: edns_code_name(code),
        payload_kind,
        payload,
    }
}

fn client_subnet_json(value: &ClientSubnet) -> Value {
    json!({
        "addr": value.addr().to_string(),
        "source_prefix": value.source_prefix(),
        "scope_prefix": value.scope_prefix(),
    })
}

fn extended_dns_error_json(value: &EdnsExtendedDnsError) -> Value {
    let text = std::str::from_utf8(value.extra_text())
        .ok()
        .map(str::to_string);
    json!({
        "info_code": value.info_code(),
        "extra_text": text,
        "extra_text_base64": text.is_none().then(|| STANDARD.encode(value.extra_text())),
    })
}

fn rdata_payload(rdata: &RData) -> (String, String, Value) {
    match rdata {
        RData::A(value) => ip_payload("A", IpAddr::V4(value.0)),
        RData::AAAA(value) => ip_payload("AAAA", IpAddr::V6(value.0)),
        RData::CNAME(value) => name_payload("CNAME", "target", &value.0),
        RData::NS(value) => name_payload("NS", "target", &value.0),
        RData::PTR(value) => name_payload("PTR", "target", &value.0),
        RData::DNAME(value) => name_payload("DNAME", "target", &value.0),
        RData::MD(value) => name_payload("MD", "target", &value.0),
        RData::MF(value) => name_payload("MF", "target", &value.0),
        RData::MB(value) => name_payload("MB", "target", &value.0),
        RData::MG(value) => name_payload("MG", "target", &value.0),
        RData::MR(value) => name_payload("MR", "target", &value.0),
        RData::ANAME(value) => name_payload("ANAME", "target", &value.0),
        RData::NSAPPTR(value) => name_payload("NSAPPTR", "target", &value.0),
        RData::MX(value) => (
            "MX".to_string(),
            format!("{} {}", value.preference(), value.exchange().to_fqdn()),
            json!({
                "preference": value.preference(),
                "exchange": value.exchange().to_fqdn(),
            }),
        ),
        RData::KX(value) => (
            "KX".to_string(),
            format!("{} {}", value.preference(), value.exchanger().to_fqdn()),
            json!({
                "preference": value.preference(),
                "exchange": value.exchanger().to_fqdn(),
            }),
        ),
        RData::SRV(value) => (
            "SRV".to_string(),
            format!(
                "{} {} {} {}",
                value.priority(),
                value.weight(),
                value.port(),
                value.target().to_fqdn()
            ),
            json!({
                "priority": value.priority(),
                "weight": value.weight(),
                "port": value.port(),
                "target": value.target().to_fqdn(),
            }),
        ),
        RData::SOA(value) => soa_payload(value),
        RData::TXT(value) => txt_payload("TXT", value),
        RData::SPF(value) => txt_payload("SPF", &value.0),
        RData::CAA(value) => caa_payload(value),
        RData::URI(value) => uri_payload(value),
        RData::SVCB(value) => svcb_payload("SVCB", value),
        RData::HTTPS(value) => svcb_payload("HTTPS", &value.0),
        RData::RRSIG(value) => rrsig_payload("RRSIG", value),
        RData::SIG(value) => rrsig_payload("SIG", &value.0),
        RData::NSEC(value) => nsec_payload(value),
        RData::NSEC3(value) => nsec3_payload(value),
        RData::NSEC3PARAM(value) => nsec3param_payload(value),
        RData::DNSKEY(value) => dnskey_payload("DNSKEY", value),
        RData::CDNSKEY(value) => dnskey_payload("CDNSKEY", &value.0),
        RData::DS(value) => ds_payload("DS", value),
        RData::CDS(value) => ds_payload("CDS", &value.0),
        RData::DLV(value) => ds_payload("DLV", &value.0),
        RData::TA(value) => ds_payload("TA", &value.0),
        RData::TLSA(value) => tlsa_payload("TLSA", value),
        RData::SMIMEA(value) => tlsa_payload("SMIMEA", &value.0),
        RData::SSHFP(value) => sshfp_payload(value),
        RData::OPENPGPKEY(value) => (
            "OPENPGPKEY".to_string(),
            "OPENPGPKEY".to_string(),
            json!({ "public_key_base64": STANDARD.encode(&value.0) }),
        ),
        RData::NULL(value) => (
            "NULL".to_string(),
            "NULL".to_string(),
            json!({ "data_base64": STANDARD.encode(value.data()) }),
        ),
        RData::OPT(_) => ("OPT".to_string(), "OPT".to_string(), json!({})),
        RData::Unknown { rr_type, data } => (
            format!("TYPE{rr_type}"),
            format!("TYPE{rr_type}"),
            json!({
                "unknown_rr_type": rr_type,
                "data_base64": STANDARD.encode(data),
            }),
        ),
        other => (
            record_type_name(other.rr_type()),
            format!("{other:?}"),
            json!({ "display": format!("{other:?}") }),
        ),
    }
}

fn ip_payload(kind: &str, ip: IpAddr) -> (String, String, Value) {
    let ip = ip.to_string();
    (kind.to_string(), ip.clone(), json!({ "ip": ip }))
}

fn name_payload(kind: &str, field: &str, name: &crate::proto::Name) -> (String, String, Value) {
    let target = name.to_fqdn();
    (kind.to_string(), target.clone(), json!({ field: target }))
}

fn soa_payload(value: &SOA) -> (String, String, Value) {
    (
        "SOA".to_string(),
        format!("{} {}", value.mname().to_fqdn(), value.rname().to_fqdn()),
        json!({
            "mname": value.mname().to_fqdn(),
            "rname": value.rname().to_fqdn(),
            "serial": value.serial(),
            "refresh": value.refresh(),
            "retry": value.retry(),
            "expire": value.expire(),
            "minimum": value.minimum(),
        }),
    )
}

fn txt_payload(kind: &str, value: &TXT) -> (String, String, Value) {
    let mut strings = Vec::new();
    let mut parts = Vec::new();
    let mut all_utf8 = true;
    for part in value.txt_data() {
        match std::str::from_utf8(part) {
            Ok(text) => {
                strings.push(text.to_string());
                parts.push(json!({ "text": text }));
            }
            Err(_) => {
                all_utf8 = false;
                let encoded = STANDARD.encode(part);
                parts.push(json!({ "data_base64": encoded }));
            }
        }
    }

    let payload = if all_utf8 {
        json!({ "strings": strings })
    } else {
        json!({ "parts": parts })
    };

    let payload_text = if strings.is_empty() {
        kind.to_string()
    } else {
        strings.join(" ")
    };

    (kind.to_string(), payload_text, payload)
}

fn caa_payload(value: &CAA) -> (String, String, Value) {
    let tag = bytes_to_text_or_base64(value.tag());
    let caa_value = bytes_to_text_or_base64(value.value());
    (
        "CAA".to_string(),
        format!("{} {}", tag.text, caa_value.text),
        json!({
            "flag": value.flag(),
            "tag": tag.text_value,
            "tag_base64": tag.base64_value,
            "value": caa_value.text_value,
            "value_base64": caa_value.base64_value,
        }),
    )
}

fn uri_payload(value: &URI) -> (String, String, Value) {
    let target = bytes_to_text_or_base64(value.target());
    (
        "URI".to_string(),
        target.text.clone(),
        json!({
            "priority": value.priority(),
            "weight": value.weight(),
            "target": target.text_value,
            "target_base64": target.base64_value,
        }),
    )
}

fn svcb_payload(kind: &str, value: &SVCB) -> (String, String, Value) {
    let params = value
        .params()
        .iter()
        .map(|param| {
            json!({
                "key": param.key(),
                "name": svcb_param_name(param.key()),
                "value_base64": STANDARD.encode(param.value()),
                "parsed": svcb_param_value_json(param.parsed()),
            })
        })
        .collect::<Vec<_>>();

    (
        kind.to_string(),
        value.target().to_fqdn(),
        json!({
            "priority": value.priority(),
            "target": value.target().to_fqdn(),
            "params": params,
        }),
    )
}

fn rrsig_payload(kind: &str, value: &RRSIG) -> (String, String, Value) {
    (
        kind.to_string(),
        value.signer_name().to_fqdn(),
        json!({
            "type_covered": format_record_type_from_u16(value.type_covered()),
            "algorithm": value.algorithm(),
            "labels": value.labels(),
            "orig_ttl": value.orig_ttl(),
            "expiration": value.expiration(),
            "inception": value.inception(),
            "key_tag": value.key_tag(),
            "signer_name": value.signer_name().to_fqdn(),
            "signature_base64": STANDARD.encode(value.signature()),
        }),
    )
}

fn nsec_payload(value: &NSEC) -> (String, String, Value) {
    (
        "NSEC".to_string(),
        value.next_domain().to_fqdn(),
        json!({
            "next_domain": value.next_domain().to_fqdn(),
            "type_bitmap": value.type_bitmap_types().iter().map(|ty| record_type_name(*ty)).collect::<Vec<_>>(),
            "type_bitmap_base64": STANDARD.encode(value.type_bitmap()),
        }),
    )
}

fn nsec3_payload(value: &NSEC3) -> (String, String, Value) {
    (
        "NSEC3".to_string(),
        "NSEC3".to_string(),
        json!({
            "hash": value.hash(),
            "flags": value.flags(),
            "iterations": value.iterations(),
            "salt_base64": STANDARD.encode(value.salt()),
            "next_domain_base64": STANDARD.encode(value.next_domain()),
            "type_bitmap": value.type_bitmap_types().iter().map(|ty| record_type_name(*ty)).collect::<Vec<_>>(),
            "type_bitmap_base64": STANDARD.encode(value.type_bitmap()),
        }),
    )
}

fn nsec3param_payload(value: &NSEC3PARAM) -> (String, String, Value) {
    (
        "NSEC3PARAM".to_string(),
        "NSEC3PARAM".to_string(),
        json!({
            "hash": value.hash(),
            "flags": value.flags(),
            "iterations": value.iterations(),
            "salt_base64": STANDARD.encode(value.salt()),
        }),
    )
}

fn dnskey_payload(kind: &str, value: &DNSKEY) -> (String, String, Value) {
    (
        kind.to_string(),
        kind.to_string(),
        json!({
            "flags": value.flags(),
            "protocol": value.protocol(),
            "algorithm": value.algorithm(),
            "public_key_base64": STANDARD.encode(value.public_key()),
        }),
    )
}

fn ds_payload(kind: &str, value: &DS) -> (String, String, Value) {
    (
        kind.to_string(),
        kind.to_string(),
        json!({
            "key_tag": value.key_tag(),
            "algorithm": value.algorithm(),
            "digest_type": value.digest_type(),
            "digest_base64": STANDARD.encode(value.digest()),
        }),
    )
}

fn tlsa_payload(kind: &str, value: &TLSA) -> (String, String, Value) {
    (
        kind.to_string(),
        kind.to_string(),
        json!({
            "usage": value.usage(),
            "selector": value.selector(),
            "matching_type": value.matching_type(),
            "certificate_base64": STANDARD.encode(value.certificate()),
        }),
    )
}

fn sshfp_payload(value: &SSHFP) -> (String, String, Value) {
    (
        "SSHFP".to_string(),
        "SSHFP".to_string(),
        json!({
            "algorithm": value.algorithm(),
            "fp_type": value.fp_type(),
            "fingerprint_base64": STANDARD.encode(value.fingerprint()),
        }),
    )
}

fn utf8_or_base64_payload(field: &str, bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({ field: text }),
        Err(_) => {
            let mut map = serde_json::Map::new();
            map.insert(
                format!("{field}_base64"),
                Value::String(STANDARD.encode(bytes)),
            );
            Value::Object(map)
        }
    }
}

#[derive(Debug)]
struct TextOrBase64 {
    text: String,
    text_value: Option<String>,
    base64_value: Option<String>,
}

fn bytes_to_text_or_base64(bytes: &[u8]) -> TextOrBase64 {
    match std::str::from_utf8(bytes) {
        Ok(text) => TextOrBase64 {
            text: text.to_string(),
            text_value: Some(text.to_string()),
            base64_value: None,
        },
        Err(_) => {
            let encoded = STANDARD.encode(bytes);
            TextOrBase64 {
                text: encoded.clone(),
                text_value: None,
                base64_value: Some(encoded),
            }
        }
    }
}

fn svcb_param_value_json(value: &rdata::SvcParamValue) -> Value {
    match value {
        rdata::SvcParamValue::Mandatory(values) => json!({ "mandatory": values }),
        rdata::SvcParamValue::Alpn(values) => json!({
            "alpn": values
                .iter()
                .map(|value| std::str::from_utf8(value).ok().map(str::to_string).unwrap_or_else(|| STANDARD.encode(value)))
                .collect::<Vec<_>>()
        }),
        rdata::SvcParamValue::NoDefaultAlpn => json!({ "no_default_alpn": true }),
        rdata::SvcParamValue::Port(port) => json!({ "port": port }),
        rdata::SvcParamValue::Ipv4Hint(values) => json!({
            "ipv4_hint": values.iter().map(ToString::to_string).collect::<Vec<_>>()
        }),
        rdata::SvcParamValue::Ech(value) => json!({ "ech_base64": STANDARD.encode(value) }),
        rdata::SvcParamValue::Ipv6Hint(values) => json!({
            "ipv6_hint": values.iter().map(ToString::to_string).collect::<Vec<_>>()
        }),
        rdata::SvcParamValue::DohPath(value) => match std::str::from_utf8(value) {
            Ok(text) => json!({ "doh_path": text }),
            Err(_) => json!({ "doh_path_base64": STANDARD.encode(value) }),
        },
        rdata::SvcParamValue::Ohttp => json!({ "ohttp": true }),
        rdata::SvcParamValue::Unknown => json!({ "unknown": true }),
    }
}

fn query_records(
    runtime: Arc<RecorderRuntime>,
    query: ListQuery,
) -> std::result::Result<(Vec<RecordRow>, Option<String>), DnsError> {
    let conn = open_database(&runtime.path)
        .map_err(|err| DnsError::runtime(format!("failed to open recorder database: {err}")))?;
    let sql = format!(
        "SELECT
            id,
            created_at_ms,
            elapsed_ms,
            request_id,
            client_ip,
            questions_json,
            req_rd,
            req_cd,
            req_ad,
            req_opcode,
            req_edns_json,
            error,
            has_response,
            rcode,
            resp_aa,
            resp_tc,
            resp_ra,
            resp_ad,
            resp_cd,
            answer_count,
            authority_count,
            additional_count,
            answers_json,
            authorities_json,
            additionals_json,
            signature_json,
            resp_edns_json
         FROM {records}
         WHERE (?1 IS NULL OR created_at_ms >= ?1)
           AND (?2 IS NULL OR created_at_ms <= ?2)
           AND (?3 IS NULL
                OR created_at_ms < ?3
                OR (created_at_ms = ?3 AND id < ?4))
         ORDER BY created_at_ms DESC, id DESC
         LIMIT ?5",
        records = runtime.tables.records
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| DnsError::runtime(format!("failed to prepare list query: {err}")))?;
    let mut rows = stmt
        .query(params![
            query
                .since_ms
                .map(as_i64)
                .transpose()
                .map_err(to_runtime_error)?,
            query
                .until_ms
                .map(as_i64)
                .transpose()
                .map_err(to_runtime_error)?,
            query
                .cursor
                .map(|cursor| as_i64(cursor.created_at_ms))
                .transpose()
                .map_err(to_runtime_error)?,
            query.cursor.map(|cursor| cursor.id),
            query.limit as i64,
        ])
        .map_err(|err| DnsError::runtime(format!("failed to run list query: {err}")))?;

    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| DnsError::runtime(format!("failed to fetch list row: {err}")))?
    {
        records.push(
            read_record_row(row)
                .map_err(|err| DnsError::runtime(format!("failed to decode list row: {err}")))?,
        );
    }

    let next_cursor = records.last().map(|record| {
        encode_cursor(ListCursor {
            created_at_ms: record.created_at_ms,
            id: record.id,
        })
    });
    Ok((records, next_cursor))
}

fn load_record_detail(
    runtime: Arc<RecorderRuntime>,
    record_id: i64,
) -> std::result::Result<Option<RecordDetail>, DnsError> {
    let conn = open_database(&runtime.path)
        .map_err(|err| DnsError::runtime(format!("failed to open recorder database: {err}")))?;
    let record_sql = format!(
        "SELECT
            id,
            created_at_ms,
            elapsed_ms,
            request_id,
            client_ip,
            questions_json,
            req_rd,
            req_cd,
            req_ad,
            req_opcode,
            req_edns_json,
            error,
            has_response,
            rcode,
            resp_aa,
            resp_tc,
            resp_ra,
            resp_ad,
            resp_cd,
            answer_count,
            authority_count,
            additional_count,
            answers_json,
            authorities_json,
            additionals_json,
            signature_json,
            resp_edns_json
         FROM {records}
         WHERE id = ?1",
        records = runtime.tables.records
    );

    let record = conn
        .prepare(&record_sql)
        .map_err(|err| DnsError::runtime(format!("failed to prepare detail query: {err}")))?
        .query_row(params![record_id], read_record_row)
        .optional()
        .map_err(|err| DnsError::runtime(format!("failed to load detail row: {err}")))?;

    let Some(record) = record else {
        return Ok(None);
    };

    let steps = load_steps(&conn, &runtime.tables, record_id)?;
    Ok(Some(RecordDetail { record, steps }))
}

fn load_steps(
    conn: &Connection,
    tables: &TableNames,
    record_id: i64,
) -> std::result::Result<Vec<StepJson>, DnsError> {
    let sql = format!(
        "SELECT event_index, sequence_tag, node_index, kind, tag, outcome
         FROM {steps}
         WHERE record_id = ?1
         ORDER BY event_index ASC",
        steps = tables.steps
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| DnsError::runtime(format!("failed to prepare step query: {err}")))?;
    let mut rows = stmt
        .query(params![record_id])
        .map_err(|err| DnsError::runtime(format!("failed to run step query: {err}")))?;

    let mut steps = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| DnsError::runtime(format!("failed to fetch step row: {err}")))?
    {
        steps.push(StepJson {
            event_index: row
                .get::<_, i64>(0)
                .and_then(non_negative_usize)
                .map_err(|err| DnsError::runtime(format!("invalid step event_index: {err}")))?,
            sequence_tag: row
                .get(1)
                .map_err(|err| DnsError::runtime(format!("invalid step sequence_tag: {err}")))?,
            node_index: row
                .get::<_, Option<i64>>(2)
                .map_err(|err| DnsError::runtime(format!("invalid step node_index: {err}")))?
                .map(|value| {
                    usize::try_from(value)
                        .map_err(|_| DnsError::runtime("negative step node_index"))
                })
                .transpose()?,
            kind: row
                .get(3)
                .map_err(|err| DnsError::runtime(format!("invalid step kind: {err}")))?,
            tag: row
                .get(4)
                .map_err(|err| DnsError::runtime(format!("invalid step tag: {err}")))?,
            outcome: row
                .get(5)
                .map_err(|err| DnsError::runtime(format!("invalid step outcome: {err}")))?,
        });
    }
    Ok(steps)
}

fn load_stats_overview(
    runtime: Arc<RecorderRuntime>,
    query: StatsQuery,
) -> std::result::Result<StatsOverview, DnsError> {
    let conn = open_database(&runtime.path)
        .map_err(|err| DnsError::runtime(format!("failed to open recorder database: {err}")))?;
    let sql = format!(
        "SELECT
            COUNT(*) AS query_total,
            COALESCE(SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END), 0) AS error_total,
            AVG(elapsed_ms) AS avg_elapsed_ms
         FROM {records}
         WHERE (?1 IS NULL OR created_at_ms >= ?1)
           AND (?2 IS NULL OR created_at_ms <= ?2)",
        records = runtime.tables.records
    );

    conn.prepare(&sql)
        .map_err(|err| DnsError::runtime(format!("failed to prepare overview query: {err}")))?
        .query_row(
            params![
                query
                    .since_ms
                    .map(as_i64)
                    .transpose()
                    .map_err(to_runtime_error)?,
                query
                    .until_ms
                    .map(as_i64)
                    .transpose()
                    .map_err(to_runtime_error)?,
            ],
            |row| {
                Ok(StatsOverview {
                    query_total: row.get::<_, i64>(0).and_then(non_negative_u64)?,
                    error_total: row.get::<_, i64>(1).and_then(non_negative_u64)?,
                    avg_elapsed_ms: row.get(2)?,
                })
            },
        )
        .map_err(|err| DnsError::runtime(format!("failed to load overview stats: {err}")))
}

fn load_plugin_stats(
    runtime: Arc<RecorderRuntime>,
    query: PluginsStatsQuery,
) -> std::result::Result<(u64, Vec<PluginStatsRow>), DnsError> {
    let conn = open_database(&runtime.path)
        .map_err(|err| DnsError::runtime(format!("failed to open recorder database: {err}")))?;
    let total_records = count_records(&conn, &runtime.tables, query.since_ms, query.until_ms)?;
    let kind_filter = query.kind.sql_value();
    let sql = format!(
        "SELECT
            s.kind,
            s.tag,
            COALESCE(SUM(CASE
                WHEN s.kind = 'matcher' AND s.outcome IN ('matched', 'not_matched') THEN 1
                ELSE 0
            END), 0) AS evaluated,
            COALESCE(SUM(CASE
                WHEN s.kind = 'matcher' AND s.outcome = 'matched' THEN 1
                ELSE 0
            END), 0) AS matched,
            COALESCE(SUM(CASE
                WHEN s.kind = 'executor' AND s.outcome = 'entered' THEN 1
                WHEN s.kind = 'builtin' THEN 1
                ELSE 0
            END), 0) AS executed,
            COUNT(DISTINCT s.record_id) AS query_hits
         FROM {steps} s
         JOIN {records} r ON r.id = s.record_id
         WHERE (?1 IS NULL OR r.created_at_ms >= ?1)
           AND (?2 IS NULL OR r.created_at_ms <= ?2)
           AND (?3 = 'all' OR s.kind = ?3)
         GROUP BY s.kind, s.tag
         ORDER BY s.kind ASC, query_hits DESC, s.tag ASC",
        steps = runtime.tables.steps,
        records = runtime.tables.records
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| DnsError::runtime(format!("failed to prepare plugin stats query: {err}")))?;
    let mut rows = stmt
        .query(params![
            query
                .since_ms
                .map(as_i64)
                .transpose()
                .map_err(to_runtime_error)?,
            query
                .until_ms
                .map(as_i64)
                .transpose()
                .map_err(to_runtime_error)?,
            kind_filter,
        ])
        .map_err(|err| DnsError::runtime(format!("failed to run plugin stats query: {err}")))?;

    let mut stats = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| DnsError::runtime(format!("failed to fetch plugin stats row: {err}")))?
    {
        let query_hits = row
            .get::<_, i64>(5)
            .and_then(non_negative_u64)
            .map_err(|err| DnsError::runtime(format!("invalid plugin stats query_hits: {err}")))?;
        stats.push(PluginStatsRow {
            kind: row
                .get(0)
                .map_err(|err| DnsError::runtime(format!("invalid plugin stats kind: {err}")))?,
            tag: row
                .get(1)
                .map_err(|err| DnsError::runtime(format!("invalid plugin stats tag: {err}")))?,
            evaluated: row
                .get::<_, i64>(2)
                .and_then(non_negative_u64)
                .map_err(|err| {
                    DnsError::runtime(format!("invalid plugin stats evaluated: {err}"))
                })?,
            matched: row
                .get::<_, i64>(3)
                .and_then(non_negative_u64)
                .map_err(|err| DnsError::runtime(format!("invalid plugin stats matched: {err}")))?,
            executed: row
                .get::<_, i64>(4)
                .and_then(non_negative_u64)
                .map_err(|err| {
                    DnsError::runtime(format!("invalid plugin stats executed: {err}"))
                })?,
            query_total: query_hits,
            query_share: if total_records == 0 {
                0.0
            } else {
                query_hits as f64 / total_records as f64
            },
        });
    }
    Ok((total_records, stats))
}

fn count_records(
    conn: &Connection,
    tables: &TableNames,
    since_ms: Option<u64>,
    until_ms: Option<u64>,
) -> std::result::Result<u64, DnsError> {
    let sql = format!(
        "SELECT COUNT(*) FROM {records}
         WHERE (?1 IS NULL OR created_at_ms >= ?1)
           AND (?2 IS NULL OR created_at_ms <= ?2)",
        records = tables.records
    );
    conn.prepare(&sql)
        .map_err(|err| DnsError::runtime(format!("failed to prepare count query: {err}")))?
        .query_row(
            params![
                since_ms.map(as_i64).transpose().map_err(to_runtime_error)?,
                until_ms.map(as_i64).transpose().map_err(to_runtime_error)?,
            ],
            |row| row.get::<_, i64>(0).and_then(non_negative_u64),
        )
        .map_err(|err| DnsError::runtime(format!("failed to count records: {err}")))
}

fn read_record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecordRow> {
    Ok(RecordRow {
        id: row.get(0)?,
        created_at_ms: row.get::<_, i64>(1).and_then(non_negative_u64)?,
        elapsed_ms: row.get::<_, i64>(2).and_then(non_negative_u64)?,
        request_id: row.get::<_, i64>(3).and_then(non_negative_u16)?,
        client_ip: row.get(4)?,
        questions_json: parse_json_column(row.get(5)?)?,
        req_rd: read_bool(row, 6)?,
        req_cd: read_bool(row, 7)?,
        req_ad: read_bool(row, 8)?,
        req_opcode: row.get(9)?,
        req_edns_json: parse_optional_json_column(row.get(10)?)?,
        error: row.get(11)?,
        has_response: read_bool(row, 12)?,
        rcode: row.get(13)?,
        resp_aa: read_optional_bool(row, 14)?,
        resp_tc: read_optional_bool(row, 15)?,
        resp_ra: read_optional_bool(row, 16)?,
        resp_ad: read_optional_bool(row, 17)?,
        resp_cd: read_optional_bool(row, 18)?,
        answer_count: row.get::<_, i64>(19).and_then(non_negative_u32)?,
        authority_count: row.get::<_, i64>(20).and_then(non_negative_u32)?,
        additional_count: row.get::<_, i64>(21).and_then(non_negative_u32)?,
        answers_json: parse_json_column(row.get(22)?)?,
        authorities_json: parse_json_column(row.get(23)?)?,
        additionals_json: parse_json_column(row.get(24)?)?,
        signature_json: parse_json_column(row.get(25)?)?,
        resp_edns_json: parse_optional_json_column(row.get(26)?)?,
    })
}

fn parse_json_column<T>(raw: String) -> rusqlite::Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(raw.as_str()).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn parse_optional_json_column<T>(raw: Option<String>) -> rusqlite::Result<Option<T>>
where
    T: DeserializeOwned,
{
    raw.map(parse_json_column).transpose()
}

fn read_bool(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<bool> {
    Ok(row.get::<_, i64>(index)? != 0)
}

fn read_optional_bool(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<bool>> {
    Ok(row.get::<_, Option<i64>>(index)?.map(|value| value != 0))
}

fn parse_list_query(query: Option<&str>) -> std::result::Result<ListQuery, String> {
    let mut cursor = None;
    let mut limit = DEFAULT_LIST_LIMIT;
    let mut since_ms = None;
    let mut until_ms = None;

    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "cursor" => cursor = Some(parse_cursor(value.as_ref())?),
            "limit" => limit = parse_limit(value.as_ref())?,
            "since_ms" => since_ms = Some(parse_u64_query("since_ms", value.as_ref())?),
            "until_ms" => until_ms = Some(parse_u64_query("until_ms", value.as_ref())?),
            _ => {}
        }
    }

    Ok(ListQuery {
        cursor,
        limit,
        since_ms,
        until_ms,
    })
}

fn parse_stats_query(query: Option<&str>) -> std::result::Result<StatsQuery, String> {
    let mut since_ms = None;
    let mut until_ms = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "since_ms" => since_ms = Some(parse_u64_query("since_ms", value.as_ref())?),
            "until_ms" => until_ms = Some(parse_u64_query("until_ms", value.as_ref())?),
            _ => {}
        }
    }
    Ok(StatsQuery { since_ms, until_ms })
}

fn parse_plugins_stats_query(
    query: Option<&str>,
) -> std::result::Result<PluginsStatsQuery, String> {
    let mut since_ms = None;
    let mut until_ms = None;
    let mut kind = PluginStatsKind::All;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "since_ms" => since_ms = Some(parse_u64_query("since_ms", value.as_ref())?),
            "until_ms" => until_ms = Some(parse_u64_query("until_ms", value.as_ref())?),
            "kind" => kind = PluginStatsKind::parse(value.as_ref())?,
            _ => {}
        }
    }
    Ok(PluginsStatsQuery {
        since_ms,
        until_ms,
        kind,
    })
}

fn parse_tail_param(query: Option<&str>, max_tail: usize) -> std::result::Result<usize, String> {
    let mut tail = 0usize;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if key == "tail" {
            let requested = value
                .parse::<usize>()
                .map_err(|err| format!("invalid tail query parameter: {err}"))?;
            tail = requested.min(max_tail);
        }
    }
    Ok(tail)
}

fn parse_cursor(raw: &str) -> std::result::Result<ListCursor, String> {
    let (created_at_ms, id) = raw
        .split_once(':')
        .ok_or_else(|| "cursor must be formatted as <created_at_ms>:<id>".to_string())?;
    Ok(ListCursor {
        created_at_ms: created_at_ms
            .parse::<u64>()
            .map_err(|err| format!("invalid cursor created_at_ms: {err}"))?,
        id: id
            .parse::<i64>()
            .map_err(|err| format!("invalid cursor id: {err}"))?,
    })
}

fn encode_cursor(cursor: ListCursor) -> String {
    format!("{}:{}", cursor.created_at_ms, cursor.id)
}

fn parse_limit(raw: &str) -> std::result::Result<usize, String> {
    let limit = raw
        .parse::<usize>()
        .map_err(|err| format!("invalid limit query parameter: {err}"))?;
    if limit == 0 {
        return Err("limit must be greater than 0".to_string());
    }
    Ok(limit.min(MAX_LIST_LIMIT))
}

fn parse_u64_query(field: &str, raw: &str) -> std::result::Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|err| format!("invalid {field} query parameter: {err}"))
}

impl PluginStatsKind {
    fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw {
            "matcher" => Ok(Self::Matcher),
            "executor" => Ok(Self::Executor),
            "builtin" => Ok(Self::Builtin),
            "all" => Ok(Self::All),
            _ => Err("kind must be one of matcher, executor, builtin, all".to_string()),
        }
    }

    fn sql_value(self) -> &'static str {
        match self {
            Self::Matcher => "matcher",
            Self::Executor => "executor",
            Self::Builtin => "builtin",
            Self::All => "all",
        }
    }
}

fn opcode_name(opcode: Opcode) -> String {
    opcode.to_string()
}

fn rcode_name(rcode: Rcode) -> String {
    match rcode {
        Rcode::Unknown(code) => format!("RCODE{code}"),
        _ => rcode.to_string(),
    }
}

fn dns_class_name(class: DNSClass) -> String {
    match class {
        DNSClass::Unknown(value) => format!("CLASS{value}"),
        DNSClass::OPT(value) => format!("OPT({value})"),
        _ => class.to_string(),
    }
}

fn format_record_type_from_u16(value: u16) -> String {
    record_type_name(RecordType::from(value))
}

fn record_type_name(record_type: RecordType) -> String {
    match record_type {
        RecordType::Unknown(value) => format!("TYPE{value}"),
        _ => record_type.to_string(),
    }
}

fn edns_code_name(code: EdnsCode) -> String {
    match code {
        EdnsCode::Reserved => "Reserved".to_string(),
        EdnsCode::Llq => "Llq".to_string(),
        EdnsCode::UpdateLease => "UpdateLease".to_string(),
        EdnsCode::Nsid => "Nsid".to_string(),
        EdnsCode::Esu => "Esu".to_string(),
        EdnsCode::Dau => "Dau".to_string(),
        EdnsCode::Dhu => "Dhu".to_string(),
        EdnsCode::N3u => "N3u".to_string(),
        EdnsCode::Subnet => "Subnet".to_string(),
        EdnsCode::Expire => "Expire".to_string(),
        EdnsCode::Cookie => "Cookie".to_string(),
        EdnsCode::TcpKeepalive => "TcpKeepalive".to_string(),
        EdnsCode::Padding => "Padding".to_string(),
        EdnsCode::Chain => "Chain".to_string(),
        EdnsCode::KeyTag => "KeyTag".to_string(),
        EdnsCode::ExtendedDnsError => "ExtendedDnsError".to_string(),
        EdnsCode::ClientTag => "ClientTag".to_string(),
        EdnsCode::ServerTag => "ServerTag".to_string(),
        EdnsCode::ReportChannel => "ReportChannel".to_string(),
        EdnsCode::ZoneVersion => "ZoneVersion".to_string(),
        EdnsCode::Unknown(value) => format!("Unknown({value})"),
    }
}

fn svcb_param_name(key: u16) -> &'static str {
    match key {
        0 => "mandatory",
        1 => "alpn",
        2 => "no-default-alpn",
        3 => "port",
        4 => "ipv4hint",
        5 => "ech",
        6 => "ipv6hint",
        7 => "dohpath",
        8 => "ohttp",
        _ => "unknown",
    }
}

fn sse_record_frame(record: &RecordDetail) -> Bytes {
    match serde_json::to_vec(record) {
        Ok(data) => {
            let mut frame = Vec::with_capacity(data.len() + 32);
            frame.extend_from_slice(b"event: record\ndata: ");
            frame.extend_from_slice(&data);
            frame.extend_from_slice(b"\n\n");
            Bytes::from(frame)
        }
        Err(err) => Bytes::from(format!(
            "event: error\ndata: {{\"message\":\"failed to serialize stream record: {}\"}}\n\n",
            err
        )),
    }
}

fn as_i64(value: u64) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn non_negative_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn non_negative_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn non_negative_u16(value: i64) -> rusqlite::Result<u16> {
    u16::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn non_negative_usize(value: i64) -> rusqlite::Result<usize> {
    usize::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn to_runtime_error(err: rusqlite::Error) -> DnsError {
    DnsError::runtime(format!("{err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::{test_context, test_registry};
    use crate::proto::rdata::{A, CNAME};
    use crate::proto::{Message, Name, Question};
    use crate::proto::{RData, Record};
    use std::net::{Ipv4Addr, SocketAddr};
    use tempfile::NamedTempFile;

    #[test]
    fn test_table_names_include_tag_hash_and_version() {
        let tables = table_names("Recorder.Main");
        assert!(tables.records.starts_with("qr_recorder_main_"));
        assert!(tables.records.ends_with("_v1_records"));
        assert!(tables.steps.ends_with("_v1_steps"));
    }

    #[test]
    fn test_record_capture_without_response_uses_empty_sections() {
        let mut ctx = test_context();
        let mut request = Message::new();
        request.set_id(7);
        request.set_recursion_desired(true);
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        ctx.enable_execution_path();
        ctx.push_execution_path_event(ExecutionPathEvent::new(
            "seq",
            Some(0),
            "executor",
            Some("query_recorder"),
            "entered",
        ));

        let pending =
            PendingRecord::capture(request, &ctx, 100, 10, 0, Some(&DnsError::plugin("boom")));

        assert!(!pending.record.has_response);
        assert_eq!(pending.record.answer_count, 0);
        assert!(pending.record.answers_json.is_empty());
        assert!(
            pending
                .record
                .error
                .as_deref()
                .is_some_and(|value| value.contains("boom"))
        );
        assert_eq!(pending.steps.len(), 1);
    }

    #[test]
    fn test_record_capture_with_structured_response() {
        let mut ctx = test_context();
        let mut request = Message::new();
        request.set_id(9);
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        let mut response = request.response(Rcode::NoError);
        response.set_authoritative(true);
        response.set_recursion_available(true);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("alias.example.com.").unwrap())),
        ));
        ctx.set_response(response);
        ctx.enable_execution_path();

        let pending = PendingRecord::capture(request, &ctx, 100, 12, 0, None);

        assert!(pending.record.has_response);
        assert_eq!(pending.record.answer_count, 1);
        assert_eq!(pending.record.authority_count, 1);
        assert_eq!(pending.record.answers_json[0].payload_kind, "A");
        assert_eq!(pending.record.authorities_json[0].payload_kind, "CNAME");
    }

    #[tokio::test]
    async fn test_query_recorder_execute_enqueues_record() {
        let temp = NamedTempFile::new().unwrap();
        let config = resolve_config(Some(
            serde_yaml_ng::to_value(QueryRecorderConfig {
                path: temp.path().display().to_string(),
                queue_size: Some(16),
                batch_size: Some(1),
                flush_interval_ms: Some(10),
                memory_tail: Some(8),
                retention_days: Some(7),
                cleanup_interval_hours: Some(1),
            })
            .unwrap(),
        ))
        .unwrap();

        let mut plugin = QueryRecorder::new("rec".to_string(), config.clone(), None);
        plugin.init().await.unwrap();

        let mut ctx = DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            Message::new(),
            test_registry(),
        );
        let step = plugin.execute_with_next(&mut ctx, None).await.unwrap();
        assert_eq!(step, ExecStep::Next);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let runtime = plugin.runtime.as_ref().unwrap().clone();
        let records = tokio::task::spawn_blocking(move || {
            query_records(
                runtime,
                ListQuery {
                    cursor: None,
                    limit: 10,
                    since_ms: None,
                    until_ms: None,
                },
            )
        })
        .await
        .unwrap()
        .unwrap()
        .0;
        assert_eq!(records.len(), 1);

        plugin.destroy().await.unwrap();
    }

    #[test]
    fn test_factory_rejects_quick_setup() {
        let factory = QueryRecorderFactory;
        let err = match factory.quick_setup("rec", None, test_registry()) {
            Ok(_) => panic!("quick setup should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("does not support quick setup"));
    }

    #[test]
    fn test_resolve_config_rejects_zero_limits() {
        let config = serde_yaml_ng::to_value(QueryRecorderConfig {
            path: "test.db".to_string(),
            queue_size: Some(0),
            batch_size: Some(1),
            flush_interval_ms: Some(1),
            memory_tail: Some(1),
            retention_days: Some(1),
            cleanup_interval_hours: Some(1),
        })
        .unwrap();
        assert!(resolve_config(Some(config)).is_err());
    }
}
