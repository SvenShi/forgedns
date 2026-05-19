// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! In-memory log buffer, tracing subscriber layer, and HTTP API endpoints.
//!
//! `LogBuffer` collects recent tracing events via `LogLayer` and exposes them
//! through two API endpoints:
//!
//! - `GET /api/logs` — returns recent entries from the ring buffer (REST)
//! - `GET /api/logs/stream` — streams new entries in real-time (SSE)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode};
use hyper::body::Frame;
use jiff::Zoned;
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::api::{ApiHandler, ApiRegister, json_error, json_ok, streaming_response};
use crate::core::app_clock::AppClock;
use crate::core::error::Result;

const RING_CAP: usize = 1000;
const SSE_HEARTBEAT_SECS: u64 = 15;
const DEFAULT_FETCH_LIMIT: usize = 200;
const MAX_FETCH_LIMIT: usize = 1000;
const MAX_TAIL: usize = 500;

static GLOBAL_LOG_BUFFER: OnceLock<Arc<LogBuffer>> = OnceLock::new();

pub fn install_global_log_buffer(buffer: Arc<LogBuffer>) {
    let _ = GLOBAL_LOG_BUFFER.set(buffer);
}

pub fn global_log_buffer() -> Option<Arc<LogBuffer>> {
    GLOBAL_LOG_BUFFER.get().cloned()
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: String,
    pub elapsed_ms: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[derive(Debug)]
pub struct LogBuffer {
    ring: StdMutex<VecDeque<Arc<LogEntry>>>,
    broadcaster: broadcast::Sender<Arc<LogEntry>>,
    next_id: AtomicU64,
}

impl LogBuffer {
    pub fn new() -> Arc<Self> {
        let (sender, _) = broadcast::channel(512);
        Arc::new(Self {
            ring: StdMutex::new(VecDeque::with_capacity(RING_CAP)),
            broadcaster: sender,
            next_id: AtomicU64::new(1),
        })
    }

    pub fn push(&self, mut entry: LogEntry) {
        entry.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(entry);
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() >= RING_CAP {
                ring.pop_front();
            }
            ring.push_back(entry.clone());
        }
        let _ = self.broadcaster.send(entry);
    }

    fn recent_filtered(&self, limit: usize, min_level: Option<LevelFilter>) -> Vec<Arc<LogEntry>> {
        let Ok(ring) = self.ring.lock() else {
            return vec![];
        };
        let mut entries: Vec<Arc<LogEntry>> = ring
            .iter()
            .filter(|e| min_level.is_none_or(|f| level_passes(&e.level, f)))
            .cloned()
            .collect();
        if entries.len() > limit {
            entries.drain(..entries.len() - limit);
        }
        entries
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LogEntry>> {
        self.broadcaster.subscribe()
    }
}

// --- Level filtering ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LevelFilter {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LevelFilter {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }
}

fn level_passes(level_str: &str, min: LevelFilter) -> bool {
    let entry_priority = match level_str {
        "ERROR" => 0u8,
        "WARN" => 1,
        "INFO" => 2,
        "DEBUG" => 3,
        "TRACE" => 4,
        _ => 5,
    };
    entry_priority <= min.priority()
}

// --- Tracing subscriber layer ---

pub struct LogLayer {
    buffer: Arc<LogBuffer>,
}

impl LogLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for LogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = metadata.level().to_string();
        let target = metadata.target().to_string();
        let elapsed_ms = AppClock::elapsed_millis();
        let timestamp = format!("{}", Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z"));

        let mut visitor = FieldCollector::default();
        event.record(&mut visitor);

        self.buffer.push(LogEntry {
            id: 0,
            timestamp,
            elapsed_ms,
            level,
            target,
            message: visitor.finish(),
        });
    }
}

#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    extras: Vec<String>,
}

impl FieldCollector {
    fn finish(self) -> String {
        let mut s = self.message.unwrap_or_default();
        for extra in self.extras {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(&extra);
        }
        s
    }
}

impl Visit for FieldCollector {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.extras.push(format!("{}={}", field.name(), value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.extras.push(format!("{}={}", field.name(), value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.extras.push(format!("{}={}", field.name(), value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.extras.push(format!("{}={}", field.name(), value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.extras.push(format!("{}={}", field.name(), value));
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.extras.push(format!("{}={}", field.name(), value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.extras.push(format!("{}={:?}", field.name(), value));
        }
    }
}

// --- API response types ---

#[derive(Debug, Serialize)]
struct LogsResponse {
    ok: bool,
    total: usize,
    entries: Vec<LogEntry>,
}

// --- Handlers ---

#[derive(Debug)]
struct LogsHandler {
    buffer: Arc<LogBuffer>,
}

#[derive(Debug)]
struct LogsStreamHandler {
    buffer: Arc<LogBuffer>,
}

#[async_trait]
impl ApiHandler for LogsHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let (limit, min_level) = match parse_logs_params(request.uri().query()) {
            Ok(params) => params,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };
        let raw = self.buffer.recent_filtered(limit, min_level);
        let total = raw.len();
        let entries: Vec<LogEntry> = raw.iter().map(|e| (**e).clone()).collect();
        json_ok(
            StatusCode::OK,
            &LogsResponse {
                ok: true,
                total,
                entries,
            },
        )
    }
}

#[async_trait]
impl ApiHandler for LogsStreamHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let (tail, min_level) = match parse_stream_params(request.uri().query()) {
            Ok(params) => params,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };

        let initial = self.buffer.recent_filtered(tail, min_level);
        let pending: VecDeque<Bytes> = initial.iter().map(|e| sse_log_frame(e)).collect();
        let receiver = self.buffer.subscribe();
        let heartbeat = tokio::time::interval(Duration::from_secs(SSE_HEARTBEAT_SECS));

        let stream = futures::stream::unfold(
            SseState {
                pending,
                receiver,
                heartbeat,
                min_level,
            },
            |mut state| async move {
                if let Some(bytes) = state.pending.pop_front() {
                    return Some((Ok(Frame::data(bytes)), state));
                }

                loop {
                    tokio::select! {
                        recv = state.receiver.recv() => {
                            match recv {
                                Ok(entry) => {
                                    if state.min_level.is_none_or(|f| level_passes(&entry.level, f)) {
                                        return Some((Ok(Frame::data(sse_log_frame(&entry))), state));
                                    }
                                }
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

struct SseState {
    pending: VecDeque<Bytes>,
    receiver: broadcast::Receiver<Arc<LogEntry>>,
    heartbeat: tokio::time::Interval,
    min_level: Option<LevelFilter>,
}

fn sse_log_frame(entry: &LogEntry) -> Bytes {
    match serde_json::to_vec(entry) {
        Ok(data) => {
            let mut frame = Vec::with_capacity(data.len() + 24);
            frame.extend_from_slice(b"event: log\ndata: ");
            frame.extend_from_slice(&data);
            frame.extend_from_slice(b"\n\n");
            Bytes::from(frame)
        }
        Err(err) => Bytes::from(format!(
            "event: error\ndata: {{\"message\":\"serialize failed: {err}\"}}\n\n"
        )),
    }
}

fn parse_logs_params(
    query: Option<&str>,
) -> std::result::Result<(usize, Option<LevelFilter>), String> {
    let mut limit = DEFAULT_FETCH_LIMIT;
    let mut min_level = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "limit" => {
                limit = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid limit: {err}"))?
                    .clamp(1, MAX_FETCH_LIMIT);
            }
            "level" => {
                min_level = Some(
                    LevelFilter::parse(value.as_ref())
                        .ok_or_else(|| format!("invalid level: {}", value.as_ref()))?,
                );
            }
            _ => {}
        }
    }
    Ok((limit, min_level))
}

fn parse_stream_params(
    query: Option<&str>,
) -> std::result::Result<(usize, Option<LevelFilter>), String> {
    let mut tail = 0;
    let mut min_level = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "tail" => {
                tail = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid tail: {err}"))?
                    .min(MAX_TAIL);
            }
            "level" => {
                min_level = Some(
                    LevelFilter::parse(value.as_ref())
                        .ok_or_else(|| format!("invalid level: {}", value.as_ref()))?,
                );
            }
            _ => {}
        }
    }
    Ok((tail, min_level))
}

pub fn register_log_routes(register: &ApiRegister) -> Result<()> {
    let Some(buffer) = global_log_buffer() else {
        return Ok(());
    };
    register.register_get(
        "/logs",
        Arc::new(LogsHandler {
            buffer: buffer.clone(),
        }),
    )?;
    register.register_get("/logs/stream", Arc::new(LogsStreamHandler { buffer }))?;
    Ok(())
}
