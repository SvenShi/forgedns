// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode};
use hyper::body::Frame;
use serde::Serialize;
use tokio::sync::broadcast;

use super::backend::RecorderBackend;
use super::model::{
    ListCursor, ListQuery, PluginStatsKind, PluginStatsRow, PluginsStatsQuery, RecordDetail,
    RecordRow, StatsQuery,
};
use super::store::{load_plugin_stats, load_record_detail, load_stats_overview, query_records};
use crate::api::{
    ApiHandler, ApiRegister, json_error, json_ok, simple_response, streaming_response,
};
use crate::core::error::Result;

const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;
const SSE_HEARTBEAT_SECS: u64 = 15;

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
struct PluginStatsResponse {
    ok: bool,
    query_total: u64,
    stats: Vec<PluginStatsRow>,
}

#[derive(Debug)]
struct RecordsListHandler {
    backend: Arc<RecorderBackend>,
}

#[derive(Debug)]
struct RecordDetailHandler {
    backend: Arc<RecorderBackend>,
    path_prefix: String,
}

#[derive(Debug)]
struct StatsOverviewHandler {
    backend: Arc<RecorderBackend>,
}

#[derive(Debug)]
struct StatsPluginsHandler {
    backend: Arc<RecorderBackend>,
}

#[derive(Debug)]
struct StreamHandler {
    backend: Arc<RecorderBackend>,
}

#[async_trait]
impl ApiHandler for RecordsListHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let query = match parse_list_query(request.uri().query()) {
            Ok(query) => query,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };

        let backend = self.backend.clone();
        match tokio::task::spawn_blocking(move || query_records(backend, query)).await {
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

        let backend = self.backend.clone();
        match tokio::task::spawn_blocking(move || load_record_detail(backend, record_id)).await {
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
        let backend = self.backend.clone();
        match tokio::task::spawn_blocking(move || load_stats_overview(backend, query)).await {
            Ok(Ok(overview)) => json_ok(
                StatusCode::OK,
                &StatsOverviewResponse {
                    ok: true,
                    query_total: overview.query_total,
                    error_total: overview.error_total,
                    dropped_total: self.backend.dropped_total.load(Ordering::Relaxed),
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
        let backend = self.backend.clone();
        match tokio::task::spawn_blocking(move || load_plugin_stats(backend, query)).await {
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
        let tail_count = match parse_tail_param(request.uri().query(), self.backend.memory_tail) {
            Ok(tail_count) => tail_count,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };

        let initial = {
            let guard = match self.backend.tail.lock() {
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
        let receiver = self.backend.broadcaster.subscribe();
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
            .parse::<i64>()
            .map_err(|err| format!("invalid cursor created_at_ms: {err}"))?,
        id: id
            .parse::<i64>()
            .map_err(|err| format!("invalid cursor id: {err}"))?,
    })
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

pub(super) fn register(
    backend: &Arc<RecorderBackend>,
    api_register: Option<&ApiRegister>,
) -> Result<()> {
    let Some(api_register) = api_register else {
        return Ok(());
    };

    api_register.register_plugin_get(
        &backend.tag,
        "/records",
        Arc::new(RecordsListHandler {
            backend: backend.clone(),
        }),
    )?;

    let detail_prefix = format!("/plugins/{}/records/", backend.tag);
    api_register.register_plugin_get_prefix(
        &backend.tag,
        "/records/",
        Arc::new(RecordDetailHandler {
            backend: backend.clone(),
            path_prefix: detail_prefix,
        }),
    )?;

    api_register.register_plugin_get(
        &backend.tag,
        "/stats/overview",
        Arc::new(StatsOverviewHandler {
            backend: backend.clone(),
        }),
    )?;

    api_register.register_plugin_get(
        &backend.tag,
        "/stats/plugins",
        Arc::new(StatsPluginsHandler {
            backend: backend.clone(),
        }),
    )?;

    api_register.register_plugin_get(
        &backend.tag,
        "/stream",
        Arc::new(StreamHandler {
            backend: backend.clone(),
        }),
    )?;

    Ok(())
}
