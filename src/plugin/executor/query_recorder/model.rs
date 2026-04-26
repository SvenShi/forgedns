// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::SocketAddr;
use std::path::PathBuf;

use forgedns_proto::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::context::ExecutionPath;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct QueryRecorderConfig {
    pub(super) path: String,
    pub(super) queue_size: Option<usize>,
    pub(super) batch_size: Option<usize>,
    pub(super) flush_interval_ms: Option<u64>,
    pub(super) memory_tail: Option<usize>,
    pub(super) retention_days: Option<u64>,
    pub(super) cleanup_interval_hours: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedRecorderConfig {
    pub(super) path: PathBuf,
    pub(super) queue_size: usize,
    pub(super) batch_size: usize,
    pub(super) flush_interval_ms: u64,
    pub(super) memory_tail: usize,
    pub(super) retention_days: u64,
    pub(super) cleanup_interval_hours: u64,
}

#[derive(Debug, Clone)]
pub(super) struct TableNames {
    pub(super) records: String,
    pub(super) steps: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct QuestionJson {
    pub(super) name: String,
    pub(super) qtype: String,
    pub(super) qclass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct RecordJson {
    pub(super) name: String,
    pub(super) class: String,
    pub(super) ttl: u32,
    pub(super) rr_type: String,
    pub(super) payload_kind: String,
    pub(super) payload_text: String,
    pub(super) payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct EdnsOptionJson {
    pub(super) code: u16,
    pub(super) name: String,
    pub(super) payload_kind: String,
    pub(super) payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct EdnsJson {
    pub(super) udp_payload_size: u16,
    pub(super) ext_rcode: u8,
    pub(super) version: u8,
    pub(super) dnssec_ok: bool,
    pub(super) z: u16,
    pub(super) options: Vec<EdnsOptionJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct StepJson {
    pub(super) event_index: usize,
    pub(super) sequence_tag: String,
    pub(super) node_index: Option<usize>,
    pub(super) kind: String,
    pub(super) tag: Option<String>,
    pub(super) outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct RecordRow {
    pub(super) id: i64,
    pub(super) created_at_ms: u64,
    pub(super) elapsed_ms: u64,
    pub(super) request_id: u16,
    pub(super) client_ip: String,
    pub(super) questions_json: Vec<QuestionJson>,
    pub(super) req_rd: bool,
    pub(super) req_cd: bool,
    pub(super) req_ad: bool,
    pub(super) req_opcode: String,
    pub(super) req_edns_json: Option<EdnsJson>,
    pub(super) error: Option<String>,
    pub(super) has_response: bool,
    pub(super) rcode: Option<String>,
    pub(super) resp_aa: Option<bool>,
    pub(super) resp_tc: Option<bool>,
    pub(super) resp_ra: Option<bool>,
    pub(super) resp_ad: Option<bool>,
    pub(super) resp_cd: Option<bool>,
    pub(super) answer_count: u32,
    pub(super) authority_count: u32,
    pub(super) additional_count: u32,
    pub(super) answers_json: Vec<RecordJson>,
    pub(super) authorities_json: Vec<RecordJson>,
    pub(super) additionals_json: Vec<RecordJson>,
    pub(super) signature_json: Vec<RecordJson>,
    pub(super) resp_edns_json: Option<EdnsJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct RecordDetail {
    #[serde(flatten)]
    pub(super) record: RecordRow,
    pub(super) steps: Vec<StepJson>,
}

#[derive(Debug, Clone)]
pub(super) struct PendingRecord {
    pub(super) request: Message,
    pub(super) response: Option<Message>,
    pub(super) created_at_ms: u64,
    pub(super) elapsed_ms: u64,
    pub(super) exec_path: ExecutionPath,
    pub(super) step_start_index: usize,
    pub(super) client_ip: SocketAddr,
    pub(super) error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PluginStatsRow {
    pub(super) kind: String,
    pub(super) tag: Option<String>,
    pub(super) evaluated: u64,
    pub(super) matched: u64,
    pub(super) executed: u64,
    pub(super) query_total: u64,
    pub(super) query_share: f64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ListQuery {
    pub(super) cursor: Option<ListCursor>,
    pub(super) limit: usize,
    pub(super) since_ms: Option<u64>,
    pub(super) until_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StatsQuery {
    pub(super) since_ms: Option<u64>,
    pub(super) until_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PluginsStatsQuery {
    pub(super) since_ms: Option<u64>,
    pub(super) until_ms: Option<u64>,
    pub(super) kind: PluginStatsKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ListCursor {
    pub(super) created_at_ms: u64,
    pub(super) id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PluginStatsKind {
    Matcher,
    Executor,
    Builtin,
    All,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StatsOverview {
    pub(super) query_total: u64,
    pub(super) error_total: u64,
    pub(super) avg_elapsed_ms: Option<f64>,
}
