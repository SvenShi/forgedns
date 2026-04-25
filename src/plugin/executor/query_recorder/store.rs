// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::broadcast;

use super::backend::{RecorderBackend, WriterCommand, WriterThreadContext};
use super::model::{
    ListCursor, ListQuery, PendingRecord, PluginStatsKind, PluginStatsRow, PluginsStatsQuery,
    RecordDetail, RecordRow, StatsOverview, StatsQuery, StepJson, TableNames,
};
use crate::core::error::{DnsError, Result};

const SCHEMA_VERSION: &str = "v1";
const CLEANUP_BATCH_SIZE: usize = 1_000;

pub(super) fn table_names(tag: &str) -> TableNames {
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
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01B3);
    }
    format!("{hash:016x}")
}

pub(super) fn initialize_database(path: &Path, tables: &TableNames) -> Result<()> {
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

pub(super) fn run_writer_thread(
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

pub(super) fn query_records(
    backend: Arc<RecorderBackend>,
    query: ListQuery,
) -> std::result::Result<(Vec<RecordRow>, Option<String>), DnsError> {
    let conn = open_database(&backend.path)
        .map_err(|err| DnsError::plugin(format!("failed to open recorder database: {err}")))?;
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
        records = backend.tables.records
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| DnsError::plugin(format!("failed to prepare list query: {err}")))?;
    let mut rows = stmt
        .query(params![
            query
                .since_ms
                .map(as_i64)
                .transpose()
                .map_err(to_plugin_error)?,
            query
                .until_ms
                .map(as_i64)
                .transpose()
                .map_err(to_plugin_error)?,
            query
                .cursor
                .map(|cursor| as_i64(cursor.created_at_ms))
                .transpose()
                .map_err(to_plugin_error)?,
            query.cursor.map(|cursor| cursor.id),
            query.limit as i64,
        ])
        .map_err(|err| DnsError::plugin(format!("failed to run list query: {err}")))?;

    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| DnsError::plugin(format!("failed to fetch list row: {err}")))?
    {
        records.push(
            read_record_row(row)
                .map_err(|err| DnsError::plugin(format!("failed to decode list row: {err}")))?,
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

pub(super) fn load_record_detail(
    backend: Arc<RecorderBackend>,
    record_id: i64,
) -> std::result::Result<Option<RecordDetail>, DnsError> {
    let conn = open_database(&backend.path)
        .map_err(|err| DnsError::plugin(format!("failed to open recorder database: {err}")))?;
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
        records = backend.tables.records
    );

    let record = conn
        .prepare(&record_sql)
        .map_err(|err| DnsError::plugin(format!("failed to prepare detail query: {err}")))?
        .query_row(params![record_id], read_record_row)
        .optional()
        .map_err(|err| DnsError::plugin(format!("failed to load detail row: {err}")))?;

    let Some(record) = record else {
        return Ok(None);
    };

    let steps = load_steps(&conn, &backend.tables, record_id)?;
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
        .map_err(|err| DnsError::plugin(format!("failed to prepare step query: {err}")))?;
    let mut rows = stmt
        .query(params![record_id])
        .map_err(|err| DnsError::plugin(format!("failed to run step query: {err}")))?;

    let mut steps = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| DnsError::plugin(format!("failed to fetch step row: {err}")))?
    {
        steps.push(StepJson {
            event_index: row
                .get::<_, i64>(0)
                .and_then(non_negative_usize)
                .map_err(|err| DnsError::plugin(format!("invalid step event_index: {err}")))?,
            sequence_tag: row
                .get(1)
                .map_err(|err| DnsError::plugin(format!("invalid step sequence_tag: {err}")))?,
            node_index: row
                .get::<_, Option<i64>>(2)
                .map_err(|err| DnsError::plugin(format!("invalid step node_index: {err}")))?
                .map(|value| {
                    usize::try_from(value).map_err(|_| DnsError::plugin("negative step node_index"))
                })
                .transpose()?,
            kind: row
                .get(3)
                .map_err(|err| DnsError::plugin(format!("invalid step kind: {err}")))?,
            tag: row
                .get(4)
                .map_err(|err| DnsError::plugin(format!("invalid step tag: {err}")))?,
            outcome: row
                .get(5)
                .map_err(|err| DnsError::plugin(format!("invalid step outcome: {err}")))?,
        });
    }
    Ok(steps)
}

pub(super) fn load_stats_overview(
    backend: Arc<RecorderBackend>,
    query: StatsQuery,
) -> std::result::Result<StatsOverview, DnsError> {
    let conn = open_database(&backend.path)
        .map_err(|err| DnsError::plugin(format!("failed to open recorder database: {err}")))?;
    let sql = format!(
        "SELECT
            COUNT(*) AS query_total,
            COALESCE(SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END), 0) AS error_total,
            AVG(elapsed_ms) AS avg_elapsed_ms
         FROM {records}
         WHERE (?1 IS NULL OR created_at_ms >= ?1)
           AND (?2 IS NULL OR created_at_ms <= ?2)",
        records = backend.tables.records
    );

    conn.prepare(&sql)
        .map_err(|err| DnsError::plugin(format!("failed to prepare overview query: {err}")))?
        .query_row(
            params![
                query
                    .since_ms
                    .map(as_i64)
                    .transpose()
                    .map_err(to_plugin_error)?,
                query
                    .until_ms
                    .map(as_i64)
                    .transpose()
                    .map_err(to_plugin_error)?,
            ],
            |row| {
                Ok(StatsOverview {
                    query_total: row.get::<_, i64>(0).and_then(non_negative_u64)?,
                    error_total: row.get::<_, i64>(1).and_then(non_negative_u64)?,
                    avg_elapsed_ms: row.get(2)?,
                })
            },
        )
        .map_err(|err| DnsError::plugin(format!("failed to load overview stats: {err}")))
}

pub(super) fn load_plugin_stats(
    backend: Arc<RecorderBackend>,
    query: PluginsStatsQuery,
) -> std::result::Result<(u64, Vec<PluginStatsRow>), DnsError> {
    let conn = open_database(&backend.path)
        .map_err(|err| DnsError::plugin(format!("failed to open recorder database: {err}")))?;
    let total_records = count_records(&conn, &backend.tables, query.since_ms, query.until_ms)?;
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
        steps = backend.tables.steps,
        records = backend.tables.records
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| DnsError::plugin(format!("failed to prepare plugin stats query: {err}")))?;
    let mut rows = stmt
        .query(params![
            query
                .since_ms
                .map(as_i64)
                .transpose()
                .map_err(to_plugin_error)?,
            query
                .until_ms
                .map(as_i64)
                .transpose()
                .map_err(to_plugin_error)?,
            kind_filter,
        ])
        .map_err(|err| DnsError::plugin(format!("failed to run plugin stats query: {err}")))?;

    let mut stats = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| DnsError::plugin(format!("failed to fetch plugin stats row: {err}")))?
    {
        let query_hits = row
            .get::<_, i64>(5)
            .and_then(non_negative_u64)
            .map_err(|err| DnsError::plugin(format!("invalid plugin stats query_hits: {err}")))?;
        stats.push(PluginStatsRow {
            kind: row
                .get(0)
                .map_err(|err| DnsError::plugin(format!("invalid plugin stats kind: {err}")))?,
            tag: row
                .get(1)
                .map_err(|err| DnsError::plugin(format!("invalid plugin stats tag: {err}")))?,
            evaluated: row
                .get::<_, i64>(2)
                .and_then(non_negative_u64)
                .map_err(|err| {
                    DnsError::plugin(format!("invalid plugin stats evaluated: {err}"))
                })?,
            matched: row
                .get::<_, i64>(3)
                .and_then(non_negative_u64)
                .map_err(|err| DnsError::plugin(format!("invalid plugin stats matched: {err}")))?,
            executed: row
                .get::<_, i64>(4)
                .and_then(non_negative_u64)
                .map_err(|err| DnsError::plugin(format!("invalid plugin stats executed: {err}")))?,
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
        .map_err(|err| DnsError::plugin(format!("failed to prepare count query: {err}")))?
        .query_row(
            params![
                since_ms.map(as_i64).transpose().map_err(to_plugin_error)?,
                until_ms.map(as_i64).transpose().map_err(to_plugin_error)?,
            ],
            |row| row.get::<_, i64>(0).and_then(non_negative_u64),
        )
        .map_err(|err| DnsError::plugin(format!("failed to count records: {err}")))
}

fn encode_cursor(cursor: ListCursor) -> String {
    format!("{}:{}", cursor.created_at_ms, cursor.id)
}

impl PluginStatsKind {
    fn sql_value(self) -> &'static str {
        match self {
            Self::Matcher => "matcher",
            Self::Executor => "executor",
            Self::Builtin => "builtin",
            Self::All => "all",
        }
    }
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

fn to_plugin_error(err: rusqlite::Error) -> DnsError {
    DnsError::plugin(format!("{err}"))
}
