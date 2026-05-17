// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use super::key::{CacheKey, EcsScopeDigest};
use super::persistence::{dump_cache_to_bytes, load_cache_from_bytes};
use super::{CacheItem, CacheMap};
use crate::api::{ApiHandler, json_error, json_ok, simple_response};
use crate::core::app_clock::AppClock;
use crate::core::error::Result;
use crate::proto::{DNSClass, RData, Record, RecordType};
use crate::register_plugin_api;

pub(super) fn register(tag: &str, cache_map: CacheMap, ecs_in_key: bool) -> Result<()> {
    register_plugin_api!(
        tag,
        |plugin_api|
        GET "/entries" => CacheEntriesListHandler {
            cache_map: cache_map.clone(),
        },
        DELETE_PREFIX "/entries/" => CacheEntryDeleteHandler {
            cache_map: cache_map.clone(),
            path_prefix: plugin_api.path("/entries/")?,
        },
        GET "/flush" => CacheFlushHandler {
            cache_map: cache_map.clone(),
        },
        GET "/dump" => CacheDumpHandler {
            cache_map: cache_map.clone(),
            tag: tag.to_string(),
        },
        POST "/load_dump" => CacheLoadDumpHandler {
            cache_map,
            ecs_in_key,
        },
    )?;
    Ok(())
}

#[derive(Debug)]
struct CacheFlushHandler {
    cache_map: CacheMap,
}

#[derive(Debug, Serialize)]
struct CacheFlushResponse {
    ok: bool,
    cleared_entries: usize,
}

#[async_trait]
impl ApiHandler for CacheFlushHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        let cleared_entries = self.cache_map.len();
        self.cache_map.clear();
        info!("cache flushed, cleared entries {}", cleared_entries);
        json_ok(
            StatusCode::OK,
            &CacheFlushResponse {
                ok: true,
                cleared_entries,
            },
        )
    }
}

#[derive(Debug)]
struct CacheDumpHandler {
    cache_map: CacheMap,
    tag: String,
}

#[async_trait]
impl ApiHandler for CacheDumpHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        match dump_cache_to_bytes(&self.cache_map) {
            Ok(bytes) => {
                let mut response = simple_response(StatusCode::OK, Bytes::from(bytes));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/octet-stream"),
                );
                if let Ok(value) = http::HeaderValue::from_str(&format!(
                    "attachment; filename=\"{}.dump\"",
                    self.tag
                )) {
                    response
                        .headers_mut()
                        .insert(http::header::CONTENT_DISPOSITION, value);
                }
                response
            }
            Err(err) => {
                warn!("Failed to dump cache via API: {}", err);
                simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from("failed to dump cache"),
                )
            }
        }
    }
}

#[derive(Debug)]
struct CacheLoadDumpHandler {
    cache_map: CacheMap,
    ecs_in_key: bool,
}

#[derive(Debug, Serialize)]
struct CacheLoadDumpResponse {
    ok: bool,
    loaded_entries: usize,
}

#[async_trait]
impl ApiHandler for CacheLoadDumpHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        match load_cache_from_bytes(&self.cache_map, request.body(), self.ecs_in_key, true) {
            Ok(loaded_entries) => json_ok(
                StatusCode::OK,
                &CacheLoadDumpResponse {
                    ok: true,
                    loaded_entries,
                },
            ),
            Err(err) => {
                warn!("Failed to load cache dump via API: {}", err);
                json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_cache_dump",
                    "failed to load cache dump",
                )
            }
        }
    }
}

#[derive(Debug)]
struct CacheEntriesListHandler {
    cache_map: CacheMap,
}

#[derive(Debug)]
struct CacheEntryDeleteHandler {
    cache_map: CacheMap,
    path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntryId {
    domain: String,
    record_type: u16,
    dns_class: u16,
    do_bit: bool,
    cd_bit: bool,
    ecs_scope: Option<CacheEntryEcsId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntryEcsId {
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    network_len: u8,
    network: [u8; 16],
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntriesResponse {
    ok: bool,
    entries: Vec<CacheEntryRow>,
    next_cursor: Option<String>,
    total_entries: usize,
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntryDeleteResponse {
    ok: bool,
    deleted: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntryRow {
    id: String,
    domain: String,
    record_type: String,
    dns_class: String,
    rcode: String,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    ttl: u32,
    remaining_ttl: u32,
    fresh: bool,
    stale: bool,
    cache_time_ms: u64,
    expire_at_ms: u64,
    last_access_ms: u64,
    cache_time_unix_ms: u64,
    expire_at_unix_ms: u64,
    last_access_unix_ms: u64,
    do_bit: bool,
    cd_bit: bool,
    answers_json: Vec<CacheRecordJson>,
    authorities_json: Vec<CacheRecordJson>,
    additionals_json: Vec<CacheRecordJson>,
    signature_json: Vec<CacheRecordJson>,
    ecs_scope: Option<CacheEntryEcsRow>,
}

#[derive(Debug, Clone, Serialize)]
struct CacheRecordJson {
    name: String,
    class: String,
    ttl: u32,
    rr_type: String,
    payload_kind: String,
    payload_text: String,
    payload: Value,
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntryEcsRow {
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    network_hex: String,
}

#[async_trait]
impl ApiHandler for CacheEntriesListHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let query = match parse_cache_entries_query(request.uri().query()) {
            Ok(query) => query,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_query", err),
        };
        let now = AppClock::elapsed_millis();
        let now_unix_ms = AppClock::now_timestamp();
        let mut entries = self
            .cache_map
            .iter_entries_cloned()
            .into_iter()
            .filter(|(_, entry)| entry.expire_at_ms > now)
            .collect::<Vec<_>>();
        entries.sort_by(|(left_key, left_entry), (right_key, right_entry)| {
            right_entry
                .last_access_ms
                .cmp(&left_entry.last_access_ms)
                .then_with(|| left_key.domain.cmp(&right_key.domain))
                .then_with(|| {
                    u16::from(left_key.record_type).cmp(&u16::from(right_key.record_type))
                })
                .then_with(|| u16::from(left_key.dns_class).cmp(&u16::from(right_key.dns_class)))
        });

        let total_entries = entries.len();
        let start = query.cursor.min(total_entries);
        let end = start.saturating_add(query.limit).min(total_entries);
        let next_cursor = if end < total_entries {
            Some(end.to_string())
        } else {
            None
        };
        let rows = entries[start..end]
            .iter()
            .filter_map(|(key, entry)| cache_entry_row(key, entry, now, now_unix_ms).ok())
            .collect::<Vec<_>>();

        json_ok(
            StatusCode::OK,
            &CacheEntriesResponse {
                ok: true,
                entries: rows,
                next_cursor,
                total_entries,
            },
        )
    }
}

#[async_trait]
impl ApiHandler for CacheEntryDeleteHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let Some(raw_id) = request.uri().path().strip_prefix(self.path_prefix.as_str()) else {
            return simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"));
        };
        if raw_id.is_empty() || raw_id.contains('/') {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_cache_entry_id",
                "invalid cache entry id",
            );
        }
        let key = match decode_cache_entry_id(raw_id) {
            Ok(key) => key,
            Err(err) => {
                return json_error(StatusCode::BAD_REQUEST, "invalid_cache_entry_id", err);
            }
        };
        if !self.cache_map.remove(&key) {
            return json_error(
                StatusCode::NOT_FOUND,
                "cache_entry_not_found",
                "cache entry does not exist",
            );
        }
        json_ok(
            StatusCode::OK,
            &CacheEntryDeleteResponse {
                ok: true,
                deleted: true,
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct CacheEntriesQuery {
    limit: usize,
    cursor: usize,
}

fn parse_cache_entries_query(
    query: Option<&str>,
) -> std::result::Result<CacheEntriesQuery, String> {
    let mut limit = 100usize;
    let mut cursor = 0usize;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "limit" => {
                limit = value
                    .parse::<usize>()
                    .map_err(|_| "limit must be a positive integer".to_string())?
                    .clamp(1, 500);
            }
            "cursor" => {
                cursor = value
                    .parse::<usize>()
                    .map_err(|_| "cursor must be a non-negative integer".to_string())?;
            }
            _ => {}
        }
    }
    Ok(CacheEntriesQuery { limit, cursor })
}

fn cache_entry_row(
    key: &CacheKey,
    entry: &crate::core::ttl_cache::TtlCacheEntry<Arc<CacheItem>>,
    now: u64,
    now_unix_ms: u64,
) -> std::result::Result<CacheEntryRow, String> {
    let item = entry.value.as_ref();
    let fresh = now < item.fresh_until_ms;
    let stale = !fresh && now < entry.expire_at_ms;
    Ok(CacheEntryRow {
        id: encode_cache_entry_id(key)?,
        domain: key.domain.clone(),
        record_type: key.record_type.to_string(),
        dns_class: key.dns_class.to_string(),
        rcode: item.resp.rcode().to_string(),
        answer_count: item.resp.answer_count(),
        authority_count: item.resp.authority_count(),
        additional_count: item.resp.additionals().len() as u16,
        ttl: item.ttl,
        remaining_ttl: entry.expire_at_ms.saturating_sub(now).saturating_div(1000) as u32,
        fresh,
        stale,
        cache_time_ms: entry.cache_time_ms,
        expire_at_ms: entry.expire_at_ms,
        last_access_ms: entry.last_access_ms,
        cache_time_unix_ms: elapsed_to_unix_ms(entry.cache_time_ms, now, now_unix_ms),
        expire_at_unix_ms: elapsed_to_unix_ms(entry.expire_at_ms, now, now_unix_ms),
        last_access_unix_ms: elapsed_to_unix_ms(entry.last_access_ms, now, now_unix_ms),
        do_bit: key.do_bit,
        cd_bit: key.cd_bit,
        answers_json: item.resp.answers().iter().map(cache_record_json).collect(),
        authorities_json: item
            .resp
            .authorities()
            .iter()
            .map(cache_record_json)
            .collect(),
        additionals_json: item
            .resp
            .additionals()
            .iter()
            .map(cache_record_json)
            .collect(),
        signature_json: item
            .resp
            .signature()
            .iter()
            .map(cache_record_json)
            .collect(),
        ecs_scope: key.ecs_scope.as_ref().map(|ecs| CacheEntryEcsRow {
            family: ecs.family,
            source_prefix: ecs.source_prefix,
            scope_prefix: ecs.scope_prefix,
            network_hex: ecs.network[..usize::from(ecs.network_len)]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        }),
    })
}

fn elapsed_to_unix_ms(elapsed_ms: u64, now_ms: u64, now_unix_ms: u64) -> u64 {
    if elapsed_ms <= now_ms {
        now_unix_ms.saturating_sub(now_ms - elapsed_ms)
    } else {
        now_unix_ms.saturating_add(elapsed_ms - now_ms)
    }
}

fn cache_record_json(record: &Record) -> CacheRecordJson {
    let (payload_kind, payload_text, payload) = cache_rdata_payload(record.data());
    CacheRecordJson {
        name: record.name().to_fqdn(),
        class: dns_class_name(record.class()),
        ttl: record.ttl(),
        rr_type: record_type_name(record.rr_type()),
        payload_kind,
        payload_text,
        payload,
    }
}

fn cache_rdata_payload(rdata: &RData) -> (String, String, Value) {
    match rdata {
        RData::A(value) => ip_payload("A", IpAddr::V4(value.0)),
        RData::AAAA(value) => ip_payload("AAAA", IpAddr::V6(value.0)),
        RData::CNAME(value) => name_payload("CNAME", "target", &value.0),
        RData::NS(value) => name_payload("NS", "target", &value.0),
        RData::PTR(value) => name_payload("PTR", "target", &value.0),
        RData::DNAME(value) => name_payload("DNAME", "target", &value.0),
        RData::MX(value) => (
            "MX".to_string(),
            format!("{} {}", value.preference(), value.exchange().to_fqdn()),
            json!({
                "preference": value.preference(),
                "exchange": value.exchange().to_fqdn(),
            }),
        ),
        RData::SRV(value) => (
            "SRV".to_string(),
            format!(
                "{} {} {} {}",
                value.priority(),
                value.weight(),
                value.port(),
                value.target().to_fqdn(),
            ),
            json!({
                "priority": value.priority(),
                "weight": value.weight(),
                "port": value.port(),
                "target": value.target().to_fqdn(),
            }),
        ),
        RData::SOA(value) => (
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
        ),
        RData::TXT(value) => txt_payload("TXT", value),
        RData::SVCB(value) => svcb_payload("SVCB", value),
        RData::HTTPS(value) => svcb_payload("HTTPS", &value.0),
        RData::NULL(value) => (
            "NULL".to_string(),
            "NULL".to_string(),
            json!({ "data_base64": STANDARD.encode(value.data()) }),
        ),
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

fn txt_payload(kind: &str, value: &crate::proto::TXT) -> (String, String, Value) {
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
                parts.push(json!({ "data_base64": STANDARD.encode(part) }));
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

fn svcb_payload(kind: &str, value: &crate::proto::SVCB) -> (String, String, Value) {
    (
        kind.to_string(),
        value.target().to_fqdn(),
        json!({
            "priority": value.priority(),
            "target": value.target().to_fqdn(),
            "params": value.params().len(),
        }),
    )
}

fn dns_class_name(class: DNSClass) -> String {
    match class {
        DNSClass::Unknown(value) => format!("CLASS{value}"),
        DNSClass::OPT(value) => format!("OPT({value})"),
        _ => class.to_string(),
    }
}

fn record_type_name(record_type: RecordType) -> String {
    match record_type {
        RecordType::Unknown(value) => format!("TYPE{value}"),
        _ => record_type.to_string(),
    }
}

fn encode_cache_entry_id(key: &CacheKey) -> std::result::Result<String, String> {
    let id = CacheEntryId {
        domain: key.domain.clone(),
        record_type: u16::from(key.record_type),
        dns_class: u16::from(key.dns_class),
        do_bit: key.do_bit,
        cd_bit: key.cd_bit,
        ecs_scope: key.ecs_scope.as_ref().map(|ecs| CacheEntryEcsId {
            family: ecs.family,
            source_prefix: ecs.source_prefix,
            scope_prefix: ecs.scope_prefix,
            network_len: ecs.network_len,
            network: ecs.network,
        }),
    };
    serde_json::to_vec(&id)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|err| format!("failed to encode cache entry id: {err}"))
}

fn decode_cache_entry_id(raw: &str) -> std::result::Result<CacheKey, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| "cache entry id is not valid base64url".to_string())?;
    let id: CacheEntryId = serde_json::from_slice(&bytes)
        .map_err(|_| "cache entry id is not valid json".to_string())?;
    if id.domain.trim().is_empty() {
        return Err("cache entry id domain is empty".to_string());
    }
    Ok(CacheKey {
        domain: id.domain,
        record_type: id.record_type.into(),
        dns_class: id.dns_class.into(),
        do_bit: id.do_bit,
        cd_bit: id.cd_bit,
        ecs_scope: id.ecs_scope.map(|ecs| EcsScopeDigest {
            family: ecs.family,
            source_prefix: ecs.source_prefix,
            scope_prefix: ecs.scope_prefix,
            network_len: ecs.network_len,
            network: ecs.network,
        }),
    })
}
