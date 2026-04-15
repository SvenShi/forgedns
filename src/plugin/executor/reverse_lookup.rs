/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `reverse_lookup` executor plugin.
//!
//! Caches answer IP -> domain mappings and optionally serves PTR queries.
//!
//! Pipeline semantics:
//! - `execute`: optionally intercepts PTR requests and answers directly from
//!   cache (`handle_ptr = true`).
//! - continuation post-stage: after downstream response is available, extracts A/AAAA
//!   answer IPs and updates cache with bounded TTL.
//!
//! Cache design:
//! - shared TTL cache component for consistent cache behavior across plugins.
//! - periodic cleanup removes expired entries and trims overflow in batches.
//! - IPv4-mapped IPv6 addresses are normalized to keep lookup keys consistent.

use crate::api::{ApiHandler, ApiRegister, simple_response};
use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::core::ttl_cache::TtlCache;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::Rcode;
use crate::proto::{Name, PTR, RData, Record, RecordType};
use crate::{continue_next, register_plugin_factory};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const DEFAULT_SIZE: usize = 65_535;
const DEFAULT_TTL: u32 = 7_200;
const CLEANUP_INTERVAL_SECS: u64 = 30;
const EVICTION_BATCH: usize = 512;

#[derive(Debug, Clone, Deserialize, Default)]
struct ReverseLookupConfig {
    /// Maximum number of reverse lookup cache entries.
    size: Option<usize>,
    /// Whether PTR queries should be resolved via reverse cache.
    handle_ptr: Option<bool>,
    /// Cache TTL in seconds for IP -> domain mappings.
    ttl: Option<u32>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    domain: Name,
}

#[derive(Debug)]
struct ReverseLookup {
    tag: String,
    cache: TtlCache<IpAddr, Arc<CacheEntry>>,
    size: usize,
    ttl: u32,
    handle_ptr: bool,
    cleanup_started: AtomicBool,
    cleanup_task_id: Option<u64>,
    api_register: Option<ApiRegister>,
}

#[async_trait]
impl Plugin for ReverseLookup {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        self.register_api_routes()?;

        if self.cleanup_started.swap(true, Ordering::Relaxed) {
            return Ok(());
        }

        let cache = self.cache.clone();
        let size = self.size;
        self.cleanup_task_id = Some(task_center::spawn_fixed(
            format!("reverse_lookup:{}:cleanup", self.tag),
            Duration::from_secs(CLEANUP_INTERVAL_SECS),
            move || {
                let cache = cache.clone();
                async move {
                    let now = AppClock::elapsed_millis();

                    while cache.remove_expired_batch(now, EVICTION_BATCH) > 0 {}

                    if cache.len() <= size {
                        return;
                    }
                    let overflow = cache.len().saturating_sub(size).min(EVICTION_BATCH);
                    if overflow == 0 {
                        return;
                    }

                    let mut keys: Vec<(IpAddr, u64)> = cache.sample_last_access(overflow);
                    keys.sort_unstable_by_key(|(_, last_access_ms)| *last_access_ms);
                    for (key, _) in keys.into_iter().take(overflow) {
                        let _ = cache.remove(&key);
                    }
                }
            },
        ));
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(task_id) = self.cleanup_task_id {
            task_center::stop_task(task_id).await;
        }
        self.cleanup_started.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait]
impl Executor for ReverseLookup {
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
        if self.handle_ptr
            && let Some(response) = self.try_handle_ptr(&context.request)
        {
            context.set_response(response);
            return Ok(ExecStep::Stop);
        }

        let step = continue_next!(next, context)?;
        let query_name = context
            .request
            .first_question()
            .map(|question| question.name().clone());
        let Some(response) = context.response_mut() else {
            return Ok(step);
        };
        let now = AppClock::elapsed_millis();
        for record in response.answers_mut() {
            let Some(ip) = record.ip_addr() else {
                continue;
            };

            let effective_ttl = record.ttl().min(self.ttl);
            record.set_ttl(effective_ttl);
            let expire_at_ms = now.saturating_add(effective_ttl as u64 * 1000);

            let domain = query_name
                .as_ref()
                .cloned()
                .unwrap_or_else(|| record.name().clone());
            self.cache.insert_or_update(
                normalize_ip(ip),
                Arc::new(CacheEntry { domain }),
                now,
                expire_at_ms,
            );
        }

        Ok(step)
    }
}

impl ReverseLookup {
    fn register_api_routes(&self) -> Result<()> {
        let Some(api_register) = &self.api_register else {
            return Ok(());
        };

        api_register.register_plugin_get(
            &self.tag,
            "",
            Arc::new(ReverseLookupQueryHandler {
                cache: self.cache.clone(),
            }),
        )
    }

    fn try_handle_ptr(&self, request: &crate::proto::Message) -> Option<crate::proto::Message> {
        if request.question_count() != 1 || request.first_qtype()? != RecordType::PTR {
            return None;
        }

        let qname = request.first_question()?.name().clone();
        let ip = parse_ptr_name(&qname)?;
        let ip = normalize_ip(ip);
        let now = AppClock::elapsed_millis();
        let entry = self.cache.get_retained_cloned(&ip, now, 1000)?;

        let mut response = request.response(Rcode::NoError);
        response.answers_mut().push(Record::from_rdata(
            qname,
            5,
            RData::PTR(PTR(entry.value.domain.clone())),
        ));
        Some(response)
    }
}

#[derive(Debug, Clone)]
pub struct ReverseLookupFactory;

register_plugin_factory!("reverse_lookup", ReverseLookupFactory {});

impl PluginFactory for ReverseLookupFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let cfg = plugin_config
            .args
            .clone()
            .map(serde_yaml_ng::from_value::<ReverseLookupConfig>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse reverse_lookup config: {}", e)))?
            .unwrap_or_default();

        let size = cfg.size.unwrap_or(DEFAULT_SIZE);
        let ttl = cfg.ttl.unwrap_or(DEFAULT_TTL);

        Ok(UninitializedPlugin::Executor(Box::new(ReverseLookup {
            tag: plugin_config.tag.clone(),
            cache: TtlCache::with_capacity(size),
            size,
            ttl,
            handle_ptr: cfg.handle_ptr.unwrap_or(false),
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
            api_register: registry.api_register(),
        })))
    }
}

#[derive(Debug)]
struct ReverseLookupQueryHandler {
    cache: TtlCache<IpAddr, Arc<CacheEntry>>,
}

#[async_trait]
impl ApiHandler for ReverseLookupQueryHandler {
    async fn handle(&self, request: Request<Bytes>) -> Response<Bytes> {
        let Some(raw_ip) = get_single_query_value(request.uri().query(), "ip") else {
            return simple_response(
                StatusCode::BAD_REQUEST,
                Bytes::from("missing required query parameter: ip"),
            );
        };

        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            return simple_response(
                StatusCode::BAD_REQUEST,
                Bytes::from("invalid ip query parameter"),
            );
        };

        let ip = normalize_ip(ip);
        let now = AppClock::elapsed_millis();
        let Some(entry) = self.cache.get_retained_cloned(&ip, now, 1000) else {
            return simple_response(StatusCode::OK, Bytes::new());
        };

        simple_response(
            StatusCode::OK,
            Bytes::from(format_fqdn(&entry.value.domain)),
        )
    }
}

fn get_single_query_value<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    let query = query?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name != key || value.is_empty() {
            return None;
        }
        Some(value)
    })
}

fn format_fqdn(name: &Name) -> String {
    name.to_fqdn()
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

fn parse_ptr_name(name: &Name) -> Option<IpAddr> {
    name.parse_arpa_name().ok().map(|net| net.addr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::rdata::A;
    use crate::proto::{Message, Question};
    use crate::proto::{Name, RData, Record};
    use http::Method;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_ptr_name_ipv4_and_invalid() {
        let valid = Name::from_ascii("1.0.0.127.in-addr.arpa.").unwrap();
        assert_eq!(
            parse_ptr_name(&valid),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
        );

        let invalid = Name::from_ascii("example.com.").unwrap();
        assert!(parse_ptr_name(&invalid).is_none());
    }

    fn make_context(name: &str, qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).unwrap(),
            qtype,
            crate::proto::DNSClass::IN,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    #[tokio::test]
    async fn test_reverse_lookup_with_next_caches_and_serves_ptr() {
        let plugin = ReverseLookup {
            tag: "reverse_lookup".to_string(),
            cache: TtlCache::with_capacity(64),
            size: 64,
            ttl: 120,
            handle_ptr: true,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
            api_register: None,
        };

        let mut a_ctx = make_context("www.example.com.", RecordType::A);
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(8, 8, 4, 4))),
        ));
        a_ctx.set_response(response);

        plugin
            .execute_with_next(&mut a_ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            a_ctx.response().expect("response should exist").answers()[0].ttl(),
            120
        );

        let mut ptr_ctx = make_context("4.4.8.8.in-addr.arpa.", RecordType::PTR);
        let step = plugin
            .execute(&mut ptr_ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Stop));

        let ptr_resp = ptr_ctx.response().expect("PTR response should be returned");
        assert_eq!(ptr_resp.answers().len(), 1);
        assert_eq!(ptr_resp.answers()[0].rr_type(), RecordType::PTR);
    }

    #[tokio::test]
    async fn test_reverse_lookup_rewrites_response() {
        let plugin = ReverseLookup {
            tag: "reverse_lookup".to_string(),
            cache: TtlCache::with_capacity(64),
            size: 64,
            ttl: 120,
            handle_ptr: false,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
            api_register: None,
        };

        let mut ctx = make_context("www.example.com.", RecordType::A);
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(8, 8, 4, 4))),
        ));
        ctx.set_response(response);

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            ctx.response().expect("response should exist").answers()[0].ttl(),
            120
        );
    }

    #[tokio::test]
    async fn test_reverse_lookup_query_api_returns_fqdn() {
        let cache = TtlCache::with_capacity(8);
        let now = AppClock::elapsed_millis();
        cache.insert_or_update(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            Arc::new(CacheEntry {
                domain: Name::from_ascii("dns.google.").unwrap(),
            }),
            now,
            now + 60_000,
        );
        let handler = ReverseLookupQueryHandler { cache };

        let response = handler
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/plugins/reverse_lookup?ip=8.8.8.8")
                    .body(Bytes::new())
                    .expect("request should build"),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &Bytes::from_static(b"dns.google."));
    }

    #[tokio::test]
    async fn test_reverse_lookup_query_api_rejects_missing_ip() {
        let handler = ReverseLookupQueryHandler {
            cache: TtlCache::with_capacity(8),
        };

        let response = handler
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/plugins/reverse_lookup")
                    .body(Bytes::new())
                    .expect("request should build"),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
