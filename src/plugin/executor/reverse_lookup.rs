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
//! - `post_execute`: after downstream response is available, extracts A/AAAA
//!   answer IPs and updates cache with bounded TTL.
//!
//! Cache design:
//! - shared TTL cache component for consistent cache behavior across plugins.
//! - periodic cleanup removes expired entries and trims overflow in batches.
//! - IPv4-mapped IPv6 addresses are normalized to keep lookup keys consistent.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::dns_utils::{build_response_from_request, rr_to_ip};
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::core::ttl_cache::TtlCache;
use crate::message::Packet;
use crate::message::ResponseCode;
use crate::message::rdata::name::PTR;
use crate::message::{Name, RData, Record, RecordType};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use smallvec::SmallVec;
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
    cache: TtlCache<IpAddr, CacheEntry>,
    size: usize,
    ttl: u32,
    handle_ptr: bool,
    cleanup_started: AtomicBool,
    cleanup_task_id: Option<u64>,
}

#[async_trait]
impl Plugin for ReverseLookup {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
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
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if self.handle_ptr
            && let Some(response) = self.try_handle_ptr(&context.request)
        {
            context.response = Some(response.into());
            return Ok(ExecStep::Stop);
        }

        Ok(ExecStep::NextWithPost(None))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let _ = state;

        let query_name = context.request.first_question_name_owned();
        if let Some(rewritten) = self.rewrite_packet_response(context, query_name.as_ref())? {
            context.set_response_packet(rewritten)?;
            return Ok(());
        }

        let Some(response) = context.response_message_mut()? else {
            return Ok(());
        };
        let now = AppClock::elapsed_millis();
        for record in response.answers_mut() {
            let Some(ip) = rr_to_ip(record) else {
                continue;
            };

            let effective_ttl = record.ttl().min(self.ttl);
            record.set_ttl(effective_ttl);
            let expire_at_ms = now.saturating_add(effective_ttl as u64 * 1000);

            let domain = query_name
                .as_ref()
                .cloned()
                .unwrap_or_else(|| record.name().clone());
            self.cache
                .insert_or_update(normalize_ip(ip), CacheEntry { domain }, now, expire_at_ms);
        }

        Ok(())
    }
}

impl ReverseLookup {
    fn rewrite_packet_response(
        &self,
        context: &DnsContext,
        query_name: Option<&Name>,
    ) -> Result<Option<Packet>> {
        let Some(packet) = context
            .response
            .as_ref()
            .and_then(|response| response.packet())
        else {
            return Ok(None);
        };

        let parsed = packet.parse()?;
        let now = AppClock::elapsed_millis();
        let mut patches = SmallVec::<[(usize, u32); 8]>::new();

        for record in parsed.answer_records() {
            let record = record?;
            let Some(ip) = record.ip_addr() else {
                continue;
            };

            let effective_ttl = record.ttl().min(self.ttl);
            if effective_ttl != record.ttl() {
                patches.push((record.ttl_offset(), effective_ttl));
            }

            let expire_at_ms = now.saturating_add(effective_ttl as u64 * 1000);
            let domain = query_name
                .cloned()
                .unwrap_or_else(|| Name::from_wire_ref(record.name()));
            self.cache
                .insert_or_update(normalize_ip(ip), CacheEntry { domain }, now, expire_at_ms);
        }

        if patches.is_empty() {
            return Ok(Some(packet.clone()));
        }

        let mut bytes = packet.as_slice().to_vec();
        for (offset, ttl) in patches {
            bytes[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
        }
        Ok(Some(Packet::from_vec(bytes)))
    }

    fn try_handle_ptr(&self, request: &crate::message::Message) -> Option<crate::message::Message> {
        if request.question_count() != 1 || request.first_question_type()? != RecordType::PTR {
            return None;
        }

        let qname = request.first_question_name_owned()?;
        let ip = parse_ptr_name(&qname)?;
        let ip = normalize_ip(ip);
        let now = AppClock::elapsed_millis();
        let entry = self.cache.get_fresh_cloned(&ip, now, 1000)?;

        let mut response = build_response_from_request(request, ResponseCode::NoError);
        response.answers_mut().push(Record::from_rdata(
            qname,
            5,
            RData::PTR(PTR(entry.value.domain)),
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
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg = plugin_config
            .args
            .clone()
            .map(serde_yml::from_value::<ReverseLookupConfig>)
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
        })))
    }
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
    use crate::core::context::{DnsContext, ExecFlowState};
    use crate::message::rdata::A;
    use crate::message::{Message, Question};
    use crate::message::{Name, RData, Record};
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
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
        request.add_question(Question::new(Name::from_ascii(name).unwrap(), qtype));
        DnsContext {
            src_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            request_meta: Default::default(),
            query_view: None,
            query_view_version: None,
            registry: test_registry(),
        }
    }

    #[tokio::test]
    async fn test_reverse_lookup_post_execute_caches_and_serves_ptr() {
        let plugin = ReverseLookup {
            tag: "reverse_lookup".to_string(),
            cache: TtlCache::with_capacity(64),
            size: 64,
            ttl: 120,
            handle_ptr: true,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
        };

        let mut a_ctx = make_context("www.example.com.", RecordType::A);
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(8, 8, 4, 4))),
        ));
        a_ctx.response = Some(response.into());

        plugin
            .post_execute(&mut a_ctx, None)
            .await
            .expect("post_execute should succeed");
        assert_eq!(
            a_ctx
                .response
                .as_ref()
                .expect("response should exist")
                .to_message()
                .expect("response should materialize")
                .answers()[0]
                .ttl(),
            120
        );

        let mut ptr_ctx = make_context("4.4.8.8.in-addr.arpa.", RecordType::PTR);
        let step = plugin
            .execute(&mut ptr_ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Stop));

        let ptr_resp = ptr_ctx
            .response
            .expect("PTR response should be returned")
            .to_message()
            .expect("response should materialize");
        assert_eq!(ptr_resp.answers().len(), 1);
        assert_eq!(ptr_resp.answers()[0].record_type(), RecordType::PTR);
    }

    #[tokio::test]
    async fn test_reverse_lookup_rewrites_packet_backed_response() {
        let plugin = ReverseLookup {
            tag: "reverse_lookup".to_string(),
            cache: TtlCache::with_capacity(64),
            size: 64,
            ttl: 120,
            handle_ptr: false,
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: None,
        };

        let mut ctx = make_context("www.example.com.", RecordType::A);
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(8, 8, 4, 4))),
        ));
        ctx.set_response_packet(Packet::from_vec(response.to_bytes().unwrap()))
            .expect("packet response should decode");

        plugin
            .post_execute(&mut ctx, None)
            .await
            .expect("post_execute should succeed");

        assert!(
            ctx.response
                .as_ref()
                .and_then(|response| response.packet())
                .is_some(),
            "packet-backed response should stay packet-backed"
        );
        assert_eq!(
            ctx.response
                .expect("response should exist")
                .to_message()
                .expect("response should materialize")
                .answers()[0]
                .ttl(),
            120
        );
    }
}
