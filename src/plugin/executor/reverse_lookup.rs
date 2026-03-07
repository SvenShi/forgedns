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
use crate::core::ttl_cache::TtlCache;
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::name::PTR;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::watch;

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
    shutdown_tx: watch::Sender<bool>,
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
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let interval = Duration::from_secs(CLEANUP_INTERVAL_SECS);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                }
                let now = AppClock::elapsed_millis();

                while cache.remove_expired_batch(now, EVICTION_BATCH) > 0 {}

                if cache.len() <= size {
                    continue;
                }
                let overflow = cache.len().saturating_sub(size).min(EVICTION_BATCH);
                if overflow == 0 {
                    continue;
                }

                let mut keys: Vec<(IpAddr, u64)> = cache.sample_last_access(overflow);
                keys.sort_unstable_by_key(|(_, last_access_ms)| *last_access_ms);
                for (key, _) in keys.into_iter().take(overflow) {
                    let _ = cache.remove(&key);
                }
            }
        });
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
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
            context.response = Some(response);
            return Ok(ExecStep::Stop);
        }

        Ok(ExecStep::NextWithPost(None))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let _ = state;

        let Some(response) = context.response.as_mut() else {
            return Ok(());
        };

        let query_name = context.request.query().map(|q| q.name().clone());
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
    fn try_handle_ptr(
        &self,
        request: &hickory_proto::op::Message,
    ) -> Option<hickory_proto::op::Message> {
        let query = request.query()?;
        if query.query_type != RecordType::PTR {
            return None;
        }

        let ip = parse_ptr_name(query.name())?;
        let ip = normalize_ip(ip);
        let now = AppClock::elapsed_millis();
        let entry = self.cache.get_fresh_cloned(&ip, now, 1000)?;

        let mut response = build_response_from_request(request, ResponseCode::NoError);
        response.answers_mut().push(Record::from_rdata(
            query.name().clone(),
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
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        if let Some(args) = plugin_config.args.clone() {
            let _: ReverseLookupConfig = serde_yml::from_value(args).map_err(|e| {
                DnsError::plugin(format!("failed to parse reverse_lookup config: {}", e))
            })?;
        }
        Ok(())
    }

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
            shutdown_tx: watch::channel(false).0,
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
