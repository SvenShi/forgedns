/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `reverse_lookup` executor plugin.
//!
//! Caches answer IP -> domain mapping and optionally serves PTR queries.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::dns_utils::{build_response_from_request, rr_to_ip};
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::name::PTR;
use hickory_proto::rr::{Name, RData, Record, RecordType};
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
    size: Option<usize>,
    handle_ptr: Option<bool>,
    ttl: Option<u32>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    domain: Name,
    expire_at_ms: u64,
}

#[derive(Debug)]
struct ReverseLookup {
    tag: String,
    cache: Arc<DashMap<IpAddr, CacheEntry>>,
    size: usize,
    ttl: u32,
    handle_ptr: bool,
    cleanup_started: AtomicBool,
}

#[async_trait]
impl Plugin for ReverseLookup {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        if self.cleanup_started.swap(true, Ordering::Relaxed) {
            return;
        }

        let cache = self.cache.clone();
        let size = self.size;
        tokio::spawn(async move {
            let interval = Duration::from_secs(CLEANUP_INTERVAL_SECS);
            loop {
                tokio::time::sleep(interval).await;
                let now = AppClock::elapsed_millis();
                cache.retain(|_, entry| entry.expire_at_ms > now);

                if cache.len() <= size {
                    continue;
                }
                let overflow = cache.len().saturating_sub(size).min(EVICTION_BATCH);
                if overflow == 0 {
                    continue;
                }
                let keys: Vec<IpAddr> = cache
                    .iter()
                    .take(overflow)
                    .map(|entry| *entry.key())
                    .collect();
                for key in keys {
                    cache.remove(&key);
                }
            }
        });
    }

    async fn destroy(&self) {}
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
            self.cache.insert(
                normalize_ip(ip),
                CacheEntry {
                    domain,
                    expire_at_ms,
                },
            );
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
        let entry = self.cache.get(&ip)?;
        if entry.expire_at_ms <= now {
            self.cache.remove(&ip);
            return None;
        }

        let mut response = build_response_from_request(request, ResponseCode::NoError);
        response.answers_mut().push(Record::from_rdata(
            query.name().clone(),
            5,
            RData::PTR(PTR(entry.domain.clone())),
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
            cache: Arc::new(DashMap::with_capacity(size)),
            size,
            ttl,
            handle_ptr: cfg.handle_ptr.unwrap_or(false),
            cleanup_started: AtomicBool::new(false),
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
