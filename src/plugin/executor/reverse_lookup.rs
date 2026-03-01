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

const DEFAULT_SIZE: usize = 65_535;
const DEFAULT_TTL: u32 = 7_200;

#[derive(Debug, Clone, Deserialize, Default)]
struct ReverseLookupConfig {
    size: Option<usize>,
    handle_ptr: Option<bool>,
    ttl: Option<u32>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    domain: String,
    expire_at_ms: u64,
}

#[derive(Debug)]
struct ReverseLookup {
    tag: String,
    cache: DashMap<IpAddr, CacheEntry>,
    size: usize,
    ttl: u32,
    handle_ptr: bool,
}

#[derive(Debug)]
struct PostState {
    query_name: Option<String>,
}

#[async_trait]
impl Plugin for ReverseLookup {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

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

        let query_name = context.request.query().map(|q| q.name().to_utf8());
        Ok(ExecStep::NextWithPost(Some(
            Box::new(PostState { query_name }) as ExecState,
        )))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let query_name = state
            .and_then(|boxed| boxed.downcast::<PostState>().ok())
            .and_then(|boxed| boxed.query_name.clone());

        let Some(response) = context.response.as_mut() else {
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
                .clone()
                .unwrap_or_else(|| record.name().to_utf8());
            self.cache.insert(
                normalize_ip(ip),
                CacheEntry {
                    domain,
                    expire_at_ms,
                },
            );
        }

        self.evict_if_needed(now);
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
        let target = hickory_proto::rr::Name::from_ascii(entry.domain.as_str()).ok()?;
        response.answers_mut().push(Record::from_rdata(
            query.name().clone(),
            5,
            RData::PTR(PTR(target)),
        ));
        Some(response)
    }

    fn evict_if_needed(&self, now: u64) {
        if self.cache.len() <= self.size {
            return;
        }

        let expired_keys: Vec<IpAddr> = self
            .cache
            .iter()
            .filter(|entry| entry.value().expire_at_ms <= now)
            .map(|entry| *entry.key())
            .collect();
        for key in expired_keys {
            self.cache.remove(&key);
        }

        if self.cache.len() <= self.size {
            return;
        }

        let overflow = self.cache.len().saturating_sub(self.size);
        if overflow == 0 {
            return;
        }

        let keys: Vec<IpAddr> = self
            .cache
            .iter()
            .take(overflow)
            .map(|entry| *entry.key())
            .collect();
        for key in keys {
            self.cache.remove(&key);
        }
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
            cache: DashMap::with_capacity(size),
            size,
            ttl,
            handle_ptr: cfg.handle_ptr.unwrap_or(false),
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
