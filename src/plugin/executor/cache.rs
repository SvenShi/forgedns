/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS response cache executor plugin
//!
//! Provides an in-memory cache keyed by (domain, record type, class).
//! Cache entries expire based on DNS TTL and are periodically cleaned up.
//! A lightweight, lock-free LRU strategy evicts the least recently accessed
//! entries when the cache grows beyond a threshold.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::Executor;
use crate::plugin::executor::sequence::chain::ChainNode;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;
use tokio::time::sleep;
use tracing::{Level, debug, event_enabled, info, warn};

// Default cache size
const DEFAULT_CACHE_SIZE: usize = 1024;
// Default cleanup interval (seconds)
const DEFAULT_CLEANUP_INTERVAL: u64 = 60;
// Default TTL (seconds)
const DEFAULT_TTL: u32 = 300;
// LRU eviction threshold
const LRU_EVICTION_THRESHOLD: f32 = 0.9;
// Default dump interval (seconds)
const DEFAULT_DUMP_INTERVAL: u64 = 600;

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of entries allowed in the cache.
    ///
    /// - When omitted, defaults to `DEFAULT_CACHE_SIZE`.
    size: Option<usize>,

    /// Optional override TTL (seconds) for newly cached responses.
    ///
    /// - When set, this replaces the response-derived TTL.
    lazy_cache_ttl: Option<u32>,

    /// Optional path to persist cache contents.
    ///
    /// - When set, cache is loaded on startup and periodically dumped.
    dump_file: Option<String>,

    /// Interval (seconds) for dumping cache contents to disk.
    ///
    /// - Defaults to `DEFAULT_DUMP_INTERVAL` when `dump_file` is set.
    dump_interval: Option<u64>,

    /// Whether to short-circuit the executor chain on cache hit.
    ///
    /// - When true, a cache hit returns immediately and skips remaining plugins.
    short_circuit: Option<bool>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CacheItem {
    /// Cached DNS response message.
    resp: Message,
    /// Timestamp when the entry was cached (milliseconds).
    cache_time: u64,
    /// Original TTL derived from the response (seconds).
    ttl: u32,
    /// Absolute expiration time (milliseconds).
    expire_time: u64,
    /// Last access time for LRU eviction (milliseconds).
    last_access_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedCacheEntry {
    domain: String,
    record_type: u16,
    dns_class: u16,
    resp_bytes: Vec<u8>,
    cache_age_ms: u64,
    last_access_age_ms: u64,
    ttl: u32,
    remaining_ttl_ms: u64,
}

/// DNS response cache executor
///
/// Stores responses in a concurrent map and reuses them for repeated queries.
/// The cache is initialized lazily and cleaned periodically in a background task.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Cache {
    /// Thread-safe cache map shared across tasks.
    domain_map: OnceCell<Arc<DashMap<(String, RecordType, DNSClass), CacheItem>>>,
    /// Plugin identifier.
    tag: String,
    /// Cache configuration parameters.
    config: CacheConfig,
    /// Whether to short-circuit the executor chain on cache hit.
    short_circuit: bool,
}

impl Cache {
    #[inline]
    fn cache_size(&self) -> usize {
        self.config.size.unwrap_or(DEFAULT_CACHE_SIZE)
    }

    fn spawn_load_task(
        &self,
        domain_map: Arc<DashMap<(String, RecordType, DNSClass), CacheItem>>,
        dump_path: String,
    ) {
        tokio::spawn(async move {
            if let Err(e) = load_cache_from_file(&domain_map, &dump_path).await {
                warn!("Failed to load cache from {}: {}", dump_path, e);
            }
        });
    }

    fn spawn_dump_task(
        &self,
        domain_map: Arc<DashMap<(String, RecordType, DNSClass), CacheItem>>,
        dump_path: String,
        dump_interval: u64,
    ) {
        tokio::spawn(async move {
            let interval = Duration::from_secs(dump_interval);
            loop {
                sleep(interval).await;
                if let Err(e) = dump_cache_to_file(&domain_map, &dump_path).await {
                    warn!("Failed to dump cache to {}: {}", dump_path, e);
                }
            }
        });
    }

    fn spawn_cleanup_task(
        &self,
        domain_map: Arc<DashMap<(String, RecordType, DNSClass), CacheItem>>,
        cache_size: usize,
    ) {
        tokio::spawn(async move {
            let cleanup_interval = Duration::from_secs(DEFAULT_CLEANUP_INTERVAL);
            loop {
                sleep(cleanup_interval).await;

                let now = AppClock::elapsed_millis();
                let expired_keys: Vec<_> = domain_map
                    .iter()
                    .filter(|item| item.value().expire_time <= now)
                    .map(|item| item.key().clone())
                    .collect();

                for key in &expired_keys {
                    domain_map.remove(key);
                }

                if !expired_keys.is_empty() {
                    debug!("Cleaned {} expired cache entries", expired_keys.len());
                }

                let current_size = domain_map.len();
                let threshold_size = (cache_size as f32 * LRU_EVICTION_THRESHOLD) as usize;

                if current_size > threshold_size {
                    let mut entries: Vec<((String, RecordType, DNSClass), u64)> = domain_map
                        .iter()
                        .map(|item| (item.key().clone(), item.value().last_access_time))
                        .collect();

                    entries.sort_by_key(|(_, last)| *last);

                    let evict_count = current_size - (threshold_size - threshold_size / 10);
                    let mut evicted = 0;
                    for (key, _) in entries.into_iter().take(evict_count) {
                        if domain_map.remove(&key).is_some() {
                            evicted += 1;
                        }
                    }

                    if evicted > 0 {
                        warn!(
                            "LRU eviction: removed {} items, cache size {} -> {}",
                            evicted,
                            current_size,
                            domain_map.len()
                        );
                    }
                }
            }
        });
    }

    #[inline]
    fn update_response_ttl(resp: &mut Message, remaining_ttl: u32) {
        for record in resp.answers_mut() {
            record.set_ttl(remaining_ttl);
        }
        for record in resp.name_servers_mut() {
            record.set_ttl(remaining_ttl);
        }
        for record in resp.additionals_mut() {
            record.set_ttl(remaining_ttl);
        }
    }

    #[inline]
    fn try_cache_hit(
        &self,
        context: &mut DnsContext,
        domain_map: &DashMap<(String, RecordType, DNSClass), CacheItem>,
    ) -> (Option<(String, RecordType, DNSClass)>, bool) {
        let mut cache_key = None;
        let mut cache_hit = false;

        if let Some(query) = context.request.query() {
            let domain = query.name().to_string();
            let key = (domain.clone(), query.query_type, query.query_class);
            cache_key = Some(key.clone());

            if let Some(mut item) = domain_map.get_mut(&key) {
                let now = AppClock::elapsed_millis();
                if now < item.expire_time {
                    item.last_access_time = now;
                    let mut resp = item.resp.clone();
                    let remaining_ttl =
                        item.expire_time.saturating_sub(now).saturating_div(1000) as u32;
                    resp.set_id(context.request.id());
                    Self::update_response_ttl(&mut resp, remaining_ttl);
                    context.response = Some(resp);
                    cache_hit = true;
                    debug!(
                        "cache hit: domain={}, type={:?}, class={:?}",
                        domain, query.query_type, query.query_class
                    );
                } else {
                    domain_map.remove(&key);
                    debug!(
                        "cache expired: domain={}, type={:?}, class={:?}",
                        domain, query.query_type, query.query_class
                    );
                }
            } else {
                debug!(
                    "cache miss: domain={}, type={:?}, class={:?}",
                    domain, query.query_type, query.query_class
                );
            }
        }

        (cache_key, cache_hit)
    }

    #[inline]
    fn should_short_circuit(
        &self,
        cache_hit: bool,
        cache_key: Option<&(String, RecordType, DNSClass)>,
    ) -> bool {
        if !cache_hit || !self.short_circuit {
            return false;
        }

        if event_enabled!(Level::DEBUG) {
            if let Some((domain, record_type, dns_class)) = cache_key {
                debug!(
                    "cache short-circuit hit: domain={}, type={:?}, class={:?}",
                    domain, record_type, dns_class
                );
            }
        }

        true
    }

    #[inline]
    fn compute_response_ttl(response: &Message) -> u32 {
        if !response.answers().is_empty() {
            response
                .answers()
                .iter()
                .map(|answer| answer.ttl())
                .min()
                .unwrap_or(DEFAULT_TTL)
        } else {
            60
        }
    }

    #[inline]
    fn compute_expire_time(&self, now: u64, ttl: u32) -> u64 {
        if let Some(lazy_ttl) = self.config.lazy_cache_ttl {
            now + (lazy_ttl as u64 * 1000)
        } else {
            now + (ttl as u64 * 1000)
        }
    }

    #[inline]
    fn update_cache_entry(
        &self,
        domain_map: &DashMap<(String, RecordType, DNSClass), CacheItem>,
        key: (String, RecordType, DNSClass),
        response: Message,
    ) {
        let ttl = Self::compute_response_ttl(&response);
        let now = AppClock::elapsed_millis();
        let expire_time = self.compute_expire_time(now, ttl);

        let cache = domain_map.get_mut(&key);
        match cache {
            Some(mut existing) => {
                let entry = existing.value_mut();
                entry.resp = response;
                entry.cache_time = now;
                entry.ttl = ttl;
                entry.expire_time = expire_time;
                entry.last_access_time = now;
            }
            None => {
                debug!("cached: domain={}, ttl={}", &key.0, ttl);
                domain_map.insert(
                    key,
                    CacheItem {
                        resp: response,
                        cache_time: now,
                        ttl,
                        expire_time,
                        last_access_time: now,
                    },
                );
            }
        }
    }
}

#[async_trait]
impl Plugin for Cache {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        let cache_size = self.cache_size();
        let domain_map = Arc::new(DashMap::with_capacity(cache_size));

        let _ = self.domain_map.set(domain_map.clone());

        if let Some(dump_file) = &self.config.dump_file {
            self.spawn_load_task(domain_map.clone(), dump_file.clone());
            let dump_interval = self.config.dump_interval.unwrap_or(DEFAULT_DUMP_INTERVAL);
            self.spawn_dump_task(domain_map.clone(), dump_file.clone(), dump_interval);
        }

        self.spawn_cleanup_task(domain_map, cache_size);
    }

    async fn destroy(&mut self) {
        if let Some(dump_file) = &self.config.dump_file {
            if let Some(domain_map) = self.domain_map.get() {
                if let Err(e) = dump_cache_to_file(domain_map, dump_file).await {
                    warn!("Failed to dump cache to {}: {}", dump_file, e);
                }
            }
        }
    }
}

#[async_trait]
impl Executor for Cache {
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<ChainNode>>) {
        let domain_map = self.domain_map.get().unwrap();
        let (cache_key, cache_hit) = self.try_cache_hit(context, domain_map);

        if self.should_short_circuit(cache_hit, cache_key.as_ref()) {
            return;
        }

        continue_next!(next, context);

        if let (Some(response), Some(key)) = (&context.response, cache_key) {
            self.update_cache_entry(domain_map, key, response.clone());
        }
    }
}

async fn dump_cache_to_file(
    domain_map: &DashMap<(String, RecordType, DNSClass), CacheItem>,
    dump_path: &str,
) -> io::Result<()> {
    let now = AppClock::elapsed_millis();
    let mut entries: Vec<PersistedCacheEntry> = Vec::with_capacity(domain_map.len());

    for item in domain_map.iter() {
        let value = item.value();
        if value.expire_time <= now {
            continue;
        }

        let remaining_ttl_ms = value.expire_time.saturating_sub(now);
        if remaining_ttl_ms == 0 {
            continue;
        }

        let resp_bytes = match value.resp.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    "Failed to serialize DNS message for {}: {}",
                    item.key().0,
                    e
                );
                continue;
            }
        };

        entries.push(PersistedCacheEntry {
            domain: item.key().0.clone(),
            record_type: u16::from(item.key().1),
            dns_class: u16::from(item.key().2),
            resp_bytes,
            cache_age_ms: now.saturating_sub(value.cache_time),
            last_access_age_ms: now.saturating_sub(value.last_access_time),
            ttl: value.ttl,
            remaining_ttl_ms,
        });
    }

    let encoded =
        bincode::serialize(&entries).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let tmp_path = format!("{}.tmp", dump_path);
    let mut file = File::create(&tmp_path).await?;
    file.write_all(&encoded).await?;
    file.sync_all().await?;
    fs::rename(&tmp_path, dump_path).await?;
    Ok(())
}

async fn load_cache_from_file(
    domain_map: &DashMap<(String, RecordType, DNSClass), CacheItem>,
    dump_path: &str,
) -> io::Result<()> {
    if !Path::new(dump_path).exists() {
        return Ok(());
    }

    let data = fs::read(dump_path).await?;
    let entries: Vec<PersistedCacheEntry> =
        bincode::deserialize(&data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let now = AppClock::elapsed_millis();
    let mut loaded = 0usize;
    for entry in entries {
        if entry.remaining_ttl_ms == 0 {
            continue;
        }

        let resp = match Message::from_bytes(&entry.resp_bytes) {
            Ok(message) => message,
            Err(e) => {
                warn!(
                    "Failed to parse cached DNS message for {}: {}",
                    entry.domain, e
                );
                continue;
            }
        };

        let key = (
            entry.domain,
            RecordType::from(entry.record_type),
            DNSClass::from(entry.dns_class),
        );

        let expire_time = now.saturating_add(entry.remaining_ttl_ms);
        let cache_time = now.saturating_sub(entry.cache_age_ms);
        let last_access_time = now.saturating_sub(entry.last_access_age_ms);

        domain_map.insert(
            key,
            CacheItem {
                resp,
                cache_time,
                ttl: entry.ttl,
                expire_time,
                last_access_time,
            },
        );
        loaded += 1;
    }

    if loaded > 0 {
        info!("Loaded {} cache entries from {}", loaded, dump_path);
    }

    Ok(())
}

/// Factory for creating cache executor plugins.
#[derive(Debug)]
pub struct CacheFactory;

register_plugin_factory!("cache", CacheFactory {});

impl PluginFactory for CacheFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cache_config = if let Some(args) = &plugin_config.args {
            serde_yml::from_value::<CacheConfig>(args.clone())?
        } else {
            CacheConfig {
                size: None,
                lazy_cache_ttl: None,
                dump_file: None,
                dump_interval: None,
                short_circuit: None,
            }
        };

        Ok(UninitializedPlugin::Executor(Box::new(Cache {
            domain_map: OnceCell::new(),
            tag: plugin_config.tag.clone(),
            short_circuit: cache_config.short_circuit.unwrap_or(false),
            config: cache_config,
        })))
    }
}
