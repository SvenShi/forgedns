// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS response cache executor plugin.
//!
//! Provides an in-memory cache keyed by normalized query name + query context
//! (qtype/qclass/DO/CD and optional ECS scope). Cache entries expire by TTL and
//! are periodically cleaned up.
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ahash::AHashSet;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use tokio::sync::OnceCell;
use tracing::{Level, debug, event_enabled, info, warn};

use self::key::{CacheKey, build_cache_key as build_cache_key_internal};
use self::persistence::{
    dump_cache_to_bytes, dump_cache_to_file, load_cache_from_bytes, load_cache_from_file,
};
use crate::api::{ApiHandler, ApiRegister, json_error, json_ok, simple_response};
use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::core::ttl_cache::TtlCache;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{Message, Rcode};
use crate::{continue_next, register_plugin_factory};

mod key;
mod persistence;

// Default cache size.
const DEFAULT_CACHE_SIZE: usize = 1024;
// Default cleanup interval (seconds).
const DEFAULT_CLEANUP_INTERVAL: u64 = 60;
// Default dump interval (seconds).
const DEFAULT_DUMP_INTERVAL: u64 = 600;
// Minimum key updates required to trigger periodic dump.
const MINIMUM_CHANGES_TO_DUMP: u64 = 1024;
// Default fallback TTL (seconds) for NXDOMAIN/NODATA without SOA.
const DEFAULT_NEGATIVE_TTL_WITHOUT_SOA: u32 = 60;
// Default max TTL (seconds) for negative cache entries.
const DEFAULT_MAX_NEGATIVE_TTL: u32 = 300;
// Minimum interval for updating LRU timestamp on cache hit.
const LAST_ACCESS_TOUCH_INTERVAL_MS: u64 = 1000;

// Cleanup tuning.
const EVICT_HIGH_WATERMARK_PERCENT: usize = 95;
const EVICT_LOW_WATERMARK_PERCENT: usize = 85;
const EXPIRED_SWEEP_BATCH: usize = 2048;
const EXPIRED_SWEEP_ROUNDS: usize = 4;
const EVICTION_SAMPLE_SIZE: usize = 4096;
const EVICTION_MAX_BATCH: usize = 2048;
const DEFAULT_LAZY_REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of entries allowed in the cache.
    size: Option<usize>,

    /// Optional override TTL (seconds) for newly cached responses.
    ///
    /// When set, this replaces computed positive/negative TTL.
    lazy_cache_ttl: Option<u32>,

    /// Optional path to persist cache contents.
    dump_file: Option<String>,

    /// Interval (seconds) for dumping cache contents to disk.
    dump_interval: Option<u64>,

    /// Whether to short-circuit the executor chain on cache hit.
    short_circuit: Option<bool>,

    /// Whether to cache negative responses (NXDOMAIN/NODATA).
    cache_negative: Option<bool>,

    /// Maximum TTL (seconds) for negative responses.
    max_negative_ttl: Option<u32>,

    /// Fallback TTL (seconds) when negative response has no SOA.
    ///
    /// If set to 0, negative response without SOA will not be cached.
    negative_ttl_without_soa: Option<u32>,

    /// Optional upper bound TTL (seconds) for positive responses.
    max_positive_ttl: Option<u32>,

    /// Whether ECS scope is part of cache key.
    ///
    /// Default: false.
    ecs_in_key: Option<bool>,
}

type CacheMap = TtlCache<CacheKey, Arc<CacheItem>>;

#[derive(Debug, Clone)]
pub struct CacheItem {
    /// Cached DNS response message.
    resp: Message,

    /// TTL used for this cached entry (seconds).
    ttl: u32,

    /// Deadline when the response transitions from fresh to stale.
    fresh_until_ms: u64,
}

impl CacheItem {
    fn new(resp: Message, ttl: u32, fresh_until_ms: u64) -> Self {
        Self {
            resp,
            ttl,
            fresh_until_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheHitKind {
    Fresh,
    Stale,
}

#[derive(Debug, Clone)]
struct CacheLookup {
    key: CacheKey,
    hit_kind: Option<CacheHitKind>,
}

/// DNS response cache executor.
#[derive(Debug)]
pub struct Cache {
    /// Thread-safe cache map shared across tasks.
    cache_map: OnceCell<CacheMap>,

    /// Plugin identifier.
    tag: String,

    /// Whether to cache negative responses (NXDOMAIN/NODATA).
    cache_negative: bool,

    /// Maximum TTL (seconds) for negative responses.
    max_negative_ttl: u32,

    /// Fallback TTL (seconds) when negative response has no SOA.
    ///
    /// If set to 0, negative response without SOA will not be cached.
    negative_ttl_without_soa: u32,

    /// Maximum number of entries allowed in the cache.
    cache_size: usize,

    /// Cache configuration parameters.
    config: CacheConfig,

    /// Whether to short-circuit the executor chain on cache hit.
    short_circuit: bool,

    /// Whether to include ECS scope in cache key.
    ecs_in_key: bool,

    /// Number of cache entry updates since last dump.
    updated_keys: Arc<AtomicU64>,

    /// Periodic dump task id, if dump persistence is enabled.
    dump_task_id: Mutex<Option<u64>>,

    /// Periodic cleanup task id.
    cleanup_task_id: Mutex<Option<u64>>,

    /// Management API route register, when global API is enabled.
    api_register: Option<ApiRegister>,

    /// Deduplicates background refreshes for stale lazy cache hits.
    lazy_refresh_inflight: Arc<Mutex<AHashSet<CacheKey>>>,
}

impl Cache {
    fn spawn_load_task(&self, cache_map: CacheMap, dump_path: String, ecs_in_key: bool) {
        tokio::spawn(async move {
            if let Err(e) = load_cache_from_file(&cache_map, &dump_path, ecs_in_key).await {
                warn!("Failed to load cache from {}: {}", dump_path, e);
            }
        });
    }

    fn spawn_dump_task(
        &self,
        cache_map: CacheMap,
        dump_path: String,
        dump_interval: u64,
        updated_keys: Arc<AtomicU64>,
    ) -> u64 {
        task_center::spawn_fixed(
            format!("cache:{}:dump", self.tag),
            Duration::from_secs(dump_interval),
            move || {
                let cache_map = cache_map.clone();
                let dump_path = dump_path.clone();
                let updated_keys = updated_keys.clone();
                async move {
                    let changed = updated_keys.swap(0, Ordering::Relaxed);
                    if changed < MINIMUM_CHANGES_TO_DUMP {
                        // Keep sparse updates accumulated so low-write workloads still persist
                        // eventually without triggering dump every interval.
                        if changed > 0 {
                            updated_keys.fetch_add(changed, Ordering::Relaxed);
                        }
                        return;
                    }
                    if let Err(e) = dump_cache_to_file(&cache_map, &dump_path).await {
                        warn!("Failed to dump cache to {}: {}", dump_path, e);
                    }
                }
            },
        )
    }

    fn spawn_cleanup_task(&self, cache_map: CacheMap, cache_size: usize) -> u64 {
        task_center::spawn_fixed(
            format!("cache:{}:cleanup", self.tag),
            Duration::from_secs(DEFAULT_CLEANUP_INTERVAL),
            move || {
                let cache_map = cache_map.clone();
                async move {
                    let now = AppClock::elapsed_millis();
                    let mut expired_removed = 0usize;
                    for _ in 0..EXPIRED_SWEEP_ROUNDS {
                        let removed = cache_map.remove_expired_batch(now, EXPIRED_SWEEP_BATCH);
                        if removed == 0 {
                            break;
                        }
                        expired_removed += removed;
                    }

                    if expired_removed > 0 {
                        debug!("Cleaned {} expired cache entries", expired_removed);
                    }

                    let current_size = cache_map.len();
                    let high_watermark = cache_size
                        .saturating_mul(EVICT_HIGH_WATERMARK_PERCENT)
                        .saturating_div(100)
                        .max(1);
                    if current_size <= high_watermark {
                        return;
                    }

                    let low_watermark = cache_size
                        .saturating_mul(EVICT_LOW_WATERMARK_PERCENT)
                        .saturating_div(100)
                        .max(1);
                    let target_size = low_watermark.min(current_size);
                    let mut evict_target = current_size.saturating_sub(target_size);
                    evict_target = evict_target.min(EVICTION_MAX_BATCH);

                    let sample_cap = current_size.min(EVICTION_SAMPLE_SIZE);
                    let mut sample = cache_map.sample_last_access(sample_cap);

                    if sample.is_empty() || evict_target == 0 {
                        return;
                    }

                    // Approximate LRU: sort sampled keys by last-access and evict oldest subset.
                    sample.sort_unstable_by_key(|(_, last)| *last);

                    let mut evicted = 0usize;
                    for (key, _) in sample.into_iter().take(evict_target) {
                        if cache_map.remove(&key) {
                            evicted += 1;
                        }
                    }

                    if evicted > 0 {
                        warn!(
                            "LRU eviction: removed {} items, cache size {} -> {}",
                            evicted,
                            current_size,
                            cache_map.len()
                        );
                    }
                }
            },
        )
    }

    #[inline]
    fn build_cache_key(context: &mut DnsContext, ecs_in_key: bool) -> Option<CacheKey> {
        build_cache_key_internal(context, ecs_in_key)
    }

    #[inline]
    fn rewrite_message_ttls(message: &mut Message, ttl: u32) {
        for record in message.answers_mut() {
            record.set_ttl(ttl);
        }
        for record in message.authorities_mut() {
            record.set_ttl(ttl);
        }
        for record in message.additionals_mut() {
            record.set_ttl(ttl);
        }
    }

    #[inline]
    fn restore_cached_message(item: &CacheItem, request_id: u16, remaining_ttl: u32) -> Message {
        let mut response = item.resp.clone();
        response.set_id(request_id);
        Self::rewrite_message_ttls(&mut response, remaining_ttl);
        response
    }

    #[inline]
    fn stale_reply_ttl(&self, item: &CacheItem) -> u32 {
        self.config
            .lazy_cache_ttl
            .map(|ttl| ttl.min(item.ttl))
            .unwrap_or(item.ttl)
    }

    #[inline]
    fn can_lazy_cache_response(&self, response: &Message) -> bool {
        self.config.lazy_cache_ttl.is_some()
            && response.rcode() == Rcode::NoError
            && !response.answers().is_empty()
            && self.compute_positive_ttl(response).is_some()
    }

    #[inline]
    fn compute_fresh_until_ms(now: u64, ttl: u32) -> u64 {
        now.saturating_add(u64::from(ttl) * 1000)
    }

    #[inline]
    fn compute_expire_time(&self, now: u64, ttl: u32, enable_lazy: bool) -> u64 {
        if enable_lazy && let Some(lazy_ttl) = self.config.lazy_cache_ttl {
            return now.saturating_add(u64::from(ttl.max(lazy_ttl)) * 1000);
        }
        Self::compute_fresh_until_ms(now, ttl)
    }

    #[inline]
    #[hotpath::measure]
    fn try_cache_hit(&self, context: &mut DnsContext, cache_map: &CacheMap) -> Option<CacheLookup> {
        let key = Self::build_cache_key(context, self.ecs_in_key)?;

        let now = AppClock::elapsed_millis();

        if let Some(item) = cache_map.get_retained_cloned(&key, now, LAST_ACCESS_TOUCH_INTERVAL_MS)
        {
            if now < item.value.fresh_until_ms {
                let remaining_ttl = item
                    .value
                    .fresh_until_ms
                    .saturating_sub(now)
                    .saturating_div(1000) as u32;
                let resp =
                    Self::restore_cached_message(&item.value, context.request.id(), remaining_ttl);
                context.set_response(resp);

                debug!(
                    "cache hit: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}, kind=fresh",
                    key.domain,
                    key.record_type,
                    key.dns_class,
                    key.do_bit,
                    key.cd_bit,
                    key.ecs_scope.is_some()
                );
                return Some(CacheLookup {
                    key,
                    hit_kind: Some(CacheHitKind::Fresh),
                });
            }

            if self.config.lazy_cache_ttl.is_some() && now < item.expire_at_ms {
                let resp = Self::restore_cached_message(
                    &item.value,
                    context.request.id(),
                    self.stale_reply_ttl(&item.value),
                );
                context.set_response(resp);

                debug!(
                    "cache hit: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}, kind=stale",
                    key.domain,
                    key.record_type,
                    key.dns_class,
                    key.do_bit,
                    key.cd_bit,
                    key.ecs_scope.is_some()
                );
                return Some(CacheLookup {
                    key,
                    hit_kind: Some(CacheHitKind::Stale),
                });
            }
        }

        if cache_map.remove_if_expired(&key, now) {
            debug!(
                "cache expired: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                key.domain,
                key.record_type,
                key.dns_class,
                key.do_bit,
                key.cd_bit,
                key.ecs_scope.is_some()
            );
        } else {
            debug!(
                "cache miss: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                key.domain,
                key.record_type,
                key.dns_class,
                key.do_bit,
                key.cd_bit,
                key.ecs_scope.is_some()
            );
        }

        Some(CacheLookup {
            key,
            hit_kind: None,
        })
    }

    #[inline]
    fn should_short_circuit(&self, cache_hit: bool) -> bool {
        if !cache_hit || !self.short_circuit {
            return false;
        }

        if event_enabled!(Level::DEBUG) {
            debug!("cache short-circuit hit");
        }

        true
    }

    #[inline]
    fn compute_positive_ttl(&self, response: &Message) -> Option<u32> {
        if response.rcode() != Rcode::NoError {
            return None;
        }

        let ttl = response.min_answer_ttl()?;
        let ttl = if let Some(max) = self.config.max_positive_ttl {
            ttl.min(max)
        } else {
            ttl
        };

        if ttl == 0 { None } else { Some(ttl) }
    }

    #[inline]
    fn compute_negative_ttl(&self, response: &Message) -> Option<u32> {
        if !self.cache_negative {
            return None;
        }

        let rcode = response.rcode();
        let is_nxdomain = rcode == Rcode::NXDomain;
        let is_nodata = rcode == Rcode::NoError && response.min_answer_ttl().is_none();

        if !is_nxdomain && !is_nodata {
            return None;
        }

        let mut ttl = if let Some(soa_ttl) = response.negative_ttl_from_soa() {
            soa_ttl
        } else {
            self.negative_ttl_without_soa
        };

        ttl = ttl.min(self.max_negative_ttl);

        if ttl == 0 { None } else { Some(ttl) }
    }

    #[inline]
    fn compute_cache_ttl(&self, response: &Message) -> Option<u32> {
        self.compute_positive_ttl(response)
            .or_else(|| self.compute_negative_ttl(response))
    }

    #[inline]
    #[hotpath::measure]
    fn update_cache_entry(&self, cache_map: &CacheMap, key: CacheKey, response: Message, ttl: u32) {
        let now = AppClock::elapsed_millis();
        let fresh_until_ms = Self::compute_fresh_until_ms(now, ttl);
        let expire_time =
            self.compute_expire_time(now, ttl, self.can_lazy_cache_response(&response));
        let item = CacheItem::new(response, ttl, fresh_until_ms);
        debug!(
            "cached: domain={}, type={:?}, class={:?}, ttl={}",
            key.domain, key.record_type, key.dns_class, ttl
        );
        cache_map.insert_or_update(key, Arc::new(item), now, expire_time);
        self.updated_keys.fetch_add(1, Ordering::Relaxed);
    }

    fn try_start_lazy_refresh(
        &self,
        key: &CacheKey,
        cache_map: &CacheMap,
        context: &DnsContext,
        next: Option<&ExecutorNext>,
    ) {
        let Some(next) = next.cloned() else {
            return;
        };

        {
            let mut inflight = self
                .lazy_refresh_inflight
                .lock()
                .expect("lazy_refresh_inflight poisoned");
            if !inflight.insert(key.clone()) {
                return;
            }
        }

        let key = key.clone();
        let cache_map = cache_map.clone();
        let inflight = self.lazy_refresh_inflight.clone();
        let mut sub_ctx = context.copy_for_subquery();
        sub_ctx.clear_response();
        let lazy_cache_ttl = self.config.lazy_cache_ttl;
        let max_positive_ttl = self.config.max_positive_ttl;
        let cache_negative = self.cache_negative;
        let max_negative_ttl = self.max_negative_ttl;
        let negative_ttl_without_soa = self.negative_ttl_without_soa;
        let updated_keys = self.updated_keys.clone();

        tokio::spawn(async move {
            let refresh = tokio::time::timeout(DEFAULT_LAZY_REFRESH_TIMEOUT, async {
                let _ = next.next(&mut sub_ctx).await?;
                Ok::<Option<Message>, DnsError>(sub_ctx.response().cloned())
            })
            .await;

            match refresh {
                Ok(Ok(Some(response))) if !response.truncated() => {
                    let ttl = compute_cache_ttl_with_policy(
                        &response,
                        max_positive_ttl,
                        cache_negative,
                        max_negative_ttl,
                        negative_ttl_without_soa,
                    );
                    if let Some(ttl) = ttl {
                        let now = AppClock::elapsed_millis();
                        let fresh_until_ms = Cache::compute_fresh_until_ms(now, ttl);
                        let enable_lazy = lazy_cache_ttl.is_some()
                            && response.rcode() == Rcode::NoError
                            && !response.answers().is_empty()
                            && compute_positive_ttl_with_cap(&response, max_positive_ttl).is_some();
                        let expire_at_ms = if enable_lazy {
                            now.saturating_add(
                                u64::from(ttl.max(lazy_cache_ttl.unwrap_or(ttl))) * 1000,
                            )
                        } else {
                            fresh_until_ms
                        };
                        cache_map.insert_or_update(
                            key.clone(),
                            Arc::new(CacheItem::new(response, ttl, fresh_until_ms)),
                            now,
                            expire_at_ms,
                        );
                        updated_keys.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => warn!("lazy cache refresh failed for {}: {}", key.domain, err),
                Err(_) => warn!("lazy cache refresh timed out for {}", key.domain),
            }

            inflight
                .lock()
                .expect("lazy_refresh_inflight poisoned")
                .remove(&key);
        });
    }

    fn register_api_routes(&self, cache_map: CacheMap) -> Result<()> {
        let Some(api_register) = &self.api_register else {
            return Ok(());
        };

        let tag = self.tag.clone();
        let ecs_in_key = self.ecs_in_key;
        api_register.register_plugin_get(
            &tag,
            "/flush",
            Arc::new(CacheFlushHandler {
                cache_map: cache_map.clone(),
            }),
        )?;
        api_register.register_plugin_get(
            &tag,
            "/dump",
            Arc::new(CacheDumpHandler {
                cache_map: cache_map.clone(),
                tag: tag.clone(),
            }),
        )?;
        api_register.register_plugin_post(
            &tag,
            "/load_dump",
            Arc::new(CacheLoadDumpHandler {
                cache_map,
                ecs_in_key,
            }),
        )?;
        Ok(())
    }
}

#[async_trait]
impl Plugin for Cache {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        let cache_map = CacheMap::with_capacity(self.cache_size);

        let _ = self.cache_map.set(cache_map.clone());
        self.register_api_routes(cache_map.clone())?;

        if let Some(dump_file) = &self.config.dump_file {
            self.spawn_load_task(cache_map.clone(), dump_file.clone(), self.ecs_in_key);
            let dump_interval = self.config.dump_interval.unwrap_or(DEFAULT_DUMP_INTERVAL);
            let task_id = self.spawn_dump_task(
                cache_map.clone(),
                dump_file.clone(),
                dump_interval,
                self.updated_keys.clone(),
            );
            *self.dump_task_id.lock().expect("dump_task_id poisoned") = Some(task_id);
        }

        let cleanup_task_id = self.spawn_cleanup_task(cache_map, self.cache_size);
        *self
            .cleanup_task_id
            .lock()
            .expect("cleanup_task_id poisoned") = Some(cleanup_task_id);
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        let dump_task_id = self
            .dump_task_id
            .lock()
            .expect("dump_task_id poisoned")
            .take();
        let cleanup_task_id = self
            .cleanup_task_id
            .lock()
            .expect("cleanup_task_id poisoned")
            .take();

        if let Some(task_id) = dump_task_id {
            task_center::stop_task(task_id).await;
        }
        if let Some(task_id) = cleanup_task_id {
            task_center::stop_task(task_id).await;
        }
        if let Some(dump_file) = &self.config.dump_file
            && let Some(cache_map) = self.cache_map.get()
            && let Err(e) = dump_cache_to_file(cache_map, dump_file).await
        {
            warn!("Failed to dump cache to {}: {}", dump_file, e);
        }
        Ok(())
    }
}

#[async_trait]
impl Executor for Cache {
    fn with_next(&self) -> bool {
        true
    }

    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.execute_with_next(context, None).await
    }

    #[hotpath::measure]
    async fn execute_with_next(
        &self,
        context: &mut DnsContext,
        next: Option<ExecutorNext>,
    ) -> Result<ExecStep> {
        let Some(cache_map) = self.cache_map.get() else {
            return continue_next!(next, context);
        };

        let cache_lookup = self.try_cache_hit(context, cache_map);
        let cache_hit = cache_lookup
            .as_ref()
            .and_then(|lookup| lookup.hit_kind)
            .is_some();

        if let Some(lookup) = cache_lookup.as_ref()
            && lookup.hit_kind == Some(CacheHitKind::Stale)
        {
            self.try_start_lazy_refresh(&lookup.key, cache_map, context, next.as_ref());
        }

        if self.should_short_circuit(cache_hit) {
            return Ok(ExecStep::Stop);
        }

        // Cache hit without short-circuit keeps chain running but does not
        // rewrite cache in post stage. This avoids TTL drift on repeated hits.
        if cache_hit {
            return continue_next!(next, context);
        }

        let next_step = continue_next!(next, context)?;

        if let Some(key) = cache_lookup.and_then(|lookup| {
            if lookup.hit_kind.is_none() {
                Some(lookup.key)
            } else {
                None
            }
        }) {
            let Some(response) = context.response() else {
                return Ok(next_step);
            };

            if response.truncated() {
                return Ok(next_step);
            }

            if let Some(ttl) = self.compute_cache_ttl(response) {
                self.update_cache_entry(cache_map, key, response.clone(), ttl);
            }
        }
        Ok(next_step)
    }
}

fn compute_positive_ttl_with_cap(response: &Message, max_positive_ttl: Option<u32>) -> Option<u32> {
    if response.rcode() != Rcode::NoError {
        return None;
    }

    let ttl = response.min_answer_ttl()?;
    let ttl = max_positive_ttl.map(|max| ttl.min(max)).unwrap_or(ttl);
    if ttl == 0 { None } else { Some(ttl) }
}

fn compute_negative_ttl_with_policy(
    response: &Message,
    cache_negative: bool,
    max_negative_ttl: u32,
    negative_ttl_without_soa: u32,
) -> Option<u32> {
    if !cache_negative {
        return None;
    }

    let rcode = response.rcode();
    let is_nxdomain = rcode == Rcode::NXDomain;
    let is_nodata = rcode == Rcode::NoError && response.min_answer_ttl().is_none();

    if !is_nxdomain && !is_nodata {
        return None;
    }

    let ttl = response
        .negative_ttl_from_soa()
        .unwrap_or(negative_ttl_without_soa)
        .min(max_negative_ttl);
    if ttl == 0 { None } else { Some(ttl) }
}

fn compute_cache_ttl_with_policy(
    response: &Message,
    max_positive_ttl: Option<u32>,
    cache_negative: bool,
    max_negative_ttl: u32,
    negative_ttl_without_soa: u32,
) -> Option<u32> {
    compute_positive_ttl_with_cap(response, max_positive_ttl).or_else(|| {
        compute_negative_ttl_with_policy(
            response,
            cache_negative,
            max_negative_ttl,
            negative_ttl_without_soa,
        )
    })
}

fn parse_cache_config(args: Option<Value>) -> Result<CacheConfig> {
    if let Some(args) = args {
        return serde_yaml_ng::from_value::<CacheConfig>(args)
            .map_err(|e| DnsError::plugin(format!("failed to parse cache config: {}", e)));
    }

    Ok(CacheConfig {
        size: None,
        lazy_cache_ttl: None,
        dump_file: None,
        dump_interval: None,
        short_circuit: None,
        cache_negative: None,
        max_negative_ttl: None,
        negative_ttl_without_soa: None,
        max_positive_ttl: None,
        ecs_in_key: None,
    })
}

fn validate_cache_config(config: &CacheConfig) -> Result<()> {
    if let Some(size) = config.size
        && size == 0
    {
        return Err(DnsError::plugin("cache size must be greater than 0"));
    }

    if config.dump_file.is_some()
        && let Some(interval) = config.dump_interval
        && interval == 0
    {
        return Err(DnsError::plugin(
            "cache dump_interval must be greater than 0 when dump_file is set",
        ));
    }

    if let Some(ttl) = config.lazy_cache_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache lazy_cache_ttl must be greater than 0",
        ));
    }

    if let Some(ttl) = config.max_negative_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache max_negative_ttl must be greater than 0",
        ));
    }

    if let Some(ttl) = config.max_positive_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache max_positive_ttl must be greater than 0",
        ));
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
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let cache_config = parse_cache_config(plugin_config.args.clone())?;
        validate_cache_config(&cache_config)?;
        self.build_cache(plugin_config.tag.clone(), cache_config, registry)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cache_config = parse_cache_quick_setup(param.as_deref().unwrap_or_default())?;
        validate_cache_config(&cache_config)?;
        self.build_cache(tag.to_string(), cache_config, registry)
    }
}

impl CacheFactory {
    fn build_cache(
        &self,
        tag: String,
        cache_config: CacheConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(Cache {
            cache_map: OnceCell::new(),
            tag,
            cache_negative: cache_config.cache_negative.unwrap_or(true),
            max_negative_ttl: cache_config
                .max_negative_ttl
                .unwrap_or(DEFAULT_MAX_NEGATIVE_TTL),
            negative_ttl_without_soa: cache_config
                .negative_ttl_without_soa
                .unwrap_or(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA),
            short_circuit: cache_config.short_circuit.unwrap_or(false),
            ecs_in_key: cache_config.ecs_in_key.unwrap_or(false),
            cache_size: cache_config.size.unwrap_or(DEFAULT_CACHE_SIZE),
            config: cache_config,
            updated_keys: Arc::new(AtomicU64::new(0)),
            dump_task_id: Mutex::new(None),
            cleanup_task_id: Mutex::new(None),
            api_register: registry.api_register(),
            lazy_refresh_inflight: Arc::new(Mutex::new(AHashSet::new())),
        })))
    }
}

fn parse_cache_quick_setup(raw: &str) -> Result<CacheConfig> {
    let mut config = CacheConfig {
        size: None,
        lazy_cache_ttl: None,
        dump_file: None,
        dump_interval: None,
        short_circuit: None,
        cache_negative: None,
        max_negative_ttl: None,
        negative_ttl_without_soa: None,
        max_positive_ttl: None,
        ecs_in_key: None,
    };

    for token in raw.split_whitespace() {
        if token == "short_circuit" {
            config.short_circuit = Some(true);
            continue;
        }

        let Some(value) = token.strip_prefix("short_circuit=") else {
            return Err(DnsError::plugin(format!(
                "unsupported cache quick setup token '{}'",
                token
            )));
        };

        config.short_circuit = Some(match value {
            "true" => true,
            "false" => false,
            _ => {
                return Err(DnsError::plugin(format!(
                    "invalid short_circuit value '{}', expected true or false",
                    value
                )));
            }
        });
    }

    Ok(config)
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use async_trait::async_trait;

    use super::*;
    use crate::plugin::PluginRegistry;
    use crate::plugin::executor::Executor;
    use crate::plugin::executor::sequence::chain::ChainProgram;
    use crate::proto::rdata::SOA;
    use crate::proto::{
        DNSClass, Edns, EdnsOption, Message, Name, Question, RData, Record, RecordType,
    };

    fn test_cache(config: CacheConfig) -> Cache {
        let cache_negative = config.cache_negative.unwrap_or(true);
        let max_negative_ttl = config.max_negative_ttl.unwrap_or(DEFAULT_MAX_NEGATIVE_TTL);
        let negative_ttl_without_soa = config
            .negative_ttl_without_soa
            .unwrap_or(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA);
        let cache_size = config.size.unwrap_or(DEFAULT_CACHE_SIZE);
        let ecs_in_key = config.ecs_in_key.unwrap_or(false);
        let short_circuit = config.short_circuit.unwrap_or(false);

        Cache {
            cache_map: OnceCell::new(),
            tag: "cache_test".to_string(),
            cache_negative,
            max_negative_ttl,
            negative_ttl_without_soa,
            short_circuit,
            ecs_in_key,
            config,
            updated_keys: Arc::new(AtomicU64::new(0)),
            cache_size,
            dump_task_id: Mutex::new(None),
            cleanup_task_id: Mutex::new(None),
            api_register: None,
            lazy_refresh_inflight: Arc::new(Mutex::new(AHashSet::new())),
        }
    }

    fn default_test_config() -> CacheConfig {
        CacheConfig {
            size: Some(128),
            lazy_cache_ttl: None,
            dump_file: None,
            dump_interval: None,
            short_circuit: Some(false),
            cache_negative: Some(true),
            max_negative_ttl: Some(DEFAULT_MAX_NEGATIVE_TTL),
            negative_ttl_without_soa: Some(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA),
            max_positive_ttl: None,
            ecs_in_key: None,
        }
    }

    #[test]
    fn parse_cache_quick_setup_supports_short_circuit() {
        let cfg = parse_cache_quick_setup("short_circuit=true").expect("quick setup should parse");
        assert_eq!(cfg.short_circuit, Some(true));
    }

    fn make_context(request: Message) -> DnsContext {
        DnsContext::new(
            "127.0.0.1:5300".parse::<SocketAddr>().unwrap(),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn make_request_with_query(name: &str, do_bit: bool, cd_bit: bool) -> Message {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        request.set_checking_disabled(cd_bit);

        let mut edns = Edns::new();
        edns.flags_mut().dnssec_ok = do_bit;
        request.set_edns(edns);

        request
    }

    fn add_ecs(request: &mut Message, subnet: &str) {
        let mut edns = request.edns().clone().unwrap_or_default();
        edns.insert(EdnsOption::Subnet(subnet.parse().unwrap()));
        request.set_edns(edns);
    }

    #[derive(Debug)]
    struct StubRefreshExecutor {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for StubRefreshExecutor {
        fn tag(&self) -> &str {
            "stub_refresh_executor"
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for StubRefreshExecutor {
        fn with_next(&self) -> bool {
            true
        }

        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Ok(ExecStep::Next)
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            next: Option<ExecutorNext>,
        ) -> Result<ExecStep> {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            let mut response = Message::new();
            response.set_rcode(Rcode::NoError);
            response.add_question(Question::new(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
                DNSClass::IN,
            ));
            response.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                55,
                RData::A(crate::proto::rdata::A(Ipv4Addr::new(9, 9, 9, 9))),
            ));
            context.set_response(response);
            continue_next!(next, context)
        }
    }

    #[test]
    fn cache_key_uses_normalized_domain_from_query_view() {
        let mut ctx_upper = make_context(make_request_with_query("Example.COM.", false, false));
        let mut ctx_lower = make_context(make_request_with_query("example.com", false, false));

        let key_upper = Cache::build_cache_key(&mut ctx_upper, true).unwrap();
        let key_lower = Cache::build_cache_key(&mut ctx_lower, true).unwrap();

        assert_eq!(key_upper.domain, "example.com");
        assert_eq!(key_upper, key_lower);
    }

    #[test]
    fn cache_key_separates_do_cd_and_ecs_when_enabled() {
        let mut req_base = make_request_with_query("example.com.", false, false);
        let req_do = make_request_with_query("example.com.", true, false);
        let req_cd = make_request_with_query("example.com.", false, true);

        add_ecs(&mut req_base, "192.0.2.0/24");
        let mut req_ecs_other = make_request_with_query("example.com.", false, false);
        add_ecs(&mut req_ecs_other, "192.0.3.0/24");

        let mut ctx_base = make_context(req_base);
        let mut ctx_do = make_context(req_do);
        let mut ctx_cd = make_context(req_cd);
        let mut ctx_ecs_other = make_context(req_ecs_other);

        let key_base = Cache::build_cache_key(&mut ctx_base, true).unwrap();
        let key_do = Cache::build_cache_key(&mut ctx_do, true).unwrap();
        let key_cd = Cache::build_cache_key(&mut ctx_cd, true).unwrap();
        let key_ecs_other = Cache::build_cache_key(&mut ctx_ecs_other, true).unwrap();

        assert_ne!(key_base, key_do);
        assert_ne!(key_base, key_cd);
        assert_ne!(key_base, key_ecs_other);
    }

    #[test]
    fn cache_key_ignores_ecs_when_disabled() {
        let mut req_ecs_a = make_request_with_query("example.com.", false, false);
        add_ecs(&mut req_ecs_a, "192.0.2.0/24");

        let mut req_ecs_b = make_request_with_query("example.com.", false, false);
        add_ecs(&mut req_ecs_b, "192.0.3.0/24");

        let mut ctx_ecs_a = make_context(req_ecs_a);
        let mut ctx_ecs_b = make_context(req_ecs_b);

        let key_ecs_a = Cache::build_cache_key(&mut ctx_ecs_a, false).unwrap();
        let key_ecs_b = Cache::build_cache_key(&mut ctx_ecs_b, false).unwrap();

        assert_eq!(key_ecs_a, key_ecs_b);
        assert!(key_ecs_a.ecs_scope.is_none());
        assert!(key_ecs_b.ecs_scope.is_none());
    }

    #[test]
    fn rewrite_response_ttls_skips_opt_record() {
        let mut response = Message::new();
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        edns.flags_mut().dnssec_ok = true;
        response.set_edns(edns);

        Cache::rewrite_message_ttls(&mut response, 42);

        assert_eq!(response.answers()[0].ttl(), 42);
        let edns = response.edns().as_ref().expect("edns should exist");
        assert_eq!(edns.udp_payload_size(), 1232);
        assert!(edns.flags().dnssec_ok);
    }

    #[test]
    fn negative_ttl_uses_soa_and_applies_max_cap() {
        let mut cfg = default_test_config();
        cfg.max_negative_ttl = Some(20);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NXDomain);
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                30,
            )),
        ));

        assert_eq!(cache.compute_negative_ttl(&response), Some(20));
    }

    #[test]
    fn negative_ttl_without_soa_uses_fallback() {
        let mut cfg = default_test_config();
        cfg.negative_ttl_without_soa = Some(45);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NXDomain);

        assert_eq!(cache.compute_negative_ttl(&response), Some(45));
    }

    #[test]
    fn negative_ttl_without_soa_zero_disables_negative_cache() {
        let mut cfg = default_test_config();
        cfg.negative_ttl_without_soa = Some(0);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NXDomain);

        assert_eq!(cache.compute_negative_ttl(&response), None);
    }

    #[test]
    fn servfail_is_not_cacheable() {
        let cache = test_cache(default_test_config());

        let mut response = Message::new();
        response.set_rcode(Rcode::ServFail);

        assert_eq!(cache.compute_cache_ttl(&response), None);
    }

    #[tokio::test]
    async fn truncated_response_is_not_cached() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.set_truncated(true);
        context.set_response(response);

        cache.execute_with_next(&mut context, None).await.unwrap();

        let cache_map = cache.cache_map.get().unwrap();
        assert_eq!(cache_map.len(), 0);
    }

    #[tokio::test]
    async fn cache_hit_sets_outbound_message_response() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init().await;

        let mut request = make_request_with_query("example.com.", false, false);
        request.set_id(7);
        let mut context = make_context(request.clone());
        let key = Cache::build_cache_key(&mut context, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        cache.update_cache_entry(cache.cache_map.get().unwrap(), key, response, 120);

        let lookup = cache
            .try_cache_hit(&mut context, cache.cache_map.get().unwrap())
            .expect("cache lookup should exist");
        assert_eq!(lookup.hit_kind, Some(CacheHitKind::Fresh));
        assert!(context.response().is_some_and(|response| {
            response.has_answer_ip(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        }));
        let response = context.response().expect("cache hit should set response");
        assert_eq!(response.id(), 7);
        assert_eq!(response.answers().len(), 1);
        assert!(
            (119..=120).contains(&response.answers()[0].ttl()),
            "fresh cache hit should preserve the original TTL or decrement by at most one second"
        );
    }

    #[tokio::test]
    async fn lazy_cache_hit_returns_stale_response_with_lazy_ttl() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        let mut cache = test_cache(cfg);
        let _ = cache.init().await;

        let mut request = make_request_with_query("example.com.", false, false);
        request.set_id(9);
        let mut context = make_context(request);
        let key = Cache::build_cache_key(&mut context, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.cache_map.get().unwrap().insert_or_update_with_meta(
            key,
            Arc::new(CacheItem::new(response, 120, now.saturating_sub(1_000))),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let lookup = cache
            .try_cache_hit(&mut context, cache.cache_map.get().unwrap())
            .expect("cache lookup should exist");
        assert_eq!(lookup.hit_kind, Some(CacheHitKind::Stale));
        let response = context
            .response()
            .expect("stale cache hit should populate response");
        assert_eq!(response.id(), 9);
        assert_eq!(response.answers()[0].ttl(), 30);
    }

    #[tokio::test]
    async fn lazy_cache_ttl_does_not_shorten_fresh_window() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        let mut cache = test_cache(cfg);
        let _ = cache.init().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let key = Cache::build_cache_key(&mut context, false).unwrap();
        cache.update_cache_entry(cache.cache_map.get().unwrap(), key.clone(), response, 120);

        let stored = cache
            .cache_map
            .get()
            .unwrap()
            .get_retained_cloned(&key, AppClock::elapsed_millis(), 0)
            .expect("entry should be present");
        assert_eq!(
            stored
                .expire_at_ms
                .saturating_sub(stored.value.fresh_until_ms)
                / 1000,
            0
        );
        assert_eq!(
            stored
                .value
                .fresh_until_ms
                .saturating_sub(stored.cache_time_ms)
                / 1000,
            120
        );
    }

    #[tokio::test]
    async fn stale_hit_triggers_only_one_background_refresh() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init().await;

        let calls = Arc::new(AtomicUsize::new(0));
        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(StubRefreshExecutor {
                calls: calls.clone(),
            }));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context_a = make_context(make_request_with_query("example.com.", false, false));
        let mut context_b = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context_a, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.cache_map.get().unwrap().insert_or_update_with_meta(
            key.clone(),
            Arc::new(CacheItem::new(response, 120, now.saturating_sub(1_000))),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let _ = cache
            .execute_with_next(&mut context_a, Some(next.clone()))
            .await
            .unwrap();
        let _ = cache
            .execute_with_next(&mut context_b, Some(next))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        let stored = cache
            .cache_map
            .get()
            .unwrap()
            .get_retained_cloned(&key, AppClock::elapsed_millis(), 0)
            .expect("entry should exist");
        assert!(
            stored
                .value
                .resp
                .has_answer_ip(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
    }

    #[test]
    fn validate_config_rejects_zero_dump_interval_when_dump_file_is_set() {
        let cfg = CacheConfig {
            size: Some(128),
            lazy_cache_ttl: None,
            dump_file: Some("cache.dump".to_string()),
            dump_interval: Some(0),
            short_circuit: Some(false),
            cache_negative: Some(true),
            max_negative_ttl: Some(60),
            negative_ttl_without_soa: Some(60),
            max_positive_ttl: None,
            ecs_in_key: None,
        };

        assert!(validate_cache_config(&cfg).is_err());
    }
}
