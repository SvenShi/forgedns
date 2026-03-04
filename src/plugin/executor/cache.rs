/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS response cache executor plugin.
//!
//! Provides an in-memory cache keyed by normalized query name + query context
//! (qtype/qclass/DO/CD and optional ECS scope). Cache entries expire by TTL and are
//! periodically cleaned up.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::ttl_cache::TtlCache;
use crate::plugin::executor::{ExecResult, ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::sleep;
use tracing::{Level, debug, event_enabled, warn};

mod key;
mod persistence;

use self::key::{CacheKey, build_cache_key as build_cache_key_internal};
use self::persistence::{dump_cache_to_file, load_cache_from_file};

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

type CacheMap = TtlCache<CacheKey, CacheItem>;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CacheItem {
    /// Cached DNS response message.
    resp: Message,

    /// TTL used for this cached entry (seconds).
    ttl: u32,
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
    ) {
        tokio::spawn(async move {
            let interval = Duration::from_secs(dump_interval);
            loop {
                sleep(interval).await;
                let changed = updated_keys.swap(0, Ordering::Relaxed);
                if changed < MINIMUM_CHANGES_TO_DUMP {
                    // Keep sparse updates accumulated so low-write workloads still persist
                    // eventually without triggering dump every interval.
                    if changed > 0 {
                        updated_keys.fetch_add(changed, Ordering::Relaxed);
                    }
                    continue;
                }
                if let Err(e) = dump_cache_to_file(&cache_map, &dump_path).await {
                    warn!("Failed to dump cache to {}: {}", dump_path, e);
                }
            }
        });
    }

    fn spawn_cleanup_task(&self, cache_map: CacheMap, cache_size: usize) {
        tokio::spawn(async move {
            let cleanup_interval = Duration::from_secs(DEFAULT_CLEANUP_INTERVAL);
            loop {
                sleep(cleanup_interval).await;

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
                    continue;
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
                    continue;
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
            if record.record_type() == RecordType::OPT {
                continue;
            }
            record.set_ttl(remaining_ttl);
        }
    }

    #[inline]
    fn build_cache_key(context: &mut DnsContext, ecs_in_key: bool) -> Option<CacheKey> {
        build_cache_key_internal(context, ecs_in_key)
    }

    #[inline]
    #[hotpath::measure]
    fn try_cache_hit(
        &self,
        context: &mut DnsContext,
        cache_map: &CacheMap,
    ) -> (Option<CacheKey>, bool) {
        let Some(key) = Self::build_cache_key(context, self.ecs_in_key) else {
            return (None, false);
        };

        let now = AppClock::elapsed_millis();

        if let Some(item) = cache_map.get_fresh_cloned(&key, now, LAST_ACCESS_TOUCH_INTERVAL_MS) {
            let remaining_ttl = item.expire_at_ms.saturating_sub(now).saturating_div(1000) as u32;
            let mut resp = item.value.resp;
            resp.set_id(context.request.id());
            Self::update_response_ttl(&mut resp, remaining_ttl);
            context.response = Some(resp);

            debug!(
                "cache hit: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                key.domain,
                key.record_type,
                key.dns_class,
                key.do_bit,
                key.cd_bit,
                key.ecs_scope.is_some()
            );
            return (None, true);
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
            return (Some(key), false);
        }

        debug!(
            "cache miss: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
            key.domain,
            key.record_type,
            key.dns_class,
            key.do_bit,
            key.cd_bit,
            key.ecs_scope.is_some()
        );

        (Some(key), false)
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
        if response.response_code() != ResponseCode::NoError || response.answers().is_empty() {
            return None;
        }

        let ttl = response.answers().iter().map(|answer| answer.ttl()).min()?;
        let ttl = if let Some(max) = self.config.max_positive_ttl {
            ttl.min(max)
        } else {
            ttl
        };

        if ttl == 0 { None } else { Some(ttl) }
    }

    #[inline]
    fn extract_negative_ttl_from_soa(response: &Message) -> Option<u32> {
        let mut best: Option<u32> = None;

        for record in response.name_servers() {
            let RData::SOA(soa) = record.data() else {
                continue;
            };

            let ttl = record.ttl().min(soa.minimum());
            best = Some(match best {
                Some(existing) => existing.min(ttl),
                None => ttl,
            });
        }

        best
    }

    #[inline]
    fn compute_negative_ttl(&self, response: &Message) -> Option<u32> {
        if !self.cache_negative {
            return None;
        }

        let rcode = response.response_code();
        let is_nxdomain = rcode == ResponseCode::NXDomain;
        let is_nodata = rcode == ResponseCode::NoError && response.answers().is_empty();

        if !is_nxdomain && !is_nodata {
            return None;
        }

        let mut ttl = if let Some(soa_ttl) = Self::extract_negative_ttl_from_soa(response) {
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
    fn compute_expire_time(&self, now: u64, ttl: u32) -> u64 {
        let effective_ttl = self.config.lazy_cache_ttl.unwrap_or(ttl);
        now.saturating_add(effective_ttl as u64 * 1000)
    }

    #[inline]
    #[hotpath::measure]
    fn update_cache_entry(&self, cache_map: &CacheMap, key: CacheKey, response: Message, ttl: u32) {
        let now = AppClock::elapsed_millis();
        let expire_time = self.compute_expire_time(now, ttl);
        debug!(
            "cached: domain={}, type={:?}, class={:?}, ttl={}",
            key.domain, key.record_type, key.dns_class, ttl
        );
        cache_map.insert_or_update(
            key,
            CacheItem {
                resp: response,
                ttl,
            },
            now,
            expire_time,
        );
        self.updated_keys.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl Plugin for Cache {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        let cache_map = CacheMap::with_capacity(self.cache_size);

        let _ = self.cache_map.set(cache_map.clone());

        if let Some(dump_file) = &self.config.dump_file {
            self.spawn_load_task(cache_map.clone(), dump_file.clone(), self.ecs_in_key);
            let dump_interval = self.config.dump_interval.unwrap_or(DEFAULT_DUMP_INTERVAL);
            self.spawn_dump_task(
                cache_map.clone(),
                dump_file.clone(),
                dump_interval,
                self.updated_keys.clone(),
            );
        }

        self.spawn_cleanup_task(cache_map, self.cache_size);
    }

    async fn destroy(&self) {
        if let Some(dump_file) = &self.config.dump_file
            && let Some(cache_map) = self.cache_map.get()
            && let Err(e) = dump_cache_to_file(cache_map, dump_file).await
        {
            warn!("Failed to dump cache to {}: {}", dump_file, e);
        }
    }
}

#[async_trait]
impl Executor for Cache {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let Some(cache_map) = self.cache_map.get() else {
            return Ok(ExecStep::Next);
        };

        let (miss_key, cache_hit) = self.try_cache_hit(context, cache_map);

        if self.should_short_circuit(cache_hit) {
            return Ok(ExecStep::Stop);
        }

        // Cache hit without short-circuit keeps chain running but does not
        // rewrite cache in post stage. This avoids TTL drift on repeated hits.
        if cache_hit {
            return Ok(ExecStep::Next);
        }

        if let Some(key) = miss_key {
            return Ok(ExecStep::NextWithPost(Some(Box::new(key) as ExecState)));
        }

        Ok(ExecStep::Next)
    }

    #[hotpath::measure]
    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> ExecResult {
        let Some(cache_map) = self.cache_map.get() else {
            return Ok(());
        };

        let cache_key = state
            .and_then(|boxed| boxed.downcast::<CacheKey>().ok())
            .map(|boxed| *boxed);

        if let (Some(response), Some(key)) = (&context.response, cache_key) {
            if response.truncated() {
                return Ok(());
            }

            if let Some(ttl) = self.compute_cache_ttl(response) {
                self.update_cache_entry(cache_map, key, response.clone(), ttl);
            }
        }

        Ok(())
    }
}

fn parse_cache_config(args: Option<serde_yml::Value>) -> Result<CacheConfig> {
    if let Some(args) = args {
        return serde_yml::from_value::<CacheConfig>(args)
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
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let config = parse_cache_config(plugin_config.args.clone())?;
        validate_cache_config(&config)
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cache_config = parse_cache_config(plugin_config.args.clone())?;
        validate_cache_config(&cache_config)?;

        Ok(UninitializedPlugin::Executor(Box::new(Cache {
            cache_map: OnceCell::new(),
            tag: plugin_config.tag.clone(),
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
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginRegistry;
    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::{Ipv4Addr, SocketAddr};

    fn test_cache(config: CacheConfig) -> Cache {
        let cache_negative = config.cache_negative.unwrap_or(true);
        let max_negative_ttl = config.max_negative_ttl.unwrap_or(DEFAULT_MAX_NEGATIVE_TTL);
        let negative_ttl_without_soa = config
            .negative_ttl_without_soa
            .unwrap_or(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA);
        let cache_size = config.size.unwrap_or(DEFAULT_CACHE_SIZE);
        let ecs_in_key = config.ecs_in_key.unwrap_or(false);

        Cache {
            cache_map: OnceCell::new(),
            tag: "cache_test".to_string(),
            cache_negative,
            max_negative_ttl,
            negative_ttl_without_soa,
            short_circuit: false,
            ecs_in_key,
            config,
            updated_keys: Arc::new(AtomicU64::new(0)),
            cache_size,
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

    fn make_context(request: Message) -> DnsContext {
        DnsContext {
            src_addr: "127.0.0.1:5300".parse::<SocketAddr>().unwrap(),
            request,
            response: None,
            exec_flow_state: crate::core::context::ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            query_view: None,
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    fn make_request_with_query(name: &str, do_bit: bool, cd_bit: bool) -> Message {
        let mut request = Message::new();
        request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        request.set_checking_disabled(cd_bit);

        let mut edns = Edns::new();
        edns.flags_mut().dnssec_ok = do_bit;
        request.set_edns(edns);

        request
    }

    fn add_ecs(request: &mut Message, subnet: &str) {
        let mut edns = request.extensions().clone().unwrap_or_else(Edns::new);
        edns.options_mut()
            .insert(EdnsOption::Subnet(subnet.parse().unwrap()));
        request.set_edns(edns);
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
    fn update_response_ttl_skips_opt_record() {
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        response.add_additional(Record::from_rdata(
            Name::root(),
            123,
            RData::OPT(hickory_proto::rr::rdata::OPT::default()),
        ));

        Cache::update_response_ttl(&mut response, 42);

        assert_eq!(response.answers()[0].ttl(), 42);
        assert_eq!(response.additionals()[0].ttl(), 123);
    }

    #[test]
    fn negative_ttl_uses_soa_and_applies_max_cap() {
        let mut cfg = default_test_config();
        cfg.max_negative_ttl = Some(20);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_response_code(ResponseCode::NXDomain);
        response.add_name_server(Record::from_rdata(
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
        response.set_response_code(ResponseCode::NXDomain);

        assert_eq!(cache.compute_negative_ttl(&response), Some(45));
    }

    #[test]
    fn negative_ttl_without_soa_zero_disables_negative_cache() {
        let mut cfg = default_test_config();
        cfg.negative_ttl_without_soa = Some(0);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_response_code(ResponseCode::NXDomain);

        assert_eq!(cache.compute_negative_ttl(&response), None);
    }

    #[test]
    fn servfail_is_not_cacheable() {
        let cache = test_cache(default_test_config());

        let mut response = Message::new();
        response.set_response_code(ResponseCode::ServFail);

        assert_eq!(cache.compute_cache_ttl(&response), None);
    }

    #[tokio::test]
    async fn truncated_response_is_not_cached() {
        let mut cache = test_cache(default_test_config());
        cache.init().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let state = match cache.execute(&mut context).await.unwrap() {
            ExecStep::NextWithPost(state) => state,
            other => panic!("unexpected execute step: {:?}", other),
        };

        let mut response = Message::new();
        response.set_response_code(ResponseCode::NoError);
        response.set_truncated(true);
        context.response = Some(response);

        cache.post_execute(&mut context, state).await.unwrap();

        let cache_map = cache.cache_map.get().unwrap();
        assert_eq!(cache_map.len(), 0);
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
