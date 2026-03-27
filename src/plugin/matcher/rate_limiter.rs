/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `rate_limiter` matcher plugin.
//!
//! Token-bucket matcher keyed by masked client IP.
//!
//! Matching semantics:
//! - each masked IP owns one token bucket.
//! - matcher returns `true` when one token can be consumed.
//! - matcher returns `false` when bucket is exhausted.
//!
//! Configuration controls:
//! - `qps`: refill rate per second.
//! - `burst`: bucket capacity.
//! - `mask4`/`mask6`: aggregation granularity for IPv4/IPv6 clients.
//!
//! Lifecycle:
//! - `init` starts periodic cleanup for stale buckets.
//! - `destroy` stops cleanup task and releases background resources.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::task_center;
use crate::core::ttl_cache::TtlCache;
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const DEFAULT_QPS: f64 = 20.0;
const DEFAULT_BURST: f64 = 40.0;
const DEFAULT_MASK4: u8 = 32;
const DEFAULT_MASK6: u8 = 48;
const STALE_TIMEOUT_MS: u64 = 5 * 60 * 1000;
const CLEANUP_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Deserialize, Default)]
struct RateLimiterConfig {
    /// Refill rate in queries per second.
    qps: Option<f64>,
    /// Maximum burst size in tokens.
    burst: Option<u32>,
    /// IPv4 prefix length for client key aggregation.
    mask4: Option<u8>,
    /// IPv6 prefix length for client key aggregation.
    mask6: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

#[derive(Debug)]
struct RateLimiter {
    tag: String,
    qps: f64,
    burst: f64,
    mask4: u8,
    mask6: u8,
    buckets: TtlCache<IpAddr, Bucket>,
    cleanup_started: AtomicBool,
    cleanup_task_id: Mutex<Option<u64>>,
}

#[derive(Debug, Clone)]
pub struct RateLimiterFactory;

register_plugin_factory!("rate_limiter", RateLimiterFactory {});

impl PluginFactory for RateLimiterFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;
        validate_cfg(&cfg)?;

        Ok(UninitializedPlugin::Matcher(Box::new(RateLimiter {
            tag: plugin_config.tag.clone(),
            qps: cfg.qps.unwrap_or(DEFAULT_QPS),
            burst: cfg.burst.unwrap_or(DEFAULT_BURST as u32) as f64,
            mask4: cfg.mask4.unwrap_or(DEFAULT_MASK4),
            mask6: cfg.mask6.unwrap_or(DEFAULT_MASK6),
            buckets: TtlCache::with_capacity(4096),
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: Mutex::new(None),
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let cfg = parse_quick_setup(param)?;
        validate_cfg(&cfg)?;

        Ok(UninitializedPlugin::Matcher(Box::new(RateLimiter {
            tag: tag.to_string(),
            qps: cfg.qps.unwrap_or(DEFAULT_QPS),
            burst: cfg.burst.unwrap_or(DEFAULT_BURST as u32) as f64,
            mask4: cfg.mask4.unwrap_or(DEFAULT_MASK4),
            mask6: cfg.mask6.unwrap_or(DEFAULT_MASK6),
            buckets: TtlCache::with_capacity(4096),
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: Mutex::new(None),
        })))
    }
}

#[async_trait]
impl Plugin for RateLimiter {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        if self.cleanup_started.swap(true, Ordering::Relaxed) {
            return Ok(());
        }

        let buckets = self.buckets.clone();
        let task_id = task_center::spawn_fixed(
            format!("rate_limiter:{}:cleanup", self.tag),
            Duration::from_secs(CLEANUP_INTERVAL_SECS),
            move || {
                let buckets = buckets.clone();
                async move {
                    let now = AppClock::elapsed_millis();
                    while buckets.remove_expired_batch(now, 2048) > 0 {}
                }
            },
        );
        if let Ok(mut guard) = self.cleanup_task_id.lock() {
            *guard = Some(task_id);
        }
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        let task_id = if let Ok(mut guard) = self.cleanup_task_id.lock() {
            guard.take()
        } else {
            None
        };
        if let Some(task_id) = task_id {
            task_center::stop_task(task_id).await;
        }
        self.cleanup_started.store(false, Ordering::Relaxed);
        Ok(())
    }
}

impl Matcher for RateLimiter {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let masked = mask_ip(context.peer_addr().ip(), self.mask4, self.mask6);
        let Some(masked) = masked else {
            return true;
        };

        let now = AppClock::elapsed_millis();
        let expire_at_ms = now.saturating_add(STALE_TIMEOUT_MS);

        if let Some(entry) = self.buckets.get_fresh_cloned(&masked, now, 0) {
            let mut bucket = entry.value;
            let elapsed = now.saturating_sub(bucket.last_ms) as f64 / 1000.0;
            if elapsed > 0.0 {
                bucket.tokens = (bucket.tokens + elapsed * self.qps).min(self.burst);
                bucket.last_ms = now;
            }

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                self.buckets
                    .insert_or_update(masked, bucket, now, expire_at_ms);
                true
            } else {
                self.buckets
                    .insert_or_update(masked, bucket, now, expire_at_ms);
                false
            }
        } else {
            let tokens = (self.burst - 1.0).max(0.0);
            self.buckets.insert_or_update(
                masked,
                Bucket {
                    tokens,
                    last_ms: now,
                },
                now,
                expire_at_ms,
            );
            true
        }
    }
}

fn parse_config(args: Option<serde_yml::Value>) -> DnsResult<RateLimiterConfig> {
    let Some(args) = args else {
        return Ok(RateLimiterConfig::default());
    };

    serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse rate_limiter config: {}", e)))
}

fn parse_quick_setup(param: Option<String>) -> DnsResult<RateLimiterConfig> {
    let Some(raw) = param else {
        return Ok(RateLimiterConfig::default());
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(RateLimiterConfig::default());
    }

    let parts: Vec<&str> = raw.split_whitespace().collect();
    let mut cfg = RateLimiterConfig::default();

    if let Some(v) = parts.first() {
        cfg.qps =
            Some(v.parse::<f64>().map_err(|e| {
                DnsError::plugin(format!("invalid rate_limiter qps '{}': {}", v, e))
            })?);
    }
    if let Some(v) = parts.get(1) {
        cfg.burst =
            Some(v.parse::<u32>().map_err(|e| {
                DnsError::plugin(format!("invalid rate_limiter burst '{}': {}", v, e))
            })?);
    }
    if let Some(v) = parts.get(2) {
        cfg.mask4 =
            Some(v.parse::<u8>().map_err(|e| {
                DnsError::plugin(format!("invalid rate_limiter mask4 '{}': {}", v, e))
            })?);
    }
    if let Some(v) = parts.get(3) {
        cfg.mask6 =
            Some(v.parse::<u8>().map_err(|e| {
                DnsError::plugin(format!("invalid rate_limiter mask6 '{}': {}", v, e))
            })?);
    }

    Ok(cfg)
}

fn validate_cfg(cfg: &RateLimiterConfig) -> DnsResult<()> {
    let qps = cfg.qps.unwrap_or(DEFAULT_QPS);
    if qps <= 0.0 {
        return Err(DnsError::plugin("rate_limiter qps must be > 0"));
    }

    let burst = cfg.burst.unwrap_or(DEFAULT_BURST as u32);
    if burst == 0 {
        return Err(DnsError::plugin("rate_limiter burst must be > 0"));
    }

    let mask4 = cfg.mask4.unwrap_or(DEFAULT_MASK4);
    let mask6 = cfg.mask6.unwrap_or(DEFAULT_MASK6);
    if mask4 > 32 {
        return Err(DnsError::plugin(
            "rate_limiter mask4 must be in range 0..=32",
        ));
    }
    if mask6 > 128 {
        return Err(DnsError::plugin(
            "rate_limiter mask6 must be in range 0..=128",
        ));
    }

    Ok(())
}

fn mask_ip(ip: IpAddr, mask4: u8, mask6: u8) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(v4) => {
            if mask4 == 0 {
                return Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            }
            let raw = u32::from(v4);
            let mask = if mask4 == 32 {
                u32::MAX
            } else {
                (!0u32) << (32 - mask4)
            };
            Some(IpAddr::V4(Ipv4Addr::from(raw & mask)))
        }
        IpAddr::V6(v6) => {
            let mut bytes = v6.octets();
            let mut remaining = mask6;
            for byte in &mut bytes {
                if remaining >= 8 {
                    remaining -= 8;
                    continue;
                }
                if remaining == 0 {
                    *byte = 0;
                } else {
                    let keep = 8 - remaining;
                    *byte &= 0xFF << keep;
                    remaining = 0;
                }
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::Message;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_context(ip: Ipv4Addr) -> DnsContext {
        DnsContext::new(
            SocketAddr::from((ip, 5300)),
            Message::new(),
            test_registry(),
        )
    }

    #[test]
    fn test_parse_quick_setup_validation() {
        assert!(parse_quick_setup(None).is_ok());
        let invalid = parse_quick_setup(Some("0".to_string())).expect("parse should succeed");
        assert!(validate_cfg(&invalid).is_err());
        let valid = parse_quick_setup(Some("10".to_string())).expect("parse should succeed");
        assert!(validate_cfg(&valid).is_ok());
    }

    #[test]
    fn test_rate_limiter_consumes_tokens_and_blocks_when_exhausted() {
        let limiter = RateLimiter {
            tag: "rl".to_string(),
            qps: 1.0,
            burst: 1.0,
            mask4: 32,
            mask6: 128,
            buckets: TtlCache::with_capacity(16),
            cleanup_started: AtomicBool::new(false),
            cleanup_task_id: Mutex::new(None),
        };

        let mut ctx = make_context(Ipv4Addr::new(10, 0, 0, 1));
        assert!(limiter.is_match(&mut ctx));
        assert!(!limiter.is_match(&mut ctx));
    }

    #[test]
    fn test_mask_ip_respects_ipv4_and_ipv6_masks() {
        let v4 = mask_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 99)), 24, 64)
            .expect("mask should return value");
        assert_eq!(v4, IpAddr::V4(Ipv4Addr::new(192, 168, 10, 0)));

        let v6 = mask_ip(IpAddr::V6("2001:db8:abcd:1234::1".parse().unwrap()), 24, 64)
            .expect("mask should return value");
        assert_eq!(v6, "2001:db8:abcd:1234::".parse::<IpAddr>().unwrap());
    }
}
