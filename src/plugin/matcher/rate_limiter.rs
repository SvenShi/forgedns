/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `rate_limiter` matcher plugin.
//!
//! Token-bucket matcher keyed by masked client IP.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
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
    qps: Option<f64>,
    burst: Option<u32>,
    mask4: Option<u8>,
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
    buckets: Arc<DashMap<IpAddr, Bucket>>,
    cleanup_started: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct RateLimiterFactory;

register_plugin_factory!("rate_limiter", RateLimiterFactory {});

impl PluginFactory for RateLimiterFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let cfg = parse_config(plugin_config.args.clone())?;
        validate_cfg(&cfg)
    }

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
            buckets: Arc::new(DashMap::new()),
            cleanup_started: AtomicBool::new(false),
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
            buckets: Arc::new(DashMap::new()),
            cleanup_started: AtomicBool::new(false),
        })))
    }
}

#[async_trait]
impl Plugin for RateLimiter {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        if self.cleanup_started.swap(true, Ordering::Relaxed) {
            return;
        }

        let buckets = self.buckets.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(CLEANUP_INTERVAL_SECS);
            loop {
                tokio::time::sleep(interval).await;
                let now = AppClock::elapsed_millis();
                buckets.retain(|_, bucket| now.saturating_sub(bucket.last_ms) <= STALE_TIMEOUT_MS);
            }
        });
    }

    async fn destroy(&self) {}
}

impl Matcher for RateLimiter {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let masked = mask_ip(context.src_addr.ip(), self.mask4, self.mask6);
        let Some(masked) = masked else {
            return true;
        };

        let now = AppClock::elapsed_millis();

        if let Some(mut entry) = self.buckets.get_mut(&masked) {
            let mut bucket = *entry;
            let elapsed = now.saturating_sub(bucket.last_ms) as f64 / 1000.0;
            if elapsed > 0.0 {
                bucket.tokens = (bucket.tokens + elapsed * self.qps).min(self.burst);
                bucket.last_ms = now;
            }

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                *entry = bucket;
                true
            } else {
                *entry = bucket;
                false
            }
        } else {
            let tokens = (self.burst - 1.0).max(0.0);
            self.buckets.insert(
                masked,
                Bucket {
                    tokens,
                    last_ms: now,
                },
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
