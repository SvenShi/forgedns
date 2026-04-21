/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `nftset` executor plugin.
//!
//! Writes response IP addresses into nftables sets via the embedded Rust
//! netlink backend.
//!
//! Operational model:
//! - extracts unique A/AAAA addresses from response answers.
//! - converts addresses to configured CIDR prefixes (`mask4`/`mask6`).
//! - enqueues batched writes to a dedicated background writer thread.
//!
//! Hot-path and failure semantics:
//! - DNS path is best-effort and non-blocking (`try_send`); full queue drops
//!   side-effects instead of stalling request processing.
//! - when writer/backend disconnects, plugin disables itself to avoid repeated
//!   errors and extra overhead.
//! - on non-Linux platforms this plugin degrades to no-op behavior.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use ripset::{IpCidr, nftset_add};
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use tracing::warn;

#[cfg(target_os = "linux")]
const NFTSET_WRITER_QUEUE_SIZE: usize = 256;

#[derive(Debug, Clone, Deserialize, Default)]
struct NftSetConfig {
    /// Legacy IPv4 table family (for quick setup compatibility).
    table_family4: Option<String>,
    /// Legacy IPv6 table family (for quick setup compatibility).
    table_family6: Option<String>,
    /// Legacy IPv4 table name (for quick setup compatibility).
    table_name4: Option<String>,
    /// Legacy IPv6 table name (for quick setup compatibility).
    table_name6: Option<String>,
    /// Legacy IPv4 set name (for quick setup compatibility).
    set_name4: Option<String>,
    /// Legacy IPv6 set name (for quick setup compatibility).
    set_name6: Option<String>,
    /// Legacy IPv4 prefix length.
    mask4: Option<u8>,
    /// Legacy IPv6 prefix length.
    mask6: Option<u8>,

    /// Structured IPv4 nftset target arguments.
    ipv4: Option<NftSetArgs>,
    /// Structured IPv6 nftset target arguments.
    ipv6: Option<NftSetArgs>,
}

#[derive(Debug, Clone, Deserialize)]
struct NftSetArgs {
    /// nftables table family, e.g. `ip` or `ip6`.
    table_family: String,
    /// nftables table name.
    table_name: String,
    /// nftables set name.
    set_name: String,
    /// Prefix length used when writing matched addresses.
    mask: Option<u8>,
}

#[derive(Debug, Clone)]
struct ResolvedSet {
    table_family: String,
    table_name: String,
    set_name: String,
    mask: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct IpPrefix {
    addr: IpAddr,
    mask: u8,
}

#[derive(Debug)]
struct NftSetExecutor {
    tag: String,
    ipv4: Option<ResolvedSet>,
    ipv6: Option<ResolvedSet>,
    enabled: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    writer: SyncSender<NftSetBatch>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct NftSetBatch {
    ipv4_prefixes: Vec<IpPrefix>,
    ipv6_prefixes: Vec<IpPrefix>,
}

#[async_trait]
impl Plugin for NftSetExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        self.enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            // Wake the writer thread if blocked on recv so it can stop.
            let _ = self.writer.try_send(NftSetBatch {
                ipv4_prefixes: Vec::new(),
                ipv6_prefixes: Vec::new(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl Executor for NftSetExecutor {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(ExecStep::Next);
        }

        let Some(response) = context.response() else {
            return Ok(ExecStep::Next);
        };
        let answers = response.answers();
        if answers.is_empty() {
            return Ok(ExecStep::Next);
        }

        let mut ipv4_prefixes = AHashSet::new();
        let mut ipv6_prefixes = AHashSet::new();

        for answer in answers {
            if let Some(ip) = answer.ip_addr() {
                match ip {
                    IpAddr::V4(v4) => {
                        if let Some(set) = self.ipv4.as_ref() {
                            ipv4_prefixes.insert(IpPrefix {
                                addr: IpAddr::V4(v4),
                                mask: set.mask,
                            });
                        }
                    }
                    IpAddr::V6(v6) => {
                        if let Some(set) = self.ipv6.as_ref() {
                            ipv6_prefixes.insert(IpPrefix {
                                addr: IpAddr::V6(v6),
                                mask: set.mask,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if !ipv4_prefixes.is_empty() || !ipv6_prefixes.is_empty() {
                let batch = NftSetBatch {
                    ipv4_prefixes: ipv4_prefixes.into_iter().collect(),
                    ipv6_prefixes: ipv6_prefixes.into_iter().collect(),
                };
                if let Err(e) = self.writer.try_send(batch) {
                    match e {
                        TrySendError::Full(_) => {
                            // Best-effort side effect: dropping write preserves DNS path latency.
                        }
                        TrySendError::Disconnected(_) => {
                            warn!(
                                plugin = %self.tag,
                                "nftset writer disconnected, disabling plugin"
                            );
                            self.enabled.store(false, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = ipv4_prefixes;
            let _ = ipv6_prefixes;
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct NftSetFactory;

register_plugin_factory!("nftset", NftSetFactory {});

impl PluginFactory for NftSetFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let (ipv4, ipv6) = resolve_sets(&cfg)?;

        #[cfg(target_os = "linux")]
        let enabled = Arc::new(AtomicBool::new(true));
        #[cfg(target_os = "linux")]
        let writer = spawn_nftset_writer(
            plugin_config.tag.as_str(),
            enabled.clone(),
            ipv4.clone(),
            ipv6.clone(),
        )?;

        #[cfg(not(target_os = "linux"))]
        let enabled = Arc::new(AtomicBool::new(true));

        Ok(UninitializedPlugin::Executor(Box::new(NftSetExecutor {
            tag: plugin_config.tag.clone(),
            ipv4,
            ipv6,
            enabled,
            #[cfg(target_os = "linux")]
            writer,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let raw = param.unwrap_or_default();
        let mut ipv4 = None;
        let mut ipv6 = None;

        for field in raw.split_whitespace() {
            let parts: Vec<&str> = field.split(',').collect();
            if parts.len() != 5 {
                return Err(DnsError::plugin(format!(
                    "invalid nftset quick setup token '{}', expected family,table,set,type,mask",
                    field
                )));
            }
            let mask = parts[4].parse::<u8>().map_err(|e| {
                DnsError::plugin(format!("invalid nftset mask '{}': {}", parts[4], e))
            })?;
            let set = ResolvedSet {
                table_family: parts[0].to_string(),
                table_name: parts[1].to_string(),
                set_name: parts[2].to_string(),
                mask,
            };
            validate_set(&set, parts[3])?;
            match parts[3] {
                "ipv4_addr" => ipv4 = Some(set),
                "ipv6_addr" => ipv6 = Some(set),
                _ => {}
            }
        }

        #[cfg(target_os = "linux")]
        let enabled = Arc::new(AtomicBool::new(true));
        #[cfg(target_os = "linux")]
        let writer = spawn_nftset_writer(tag, enabled.clone(), ipv4.clone(), ipv6.clone())?;

        #[cfg(not(target_os = "linux"))]
        let enabled = Arc::new(AtomicBool::new(true));

        Ok(UninitializedPlugin::Executor(Box::new(NftSetExecutor {
            tag: tag.to_string(),
            ipv4,
            ipv6,
            enabled,
            #[cfg(target_os = "linux")]
            writer,
        })))
    }
}

fn parse_config(args: Option<Value>) -> Result<NftSetConfig> {
    let Some(args) = args else {
        return Ok(NftSetConfig::default());
    };

    serde_yaml_ng::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse nftset config: {}", e)))
}

fn resolve_sets(cfg: &NftSetConfig) -> Result<(Option<ResolvedSet>, Option<ResolvedSet>)> {
    let mut ipv4 = cfg.ipv4.as_ref().map(|v| ResolvedSet {
        table_family: v.table_family.clone(),
        table_name: v.table_name.clone(),
        set_name: v.set_name.clone(),
        mask: v.mask.unwrap_or(24),
    });

    let mut ipv6 = cfg.ipv6.as_ref().map(|v| ResolvedSet {
        table_family: v.table_family.clone(),
        table_name: v.table_name.clone(),
        set_name: v.set_name.clone(),
        mask: v.mask.unwrap_or(48),
    });

    if ipv4.is_none()
        && cfg.table_family4.is_some()
        && cfg.table_name4.is_some()
        && cfg.set_name4.is_some()
    {
        ipv4 = Some(ResolvedSet {
            table_family: cfg.table_family4.clone().unwrap_or_default(),
            table_name: cfg.table_name4.clone().unwrap_or_default(),
            set_name: cfg.set_name4.clone().unwrap_or_default(),
            mask: cfg.mask4.unwrap_or(24),
        });
    }

    if ipv6.is_none()
        && cfg.table_family6.is_some()
        && cfg.table_name6.is_some()
        && cfg.set_name6.is_some()
    {
        ipv6 = Some(ResolvedSet {
            table_family: cfg.table_family6.clone().unwrap_or_default(),
            table_name: cfg.table_name6.clone().unwrap_or_default(),
            set_name: cfg.set_name6.clone().unwrap_or_default(),
            mask: cfg.mask6.unwrap_or(48),
        });
    }

    if let Some(set) = ipv4.as_ref() {
        validate_set(set, "ipv4_addr")?;
    }
    if let Some(set) = ipv6.as_ref() {
        validate_set(set, "ipv6_addr")?;
    }

    Ok((ipv4, ipv6))
}

fn validate_set(set: &ResolvedSet, ip_type: &str) -> Result<()> {
    match set.table_family.as_str() {
        "ip" | "ip6" | "inet" => {}
        other => {
            return Err(DnsError::plugin(format!(
                "unsupported nft table family '{}', expected ip/ip6/inet",
                other
            )));
        }
    }

    if set.table_name.trim().is_empty() || set.set_name.trim().is_empty() {
        return Err(DnsError::plugin("nft table_name/set_name cannot be empty"));
    }

    if ip_type == "ipv4_addr" && set.mask > 32 {
        return Err(DnsError::plugin("nftset ipv4 mask must be in range 0..=32"));
    }
    if ip_type == "ipv6_addr" && set.mask > 128 {
        return Err(DnsError::plugin(
            "nftset ipv6 mask must be in range 0..=128",
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_nftset_writer(
    tag: &str,
    enabled: Arc<AtomicBool>,
    ipv4: Option<ResolvedSet>,
    ipv6: Option<ResolvedSet>,
) -> Result<SyncSender<NftSetBatch>> {
    let (tx, rx) = sync_channel::<NftSetBatch>(NFTSET_WRITER_QUEUE_SIZE);
    let thread_tag = tag.to_string();

    thread::Builder::new()
        .name(format!("nftset-{}", thread_tag))
        .spawn(move || {
            while enabled.load(Ordering::Relaxed) {
                let Ok(batch) = rx.recv() else {
                    break;
                };

                if let Some(set) = ipv4.as_ref()
                    && !batch.ipv4_prefixes.is_empty()
                    && let Err(e) = write_nftset_prefixes(set, &batch.ipv4_prefixes)
                {
                    warn!(
                        plugin = %thread_tag,
                        err = %e,
                        family = %set.table_family,
                        table = %set.table_name,
                        set = %set.set_name,
                        "nftset netlink add element failed"
                    );
                    enabled.store(false, Ordering::Relaxed);
                    break;
                }

                if let Some(set) = ipv6.as_ref()
                    && !batch.ipv6_prefixes.is_empty()
                    && let Err(e) = write_nftset_prefixes(set, &batch.ipv6_prefixes)
                {
                    warn!(
                        plugin = %thread_tag,
                        err = %e,
                        family = %set.table_family,
                        table = %set.table_name,
                        set = %set.set_name,
                        "nftset netlink add element failed"
                    );
                    enabled.store(false, Ordering::Relaxed);
                    break;
                }
            }
        })
        .map_err(|e| DnsError::plugin(format!("failed to spawn nftset writer thread: {}", e)))?;
    Ok(tx)
}

#[cfg(target_os = "linux")]
fn write_nftset_prefixes(set: &ResolvedSet, prefixes: &[IpPrefix]) -> Result<()> {
    for prefix in prefixes {
        let cidr = IpCidr::new(prefix.addr, prefix.mask).map_err(|e| {
            DnsError::plugin(format!("invalid nftset prefix '{}': {}", prefix.addr, e))
        })?;
        nftset_add(
            set.table_family.as_str(),
            set.table_name.as_str(),
            set.set_name.as_str(),
            cidr,
        )
        .map_err(|e| {
            DnsError::plugin(format!(
                "nft add element failed for {}/{}/{} and prefix '{}': {}",
                set.table_family, set.table_name, set.set_name, cidr, e
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use ripset::IpCidr;

    #[test]
    fn test_parse_config_rejects_empty_table_or_set_name() {
        assert!(parse_config(Some(Value::String("bad".into()))).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_ipcidr_normalizes_nft_prefix() {
        assert_eq!(
            IpCidr::new(IpAddr::V4("192.0.2.10".parse().unwrap()), 24)
                .unwrap()
                .to_string(),
            "192.0.2.0/24"
        );
    }
}
