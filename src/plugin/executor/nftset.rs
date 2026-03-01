/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `nftset` executor plugin.
//!
//! Writes response IP addresses into nftables sets via netlink.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::dns_utils::rr_to_ip;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::plugin::executor::netlink_nf::{
    NLM_F_REQUEST_ACK, NfNetlinkSocket, nla_put, nla_put_nested, nla_put_strz, nla_put_u32,
};

#[cfg(target_os = "linux")]
const NFTSET_WRITER_QUEUE_SIZE: usize = 256;

#[derive(Debug, Clone, Deserialize, Default)]
struct NftSetConfig {
    table_family4: Option<String>,
    table_family6: Option<String>,
    table_name4: Option<String>,
    table_name6: Option<String>,
    set_name4: Option<String>,
    set_name6: Option<String>,
    mask4: Option<u8>,
    mask6: Option<u8>,

    ipv4: Option<NftSetArgs>,
    ipv6: Option<NftSetArgs>,
}

#[derive(Debug, Clone, Deserialize)]
struct NftSetArgs {
    table_family: String,
    table_name: String,
    set_name: String,
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

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct NftSetBackend {
    socket: NfNetlinkSocket,
}

#[cfg(target_os = "linux")]
impl NftSetBackend {
    fn new() -> Result<Self> {
        Ok(Self {
            socket: NfNetlinkSocket::open()?,
        })
    }

    fn add_prefixes(&mut self, set: &ResolvedSet, prefixes: &[IpPrefix]) -> Result<()> {
        let family = nfproto_from_table_family(&set.table_family)?;

        let mut attrs = Vec::with_capacity(512);
        nla_put_strz(&mut attrs, NFTA_SET_ELEM_LIST_TABLE, &set.table_name);
        nla_put_strz(&mut attrs, NFTA_SET_ELEM_LIST_SET, &set.set_name);

        let mut list = Vec::with_capacity(512);
        for prefix in prefixes {
            append_prefix_elements(&mut list, prefix);
        }
        nla_put_nested(&mut attrs, NFTA_SET_ELEM_LIST_ELEMENTS, &list);

        self.socket.request(
            NFNL_SUBSYS_NFTABLES,
            NFT_MSG_NEWSETELEM,
            NLM_F_REQUEST_ACK,
            family,
            &attrs,
            true,
        )?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn append_prefix_elements(buf: &mut Vec<u8>, prefix: &IpPrefix) {
    match prefix.addr {
        IpAddr::V4(v4) => {
            let (start, end) = prefix_range_v4(v4, prefix.mask);
            append_element(buf, &start.octets(), false);
            if let Some(end) = end {
                append_element(buf, &end.octets(), true);
            }
        }
        IpAddr::V6(v6) => {
            let (start, end) = prefix_range_v6(v6, prefix.mask);
            append_element(buf, &start.octets(), false);
            if let Some(end) = end {
                append_element(buf, &end.octets(), true);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn append_element(buf: &mut Vec<u8>, key: &[u8], interval_end: bool) {
    let mut elem = Vec::with_capacity(64);
    let mut key_data = Vec::with_capacity(32);
    nla_put(&mut key_data, NFTA_DATA_VALUE, key);
    nla_put_nested(&mut elem, NFTA_SET_ELEM_KEY, &key_data);

    if interval_end {
        nla_put_u32(&mut elem, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
    }
    nla_put_nested(buf, NFTA_LIST_ELEM, &elem);
}

#[cfg(target_os = "linux")]
fn prefix_range_v4(addr: Ipv4Addr, mask: u8) -> (Ipv4Addr, Option<Ipv4Addr>) {
    if mask >= 32 {
        return (addr, None);
    }

    let addr_u32 = u32::from(addr);
    let host_bits = 32u32 - mask as u32;
    let network_mask = if host_bits == 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let start = addr_u32 & network_mask;
    let last = if host_bits == 32 {
        u32::MAX
    } else {
        start | ((1u32 << host_bits) - 1)
    };
    let end = last.checked_add(1).map(Ipv4Addr::from);

    (Ipv4Addr::from(start), end)
}

#[cfg(target_os = "linux")]
fn prefix_range_v6(addr: Ipv6Addr, mask: u8) -> (Ipv6Addr, Option<Ipv6Addr>) {
    if mask >= 128 {
        return (addr, None);
    }

    let addr_u128 = u128::from(addr);
    let host_bits = 128u32 - mask as u32;
    let network_mask = if host_bits == 128 {
        0
    } else {
        u128::MAX << host_bits
    };
    let start = addr_u128 & network_mask;
    let last = if host_bits == 128 {
        u128::MAX
    } else {
        start | ((1u128 << host_bits) - 1)
    };
    let end = last.checked_add(1).map(Ipv6Addr::from);

    (Ipv6Addr::from(start), end)
}

#[cfg(target_os = "linux")]
fn nfproto_from_table_family(family: &str) -> Result<u8> {
    match family {
        "ip" => Ok(NFPROTO_IPV4),
        "ip6" => Ok(NFPROTO_IPV6),
        "inet" => Ok(NFPROTO_INET),
        other => Err(DnsError::plugin(format!(
            "unsupported nft table family '{}', expected ip/ip6/inet",
            other
        ))),
    }
}

#[async_trait]
impl Plugin for NftSetExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for NftSetExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(ExecStep::Next);
        }

        let Some(response) = context.response.as_ref() else {
            return Ok(ExecStep::Next);
        };

        let mut ipv4_prefixes = AHashSet::new();
        let mut ipv6_prefixes = AHashSet::new();

        for record in response.answers() {
            let Some(ip) = rr_to_ip(record) else {
                continue;
            };

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
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let _ = resolve_sets(&cfg)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
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

fn parse_config(args: Option<serde_yml::Value>) -> Result<NftSetConfig> {
    let Some(args) = args else {
        return Ok(NftSetConfig::default());
    };

    serde_yml::from_value(args)
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
    let mut backend = NftSetBackend::new()?;

    thread::Builder::new()
        .name(format!("nftset-{}", thread_tag))
        .spawn(move || {
            while enabled.load(Ordering::Relaxed) {
                let Ok(batch) = rx.recv() else {
                    break;
                };

                if let Some(set) = ipv4.as_ref()
                    && !batch.ipv4_prefixes.is_empty()
                    && let Err(e) = backend.add_prefixes(set, &batch.ipv4_prefixes)
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
                    && let Err(e) = backend.add_prefixes(set, &batch.ipv6_prefixes)
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
const NFPROTO_INET: u8 = 1;
#[cfg(target_os = "linux")]
const NFPROTO_IPV4: u8 = 2;
#[cfg(target_os = "linux")]
const NFPROTO_IPV6: u8 = 10;

#[cfg(target_os = "linux")]
const NFNL_SUBSYS_NFTABLES: u8 = 10;
#[cfg(target_os = "linux")]
const NFT_MSG_NEWSETELEM: u8 = 12;

#[cfg(target_os = "linux")]
const NFTA_LIST_ELEM: u16 = 1;
#[cfg(target_os = "linux")]
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
#[cfg(target_os = "linux")]
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
#[cfg(target_os = "linux")]
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
#[cfg(target_os = "linux")]
const NFTA_SET_ELEM_KEY: u16 = 1;
#[cfg(target_os = "linux")]
const NFTA_SET_ELEM_FLAGS: u16 = 3;
#[cfg(target_os = "linux")]
const NFTA_DATA_VALUE: u16 = 1;

#[cfg(target_os = "linux")]
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;
