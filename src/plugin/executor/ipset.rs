/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ipset` executor plugin.
//!
//! Writes response IP addresses into Linux ipset sets via netlink.

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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
#[cfg(target_os = "linux")]
use std::thread;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::plugin::executor::netlink_nf::{
    NLM_F_REQUEST_ACK, NfNetlinkSocket, nla_put, nla_put_nested, nla_put_strz, nla_put_u8,
    nla_put_u32,
};

#[cfg(target_os = "linux")]
const IPSET_WRITER_QUEUE_SIZE: usize = 256;

#[derive(Debug, Clone, Deserialize, Default)]
struct IpSetConfig {
    set_name4: Option<String>,
    set_name6: Option<String>,
    mask4: Option<u8>,
    mask6: Option<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct IpSetEntry {
    set_name: String,
    addr: IpAddr,
    mask: u8,
}

#[derive(Debug)]
struct IpSetExecutor {
    tag: String,
    set_name4: Option<String>,
    set_name6: Option<String>,
    mask4: u8,
    mask6: u8,
    enabled: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    writer: SyncSender<Vec<IpSetEntry>>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct IpSetBackend {
    socket: NfNetlinkSocket,
}

#[cfg(target_os = "linux")]
impl IpSetBackend {
    fn new() -> Result<Self> {
        Ok(Self {
            socket: NfNetlinkSocket::open()?,
        })
    }

    fn add_entries(&mut self, entries: &[IpSetEntry]) -> Result<()> {
        for entry in entries {
            let mut attrs = Vec::with_capacity(96);
            nla_put_u8(&mut attrs, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
            nla_put_strz(&mut attrs, IPSET_ATTR_SETNAME, &entry.set_name);

            let mut data = Vec::with_capacity(64);
            let mut ip = Vec::with_capacity(32);
            match entry.addr {
                IpAddr::V4(v4) => {
                    nla_put(&mut ip, IPSET_ATTR_IPADDR_IPV4, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    nla_put(&mut ip, IPSET_ATTR_IPADDR_IPV6, &v6.octets());
                }
            }
            nla_put_nested(&mut data, IPSET_ATTR_IP, &ip);
            nla_put_u8(&mut data, IPSET_ATTR_CIDR, entry.mask);
            nla_put_u32(&mut data, IPSET_ATTR_CADT_FLAGS, IPSET_FLAG_EXIST);
            nla_put_nested(&mut attrs, IPSET_ATTR_DATA, &data);

            let family = match entry.addr {
                IpAddr::V4(_) => NFPROTO_IPV4,
                IpAddr::V6(_) => NFPROTO_IPV6,
            };
            self.socket.request(
                NFNL_SUBSYS_IPSET,
                IPSET_CMD_ADD,
                NLM_F_REQUEST_ACK,
                family,
                &attrs,
                true,
            )?;
        }
        Ok(())
    }
}

#[async_trait]
impl Plugin for IpSetExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for IpSetExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(ExecStep::Next);
        }

        let Some(response) = context.response.as_ref() else {
            return Ok(ExecStep::Next);
        };

        let mut entries = AHashSet::new();
        for record in response.answers() {
            let Some(ip) = rr_to_ip(record) else {
                continue;
            };

            let (set_name, mask) = match ip {
                IpAddr::V4(_) => (self.set_name4.as_deref(), self.mask4),
                IpAddr::V6(_) => (self.set_name6.as_deref(), self.mask6),
            };
            let Some(set_name) = set_name else {
                continue;
            };

            entries.insert(IpSetEntry {
                set_name: set_name.to_string(),
                addr: ip,
                mask,
            });
        }

        if entries.is_empty() {
            return Ok(ExecStep::Next);
        }

        #[cfg(target_os = "linux")]
        {
            let entries: Vec<IpSetEntry> = entries.into_iter().collect();
            if let Err(e) = self.writer.try_send(entries) {
                match e {
                    TrySendError::Full(_) => {
                        // Best-effort side effect: dropping write preserves DNS path latency.
                    }
                    TrySendError::Disconnected(_) => {
                        warn!(
                            plugin = %self.tag,
                            "ipset writer disconnected, disabling plugin"
                        );
                        self.enabled.store(false, Ordering::Relaxed);
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = entries;
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct IpSetFactory;

register_plugin_factory!("ipset", IpSetFactory {});

impl PluginFactory for IpSetFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let cfg = parse_config(plugin_config.args.clone())?;
        validate_masks(cfg.mask4.unwrap_or(24), cfg.mask6.unwrap_or(32))
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let mask4 = cfg.mask4.unwrap_or(24);
        let mask6 = cfg.mask6.unwrap_or(32);
        validate_masks(mask4, mask6)?;

        debug!(
            plugin = %plugin_config.tag,
            set_name4 = ?cfg.set_name4,
            set_name6 = ?cfg.set_name6,
            mask4,
            mask6,
            "ipset plugin configured"
        );

        #[cfg(target_os = "linux")]
        #[cfg(target_os = "linux")]
        let enabled = Arc::new(AtomicBool::new(true));
        #[cfg(target_os = "linux")]
        let writer = spawn_ipset_writer(plugin_config.tag.as_str(), enabled.clone())?;

        #[cfg(not(target_os = "linux"))]
        let enabled = Arc::new(AtomicBool::new(true));

        Ok(UninitializedPlugin::Executor(Box::new(IpSetExecutor {
            tag: plugin_config.tag.clone(),
            set_name4: cfg.set_name4.filter(|v| !v.trim().is_empty()),
            set_name6: cfg.set_name6.filter(|v| !v.trim().is_empty()),
            mask4,
            mask6,
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
        let mut cfg = IpSetConfig::default();
        let raw = param.unwrap_or_default();

        for field in raw.split_whitespace() {
            let parts: Vec<&str> = field.split(',').collect();
            if parts.len() != 3 {
                return Err(DnsError::plugin(format!(
                    "invalid ipset quick setup token '{}', expected set,family,mask",
                    field
                )));
            }
            let mask = parts[2].parse::<u8>().map_err(|e| {
                DnsError::plugin(format!("invalid ipset mask '{}': {}", parts[2], e))
            })?;
            match parts[1] {
                "inet" => {
                    cfg.set_name4 = Some(parts[0].to_string());
                    cfg.mask4 = Some(mask);
                }
                "inet6" => {
                    cfg.set_name6 = Some(parts[0].to_string());
                    cfg.mask6 = Some(mask);
                }
                other => {
                    return Err(DnsError::plugin(format!(
                        "invalid ipset family '{}', expected inet or inet6",
                        other
                    )));
                }
            }
        }

        let mask4 = cfg.mask4.unwrap_or(24);
        let mask6 = cfg.mask6.unwrap_or(32);
        validate_masks(mask4, mask6)?;

        #[cfg(target_os = "linux")]
        #[cfg(target_os = "linux")]
        let enabled = Arc::new(AtomicBool::new(true));
        #[cfg(target_os = "linux")]
        let writer = spawn_ipset_writer(tag, enabled.clone())?;

        #[cfg(not(target_os = "linux"))]
        let enabled = Arc::new(AtomicBool::new(true));

        Ok(UninitializedPlugin::Executor(Box::new(IpSetExecutor {
            tag: tag.to_string(),
            set_name4: cfg.set_name4,
            set_name6: cfg.set_name6,
            mask4,
            mask6,
            enabled,
            #[cfg(target_os = "linux")]
            writer,
        })))
    }
}

fn parse_config(args: Option<serde_yml::Value>) -> Result<IpSetConfig> {
    let Some(args) = args else {
        return Ok(IpSetConfig::default());
    };

    serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse ipset config: {}", e)))
}

fn validate_masks(mask4: u8, mask6: u8) -> Result<()> {
    if mask4 > 32 {
        return Err(DnsError::plugin("ipset mask4 must be in range 0..=32"));
    }
    if mask6 > 128 {
        return Err(DnsError::plugin("ipset mask6 must be in range 0..=128"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_ipset_writer(tag: &str, enabled: Arc<AtomicBool>) -> Result<SyncSender<Vec<IpSetEntry>>> {
    let (tx, rx) = sync_channel::<Vec<IpSetEntry>>(IPSET_WRITER_QUEUE_SIZE);
    let mut backend = IpSetBackend::new()?;
    let thread_tag = tag.to_string();
    thread::Builder::new()
        .name(format!("ipset-{}", thread_tag))
        .spawn(move || {
            while enabled.load(Ordering::Relaxed) {
                let Ok(entries) = rx.recv() else {
                    break;
                };
                if entries.is_empty() {
                    continue;
                }
                if let Err(e) = backend.add_entries(&entries) {
                    warn!(
                        plugin = %thread_tag,
                        err = %e,
                        "ipset netlink execution failed, disabling plugin"
                    );
                    enabled.store(false, Ordering::Relaxed);
                    break;
                }
            }
        })
        .map_err(|e| DnsError::plugin(format!("failed to spawn ipset writer thread: {}", e)))?;
    Ok(tx)
}

#[cfg(target_os = "linux")]
const NFPROTO_IPV4: u8 = 2;
#[cfg(target_os = "linux")]
const NFPROTO_IPV6: u8 = 10;

#[cfg(target_os = "linux")]
const NFNL_SUBSYS_IPSET: u8 = 6;
#[cfg(target_os = "linux")]
const IPSET_PROTOCOL: u8 = 7;
#[cfg(target_os = "linux")]
const IPSET_CMD_ADD: u8 = 9;

#[cfg(target_os = "linux")]
const IPSET_ATTR_PROTOCOL: u16 = 1;
#[cfg(target_os = "linux")]
const IPSET_ATTR_SETNAME: u16 = 2;
#[cfg(target_os = "linux")]
const IPSET_ATTR_DATA: u16 = 7;

#[cfg(target_os = "linux")]
const IPSET_ATTR_IP: u16 = 1;
#[cfg(target_os = "linux")]
const IPSET_ATTR_CIDR: u16 = 4;
#[cfg(target_os = "linux")]
const IPSET_ATTR_CADT_FLAGS: u16 = 10;

#[cfg(target_os = "linux")]
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
#[cfg(target_os = "linux")]
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

#[cfg(target_os = "linux")]
const IPSET_FLAG_EXIST: u32 = 1;
