/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ipset` executor plugin.
//!
//! Writes response IP addresses into Linux ipset sets via system ipset.
//!
//! Runtime flow:
//! - scans response answers and extracts unique A/AAAA addresses.
//! - applies family-specific masks (`mask4`/`mask6`) and target sets.
//! - sends batched add requests to a dedicated background writer thread.
//!
//! Performance and resilience:
//! - request path uses non-blocking queue write (`try_send`) to avoid adding
//!   latency to DNS hot path.
//! - queue overflow drops side effects (best effort).
//! - writer failure disables plugin to prevent repeated netlink overhead.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::Command;
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
const IPSET_WRITER_QUEUE_SIZE: usize = 256;

#[derive(Debug, Clone, Deserialize, Default)]
struct IpSetConfig {
    /// IPv4 ipset name used for A answers.
    set_name4: Option<String>,
    /// IPv6 ipset name used for AAAA answers.
    set_name6: Option<String>,
    /// Prefix length used when writing IPv4 entries.
    mask4: Option<u8>,
    /// Prefix length used when writing IPv6 entries.
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
    command: &'static str,
}

#[cfg(target_os = "linux")]
impl IpSetBackend {
    fn new() -> Result<Self> {
        let output = Command::new("ipset")
            .arg("help")
            .output()
            .map_err(|e| DnsError::plugin(format!("failed to execute ipset: {}", e)))?;
        if !output.status.success() {
            return Err(DnsError::plugin(format!(
                "ipset help failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(Self { command: "ipset" })
    }

    fn add_entries(&mut self, entries: &[IpSetEntry]) -> Result<()> {
        for entry in entries {
            let prefix = format_ipset_prefix(entry.addr, entry.mask);
            let output = Command::new(self.command)
                .args(["add", &entry.set_name, &prefix, "-exist"])
                .output()
                .map_err(|e| DnsError::plugin(format!("failed to execute ipset add: {}", e)))?;
            if !output.status.success() {
                return Err(DnsError::plugin(format!(
                    "ipset add failed for set '{}' and prefix '{}': {}",
                    entry.set_name,
                    prefix,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Plugin for IpSetExecutor {
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
            // Wake the writer thread if it is blocked on recv so it can observe
            // the disabled flag and exit quickly.
            let _ = self.writer.try_send(Vec::new());
        }
        Ok(())
    }
}

#[async_trait]
impl Executor for IpSetExecutor {
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

        let mut entries = AHashSet::new();
        for answer in answers {
            if let Some(ip) = answer.ip_addr() {
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

fn parse_config(args: Option<Value>) -> Result<IpSetConfig> {
    let Some(args) = args else {
        return Ok(IpSetConfig::default());
    };

    serde_yaml_ng::from_value(args)
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
fn normalize_ip_for_mask(addr: IpAddr, mask: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) if mask < 32 => {
            let host_bits = 32u32 - mask as u32;
            let network_mask = if host_bits == 32 {
                0
            } else {
                u32::MAX << host_bits
            };
            IpAddr::V4((u32::from(v4) & network_mask).into())
        }
        IpAddr::V6(v6) if mask < 128 => {
            let host_bits = 128u32 - mask as u32;
            let network_mask = if host_bits == 128 {
                0
            } else {
                u128::MAX << host_bits
            };
            IpAddr::V6((u128::from(v6) & network_mask).into())
        }
        _ => addr,
    }
}

#[cfg(target_os = "linux")]
fn format_ipset_prefix(addr: IpAddr, mask: u8) -> String {
    format!("{}/{}", normalize_ip_for_mask(addr, mask), mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_rejects_invalid_masks() {
        assert!(validate_masks(33, 32).is_err());
        assert!(validate_masks(24, 129).is_err());
        assert!(validate_masks(24, 32).is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_normalize_ip_for_mask_truncates_host_bits() {
        assert_eq!(
            normalize_ip_for_mask(IpAddr::V4("192.0.2.10".parse().unwrap()), 24),
            IpAddr::V4("192.0.2.0".parse().unwrap())
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_format_ipset_prefix_uses_masked_network() {
        assert_eq!(
            format_ipset_prefix(IpAddr::V4("192.0.2.10".parse().unwrap()), 24),
            "192.0.2.0/24"
        );
    }
}
