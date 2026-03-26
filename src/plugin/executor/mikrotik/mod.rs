/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `mikrotik` executor plugin.
//!
//! This executor is an observer-side effect stage designed to integrate with
//! ForgeDNS sequence pipelines. It does not alter DNS decisions or response
//! content. Instead, it watches final downstream DNS answers and synchronizes
//! IPs into RouterOS address lists.
//!
//! Architecture overview:
//! - continuation pre-stage stays hot-path light.
//! - continuation post-stage extracts normalized query domain and unique A/AAAA IPs.
//! - address-list synchronization is delegated to a single-owner background
//!   manager state machine.
//! - RouterOS API details are isolated in `MikrotikApi` adapter implementations.
//! - ownership metadata is persisted in RouterOS `comment` so cleanup can
//!   safely distinguish ForgeDNS-managed entries from foreign entries.
//!
//! Behavior goals:
//! - maintain IPv4/IPv6 dynamic host entries in configured address lists.
//! - support optional always-present IP/CIDR entries via `persistent`.
//! - use RouterOS native `timeout` for dynamic expiration maintenance.
//! - preserve DNS hot-path latency (`async=true` uses non-blocking queue).
//! - provide blocking write-before-return mode (`async=false`) without
//!   affecting DNS response result.
//! - keep persistent file-backed entries self-healed via background reload and
//!   reconcile loops.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::message::Rcode;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::{AHashMap, AHashSet};
use async_trait::async_trait;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

/// Default lower TTL clamp for dynamic address-list entries.
const DEFAULT_MIN_TTL: u32 = 60;
/// Default upper TTL clamp for dynamic address-list entries.
const DEFAULT_MAX_TTL: u32 = 3600;
/// Default execution mode keeps RouterOS writes off the DNS request path.
const DEFAULT_ASYNC_MODE: bool = true;
/// Default shutdown behavior removes plugin-owned RouterOS entries.
const DEFAULT_CLEANUP_ON_SHUTDOWN: bool = true;
/// Default comment prefix used to mark ForgeDNS-owned RouterOS rows.
const DEFAULT_COMMENT_PREFIX: &str = "fdns";
/// Maximum time sync mode waits for one observe command to finish.
const SYNC_OBSERVE_TIMEOUT_SECS: u64 = 8;

mod api;
mod manager;

use self::api::{MikrotikApi, MikrotikRsClient};
use self::manager::{
    AddressListFamily, AddressListKey, AddressListManager, AddressListManagerConfig,
    AddressListManagerRuntime, ManagerCommand, ObservedAddr, PersistentReloadConfig,
};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct MikrotikConfigArgs {
    /// RouterOS API endpoint, usually `<host>:8728`.
    address: Option<String>,
    /// RouterOS login username.
    username: Option<String>,
    /// RouterOS login password.
    password: Option<String>,
    /// Whether post stage waits RouterOS writes (`false`) or queues work (`true`).
    #[serde(rename = "async")]
    async_mode: Option<bool>,
    /// IPv4 address-list name for observed IPv4 answers.
    address_list4: Option<String>,
    /// IPv6 address-list name for observed IPv6 answers.
    address_list6: Option<String>,
    /// Prefix used in RouterOS comments to mark ForgeDNS-managed entries.
    /// Defaults to `fdns` when omitted.
    comment_prefix: Option<String>,
    /// Always-present address-list items that should never expire.
    persistent: Option<PersistentArgs>,
    /// Minimum effective TTL clamp (seconds) for observed records.
    min_ttl: Option<u32>,
    /// Maximum effective TTL clamp (seconds) for observed records.
    max_ttl: Option<u32>,
    /// Optional fixed TTL override (seconds) for dynamic observed records.
    fixed_ttl: Option<u32>,
    /// Whether to clean managed address-list entries on shutdown.
    cleanup_on_shutdown: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PersistentArgs {
    /// Inline always-present IPs/CIDRs. Plain IP is normalized to host entry.
    ips: Option<Vec<String>>,
    /// File list that provides always-present IPs/CIDRs.
    files: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct MikrotikConfig {
    /// RouterOS API endpoint used by the shared client.
    address: String,
    /// Login username for RouterOS API.
    username: String,
    /// Login password for RouterOS API.
    password: String,
    /// Async mode switch for post stage writes.
    async_mode: bool,
    /// IPv4 address-list name managed by this plugin.
    address_list4: Option<String>,
    /// IPv6 address-list name managed by this plugin.
    address_list6: Option<String>,
    /// Full persistent desired set after merging inline and file sources.
    persistent_items: AHashSet<AddressListKey>,
    /// Inline-only persistent items kept separately so file reload can rebuild the merged set.
    persistent_inline_items: AHashSet<AddressListKey>,
    /// Source files periodically reloaded for persistent items.
    persistent_files: Vec<String>,
    /// Prefix used in RouterOS comments to mark plugin ownership.
    comment_prefix: String,
    /// Minimum TTL clamp for dynamic entries.
    min_ttl: u32,
    /// Maximum TTL clamp for dynamic entries.
    max_ttl: u32,
    /// Optional fixed TTL override for dynamic entries.
    fixed_ttl: Option<u32>,
    /// Whether shutdown should remove owned entries from RouterOS.
    cleanup_on_shutdown: bool,
}

impl MikrotikConfigArgs {
    /// Validate user-facing config and normalize it into a runtime-ready form.
    ///
    /// This is also where persistent input sources are parsed into normalized
    /// `AddressListKey` values so the manager does not need to re-interpret
    /// human-facing YAML at runtime.
    fn into_config(self, emit_warnings: bool) -> Result<MikrotikConfig> {
        let address = required_non_empty(self.address, "address")?;
        let username = required_non_empty(self.username, "username")?;
        let password = required_non_empty(self.password, "password")?;
        let address_list4 = optional_non_empty(self.address_list4);
        let address_list6 = optional_non_empty(self.address_list6);
        if address_list4.is_none() && address_list6.is_none() {
            return Err(DnsError::plugin(
                "mikrotik requires at least one of address_list4 or address_list6",
            ));
        }

        let comment_prefix = optional_non_empty(self.comment_prefix)
            .unwrap_or_else(|| DEFAULT_COMMENT_PREFIX.to_string());
        validate_comment_token("comment_prefix", &comment_prefix)?;

        let min_ttl = self.min_ttl.unwrap_or(DEFAULT_MIN_TTL);
        let max_ttl = self.max_ttl.unwrap_or(DEFAULT_MAX_TTL);
        if min_ttl > max_ttl {
            return Err(DnsError::plugin(format!(
                "mikrotik ttl range is invalid: min_ttl({min_ttl}) > max_ttl({max_ttl})"
            )));
        }
        let fixed_ttl = match self.fixed_ttl {
            Some(0) => {
                return Err(DnsError::plugin(
                    "mikrotik fixed_ttl must be greater than 0",
                ));
            }
            Some(ttl) => Some(ttl),
            None => None,
        };

        let parsed_persistent = parse_persistent_items(
            self.persistent,
            address_list4.as_deref(),
            address_list6.as_deref(),
        )?;
        if emit_warnings && parsed_persistent.ignored_by_family > 0 {
            warn!(
                ignored = parsed_persistent.ignored_by_family,
                "mikrotik persistent ignored entries without corresponding address list family"
            );
        }

        Ok(MikrotikConfig {
            address,
            username,
            password,
            async_mode: self.async_mode.unwrap_or(DEFAULT_ASYNC_MODE),
            address_list4,
            address_list6,
            persistent_items: parsed_persistent.all_items,
            persistent_inline_items: parsed_persistent.inline_items,
            persistent_files: parsed_persistent.files,
            comment_prefix,
            min_ttl,
            max_ttl,
            fixed_ttl,
            cleanup_on_shutdown: self
                .cleanup_on_shutdown
                .unwrap_or(DEFAULT_CLEANUP_ON_SHUTDOWN),
        })
    }
}

#[derive(Debug)]
struct MikrotikExecutor {
    /// Plugin tag from the global registry.
    tag: String,
    /// Fully validated immutable runtime config.
    config: MikrotikConfig,
    /// Pre-built manager consumed during `init()`.
    manager: Option<AddressListManager>,
    /// Sender exposed to continuation post-stage after the background runtime starts.
    command_tx: Option<mpsc::Sender<ManagerCommand>>,
    /// Runtime handle stored so `destroy()` can stop worker tasks.
    runtime: Mutex<Option<AddressListManagerRuntime>>,
}

#[async_trait]
impl Plugin for MikrotikExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        // `init()` may be called more than once by the plugin framework.
        // Keep it idempotent and only build the runtime once.
        if self.manager.is_none() || self.command_tx.is_some() {
            return Ok(());
        }

        if let Some(manager) = self.manager.as_mut() {
            manager.initialize_on_startup().await?;
        }

        let Some(manager) = self.manager.take() else {
            return Ok(());
        };

        let persistent_reload = Some(PersistentReloadConfig {
            // Runtime keeps inline and file sources separate so a file reload
            // can rebuild the merged desired set without reparsing YAML.
            inline_items: self.config.persistent_inline_items.clone(),
            files: self.config.persistent_files.clone(),
            address_list4: self.config.address_list4.clone(),
            address_list6: self.config.address_list6.clone(),
            initial_items: self.config.persistent_items.clone(),
        });
        let runtime =
            AddressListManagerRuntime::start(self.tag.clone(), manager, persistent_reload);
        self.command_tx = Some(runtime.sender());
        if let Ok(mut slot) = self.runtime.lock() {
            *slot = Some(runtime);
        }
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(runtime) = self.runtime.lock().ok().and_then(|mut slot| slot.take()) {
            runtime.shutdown(self.config.cleanup_on_shutdown).await;
        }
        Ok(())
    }
}

#[async_trait]
impl Executor for MikrotikExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        // If the runtime never started, the plugin stays side-effect free.
        let Some(tx) = self.command_tx.as_ref() else {
            return Ok(ExecStep::Next);
        };

        // This executor only reacts to successful final answers containing A/AAAA data.
        let Some((domain, addrs)) = extract_observation(context, &self.config) else {
            return Ok(ExecStep::Next);
        };

        if self.config.async_mode {
            // Async mode keeps RouterOS I/O fully off the request path.
            match tx.try_send(ManagerCommand::ObserveDomain {
                domain,
                addrs,
                wait: None,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        plugin = %self.tag,
                        "mikrotik observe queue is full, observation dropped"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!(
                        plugin = %self.tag,
                        "mikrotik manager channel closed, observation dropped"
                    );
                }
            }
            return Ok(ExecStep::Next);
        }

        // Sync mode still preserves DNS behavior on RouterOS failures. The only
        // difference is that we wait for the manager to attempt the write.
        let (wait_tx, wait_rx) = oneshot::channel::<Result<()>>();
        let send_cmd = ManagerCommand::ObserveDomain {
            domain,
            addrs,
            wait: Some(wait_tx),
        };
        let send_outcome = tokio::time::timeout(
            Duration::from_secs(SYNC_OBSERVE_TIMEOUT_SECS),
            tx.send(send_cmd),
        )
        .await;
        match send_outcome {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                warn!(
                    plugin = %self.tag,
                    "mikrotik manager channel closed in sync mode, DNS response is kept unchanged"
                );
                return Ok(ExecStep::Next);
            }
            Err(_) => {
                warn!(
                    plugin = %self.tag,
                    timeout_secs = SYNC_OBSERVE_TIMEOUT_SECS,
                    "mikrotik observe enqueue timed out in sync mode, DNS response is kept unchanged"
                );
                return Ok(ExecStep::Next);
            }
        }

        let wait_outcome =
            tokio::time::timeout(Duration::from_secs(SYNC_OBSERVE_TIMEOUT_SECS), wait_rx).await;
        match wait_outcome {
            Ok(Ok(Ok(()))) => Ok(ExecStep::Next),
            Ok(Ok(Err(e))) => {
                warn!(
                    plugin = %self.tag,
                    err = %e,
                    "mikrotik observe failed in sync mode, DNS response is kept unchanged"
                );
                Ok(ExecStep::Next)
            }
            Ok(Err(_)) => {
                warn!(
                    plugin = %self.tag,
                    "mikrotik manager dropped sync observe response, DNS response is kept unchanged"
                );
                Ok(ExecStep::Next)
            }
            Err(_) => {
                warn!(
                    plugin = %self.tag,
                    timeout_secs = SYNC_OBSERVE_TIMEOUT_SECS,
                    "mikrotik observe timed out in sync mode, DNS response is kept unchanged"
                );
                Ok(ExecStep::Next)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct MikrotikFactory;

register_plugin_factory!("mikrotik", MikrotikFactory {});

impl PluginFactory for MikrotikFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        // Plugin tag is reused inside RouterOS comment ownership metadata.
        validate_comment_token("plugin tag", plugin_config.tag.as_str())?;
        let config = parse_plugin_config(plugin_config.args.clone(), true)?;
        let api = Arc::new(MikrotikRsClient::new(
            config.address.clone(),
            config.username.clone(),
            config.password.clone(),
        )) as Arc<dyn MikrotikApi>;

        let manager_cfg = AddressListManagerConfig {
            plugin_tag: plugin_config.tag.clone(),
            address_list4: config.address_list4.clone(),
            address_list6: config.address_list6.clone(),
            persistent_items: config.persistent_items.clone(),
            comment_prefix: config.comment_prefix.clone(),
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            fixed_ttl: config.fixed_ttl,
        };
        let manager = AddressListManager::new(api, manager_cfg);

        Ok(UninitializedPlugin::Executor(Box::new(MikrotikExecutor {
            tag: plugin_config.tag.clone(),
            config,
            manager: Some(manager),
            command_tx: None,
            runtime: Mutex::new(None),
        })))
    }
}

fn extract_observation(
    context: &mut DnsContext,
    config: &MikrotikConfig,
) -> Option<(String, Vec<ObservedAddr>)> {
    // The first question is the authoritative domain label written to the
    // RouterOS comment for dynamic entries. This is intentionally lightweight:
    // we do not inspect CNAME chains or reconstruct canonical names here.

    let response = context.response()?;
    if response.rcode() != Rcode::NoError {
        return None;
    }

    let domain = context
        .request
        .first_question()
        .map(|question| question.name().normalized().to_string())?;

    // Collapse duplicate IPs inside one DNS response before sending work to
    // the manager. For duplicates we keep the largest TTL because the manager
    // should observe the strongest expiry hint from this response batch.
    let mut dedup = AHashMap::<IpAddr, u32>::new();
    for (ip, ttl_secs) in response.answer_ip_ttls() {
        match ip {
            IpAddr::V4(_) if config.address_list4.is_none() => continue,
            IpAddr::V6(_) if config.address_list6.is_none() => continue,
            _ => {}
        }

        dedup
            .entry(ip)
            .and_modify(|ttl| *ttl = (*ttl).max(ttl_secs))
            .or_insert(ttl_secs);
    }

    if dedup.is_empty() {
        return None;
    }

    let addrs = dedup
        .into_iter()
        .map(|(addr, ttl_secs)| ObservedAddr { addr, ttl_secs })
        .collect::<Vec<_>>();
    Some((domain, addrs))
}

fn parse_plugin_config(
    args: Option<serde_yml::Value>,
    emit_warnings: bool,
) -> Result<MikrotikConfig> {
    let Some(args) = args else {
        return Err(DnsError::plugin("mikrotik plugin requires args"));
    };
    let raw = serde_yml::from_value::<MikrotikConfigArgs>(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse mikrotik config: {e}")))?;
    raw.into_config(emit_warnings)
}

fn required_non_empty(value: Option<String>, field: &str) -> Result<String> {
    let Some(value) = value else {
        return Err(DnsError::plugin(format!("mikrotik '{field}' is required")));
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DnsError::plugin(format!(
            "mikrotik '{field}' cannot be empty"
        )));
    }
    Ok(trimmed.to_string())
}

fn optional_non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[inline]
fn contains_comment_delimiter(value: &str) -> bool {
    value.contains(';') || value.contains('=')
}

fn validate_comment_token(field: &str, value: &str) -> Result<()> {
    if contains_comment_delimiter(value) {
        return Err(DnsError::plugin(format!(
            "mikrotik '{field}' cannot contain ';' or '='"
        )));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct ParsedPersistentItems {
    /// Final desired set after merging inline and file sources.
    all_items: AHashSet<AddressListKey>,
    /// Inline-only subset used by periodic file reload.
    inline_items: AHashSet<AddressListKey>,
    /// File list preserved for runtime reload.
    files: Vec<String>,
    /// Count of items skipped because that family is not configured.
    ignored_by_family: usize,
}

/// Parse `persistent` config into normalized address-list keys.
///
/// The parser performs all expensive normalization and validation at startup:
/// plain IPs become host prefixes, CIDRs are masked to network form, and each
/// item is bound to the correct IPv4/IPv6 address-list name.
fn parse_persistent_items(
    persistent: Option<PersistentArgs>,
    address_list4: Option<&str>,
    address_list6: Option<&str>,
) -> Result<ParsedPersistentItems> {
    let mut parsed = ParsedPersistentItems::default();
    let Some(persistent) = persistent else {
        return Ok(parsed);
    };

    if let Some(ips) = persistent.ips {
        for (index, item) in ips.into_iter().enumerate() {
            let source = format!("persistent.ips[{index}]");
            let key = parse_persistent_item(
                item.as_str(),
                source.as_str(),
                address_list4,
                address_list6,
            )?;
            match key {
                Some(key) => {
                    parsed.inline_items.insert(key.clone());
                    parsed.all_items.insert(key);
                }
                None => {
                    parsed.ignored_by_family = parsed.ignored_by_family.saturating_add(1);
                }
            }
        }
    }

    parsed.files = parse_persistent_files(persistent.files)?;
    let (file_items, ignored_by_family) =
        load_persistent_items_from_files(parsed.files.as_slice(), address_list4, address_list6)?;
    parsed.ignored_by_family = parsed.ignored_by_family.saturating_add(ignored_by_family);
    parsed.all_items.extend(file_items);
    Ok(parsed)
}

fn parse_persistent_files(files: Option<Vec<String>>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let Some(files) = files else {
        return Ok(out);
    };
    for (index, file_raw) in files.into_iter().enumerate() {
        let file = file_raw.trim();
        if file.is_empty() {
            return Err(DnsError::plugin(format!(
                "mikrotik persistent.files[{index}] cannot be empty"
            )));
        }
        out.push(file.to_string());
    }
    Ok(out)
}

/// Parse one file body into normalized persistent items.
///
/// Files use the same item grammar as inline YAML. Empty lines and `#` comments
/// are ignored. Family-mismatched entries are skipped rather than failing
/// startup so shared source files can contain both IPv4 and IPv6 items.
fn load_persistent_items_from_content(
    source_prefix: &str,
    content: &str,
    address_list4: Option<&str>,
    address_list6: Option<&str>,
) -> Result<(AHashSet<AddressListKey>, usize)> {
    let mut out = AHashSet::new();
    let mut ignored_by_family = 0usize;

    for (line_no, line) in content.lines().enumerate() {
        let token = line.split('#').next().unwrap_or_default().trim();
        if token.is_empty() {
            continue;
        }

        let source = format!("{source_prefix} line {}", line_no + 1);
        match parse_persistent_item(token, source.as_str(), address_list4, address_list6)? {
            Some(key) => {
                out.insert(key);
            }
            None => {
                ignored_by_family = ignored_by_family.saturating_add(1);
            }
        }
    }

    Ok((out, ignored_by_family))
}

fn load_persistent_items_from_files(
    files: &[String],
    address_list4: Option<&str>,
    address_list6: Option<&str>,
) -> Result<(AHashSet<AddressListKey>, usize)> {
    let mut out = AHashSet::new();
    let mut ignored_by_family = 0usize;

    for (index, file) in files.iter().enumerate() {
        let content = fs::read_to_string(file).map_err(|e| {
            DnsError::plugin(format!(
                "mikrotik failed to read persistent file '{file}': {e}"
            ))
        })?;
        let source_prefix = format!("persistent.files[{index}]");
        let (loaded, ignored_delta) = load_persistent_items_from_content(
            source_prefix.as_str(),
            &content,
            address_list4,
            address_list6,
        )?;
        out.extend(loaded);
        ignored_by_family = ignored_by_family.saturating_add(ignored_delta);
    }

    Ok((out, ignored_by_family))
}

async fn load_persistent_items_from_files_async(
    files: &[String],
    address_list4: Option<&str>,
    address_list6: Option<&str>,
) -> Result<(AHashSet<AddressListKey>, usize)> {
    let mut out = AHashSet::new();
    let mut ignored_by_family = 0usize;

    for (index, file) in files.iter().enumerate() {
        let content = tokio_fs::read_to_string(file).await.map_err(|e| {
            DnsError::plugin(format!(
                "mikrotik failed to read persistent file '{file}': {e}"
            ))
        })?;
        let source_prefix = format!("persistent.files[{index}]");
        let (loaded, ignored_delta) = load_persistent_items_from_content(
            source_prefix.as_str(),
            &content,
            address_list4,
            address_list6,
        )?;
        out.extend(loaded);
        ignored_by_family = ignored_by_family.saturating_add(ignored_delta);
    }

    Ok((out, ignored_by_family))
}

/// Parse one human-facing persistent item and bind it to the correct list.
///
/// Return `Ok(None)` when the item is valid but its IP family has no configured
/// target list, allowing callers to ignore mixed-family source files cleanly.
fn parse_persistent_item(
    raw: &str,
    source: &str,
    address_list4: Option<&str>,
    address_list6: Option<&str>,
) -> Result<Option<AddressListKey>> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(DnsError::plugin(format!("mikrotik {source} is empty")));
    }

    let (ip, prefix) = if let Some((ip_raw, prefix_raw)) = value.split_once('/') {
        let ip = ip_raw.trim().parse::<IpAddr>().map_err(|e| {
            DnsError::plugin(format!("mikrotik {source} has invalid ip '{ip_raw}': {e}"))
        })?;
        let prefix = prefix_raw.trim().parse::<u8>().map_err(|e| {
            DnsError::plugin(format!(
                "mikrotik {source} has invalid prefix '{prefix_raw}': {e}"
            ))
        })?;
        (ip, prefix)
    } else {
        let ip = value.parse::<IpAddr>().map_err(|e| {
            DnsError::plugin(format!("mikrotik {source} has invalid ip '{value}': {e}"))
        })?;
        let family = AddressListFamily::from_ip(ip);
        (ip, family.host_prefix())
    };

    let family = AddressListFamily::from_ip(ip);
    let list = match family {
        AddressListFamily::Ipv4 => address_list4,
        AddressListFamily::Ipv6 => address_list6,
    };
    let Some(list) = list else {
        return Ok(None);
    };

    AddressListKey::new_with_prefix(ip, prefix, list.to_string())
        .ok_or_else(|| {
            DnsError::plugin(format!(
                "mikrotik {source} has invalid prefix /{prefix} for {ip}"
            ))
        })
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::rdata::{A, AAAA};
    use crate::message::{DNSClass, Message, Name, Question, RData, Rcode, Record, RecordType};
    use crate::plugin::PluginRegistry;
    use crate::plugin::executor::mikrotik::api::RouterListEntry;
    use crate::plugin::executor::mikrotik::manager::{
        OwnedCommentKind, decode_owned_comment, encode_comment,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[derive(Debug, Default)]
    struct MockApiState {
        entries: AHashMap<String, RouterListEntry>,
        next_id: u64,
        fail_next_upsert: bool,
        fail_healthcheck: bool,
        upsert_v4: u64,
        upsert_v6: u64,
        update_ops: u64,
    }

    #[derive(Debug, Clone)]
    struct MockMikrotikApi {
        state: Arc<Mutex<MockApiState>>,
    }

    impl Default for MockMikrotikApi {
        fn default() -> Self {
            Self {
                state: Arc::new(Mutex::new(MockApiState::default())),
            }
        }
    }

    impl MockMikrotikApi {
        fn storage_key(key: &AddressListKey) -> String {
            format!("{:?}:{}:{}", key.family, key.list, key.normalized_value())
        }

        fn seed_entry(&self, entry: RouterListEntry) {
            if let Ok(mut state) = self.state.lock() {
                state.entries.insert(Self::storage_key(&entry.key), entry);
            }
        }

        fn entry_count(&self) -> usize {
            self.state
                .lock()
                .map(|state| state.entries.len())
                .unwrap_or_default()
        }
    }

    #[async_trait]
    impl MikrotikApi for MockMikrotikApi {
        async fn list_entries(
            &self,
            list4: Option<&str>,
            list6: Option<&str>,
        ) -> Result<Vec<RouterListEntry>> {
            let state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            Ok(state
                .entries
                .values()
                .filter(|entry| match entry.key.family {
                    AddressListFamily::Ipv4 => list4 == Some(entry.key.list.as_str()),
                    AddressListFamily::Ipv6 => list6 == Some(entry.key.list.as_str()),
                })
                .cloned()
                .collect())
        }

        async fn upsert_owned_entry(
            &self,
            key: &AddressListKey,
            timeout: Option<&str>,
            comment: &str,
            comment_prefix: &str,
            plugin_tag: &str,
            refresh_timeout: bool,
        ) -> Result<Option<String>> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            if state.fail_next_upsert {
                state.fail_next_upsert = false;
                return Err(DnsError::plugin("mock upsert failure"));
            }

            let existing = state
                .entries
                .values()
                .filter(|entry| entry.key == *key)
                .cloned()
                .collect::<Vec<_>>();
            let mut owned = existing
                .iter()
                .filter(|entry| {
                    decode_owned_comment(comment_prefix, plugin_tag, entry.comment.as_deref())
                        .is_some()
                })
                .cloned()
                .collect::<Vec<_>>();
            let has_foreign = existing.len() > owned.len();
            if owned.is_empty() && has_foreign {
                return Ok(None);
            }

            if let Some(mut entry) = owned.pop() {
                let timeout_changed = entry.timeout.as_deref() != timeout;
                let comment_changed = entry.comment.as_deref() != Some(comment);
                if refresh_timeout || timeout_changed || comment_changed {
                    entry.timeout = timeout.map(str::to_string);
                    entry.comment = Some(comment.to_string());
                    state.update_ops = state.update_ops.saturating_add(1);
                    state.entries.insert(Self::storage_key(key), entry.clone());
                }
                return Ok(Some(entry.id));
            }

            state.next_id = state.next_id.saturating_add(1);
            let id = format!("*{}", state.next_id);
            match key.family {
                AddressListFamily::Ipv4 => state.upsert_v4 = state.upsert_v4.saturating_add(1),
                AddressListFamily::Ipv6 => state.upsert_v6 = state.upsert_v6.saturating_add(1),
            }
            state.entries.insert(
                Self::storage_key(key),
                RouterListEntry {
                    id: id.clone(),
                    key: key.clone(),
                    timeout: timeout.map(str::to_string),
                    comment: Some(comment.to_string()),
                },
            );
            Ok(Some(id))
        }

        async fn delete_entry_by_id(&self, id: &str, _family: AddressListFamily) -> Result<()> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            let key = state
                .entries
                .iter()
                .find(|(_, entry)| entry.id == id)
                .map(|(key, _)| key.clone());
            if let Some(key) = key {
                state.entries.remove(&key);
            }
            Ok(())
        }

        async fn healthcheck(&self) -> Result<()> {
            let state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            if state.fail_healthcheck {
                return Err(DnsError::plugin("mock healthcheck failure"));
            }
            Ok(())
        }
    }

    fn default_cfg(tag: &str) -> AddressListManagerConfig {
        AddressListManagerConfig {
            plugin_tag: tag.to_string(),
            address_list4: Some("forgedns_ipv4".to_string()),
            address_list6: Some("forgedns_ipv6".to_string()),
            persistent_items: AHashSet::new(),
            comment_prefix: "forgedns".to_string(),
            min_ttl: DEFAULT_MIN_TTL,
            max_ttl: DEFAULT_MAX_TTL,
            fixed_ttl: None,
        }
    }

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        DnsContext::new(
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap(),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn response_with_records(records: Vec<Record>) -> Message {
        let mut resp = Message::new();
        resp.set_rcode(Rcode::NoError);
        for record in records {
            resp.answers_mut().push(record);
        }
        resp
    }

    fn a_record(ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(A(ip)),
        )
    }

    fn aaaa_record(ip: Ipv6Addr, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::AAAA(AAAA(ip)),
        )
    }

    fn build_executor_for_test(
        tag: &str,
        async_mode: bool,
        cleanup_on_shutdown: bool,
        address_list4: Option<&str>,
        address_list6: Option<&str>,
        api: Arc<dyn MikrotikApi>,
    ) -> MikrotikExecutor {
        let config = MikrotikConfig {
            address: "127.0.0.1:8728".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
            async_mode,
            address_list4: address_list4.map(|v| v.to_string()),
            address_list6: address_list6.map(|v| v.to_string()),
            persistent_items: AHashSet::new(),
            persistent_inline_items: AHashSet::new(),
            persistent_files: Vec::new(),
            comment_prefix: "forgedns".to_string(),
            min_ttl: DEFAULT_MIN_TTL,
            max_ttl: DEFAULT_MAX_TTL,
            fixed_ttl: None,
            cleanup_on_shutdown,
        };
        let manager_cfg = AddressListManagerConfig {
            plugin_tag: tag.to_string(),
            address_list4: config.address_list4.clone(),
            address_list6: config.address_list6.clone(),
            persistent_items: config.persistent_items.clone(),
            comment_prefix: config.comment_prefix.clone(),
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            fixed_ttl: config.fixed_ttl,
        };
        MikrotikExecutor {
            tag: tag.to_string(),
            config,
            manager: Some(AddressListManager::new(api, manager_cfg)),
            command_tx: None,
            runtime: Mutex::new(None),
        }
    }

    async fn yield_until(description: &str, mut predicate: impl FnMut() -> bool) {
        for _ in 0..64 {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("condition not met after yielding: {description}");
    }

    #[test]
    fn config_validation_requires_address_list() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("address_list4 or address_list6"));
    }

    #[test]
    fn config_validation_rejects_old_route_fields() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
address_list4: "forgedns_ipv4"
routing_table: "forgedns_dynamic"
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("routing_table"));
    }

    #[test]
    fn config_validation_rejects_old_persistent_route_key() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
address_list4: "forgedns_ipv4"
persistent_route:
  ips:
    - "1.1.1.1"
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("persistent_route"));
    }

    #[test]
    fn config_validation_defaults_comment_prefix() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
address_list4: "forgedns_ipv4"
"#,
        )
        .unwrap();
        let parsed = parse_plugin_config(Some(cfg), false).unwrap();
        assert_eq!(parsed.comment_prefix, DEFAULT_COMMENT_PREFIX);
    }

    #[test]
    fn config_validation_rejects_zero_fixed_ttl() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
address_list4: "forgedns_ipv4"
fixed_ttl: 0
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("fixed_ttl"));
    }

    #[test]
    fn config_validation_ignores_persistent_item_without_family_list() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
address_list4: "forgedns_ipv4"
persistent:
  ips:
    - "2001:db8::1"
"#,
        )
        .unwrap();
        let parsed = parse_plugin_config(Some(cfg), false).unwrap();
        assert!(parsed.persistent_items.is_empty());
    }

    #[test]
    fn persistent_file_content_is_loaded_and_normalized() {
        let files = parse_persistent_files(Some(vec!["persistent.txt".to_string()])).unwrap();
        let (loaded, ignored_by_family) = load_persistent_items_from_content(
            "persistent.files[0]",
            r#"
# comments are ignored
1.1.1.1
2001:db8::/64
0.0.0.0/0
"#,
            Some("forgedns_ipv4"),
            Some("forgedns_ipv6"),
        )
        .unwrap();

        assert_eq!(files, vec!["persistent.txt".to_string()]);
        assert!(loaded.contains(&AddressListKey::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            "forgedns_ipv4".to_string()
        )));
        assert!(
            loaded.contains(
                &AddressListKey::new_with_prefix(
                    IpAddr::V6("2001:db8::".parse().unwrap()),
                    64,
                    "forgedns_ipv6".to_string()
                )
                .unwrap()
            )
        );
        assert!(
            loaded.contains(
                &AddressListKey::new_with_prefix(
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    0,
                    "forgedns_ipv4".to_string()
                )
                .unwrap()
            )
        );
        assert_eq!(ignored_by_family, 0);
    }

    #[test]
    fn comment_codec_roundtrip() {
        let comment = encode_comment(
            "forgedns",
            "mk",
            OwnedCommentKind::Dynamic,
            Some("example.com"),
        );
        let meta = decode_owned_comment("forgedns", "mk", Some(comment.as_str())).unwrap();
        assert_eq!(meta.kind, OwnedCommentKind::Dynamic);
    }

    #[tokio::test]
    async fn dynamic_observation_creates_address_list_entry() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = AddressListManager::new(api.clone(), default_cfg("mk"));
        manager
            .observe_domain(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    ttl_secs: 120,
                }],
            )
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        let entry = state.entries.values().next().unwrap();
        assert_eq!(entry.key.list, "forgedns_ipv4");
        assert_eq!(entry.timeout.as_deref(), Some("120s"));
    }

    #[tokio::test]
    async fn repeated_dynamic_observation_refreshes_timeout() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = AddressListManager::new(api.clone(), default_cfg("mk"));
        let observed = ObservedAddr {
            addr: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            ttl_secs: 120,
        };
        manager
            .observe_domain("example.com".to_string(), vec![observed])
            .await
            .unwrap();
        manager
            .observe_domain(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: observed.addr,
                    ttl_secs: 300,
                }],
            )
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        let entry = state.entries.values().next().unwrap();
        assert_eq!(entry.timeout.as_deref(), Some("300s"));
        assert!(state.update_ops >= 1);
    }

    #[tokio::test]
    async fn repeated_dynamic_observation_with_same_ttl_is_suppressed_before_refresh_window() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = AddressListManager::new(api.clone(), default_cfg("mk"));
        let observed = ObservedAddr {
            addr: IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
            ttl_secs: 300,
        };
        manager
            .observe_domain_at_for_test("example.com".to_string(), vec![observed], 0)
            .await
            .unwrap();
        manager
            .observe_domain_at_for_test("example.com".to_string(), vec![observed], 10_000)
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        assert_eq!(state.upsert_v4, 1);
        assert_eq!(state.update_ops, 0);
    }

    #[tokio::test]
    async fn shorter_ttl_does_not_force_early_refresh() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = AddressListManager::new(api.clone(), default_cfg("mk"));
        let ip = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4));
        manager
            .observe_domain_at_for_test(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: ip,
                    ttl_secs: 300,
                }],
                0,
            )
            .await
            .unwrap();
        manager
            .observe_domain_at_for_test(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: ip,
                    ttl_secs: 60,
                }],
                10_000,
            )
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        let entry = state.entries.values().next().unwrap();
        assert_eq!(entry.timeout.as_deref(), Some("300s"));
        assert_eq!(state.update_ops, 0);
    }

    #[tokio::test]
    async fn failed_refresh_clears_cache_and_next_observation_retries_immediately() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = AddressListManager::new(api.clone(), default_cfg("mk"));
        let observed = ObservedAddr {
            addr: IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)),
            ttl_secs: 120,
        };
        manager
            .observe_domain_at_for_test("example.com".to_string(), vec![observed], 0)
            .await
            .unwrap();
        {
            let mut state = api.state.lock().unwrap();
            state.fail_next_upsert = true;
        }
        let err = manager
            .observe_domain_at_for_test("example.com".to_string(), vec![observed], 90_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mock upsert failure"));
        assert_eq!(manager.dynamic_cache_len(), 0);

        manager
            .observe_domain_at_for_test("example.com".to_string(), vec![observed], 90_000)
            .await
            .unwrap();
        let state = api.state.lock().unwrap();
        assert!(state.update_ops >= 1);
    }

    #[tokio::test]
    async fn persistent_entry_is_created_without_timeout() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.persistent_items.insert(
            AddressListKey::new_with_prefix(
                IpAddr::V4(Ipv4Addr::new(100, 64, 1, 0)),
                24,
                "forgedns_ipv4".to_string(),
            )
            .unwrap(),
        );
        let mut manager = AddressListManager::new(api.clone(), cfg);

        manager.reconcile().await.unwrap();

        let state = api.state.lock().unwrap();
        let entry = state.entries.values().next().unwrap();
        assert_eq!(entry.timeout, None);
        let meta = decode_owned_comment("forgedns", "mk", entry.comment.as_deref()).unwrap();
        assert_eq!(meta.kind, OwnedCommentKind::Persistent);
    }

    #[tokio::test]
    async fn persistent_update_replaces_removed_entries() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.persistent_items.insert(
            AddressListKey::new_with_prefix(
                IpAddr::V4(Ipv4Addr::new(100, 64, 2, 0)),
                24,
                "forgedns_ipv4".to_string(),
            )
            .unwrap(),
        );
        let mut manager = AddressListManager::new(api.clone(), cfg);
        manager.reconcile().await.unwrap();

        let mut updated = AHashSet::new();
        updated.insert(
            AddressListKey::new_with_prefix(
                IpAddr::V4(Ipv4Addr::new(100, 64, 3, 0)),
                24,
                "forgedns_ipv4".to_string(),
            )
            .unwrap(),
        );
        manager.update_persistent_items(updated).await.unwrap();

        let state = api.state.lock().unwrap();
        assert!(
            state
                .entries
                .values()
                .all(|entry| entry.key.address == IpAddr::V4(Ipv4Addr::new(100, 64, 3, 0)))
        );
    }

    #[tokio::test]
    async fn persistent_entry_wins_over_dynamic_timeout() {
        let api = Arc::new(MockMikrotikApi::default());
        let key = AddressListKey::new(
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            "forgedns_ipv4".to_string(),
        );
        let mut cfg = default_cfg("mk");
        cfg.persistent_items.insert(key.clone());
        let mut manager = AddressListManager::new(api.clone(), cfg);
        manager.reconcile().await.unwrap();

        manager
            .observe_domain(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    ttl_secs: 60,
                }],
            )
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        let entry = state
            .entries
            .get(&MockMikrotikApi::storage_key(&key))
            .unwrap();
        assert_eq!(entry.timeout, None);
    }

    #[tokio::test]
    async fn foreign_entry_conflict_is_left_untouched() {
        let api = Arc::new(MockMikrotikApi::default());
        let key = AddressListKey::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            "forgedns_ipv4".to_string(),
        );
        api.seed_entry(RouterListEntry {
            id: "*200".to_string(),
            key: key.clone(),
            timeout: Some("300s".to_string()),
            comment: Some("forgedns;pg=other;kind=dynamic;dm=foreign.example".to_string()),
        });
        let mut manager = AddressListManager::new(api.clone(), default_cfg("mk"));
        manager
            .observe_domain(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    ttl_secs: 60,
                }],
            )
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        let entry = state
            .entries
            .get(&MockMikrotikApi::storage_key(&key))
            .unwrap();
        assert_eq!(entry.id, "*200");
        assert_eq!(entry.timeout.as_deref(), Some("300s"));
    }

    #[tokio::test]
    async fn dynamic_cache_prune_removes_expired_entries() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = AddressListManager::new(api, default_cfg("mk"));
        manager
            .observe_domain_at_for_test(
                "example.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)),
                    ttl_secs: 60,
                }],
                0,
            )
            .await
            .unwrap();
        assert_eq!(manager.dynamic_cache_len(), 1);

        manager
            .prune_dynamic_cache_at_for_test(61_000)
            .await
            .unwrap();
        assert_eq!(manager.dynamic_cache_len(), 0);
    }

    #[tokio::test]
    async fn execute_returns_next() {
        let api = Arc::new(MockMikrotikApi::default()) as Arc<dyn MikrotikApi>;
        let mut executor =
            build_executor_for_test("mk", true, false, Some("forgedns_ipv4"), None, api);
        let _ = executor.init().await;
        let mut ctx = make_context();
        let step = executor.execute(&mut ctx).await.unwrap();
        assert!(matches!(step, ExecStep::Next));
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn continuation_skips_unconfigured_family() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut executor = build_executor_for_test(
            "mk",
            true,
            false,
            None,
            Some("forgedns_ipv6"),
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;
        let mut ctx = make_context();
        ctx.set_response(response_with_records(vec![
            a_record(Ipv4Addr::new(1, 1, 1, 1), 300),
            aaaa_record(Ipv6Addr::LOCALHOST, 300),
        ]));
        executor.execute_with_next(&mut ctx, None).await.unwrap();
        yield_until("ipv6 entry upsert", || {
            api.state.lock().unwrap().upsert_v6 >= 1
        })
        .await;

        let state = api.state.lock().unwrap();
        assert_eq!(state.upsert_v4, 0);
        assert!(state.upsert_v6 >= 1);
        drop(state);
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn async_false_waits_and_keeps_dns_result_on_add_failure() {
        let api = Arc::new(MockMikrotikApi::default());
        {
            let mut state = api.state.lock().unwrap();
            state.fail_next_upsert = true;
        }
        let mut executor = build_executor_for_test(
            "mk",
            false,
            false,
            Some("forgedns_ipv4"),
            None,
            api as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;

        let mut ctx = make_context();
        ctx.set_response(response_with_records(vec![a_record(
            Ipv4Addr::new(10, 0, 0, 1),
            300,
        )]));
        executor.execute_with_next(&mut ctx, None).await.unwrap();
        assert!(ctx.response().is_some());
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn async_true_uses_background_manager() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut executor = build_executor_for_test(
            "mk",
            true,
            false,
            Some("forgedns_ipv4"),
            None,
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;
        let mut ctx = make_context();
        ctx.set_response(response_with_records(vec![a_record(
            Ipv4Addr::new(6, 6, 6, 6),
            300,
        )]));
        executor.execute_with_next(&mut ctx, None).await.unwrap();
        yield_until("background manager entry creation", || {
            api.entry_count() > 0
        })
        .await;
        assert!(api.entry_count() > 0);
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn shutdown_cleanup_removes_only_owned_entries() {
        let api = Arc::new(MockMikrotikApi::default());
        let owned_key = AddressListKey::new(
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            "forgedns_ipv4".to_string(),
        );
        api.seed_entry(RouterListEntry {
            id: "*301".to_string(),
            key: owned_key.clone(),
            timeout: Some("300s".to_string()),
            comment: Some(encode_comment(
                "forgedns",
                "mk",
                OwnedCommentKind::Dynamic,
                Some("example.com"),
            )),
        });
        api.seed_entry(RouterListEntry {
            id: "*302".to_string(),
            key: AddressListKey::new(
                IpAddr::V4(Ipv4Addr::new(12, 12, 12, 12)),
                "forgedns_ipv4".to_string(),
            ),
            timeout: Some("300s".to_string()),
            comment: Some("forgedns;pg=other;kind=dynamic;dm=foreign.example".to_string()),
        });

        let mut executor = build_executor_for_test(
            "mk",
            true,
            true,
            Some("forgedns_ipv4"),
            None,
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;
        let _ = executor.destroy().await;

        let state = api.state.lock().unwrap();
        assert!(
            !state
                .entries
                .contains_key(&MockMikrotikApi::storage_key(&owned_key))
        );
        assert_eq!(state.entries.len(), 1);
    }
}
