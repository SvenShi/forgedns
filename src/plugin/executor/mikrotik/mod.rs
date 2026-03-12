/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `mikrotik` executor plugin.
//!
//! This executor is an observer-side effect stage designed to integrate with
//! ForgeDNS sequence pipelines. It does not alter DNS decisions or response
//! content. Instead, it watches final downstream DNS answers and synchronizes
//! host routes into a dedicated RouterOS routing table.
//!
//! Architecture overview:
//! - `execute()` is hot-path light and always returns `NextWithPost`.
//! - `post_execute()` extracts normalized query domain and unique A/AAAA IPs.
//! - route synchronization is delegated to a single-owner background
//!   `RouteManager` state machine.
//! - RouterOS API details are isolated in `MikrotikApi` adapter implementations.
//! - route metadata is persisted in RouterOS `comment` via `RouteCommentCodec`,
//!   allowing restart recovery without local state files.
//!
//! Behavior goals:
//! - maintain `/32` (IPv4) and `/128` (IPv6) host routes in configured table.
//! - support optional always-present CIDR routes via `persistent_route`.
//! - periodically reload persistent route files and keep route table in sync.
//! - preserve DNS hot-path latency (`async=true` uses non-blocking queue).
//! - provide blocking write-before-return mode (`async=false`) without
//!   affecting DNS response result.
//! - avoid long-term route pollution via TTL sweep + startup reconciliation +
//!   optional shutdown cleanup.
//! - assume routing table/rule/default routes are already provisioned by users.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::message::ResponseCode;
use crate::plugin::executor::{ExecResult, ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::{AHashMap, AHashSet};
use async_trait::async_trait;
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

const DEFAULT_MIN_TTL: u32 = 60;
const DEFAULT_MAX_TTL: u32 = 3600;
const DEFAULT_ASYNC_MODE: bool = true;
const DEFAULT_CLEANUP_ON_SHUTDOWN: bool = true;
const DEFAULT_ROUTE_DISTANCE: u8 = 100;
const DEFAULT_COMMENT_PREFIX: &str = "fdns";
const SYNC_OBSERVE_TIMEOUT_SECS: u64 = 8;

#[derive(Debug, Clone, Deserialize, Default)]
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
    /// Dedicated RouterOS routing table for managed routes.
    routing_table: Option<String>,
    /// IPv4 gateway value for managed IPv4 routes.
    gateway4: Option<String>,
    /// IPv6 gateway value for managed IPv6 routes.
    gateway6: Option<String>,
    /// Prefix used in RouterOS route comments to mark ForgeDNS-managed routes.
    /// Defaults to `fdns` when omitted.
    comment_prefix: Option<String>,
    /// Route distance written to RouterOS for managed routes.
    distance: Option<u8>,
    /// Always-present routes that should not expire with DNS TTL.
    persistent_route: Option<PersistentRouteArgs>,
    /// Minimum effective TTL clamp (seconds) for observed records.
    min_ttl: Option<u32>,
    /// Maximum effective TTL clamp (seconds) for observed records.
    max_ttl: Option<u32>,
    /// Optional fixed TTL override (seconds) for dynamic observed records.
    fixed_ttl: Option<u32>,
    /// Whether to clean managed dynamic routes on shutdown.
    cleanup_on_shutdown: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PersistentRouteArgs {
    /// Inline always-present IPs/CIDRs. Plain IP is normalized to host route.
    ips: Option<Vec<String>>,
    /// File list that provides always-present IPs.
    files: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct MikrotikConfig {
    /// RouterOS API endpoint.
    address: String,
    /// RouterOS login username.
    username: String,
    /// RouterOS login password.
    password: String,
    /// Async mode switch for post stage RouterOS writes.
    async_mode: bool,
    /// Dedicated RouterOS routing table for this plugin.
    routing_table: String,
    /// Optional IPv4 gateway.
    gateway4: Option<String>,
    /// Optional IPv6 gateway.
    gateway6: Option<String>,
    /// Always-present routes in normalized CIDR format (`ip/prefix`).
    persistent_ips: AHashSet<String>,
    /// Inline persistent routes in normalized CIDR format.
    persistent_inline_ips: AHashSet<String>,
    /// Persistent route source files for periodic reload.
    persistent_files: Vec<String>,
    /// Managed route comment prefix.
    comment_prefix: String,
    /// Route distance written to RouterOS.
    distance: u8,
    /// Minimum effective TTL clamp in seconds.
    min_ttl: u32,
    /// Maximum effective TTL clamp in seconds.
    max_ttl: u32,
    /// Optional fixed TTL override in seconds.
    fixed_ttl: Option<u32>,
    /// Shutdown cleanup behavior for dynamic routes.
    cleanup_on_shutdown: bool,
}

impl MikrotikConfigArgs {
    fn into_config(self, emit_warnings: bool) -> Result<MikrotikConfig> {
        let address = required_non_empty(self.address, "address")?;
        let username = required_non_empty(self.username, "username")?;
        let password = required_non_empty(self.password, "password")?;
        let routing_table = required_non_empty(self.routing_table, "routing_table")?;
        let comment_prefix = optional_non_empty(self.comment_prefix)
            .unwrap_or_else(|| DEFAULT_COMMENT_PREFIX.to_string());
        validate_comment_token("comment_prefix", &comment_prefix)?;
        let distance = self.distance.unwrap_or(DEFAULT_ROUTE_DISTANCE);

        let gateway4 = optional_non_empty(self.gateway4);
        let gateway6 = optional_non_empty(self.gateway6);
        if gateway4.is_none() && gateway6.is_none() {
            return Err(DnsError::plugin(
                "mikrotik requires at least one of gateway4 or gateway6",
            ));
        }

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
        let parsed_persistent = parse_persistent_ips(
            self.persistent_route,
            gateway4.is_some(),
            gateway6.is_some(),
        )?;
        let ignored_by_gateway = parsed_persistent.ignored_by_gateway;
        if emit_warnings && ignored_by_gateway > 0 {
            warn!(
                ignored = ignored_by_gateway,
                "mikrotik persistent_route ignored entries without corresponding gateway family"
            );
        }
        let ignored_default_route = parsed_persistent.ignored_default_route;
        if emit_warnings && ignored_default_route > 0 {
            warn!(
                ignored = ignored_default_route,
                "mikrotik persistent_route ignored default-route entries (/0)"
            );
        }

        Ok(MikrotikConfig {
            address,
            username,
            password,
            async_mode: self.async_mode.unwrap_or(DEFAULT_ASYNC_MODE),
            routing_table,
            gateway4,
            gateway6,
            persistent_ips: parsed_persistent.all_ips,
            persistent_inline_ips: parsed_persistent.inline_ips,
            persistent_files: parsed_persistent.files,
            comment_prefix,
            distance,
            min_ttl,
            max_ttl,
            fixed_ttl,
            cleanup_on_shutdown: self
                .cleanup_on_shutdown
                .unwrap_or(DEFAULT_CLEANUP_ON_SHUTDOWN),
        })
    }
}

mod api;
mod manager;

use self::api::{MikrotikApi, MikrotikRsClient};
use self::manager::{
    ManagerCommand, ObservedAddr, PersistentReloadConfig, RouteManager, RouteManagerConfig,
    RouteManagerRuntime,
};

#[derive(Debug)]
struct MikrotikExecutor {
    tag: String,
    config: MikrotikConfig,
    manager: Option<RouteManager>,
    command_tx: Option<mpsc::Sender<ManagerCommand>>,
    runtime: Mutex<Option<RouteManagerRuntime>>,
}

#[async_trait]
impl Plugin for MikrotikExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
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
            inline_ips: self.config.persistent_inline_ips.clone(),
            files: self.config.persistent_files.clone(),
            initial_ips: self.config.persistent_ips.clone(),
            gateway4_enabled: self.config.gateway4.is_some(),
            gateway6_enabled: self.config.gateway6.is_some(),
        });
        let runtime = RouteManagerRuntime::start(self.tag.clone(), manager, persistent_reload);
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
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        Ok(ExecStep::NextWithPost(None))
    }

    async fn post_execute(
        &self,
        context: &mut DnsContext,
        _state: Option<ExecState>,
    ) -> ExecResult {
        let Some(tx) = self.command_tx.as_ref() else {
            return Ok(());
        };

        let Some((domain, addrs)) = extract_observation(context, &self.config) else {
            return Ok(());
        };

        if self.config.async_mode {
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
            return Ok(());
        }

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
                return Ok(());
            }
            Err(_) => {
                warn!(
                    plugin = %self.tag,
                    timeout_secs = SYNC_OBSERVE_TIMEOUT_SECS,
                    "mikrotik observe enqueue timed out in sync mode, DNS response is kept unchanged"
                );
                return Ok(());
            }
        }

        let wait_outcome =
            tokio::time::timeout(Duration::from_secs(SYNC_OBSERVE_TIMEOUT_SECS), wait_rx).await;
        match wait_outcome {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(e))) => {
                warn!(
                    plugin = %self.tag,
                    err = %e,
                    "mikrotik observe failed in sync mode, DNS response is kept unchanged"
                );
                Ok(())
            }
            Ok(Err(_)) => {
                warn!(
                    plugin = %self.tag,
                    "mikrotik manager dropped sync observe response, DNS response is kept unchanged"
                );
                Ok(())
            }
            Err(_) => {
                warn!(
                    plugin = %self.tag,
                    timeout_secs = SYNC_OBSERVE_TIMEOUT_SECS,
                    "mikrotik observe timed out in sync mode, DNS response is kept unchanged"
                );
                Ok(())
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
        validate_comment_token("plugin tag", plugin_config.tag.as_str())?;
        let config = parse_plugin_config(plugin_config.args.clone(), true)?;
        let api = Arc::new(MikrotikRsClient::new(
            config.address.clone(),
            config.username.clone(),
            config.password.clone(),
        )) as Arc<dyn MikrotikApi>;

        let manager_cfg = RouteManagerConfig {
            plugin_tag: plugin_config.tag.clone(),
            routing_table: config.routing_table.clone(),
            gateway4: config.gateway4.clone(),
            gateway6: config.gateway6.clone(),
            persistent_ips: config.persistent_ips.clone(),
            comment_prefix: config.comment_prefix.clone(),
            distance: config.distance,
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            fixed_ttl: config.fixed_ttl,
        };
        let manager = RouteManager::new(api, manager_cfg);

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
    // Prefer normalized query view if available; fallback to raw request question.
    let domain = context
        .question()
        .map(|question| question.normalized_name().to_string())
        .or_else(|| {
            context
                .request
                .first_question_name_owned()
                .map(|name| DnsContext::normalize_dns_name(&name))
        })?;

    if context.response.response_code()? != u16::from(ResponseCode::NoError) {
        return None;
    }

    // Collapse duplicated A/AAAA answers by IP and keep max TTL per IP.
    let mut dedup = AHashMap::<IpAddr, u32>::new();
    for (ip, ttl_secs) in context.response.answer_ip_ttls() {
        match ip {
            IpAddr::V4(_) if config.gateway4.is_none() => continue,
            IpAddr::V6(_) if config.gateway6.is_none() => continue,
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

/// Require non-empty string config fields and keep trimmed value.
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

/// Convert optional string to trimmed non-empty value.
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
struct ParsedPersistentRoutes {
    all_ips: AHashSet<String>,
    inline_ips: AHashSet<String>,
    files: Vec<String>,
    ignored_by_gateway: usize,
    ignored_default_route: usize,
}

/// Parse always-present route list from inline args and optional files.
///
/// Accepted item formats:
/// - `1.1.1.1`
/// - `2001:db8::1`
/// - generic CIDR: `1.1.1.0/24`, `2001:db8::/64`
///
/// Entries whose IP family has no corresponding configured gateway are skipped.
fn parse_persistent_ips(
    persistent_route: Option<PersistentRouteArgs>,
    gateway4_enabled: bool,
    gateway6_enabled: bool,
) -> Result<ParsedPersistentRoutes> {
    let mut parsed = ParsedPersistentRoutes::default();
    let Some(route) = persistent_route else {
        return Ok(parsed);
    };

    if let Some(ips) = route.ips {
        for (index, item) in ips.into_iter().enumerate() {
            let source = format!("persistent_route.ips[{index}]");
            let cidr = parse_persistent_ip_item(item.as_str(), source.as_str())?;
            if is_default_route_cidr(cidr.as_str()) {
                parsed.ignored_default_route = parsed.ignored_default_route.saturating_add(1);
                continue;
            }
            if !is_persistent_ip_family_enabled(
                cidr.as_str(),
                gateway4_enabled,
                gateway6_enabled,
                source.as_str(),
            )? {
                parsed.ignored_by_gateway = parsed.ignored_by_gateway.saturating_add(1);
                continue;
            }
            parsed.inline_ips.insert(cidr.clone());
            parsed.all_ips.insert(cidr);
        }
    }

    parsed.files = parse_persistent_route_files(route.files)?;
    let (file_ips, ignored_from_files, ignored_default_from_files) =
        load_persistent_ips_from_files(
            parsed.files.as_slice(),
            gateway4_enabled,
            gateway6_enabled,
        )?;
    parsed.ignored_by_gateway = parsed.ignored_by_gateway.saturating_add(ignored_from_files);
    parsed.ignored_default_route = parsed
        .ignored_default_route
        .saturating_add(ignored_default_from_files);
    parsed.all_ips.extend(file_ips);

    Ok(parsed)
}

fn parse_persistent_route_files(files: Option<Vec<String>>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let Some(files) = files else {
        return Ok(out);
    };
    for (index, file_raw) in files.into_iter().enumerate() {
        let file = file_raw.trim();
        if file.is_empty() {
            return Err(DnsError::plugin(format!(
                "mikrotik persistent_route.files[{index}] cannot be empty"
            )));
        }
        out.push(file.to_string());
    }
    Ok(out)
}

fn load_persistent_ips_from_content(
    source_prefix: &str,
    content: &str,
    gateway4_enabled: bool,
    gateway6_enabled: bool,
) -> Result<(AHashSet<String>, usize, usize)> {
    let mut out = AHashSet::new();
    let mut ignored_by_gateway = 0usize;
    let mut ignored_default_route = 0usize;

    for (line_no, line) in content.lines().enumerate() {
        let token = line.split('#').next().unwrap_or_default().trim();
        if token.is_empty() {
            continue;
        }

        let source = format!("{source_prefix} line {}", line_no + 1);
        let cidr = parse_persistent_ip_item(token, source.as_str())?;
        if is_default_route_cidr(cidr.as_str()) {
            ignored_default_route = ignored_default_route.saturating_add(1);
            continue;
        }
        if !is_persistent_ip_family_enabled(
            cidr.as_str(),
            gateway4_enabled,
            gateway6_enabled,
            source.as_str(),
        )? {
            ignored_by_gateway = ignored_by_gateway.saturating_add(1);
            continue;
        }
        out.insert(cidr);
    }

    Ok((out, ignored_by_gateway, ignored_default_route))
}

pub(super) fn load_persistent_ips_from_files(
    files: &[String],
    gateway4_enabled: bool,
    gateway6_enabled: bool,
) -> Result<(AHashSet<String>, usize, usize)> {
    let mut out = AHashSet::new();
    let mut ignored_by_gateway = 0usize;
    let mut ignored_default_route = 0usize;

    for (index, file) in files.iter().enumerate() {
        let content = fs::read_to_string(file).map_err(|e| {
            DnsError::plugin(format!(
                "mikrotik failed to read persistent route file '{file}': {e}"
            ))
        })?;
        let source_prefix = format!("persistent_route.files[{index}]");
        let (loaded, ignored_by_gateway_delta, ignored_default_delta) =
            load_persistent_ips_from_content(
                source_prefix.as_str(),
                &content,
                gateway4_enabled,
                gateway6_enabled,
            )?;
        out.extend(loaded);
        ignored_by_gateway = ignored_by_gateway.saturating_add(ignored_by_gateway_delta);
        ignored_default_route = ignored_default_route.saturating_add(ignored_default_delta);
    }

    Ok((out, ignored_by_gateway, ignored_default_route))
}

pub(super) async fn load_persistent_ips_from_files_async(
    files: &[String],
    gateway4_enabled: bool,
    gateway6_enabled: bool,
) -> Result<(AHashSet<String>, usize, usize)> {
    let mut out = AHashSet::new();
    let mut ignored_by_gateway = 0usize;
    let mut ignored_default_route = 0usize;

    for (index, file) in files.iter().enumerate() {
        let content = tokio_fs::read_to_string(file).await.map_err(|e| {
            DnsError::plugin(format!(
                "mikrotik failed to read persistent route file '{file}': {e}"
            ))
        })?;
        let source_prefix = format!("persistent_route.files[{index}]");
        let (loaded, ignored_by_gateway_delta, ignored_default_delta) =
            load_persistent_ips_from_content(
                source_prefix.as_str(),
                &content,
                gateway4_enabled,
                gateway6_enabled,
            )?;
        out.extend(loaded);
        ignored_by_gateway = ignored_by_gateway.saturating_add(ignored_by_gateway_delta);
        ignored_default_route = ignored_default_route.saturating_add(ignored_default_delta);
    }

    Ok((out, ignored_by_gateway, ignored_default_route))
}

/// Parse one persistent item and normalize into `ip/prefix`.
///
/// Rules:
/// - plain IPv4/IPv6 becomes `/32` or `/128`
/// - CIDR keeps its configured prefix and is normalized to network address
fn parse_persistent_ip_item(raw: &str, source: &str) -> Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(DnsError::plugin(format!("mikrotik {source} is empty")));
    }

    if let Some((ip_raw, prefix_raw)) = value.split_once('/') {
        let ip = ip_raw.trim().parse::<IpAddr>().map_err(|e| {
            DnsError::plugin(format!("mikrotik {source} has invalid ip '{ip_raw}': {e}"))
        })?;
        let prefix = prefix_raw.trim().parse::<u8>().map_err(|e| {
            DnsError::plugin(format!(
                "mikrotik {source} has invalid prefix '{prefix_raw}': {e}"
            ))
        })?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(DnsError::plugin(format!(
                "mikrotik {source} has invalid prefix /{prefix} for {ip}, max /{max_prefix}"
            )));
        }
        let network_ip = normalize_network_ip(ip, prefix);
        return Ok(format!("{network_ip}/{prefix}"));
    }

    let ip = value.parse::<IpAddr>().map_err(|e| {
        DnsError::plugin(format!("mikrotik {source} has invalid ip '{value}': {e}"))
    })?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    Ok(format!("{ip}/{prefix}"))
}

fn normalize_network_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(addr) => {
            let raw = u32::from(addr);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(raw & mask))
        }
        IpAddr::V6(addr) => {
            let raw = u128::from(addr);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(raw & mask))
        }
    }
}

#[inline]
fn is_default_route_cidr(cidr: &str) -> bool {
    cidr == "0.0.0.0/0" || cidr == "::/0"
}

/// Check whether this persistent route's family is enabled by gateway config.
///
/// Returns `Ok(false)` when family gateway is not configured so caller can skip
/// the item without failing plugin startup.
fn is_persistent_ip_family_enabled(
    cidr: &str,
    gateway4_enabled: bool,
    gateway6_enabled: bool,
    source: &str,
) -> Result<bool> {
    let (ip_raw, _) = cidr.split_once('/').ok_or_else(|| {
        DnsError::plugin(format!(
            "mikrotik {source} has invalid normalized route '{cidr}'"
        ))
    })?;
    let ip = ip_raw.parse::<IpAddr>().map_err(|e| {
        DnsError::plugin(format!(
            "mikrotik {source} has invalid normalized route '{cidr}': {e}"
        ))
    })?;

    match ip {
        IpAddr::V4(_) if !gateway4_enabled => Ok(false),
        IpAddr::V6(_) if !gateway6_enabled => Ok(false),
        _ => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::rdata::{A, AAAA};
    use crate::message::{Message, Question};
    use crate::message::{Name, RData, Record, RecordType};
    use crate::plugin::PluginRegistry;
    use crate::plugin::executor::mikrotik::api::RouterRoute;
    use crate::plugin::executor::mikrotik::manager::{
        RouteCommentCodec, RouteEntry, RouteFamily, RouteKey, SyncState,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

    #[derive(Debug, Default)]
    struct MockApiState {
        routes: AHashMap<String, RouterRoute>,
        next_id: u64,
        fail_next_upsert: bool,
        fail_healthcheck: bool,
        fail_gateway_validation: bool,
        gateway_validation_calls: u64,
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
        fn key(family: RouteFamily, table: &str, dst: &str) -> String {
            format!("{:?}:{table}:{dst}", family)
        }

        fn matches_owner(comment: Option<&str>, comment_prefix: &str, plugin_tag: &str) -> bool {
            let Some(comment) = comment else {
                return false;
            };
            if !comment_prefix.is_empty() {
                if !comment.starts_with(comment_prefix) {
                    return false;
                }
                if comment.as_bytes().get(comment_prefix.len()) != Some(&b';') {
                    return false;
                }
            }
            comment
                .split(';')
                .filter_map(|token| token.split_once('='))
                .any(|(k, v)| k.trim() == "pg" && v.trim() == plugin_tag)
        }

        fn seed_route(&self, route: RouterRoute) {
            let key = Self::key(route.family, &route.routing_table, &route.dst_address);
            if let Ok(mut state) = self.state.lock() {
                state.routes.insert(key, route);
            }
        }

        fn route_count(&self) -> usize {
            self.state
                .lock()
                .map(|state| state.routes.len())
                .unwrap_or_default()
        }
    }

    #[async_trait]
    impl MikrotikApi for MockMikrotikApi {
        async fn list_managed_routes(&self, table: &str) -> Result<Vec<RouterRoute>> {
            let state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            Ok(state
                .routes
                .values()
                .filter(|route| route.routing_table == table)
                .cloned()
                .collect())
        }

        async fn find_route(
            &self,
            key: &RouteKey,
            comment_prefix: &str,
            plugin_tag: &str,
        ) -> Result<Option<RouterRoute>> {
            let state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            let route = state
                .routes
                .get(&Self::key(key.family(), &key.table, &key.dst_address()))
                .cloned();
            if let Some(route) = route {
                if Self::matches_owner(route.comment.as_deref(), comment_prefix, plugin_tag) {
                    return Ok(Some(route));
                }
            }
            Ok(None)
        }

        async fn upsert_host_route(
            &self,
            key: &RouteKey,
            gateway: &str,
            distance: u8,
            comment: &str,
            comment_prefix: &str,
            plugin_tag: &str,
        ) -> Result<String> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            if state.fail_next_upsert {
                state.fail_next_upsert = false;
                return Err(DnsError::plugin("mock upsert failure"));
            }
            let k = Self::key(key.family(), &key.table, &key.dst_address());
            if let Some(existing) = state.routes.get_mut(&k) {
                if !Self::matches_owner(existing.comment.as_deref(), comment_prefix, plugin_tag) {
                    return Err(DnsError::plugin("mock upsert foreign route conflict"));
                }
                existing.gateway = Some(gateway.to_string());
                existing.distance = Some(distance);
                existing.comment = Some(comment.to_string());
                let id = existing.id.clone();
                state.update_ops = state.update_ops.saturating_add(1);
                return Ok(id);
            }

            state.next_id += 1;
            let id = format!("*{}", state.next_id);
            if key.family() == RouteFamily::Ipv4 {
                state.upsert_v4 += 1;
            } else {
                state.upsert_v6 += 1;
            }
            state.routes.insert(
                k,
                RouterRoute {
                    id: id.clone(),
                    family: key.family(),
                    dst_address: key.dst_address(),
                    routing_table: key.table.clone(),
                    gateway: Some(gateway.to_string()),
                    distance: Some(distance),
                    comment: Some(comment.to_string()),
                },
            );
            Ok(id)
        }

        async fn validate_route_config(
            &self,
            _key: &RouteKey,
            _gateway: &str,
            _distance: u8,
            _comment: &str,
        ) -> Result<()> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            state.gateway_validation_calls = state.gateway_validation_calls.saturating_add(1);
            if state.fail_gateway_validation {
                return Err(DnsError::plugin("mock gateway validation failure"));
            }
            Ok(())
        }

        async fn delete_route_by_id(&self, id: &str, _family: RouteFamily) -> Result<()> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DnsError::plugin("mock api lock poisoned"))?;
            let key = state
                .routes
                .iter()
                .find(|(_, route)| route.id == id)
                .map(|(k, _)| k.clone());
            if let Some(key) = key {
                state.routes.remove(&key);
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

    fn default_cfg(tag: &str) -> RouteManagerConfig {
        RouteManagerConfig {
            plugin_tag: tag.to_string(),
            routing_table: "forgedns_dynamic".to_string(),
            gateway4: Some("172.16.1.2".to_string()),
            gateway6: Some("fe80::2%ether1".to_string()),
            persistent_ips: AHashSet::new(),
            comment_prefix: "forgedns".to_string(),
            distance: DEFAULT_ROUTE_DISTANCE,
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
        ));
        DnsContext::new(
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap(),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn response_with_records(records: Vec<Record>) -> Message {
        let mut resp = Message::new();
        resp.set_response_code(ResponseCode::NoError);
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
        gateway4: Option<&str>,
        gateway6: Option<&str>,
        api: Arc<dyn MikrotikApi>,
    ) -> MikrotikExecutor {
        let config = MikrotikConfig {
            address: "127.0.0.1:8728".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
            async_mode,
            routing_table: "forgedns_dynamic".to_string(),
            gateway4: gateway4.map(|v| v.to_string()),
            gateway6: gateway6.map(|v| v.to_string()),
            persistent_ips: AHashSet::new(),
            persistent_inline_ips: AHashSet::new(),
            persistent_files: Vec::new(),
            comment_prefix: "forgedns".to_string(),
            distance: DEFAULT_ROUTE_DISTANCE,
            min_ttl: DEFAULT_MIN_TTL,
            max_ttl: DEFAULT_MAX_TTL,
            fixed_ttl: None,
            cleanup_on_shutdown,
        };
        let manager_cfg = RouteManagerConfig {
            plugin_tag: tag.to_string(),
            routing_table: config.routing_table.clone(),
            gateway4: config.gateway4.clone(),
            gateway6: config.gateway6.clone(),
            persistent_ips: config.persistent_ips.clone(),
            comment_prefix: config.comment_prefix.clone(),
            distance: config.distance,
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            fixed_ttl: config.fixed_ttl,
        };
        MikrotikExecutor {
            tag: tag.to_string(),
            config,
            manager: Some(RouteManager::new(api, manager_cfg)),
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
    fn config_validation_requires_fields() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("routing_table"));
    }

    #[test]
    fn config_validation_rejects_invalid_ttl_range() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
min_ttl: 120
max_ttl: 60
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("min_ttl"));
    }

    #[test]
    fn config_validation_defaults_comment_prefix_and_distance() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
"#,
        )
        .unwrap();
        let parsed = parse_plugin_config(Some(cfg), false).unwrap();
        assert_eq!(parsed.comment_prefix, DEFAULT_COMMENT_PREFIX);
        assert_eq!(parsed.distance, DEFAULT_ROUTE_DISTANCE);
    }

    #[test]
    fn config_validation_rejects_zero_fixed_ttl() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
fixed_ttl: 0
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("fixed_ttl"));
    }

    #[test]
    fn config_validation_requires_any_gateway() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
comment_prefix: "forgedns"
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("gateway4 or gateway6"));
    }

    #[test]
    fn config_validation_rejects_comment_prefix_with_delimiter() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns;managed"
"#,
        )
        .unwrap();
        let err = parse_plugin_config(Some(cfg), false).unwrap_err();
        assert!(err.to_string().contains("comment_prefix"));
    }

    #[test]
    fn plugin_tag_validation_rejects_comment_delimiters() {
        let mut cfg = PluginConfig {
            tag: "mk;bad".to_string(),
            plugin_type: "mikrotik".to_string(),
            args: Some(
                serde_yml::from_str::<serde_yml::Value>(
                    r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
"#,
                )
                .unwrap(),
            ),
        };
        let factory = MikrotikFactory;
        let err = match factory.create(&cfg, Arc::new(PluginRegistry::new())) {
            Ok(_) => panic!("expected create to fail for invalid plugin tag"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("plugin tag"));

        cfg.tag = "mk=bad".to_string();
        let err = match factory.create(&cfg, Arc::new(PluginRegistry::new())) {
            Ok(_) => panic!("expected create to fail for invalid plugin tag"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("plugin tag"));
    }

    #[test]
    fn config_validation_ignores_persistent_ip_without_family_gateway() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
persistent_route:
  ips:
    - "2001:db8::1"
"#,
        )
        .unwrap();
        let parsed = parse_plugin_config(Some(cfg), false).unwrap();
        assert!(parsed.persistent_ips.is_empty());
    }

    #[test]
    fn persistent_route_file_content_is_loaded_and_normalized() {
        let files = parse_persistent_route_files(Some(vec!["persistent.txt".to_string()])).unwrap();
        let (loaded, ignored_by_gateway, ignored_default_route) = load_persistent_ips_from_content(
            "persistent_route.files[0]",
            r#"
# comments are ignored
1.1.1.1
2001:db8::1/128
"#,
            true,
            true,
        )
        .unwrap();

        assert_eq!(files, vec!["persistent.txt".to_string()]);
        assert!(loaded.contains("1.1.1.1/32"));
        assert!(loaded.contains("2001:db8::1/128"));
        assert_eq!(ignored_by_gateway, 0);
        assert_eq!(ignored_default_route, 0);
    }

    #[test]
    fn config_validation_normalizes_persistent_cidr_network() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
persistent_route:
  ips:
    - "100.64.1.123/24"
"#,
        )
        .unwrap();

        let parsed = parse_plugin_config(Some(cfg), false).unwrap();
        assert!(parsed.persistent_ips.contains("100.64.1.0/24"));
        assert!(!parsed.persistent_ips.contains("100.64.1.123/24"));
    }

    #[test]
    fn config_validation_ignores_persistent_default_route() {
        let cfg = serde_yml::from_str::<serde_yml::Value>(
            r#"
address: "1.1.1.1:8728"
username: "user"
password: "pass"
routing_table: "forgedns_dynamic"
gateway4: "172.16.1.2"
comment_prefix: "forgedns"
persistent_route:
  ips:
    - "0.0.0.0/0"
    - "100.64.1.0/24"
"#,
        )
        .unwrap();
        let parsed = parse_plugin_config(Some(cfg), false).unwrap();
        assert!(!parsed.persistent_ips.contains("0.0.0.0/0"));
        assert!(parsed.persistent_ips.contains("100.64.1.0/24"));
    }

    #[test]
    fn comment_codec_roundtrip() {
        let key = RouteKey::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "tbl".to_string());
        let mut domains = AHashSet::new();
        domains.insert("example.com".to_string());
        let route = RouteEntry {
            key: key.clone(),
            family: RouteFamily::Ipv4,
            gateway: "172.16.1.2".to_string(),
            distance: DEFAULT_ROUTE_DISTANCE,
            domains,
            comment_domain: "example.com".to_string(),
            domain_expiries: AHashMap::new(),
            ref_count: 1,
            expires_at_unix: 1000,
            last_refresh_unix: 900,
            router_id: Some("*1".to_string()),
            recovered_from_comment: false,
            sync_state: SyncState::Synced,
        };
        let prefix = "forgedns";
        let comment = RouteCommentCodec::encode(prefix, "mk_tag", &route);
        assert_eq!(
            comment,
            "forgedns;pg=mk_tag;dm=example.com;exp=1000;seen=900"
        );
        let decoded =
            RouteCommentCodec::decode(prefix, "mk_tag", route.family, "1.1.1.1/32", &comment)
                .unwrap()
                .unwrap();
        assert_eq!(decoded.ip, key.ip);
        assert_eq!(decoded.family, RouteFamily::Ipv4);
        assert_eq!(decoded.comment_domain, "example.com");
        assert_eq!(decoded.expires_at_unix, 1000);
        assert_eq!(decoded.last_refresh_unix, 900);
    }

    #[tokio::test]
    async fn same_ip_observed_repeatedly_creates_one_route() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api, default_cfg("mk"));
        manager
            .observe_domain(
                "example.com".to_string(),
                vec![
                    ObservedAddr {
                        addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        ttl_secs: 120,
                    },
                    ObservedAddr {
                        addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        ttl_secs: 240,
                    },
                ],
            )
            .await
            .unwrap();

        assert_eq!(manager.routes.len(), 1);
        let route = manager.routes.values().next().unwrap();
        assert_eq!(route.ref_count, 1);
        assert_eq!(route.distance, DEFAULT_ROUTE_DISTANCE);
    }

    #[tokio::test]
    async fn shared_ip_ref_count_is_correct() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api, default_cfg("mk"));
        let observed = ObservedAddr {
            addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ttl_secs: 120,
        };
        manager
            .observe_domain("a.com".to_string(), vec![observed])
            .await
            .unwrap();
        manager
            .observe_domain("b.com".to_string(), vec![observed])
            .await
            .unwrap();

        let route = manager.routes.values().next().unwrap();
        assert_eq!(route.ref_count, 2);
        assert!(route.domains.contains("a.com"));
        assert!(route.domains.contains("b.com"));
        assert_eq!(route.comment_domain, "a.com");
    }

    #[tokio::test]
    async fn domain_ip_diff_updates_refs() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api, default_cfg("mk"));

        manager
            .observe_domain(
                "a.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    ttl_secs: 120,
                }],
            )
            .await
            .unwrap();

        manager
            .observe_domain(
                "a.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                    ttl_secs: 120,
                }],
            )
            .await
            .unwrap();

        assert_eq!(manager.routes.len(), 1);
        let route = manager.routes.values().next().unwrap();
        assert_eq!(route.key.ip, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
    }

    #[tokio::test]
    async fn ttl_refresh_updates_expiry() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api, default_cfg("mk"));

        manager
            .observe_domain(
                "ttl.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
                    ttl_secs: 60,
                }],
            )
            .await
            .unwrap();
        let key = RouteKey::new(
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
            "forgedns_dynamic".to_string(),
        );
        let first_exp = manager.routes.get(&key).unwrap().expires_at_unix;

        manager
            .observe_domain(
                "ttl.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
                    ttl_secs: 3600,
                }],
            )
            .await
            .unwrap();
        let second_exp = manager.routes.get(&key).unwrap().expires_at_unix;

        assert!(second_exp >= first_exp);
    }

    #[tokio::test]
    async fn fixed_ttl_overrides_dns_record_ttl() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.fixed_ttl = Some(7);
        let mut manager = RouteManager::new(api, cfg);

        manager
            .observe_domain(
                "fixed-ttl.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
                    ttl_secs: 3600,
                }],
            )
            .await
            .unwrap();

        let key = RouteKey::new(
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
            "forgedns_dynamic".to_string(),
        );
        let route = manager.routes.get(&key).unwrap();
        assert_eq!(
            route
                .expires_at_unix
                .saturating_sub(route.last_refresh_unix),
            7
        );
    }

    #[tokio::test]
    async fn domain_expire_releases_reference() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api, default_cfg("mk"));

        manager
            .observe_domain(
                "expire.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    ttl_secs: 120,
                }],
            )
            .await
            .unwrap();

        let key = RouteKey::new(
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            "forgedns_dynamic".to_string(),
        );
        if let Some(binding) = manager.domain_bindings.get_mut("expire.com") {
            binding.expires_at_unix = 1;
            binding
                .ip_expiries
                .insert(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1);
        }
        if let Some(route) = manager.routes.get_mut(&key) {
            route.expires_at_unix = 1;
        }

        manager.sweep().await.unwrap();
        assert!(!manager.routes.contains_key(&key));
    }

    #[tokio::test]
    async fn persistent_ip_route_survives_sweep() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.persistent_ips.insert("100.64.1.0/24".to_string());
        let mut manager = RouteManager::new(api.clone(), cfg);

        manager.sweep().await.unwrap();
        let key = RouteKey::new_with_prefix(
            IpAddr::V4(Ipv4Addr::new(100, 64, 1, 0)),
            24,
            "forgedns_dynamic".to_string(),
        )
        .unwrap();
        assert!(manager.routes.contains_key(&key));

        if let Some(route) = manager.routes.get_mut(&key) {
            route.expires_at_unix = 1;
        }
        manager.sweep().await.unwrap();
        assert!(manager.routes.contains_key(&key));
    }

    #[tokio::test]
    async fn persistent_route_does_not_rewrite_on_each_sweep() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.persistent_ips.insert("100.64.2.0/24".to_string());
        let mut manager = RouteManager::new(api.clone(), cfg);

        manager.sweep().await.unwrap();
        let first_updates = api
            .state
            .lock()
            .map(|state| state.update_ops)
            .unwrap_or_default();

        manager.sweep().await.unwrap();
        let second_updates = api
            .state
            .lock()
            .map(|state| state.update_ops)
            .unwrap_or_default();

        assert_eq!(
            first_updates, second_updates,
            "unchanged persistent routes should not be rewritten during sweep"
        );
    }

    #[tokio::test]
    async fn persistent_route_update_replaces_removed_file_entries() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.persistent_ips.insert("100.64.2.0/24".to_string());
        let mut manager = RouteManager::new(api, cfg);

        manager.sweep().await.unwrap();
        let old_key = RouteKey::new_with_prefix(
            IpAddr::V4(Ipv4Addr::new(100, 64, 2, 0)),
            24,
            "forgedns_dynamic".to_string(),
        )
        .unwrap();
        assert!(manager.routes.contains_key(&old_key));

        let mut updated = AHashSet::new();
        updated.insert("100.64.3.0/24".to_string());
        manager.update_persistent_ips(updated).await.unwrap();

        let new_key = RouteKey::new_with_prefix(
            IpAddr::V4(Ipv4Addr::new(100, 64, 3, 0)),
            24,
            "forgedns_dynamic".to_string(),
        )
        .unwrap();
        assert!(!manager.routes.contains_key(&old_key));
        assert!(manager.routes.contains_key(&new_key));
    }

    #[tokio::test]
    async fn ipv6_ref_count_and_prefix_128() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api, default_cfg("mk"));
        let ip = Ipv6Addr::from_str("2404:6800:4004:82c::200e").unwrap();

        manager
            .observe_domain(
                "v6.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V6(ip),
                    ttl_secs: 300,
                }],
            )
            .await
            .unwrap();

        let route = manager.routes.values().next().unwrap();
        assert_eq!(route.key.prefix, 128);
        assert_eq!(route.ref_count, 1);
    }

    #[tokio::test]
    async fn dual_stack_routes_are_independent() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api.clone(), default_cfg("mk"));
        manager
            .observe_domain(
                "dual.com".to_string(),
                vec![
                    ObservedAddr {
                        addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        ttl_secs: 120,
                    },
                    ObservedAddr {
                        addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        ttl_secs: 120,
                    },
                ],
            )
            .await
            .unwrap();

        let state = api.state.lock().unwrap();
        assert!(state.upsert_v4 >= 1);
        assert!(state.upsert_v6 >= 1);
    }

    #[tokio::test]
    async fn only_aaaa_does_not_create_ipv4_route() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.gateway4 = None;
        let mut manager = RouteManager::new(api, cfg);
        manager
            .observe_domain(
                "aaaa-only.com".to_string(),
                vec![ObservedAddr {
                    addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    ttl_secs: 120,
                }],
            )
            .await
            .unwrap();

        assert_eq!(manager.routes.len(), 1);
        assert!(matches!(
            manager.routes.values().next().unwrap().family,
            RouteFamily::Ipv6
        ));
    }

    #[tokio::test]
    async fn reconcile_deletes_expired_recovered_route() {
        let api = Arc::new(MockMikrotikApi::default());
        let cfg = default_cfg("mk_tag");

        let key = RouteKey::new(
            IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)),
            cfg.routing_table.clone(),
        );
        let expired_route = RouteEntry {
            key: key.clone(),
            family: RouteFamily::Ipv4,
            gateway: cfg.gateway4.clone().unwrap(),
            distance: cfg.distance,
            domains: AHashSet::new(),
            comment_domain: "recover.example".to_string(),
            domain_expiries: AHashMap::new(),
            ref_count: 0,
            expires_at_unix: 1,
            last_refresh_unix: 1,
            router_id: Some("*999".to_string()),
            recovered_from_comment: true,
            sync_state: SyncState::Synced,
        };
        let comment =
            RouteCommentCodec::encode(&cfg.comment_prefix, &cfg.plugin_tag, &expired_route);

        api.seed_route(RouterRoute {
            id: "*999".to_string(),
            family: RouteFamily::Ipv4,
            dst_address: key.dst_address(),
            routing_table: cfg.routing_table.clone(),
            gateway: cfg.gateway4.clone(),
            distance: Some(cfg.distance),
            comment: Some(comment),
        });

        let mut manager = RouteManager::new(api.clone(), cfg);
        manager.reconcile().await.unwrap();

        let state = api.state.lock().unwrap();
        assert!(
            !state.routes.values().any(|route| route.id == "*999"),
            "expired recovered route should be deleted"
        );
    }

    #[tokio::test]
    async fn reconcile_repairs_gateway_and_comment_drift() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut manager = RouteManager::new(api.clone(), default_cfg("mk"));
        let observed_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));

        manager
            .observe_domain(
                "drift.com".to_string(),
                vec![ObservedAddr {
                    addr: observed_ip,
                    ttl_secs: 300,
                }],
            )
            .await
            .unwrap();

        let updates_before = api
            .state
            .lock()
            .map(|state| state.update_ops)
            .unwrap_or_default();

        {
            let mut state = api.state.lock().unwrap();
            let route = state
                .routes
                .values_mut()
                .find(|route| route.dst_address == "8.8.4.4/32")
                .expect("expected observed route to exist");
            route.gateway = Some("10.0.0.1".to_string());
            route.distance = Some(1);
            route.comment = Some("forgedns;pg=mk;dm=wrong.example;exp=1;seen=1".to_string());
        }

        manager.reconcile().await.unwrap();

        let state = api.state.lock().unwrap();
        let repaired = state
            .routes
            .values()
            .find(|route| route.dst_address == "8.8.4.4/32")
            .expect("expected observed route to remain");
        assert_eq!(repaired.gateway.as_deref(), Some("172.16.1.2"));
        assert_eq!(repaired.distance, Some(DEFAULT_ROUTE_DISTANCE));
        let comment = repaired.comment.as_deref().unwrap_or_default();
        assert!(
            comment.contains("pg=mk") && comment.contains("dm=drift.com"),
            "managed route comment should be rewritten to expected metadata"
        );
        assert!(
            state.update_ops > updates_before,
            "drift repair should perform an in-place route update"
        );
    }

    #[tokio::test]
    async fn pending_delete_fallback_does_not_delete_foreign_route() {
        let api = Arc::new(MockMikrotikApi::default());
        let cfg = default_cfg("mk");
        let distance = cfg.distance;
        let key = RouteKey::new(
            IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
            cfg.routing_table.clone(),
        );

        api.seed_route(RouterRoute {
            id: "*200".to_string(),
            family: RouteFamily::Ipv4,
            dst_address: key.dst_address(),
            routing_table: cfg.routing_table.clone(),
            gateway: cfg.gateway4.clone(),
            distance: Some(cfg.distance),
            comment: Some("forgedns;pg=other;dm=foreign.example;exp=999999;seen=1".to_string()),
        });

        let mut manager = RouteManager::new(api.clone(), cfg);
        manager.routes.insert(
            key.clone(),
            RouteEntry {
                key,
                family: RouteFamily::Ipv4,
                gateway: "172.16.1.2".to_string(),
                distance,
                domains: AHashSet::new(),
                comment_domain: String::new(),
                domain_expiries: AHashMap::new(),
                ref_count: 0,
                expires_at_unix: 1,
                last_refresh_unix: 1,
                router_id: None,
                recovered_from_comment: false,
                sync_state: SyncState::PendingDelete,
            },
        );

        manager.reconcile().await.unwrap();

        let state = api.state.lock().unwrap();
        assert!(
            state.routes.values().any(|route| route.id == "*200"),
            "foreign route should not be deleted by fallback lookup"
        );
    }

    #[tokio::test]
    async fn execute_returns_next_with_post() {
        let api = Arc::new(MockMikrotikApi::default()) as Arc<dyn MikrotikApi>;
        let mut executor =
            build_executor_for_test("mk", true, false, Some("172.16.1.2"), None, api);
        let _ = executor.init().await;
        let mut ctx = make_context();
        let step = executor.execute(&mut ctx).await.unwrap();
        assert!(matches!(step, ExecStep::NextWithPost(_)));
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn post_execute_skips_when_no_response() {
        let api = Arc::new(MockMikrotikApi::default()) as Arc<dyn MikrotikApi>;
        let mut executor =
            build_executor_for_test("mk", true, false, Some("172.16.1.2"), None, api);
        let _ = executor.init().await;
        let mut ctx = make_context();
        executor.post_execute(&mut ctx, None).await.unwrap();
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn init_fails_when_gateway_validation_fails() {
        let api = Arc::new(MockMikrotikApi::default());
        {
            let mut state = api.state.lock().unwrap();
            state.fail_gateway_validation = true;
        }
        let mut executor = build_executor_for_test(
            "mk",
            true,
            false,
            Some("172.16.1.2"),
            None,
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let err = executor.init().await.unwrap_err();
        assert!(err.to_string().contains("gateway4 validation failed"));
        assert_eq!(
            api.state.lock().unwrap().gateway_validation_calls,
            1,
            "startup should validate the configured gateway before running"
        );
    }

    #[tokio::test]
    async fn post_execute_skips_unconfigured_family() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut executor = build_executor_for_test(
            "mk",
            true,
            false,
            None,
            Some("fe80::2%ether1"),
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;
        let mut ctx = make_context();
        ctx.response.set_message(response_with_records(vec![
            a_record(Ipv4Addr::new(1, 1, 1, 1), 300),
            aaaa_record(Ipv6Addr::LOCALHOST, 300),
        ]));
        executor.post_execute(&mut ctx, None).await.unwrap();
        yield_until("ipv6 route upsert", || {
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
            Some("172.16.1.2"),
            None,
            api as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;

        let mut ctx = make_context();
        ctx.response
            .set_message(response_with_records(vec![a_record(
                Ipv4Addr::new(10, 0, 0, 1),
                300,
            )]));
        executor.post_execute(&mut ctx, None).await.unwrap();
        assert!(
            ctx.response.has_response(),
            "DNS response should be kept unchanged"
        );
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn async_true_uses_background_manager() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut executor = build_executor_for_test(
            "mk",
            true,
            false,
            Some("172.16.1.2"),
            None,
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;
        let mut ctx = make_context();
        ctx.response
            .set_message(response_with_records(vec![a_record(
                Ipv4Addr::new(6, 6, 6, 6),
                300,
            )]));
        executor.post_execute(&mut ctx, None).await.unwrap();
        yield_until("background manager route creation", || {
            api.route_count() > 0
        })
        .await;
        assert!(api.route_count() > 0);
        let _ = executor.destroy().await;
    }

    #[tokio::test]
    async fn shutdown_cleanup_removes_dynamic_routes() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut executor = build_executor_for_test(
            "mk",
            true,
            true,
            Some("172.16.1.2"),
            None,
            api.clone() as Arc<dyn MikrotikApi>,
        );
        let _ = executor.init().await;
        let mut ctx = make_context();
        ctx.response
            .set_message(response_with_records(vec![a_record(
                Ipv4Addr::new(11, 11, 11, 11),
                300,
            )]));
        executor.post_execute(&mut ctx, None).await.unwrap();
        yield_until("dynamic route creation before shutdown", || {
            api.route_count() > 0
        })
        .await;
        assert!(api.route_count() > 0);

        let _ = executor.destroy().await;
        let state = api.state.lock().unwrap();
        assert!(state.routes.is_empty(), "dynamic routes should be cleaned");
    }

    #[tokio::test]
    async fn shutdown_cleanup_removes_all_prefix_routes() {
        let api = Arc::new(MockMikrotikApi::default());
        let mut cfg = default_cfg("mk");
        cfg.persistent_ips.insert("203.0.113.7/32".to_string());
        let mut manager = RouteManager::new(api.clone(), cfg);

        manager.sweep().await.unwrap();

        api.seed_route(RouterRoute {
            id: "*301".to_string(),
            family: RouteFamily::Ipv4,
            dst_address: "203.0.113.8/32".to_string(),
            routing_table: "forgedns_dynamic".to_string(),
            gateway: Some("172.16.1.2".to_string()),
            distance: Some(DEFAULT_ROUTE_DISTANCE),
            comment: Some("forgedns;pg=other;dm=foreign.example;exp=999999;seen=1".to_string()),
        });
        api.seed_route(RouterRoute {
            id: "*302".to_string(),
            family: RouteFamily::Ipv4,
            dst_address: "203.0.113.9/32".to_string(),
            routing_table: "forgedns_dynamic".to_string(),
            gateway: Some("172.16.1.2".to_string()),
            distance: Some(DEFAULT_ROUTE_DISTANCE),
            comment: Some("other;pg=other".to_string()),
        });

        manager.shutdown(true).await.unwrap();

        let state = api.state.lock().unwrap();
        assert!(
            !state.routes.values().any(|route| route
                .comment
                .as_deref()
                .is_some_and(|comment| comment.starts_with("forgedns;"))),
            "cleanup should remove every route whose comment matches the configured prefix"
        );
        assert!(
            state.routes.values().any(|route| route.id == "*302"),
            "routes with a different comment prefix should be kept"
        );
    }
}
