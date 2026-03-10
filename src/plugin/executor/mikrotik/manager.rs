//! Route manager state machine for mikrotik executor.
//!
//! Responsibilities:
//! - maintain domain -> IP bindings with per-IP expiry
//! - maintain route-level reference states and router ids
//! - reconcile local state with RouterOS route table/comment metadata
//! - execute idempotent create/update/delete through [`MikrotikApi`]

use super::api::MikrotikApi;
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use ahash::{AHashMap, AHashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const ROUTE_DEFAULT_V4: &str = "0.0.0.0/0";
const ROUTE_DEFAULT_V6: &str = "::/0";
const ROUTE_PREFIX_V4: u8 = 32;
const ROUTE_PREFIX_V6: u8 = 128;
const PERSISTENT_ANCHOR_DOMAIN: &str = "__forgedns_persistent__";
const PERSISTENT_EXPIRES_AT_UNIX: u64 = u64::MAX;
const MANAGER_QUEUE_SIZE: usize = 1024;
const SWEEP_INTERVAL_SECS: u64 = 30;
const RECONCILE_INTERVAL_SECS: u64 = 180;
const PERSISTENT_RELOAD_INTERVAL_SECS: u64 = 60;
const SHUTDOWN_TIMEOUT_SECS: u64 = 8;

const COMMENT_FIELD_PLUGIN: &str = "pg";
const COMMENT_FIELD_DOMAIN: &str = "dm";
const COMMENT_FIELD_EXP: &str = "exp";
const COMMENT_FIELD_SEEN: &str = "seen";
static START_UNIX_SECS: OnceLock<u64> = OnceLock::new();

#[derive(Debug, Clone)]
pub(super) struct RouteManagerConfig {
    /// Plugin tag used in comment codec for ownership check.
    pub(super) plugin_tag: String,
    /// Dedicated RouterOS routing table name.
    pub(super) routing_table: String,
    /// Optional IPv4 gateway for managed routes.
    pub(super) gateway4: Option<String>,
    /// Optional IPv6 gateway for managed routes.
    pub(super) gateway6: Option<String>,
    /// Always-present routes in CIDR form (`ip/prefix`).
    pub(super) persistent_ips: AHashSet<String>,
    /// Comment prefix that marks managed routes.
    pub(super) comment_prefix: String,
    /// Route distance written to RouterOS.
    pub(super) distance: u8,
    /// Minimum TTL clamp in seconds.
    pub(super) min_ttl: u32,
    /// Maximum TTL clamp in seconds.
    pub(super) max_ttl: u32,
    /// Optional fixed TTL override in seconds.
    pub(super) fixed_ttl: Option<u32>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(super) enum RouteFamily {
    Ipv4,
    Ipv6,
}

impl RouteFamily {
    #[inline]
    pub(super) fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    #[inline]
    fn prefix(self) -> u8 {
        match self {
            Self::Ipv4 => ROUTE_PREFIX_V4,
            Self::Ipv6 => ROUTE_PREFIX_V6,
        }
    }

    #[inline]
    fn is_valid_prefix(self, prefix: u8) -> bool {
        match self {
            Self::Ipv4 => prefix <= 32,
            Self::Ipv6 => prefix <= 128,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(super) struct DomainBinding {
    /// Normalized domain name.
    pub(super) domain: String,
    /// Active IP set observed for this domain.
    pub(super) ips: AHashSet<IpAddr>,
    /// Per-IP expiry timestamp for this domain.
    pub(super) ip_expiries: AHashMap<IpAddr, u64>,
    /// Max expiry among `ip_expiries`.
    pub(super) expires_at_unix: u64,
    /// Last refresh timestamp.
    pub(super) last_refresh_unix: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct RouteKey {
    /// Route network/base IP address.
    pub(super) ip: IpAddr,
    /// Route CIDR prefix.
    pub(super) prefix: u8,
    /// RouterOS routing table name.
    pub(super) table: String,
}

impl RouteKey {
    pub(super) fn new(ip: IpAddr, table: String) -> Self {
        let prefix = RouteFamily::from_ip(ip).prefix();
        Self { ip, prefix, table }
    }

    pub(super) fn new_with_prefix(ip: IpAddr, prefix: u8, table: String) -> Option<Self> {
        let family = RouteFamily::from_ip(ip);
        if !family.is_valid_prefix(prefix) {
            return None;
        }
        Some(Self { ip, prefix, table })
    }

    #[inline]
    pub(super) fn family(&self) -> RouteFamily {
        RouteFamily::from_ip(self.ip)
    }

    #[inline]
    pub(super) fn dst_address(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum SyncState {
    /// Route does not exist on RouterOS yet (or local state intentionally
    /// forgot the remote id) and must be created on next sync pass.
    ///
    /// Typical transitions:
    /// - new observation creates a fresh route entry
    /// - reconcile detects a missing remote route for an in-use key
    /// - recovered entry lost its `router_id`
    PendingCreate,
    /// Local route state is consistent with RouterOS.
    ///
    /// In this state no API call is needed unless route payload changes
    /// (gateway/comment/expiry metadata) or ref-count drops to zero.
    Synced,
    /// Route should be removed from RouterOS on next sync pass.
    ///
    /// This is set when the route has no active dynamic references, or when a
    /// stale recovered route is identified during reconciliation/expiration.
    PendingDelete,
    /// Route exists remotely but local payload changed and requires an update.
    ///
    /// The sync loop handles this as an idempotent upsert (`set` or `add`
    /// depending on remote presence), then returns to `Synced`.
    Dirty,
}

#[derive(Debug, Clone)]
pub(super) struct RouteEntry {
    /// Unique key of the managed route.
    pub(super) key: RouteKey,
    /// Route family.
    pub(super) family: RouteFamily,
    /// Gateway string written to RouterOS.
    pub(super) gateway: String,
    /// Route distance written to RouterOS.
    pub(super) distance: u8,
    /// Domain set currently referencing this route.
    pub(super) domains: AHashSet<String>,
    /// Comment `dm` field, using the first observed active domain when available.
    pub(super) comment_domain: String,
    /// Per-domain expiry timestamps for ref-count and max-exp calculations.
    pub(super) domain_expiries: AHashMap<String, u64>,
    /// Current reference count from `domains`.
    pub(super) ref_count: u32,
    /// Route-level expiry (max of active refs).
    pub(super) expires_at_unix: u64,
    /// Last refresh timestamp.
    pub(super) last_refresh_unix: u64,
    /// RouterOS internal route id.
    pub(super) router_id: Option<String>,
    /// Whether route was restored from RouterOS comment metadata.
    pub(super) recovered_from_comment: bool,
    /// Pending/synced transition state for API sync loop.
    pub(super) sync_state: SyncState,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct RouteCommentMeta {
    pub(super) family: RouteFamily,
    pub(super) ip: IpAddr,
    pub(super) comment_domain: String,
    pub(super) expires_at_unix: u64,
    pub(super) last_refresh_unix: u64,
}

#[derive(Debug)]
pub(super) struct RouteCommentCodec;

impl RouteCommentCodec {
    /// Encode route metadata into RouterOS comment payload.
    pub(super) fn encode(prefix: &str, plugin_tag: &str, route: &RouteEntry) -> String {
        let mut out = String::new();
        if !prefix.is_empty() {
            out.push_str(prefix);
            out.push(';');
        }
        out.push_str(COMMENT_FIELD_PLUGIN);
        out.push('=');
        out.push_str(plugin_tag);
        out.push(';');
        out.push_str(COMMENT_FIELD_DOMAIN);
        out.push('=');
        out.push_str(&route.comment_domain);
        out.push(';');
        out.push_str(COMMENT_FIELD_EXP);
        out.push('=');
        out.push_str(&route.expires_at_unix.to_string());
        out.push(';');
        out.push_str(COMMENT_FIELD_SEEN);
        out.push('=');
        out.push_str(&route.last_refresh_unix.to_string());
        out
    }

    pub(super) fn decode(
        prefix: &str,
        plugin_tag: &str,
        family: RouteFamily,
        dst_address: &str,
        comment: &str,
    ) -> Result<Option<RouteCommentMeta>> {
        // Prefix and plugin-tag checks provide cheap ownership filtering.
        if !prefix.is_empty() {
            if !comment.starts_with(prefix) {
                return Ok(None);
            }
            if comment.as_bytes().get(prefix.len()) != Some(&b';') {
                return Ok(None);
            }
        }

        let mut kv = AHashMap::new();
        for token in comment.split(';') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some((k, v)) = token.split_once('=') {
                kv.insert(k.trim().to_string(), v.trim().to_string());
            }
        }

        if kv.get(COMMENT_FIELD_PLUGIN).map(String::as_str) != Some(plugin_tag) {
            return Ok(None);
        }

        let (ip, _prefix) = parse_dst_address(dst_address).ok_or_else(|| {
            DnsError::plugin(format!(
                "mikrotik comment decode failed: invalid dst-address '{dst_address}'"
            ))
        })?;

        if RouteFamily::from_ip(ip) != family {
            return Err(DnsError::plugin(format!(
                "mikrotik comment decode failed: af/ip mismatch af={:?} ip={}",
                family, ip
            )));
        }

        let comment_domain = kv
            .get(COMMENT_FIELD_DOMAIN)
            .ok_or_else(|| DnsError::plugin("mikrotik comment decode failed: missing dm field"))?
            .to_string();
        let expires_at_unix = kv
            .get(COMMENT_FIELD_EXP)
            .ok_or_else(|| DnsError::plugin("mikrotik comment decode failed: missing exp field"))?
            .parse::<u64>()
            .map_err(|e| {
                DnsError::plugin(format!("mikrotik comment decode failed: invalid exp: {e}"))
            })?;
        let last_refresh_unix = kv
            .get(COMMENT_FIELD_SEEN)
            .ok_or_else(|| DnsError::plugin("mikrotik comment decode failed: missing seen field"))?
            .parse::<u64>()
            .map_err(|e| {
                DnsError::plugin(format!("mikrotik comment decode failed: invalid seen: {e}"))
            })?;

        Ok(Some(RouteCommentMeta {
            family,
            ip,
            comment_domain,
            expires_at_unix,
            last_refresh_unix,
        }))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct ObservedAddr {
    pub(super) addr: IpAddr,
    pub(super) ttl_secs: u32,
}

#[derive(Debug)]
pub(super) enum ManagerCommand {
    ObserveDomain {
        domain: String,
        addrs: Vec<ObservedAddr>,
        wait: Option<oneshot::Sender<Result<()>>>,
    },
    UpdatePersistentIps {
        ips: AHashSet<String>,
    },
    Sweep,
    Reconcile,
    Shutdown {
        cleanup: bool,
        done: oneshot::Sender<()>,
    },
}

#[derive(Debug, Clone)]
pub(super) struct PersistentReloadConfig {
    /// Inline persistent routes in normalized `ip/prefix` format.
    pub(super) inline_ips: AHashSet<String>,
    /// Source files that contain persistent route entries.
    pub(super) files: Vec<String>,
    /// Initial desired set merged from inline + file content at startup.
    pub(super) initial_ips: AHashSet<String>,
    /// Whether IPv4 gateway is configured.
    pub(super) gateway4_enabled: bool,
    /// Whether IPv6 gateway is configured.
    pub(super) gateway6_enabled: bool,
}

#[derive(Debug)]
pub(super) struct RouteManagerRuntime {
    tx: mpsc::Sender<ManagerCommand>,
    worker_handle: Option<JoinHandle<()>>,
    sweep_handle: Option<JoinHandle<()>>,
    reconcile_handle: Option<JoinHandle<()>>,
    persistent_reload_handle: Option<JoinHandle<()>>,
}

impl RouteManagerRuntime {
    pub(super) fn start(
        tag: String,
        manager: RouteManager,
        persistent_reload: Option<PersistentReloadConfig>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<ManagerCommand>(MANAGER_QUEUE_SIZE);

        let worker_tag = tag.clone();
        let worker_handle = Some(tokio::spawn(async move {
            run_manager_worker(worker_tag, manager, rx).await;
        }));

        let sweep_tx = tx.clone();
        let sweep_handle = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if sweep_tx.send(ManagerCommand::Sweep).await.is_err() {
                    break;
                }
            }
        }));

        let reconcile_tx = tx.clone();
        let reconcile_handle = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(RECONCILE_INTERVAL_SECS));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if reconcile_tx.send(ManagerCommand::Reconcile).await.is_err() {
                    break;
                }
            }
        }));

        let persistent_reload_handle = persistent_reload.and_then(|reload_cfg| {
            if reload_cfg.initial_ips.is_empty() && reload_cfg.files.is_empty() {
                return None;
            }

            let maintain_tx = tx.clone();
            let maintain_tag = tag.clone();
            Some(tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(Duration::from_secs(PERSISTENT_RELOAD_INTERVAL_SECS));
                let mut last_loaded_ips = reload_cfg.initial_ips;
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    match super::load_persistent_ips_from_files_async(
                        reload_cfg.files.as_slice(),
                        reload_cfg.gateway4_enabled,
                        reload_cfg.gateway6_enabled,
                    )
                    .await
                    {
                        Ok((file_ips, ignored_by_gateway, ignored_default_route)) => {
                            if ignored_by_gateway > 0 {
                                debug!(
                                    plugin = %maintain_tag,
                                    ignored = ignored_by_gateway,
                                    "mikrotik persistent file reload ignored entries without corresponding gateway family"
                                );
                            }
                            if ignored_default_route > 0 {
                                debug!(
                                    plugin = %maintain_tag,
                                    ignored = ignored_default_route,
                                    "mikrotik persistent file reload ignored default-route entries (/0)"
                                );
                            }

                            let mut desired_ips = reload_cfg.inline_ips.clone();
                            desired_ips.extend(file_ips);

                            if desired_ips != last_loaded_ips {
                                last_loaded_ips = desired_ips.clone();
                                if maintain_tx
                                    .send(ManagerCommand::UpdatePersistentIps { ips: desired_ips })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }

                            // Dedicated tick keeps persistent routes self-healed
                            // without requiring new DNS observations.
                            if maintain_tx.send(ManagerCommand::Reconcile).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                plugin = %maintain_tag,
                                err = %e,
                                "mikrotik persistent file reload failed"
                            );
                        }
                    }
                }
            }))
        });

        Self {
            tx,
            worker_handle,
            sweep_handle,
            reconcile_handle,
            persistent_reload_handle,
        }
    }

    #[inline]
    pub(super) fn sender(&self) -> mpsc::Sender<ManagerCommand> {
        self.tx.clone()
    }

    pub(super) async fn shutdown(mut self, cleanup: bool) {
        let mut shutdown_acked = false;
        let (done_tx, done_rx) = oneshot::channel::<()>();
        let shutdown_cmd = ManagerCommand::Shutdown {
            cleanup,
            done: done_tx,
        };
        let sent = match self.tx.try_send(shutdown_cmd) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
            Err(mpsc::error::TrySendError::Full(shutdown_cmd)) => matches!(
                tokio::time::timeout(
                    Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
                    self.tx.send(shutdown_cmd),
                )
                .await,
                Ok(Ok(()))
            ),
        };
        if sent {
            shutdown_acked =
                tokio::time::timeout(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS), done_rx)
                    .await
                    .is_ok();
        }

        if let Some(handle) = self.sweep_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = self.reconcile_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = self.persistent_reload_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = self.worker_handle.take() {
            if shutdown_acked {
                let _ =
                    tokio::time::timeout(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS), handle).await;
            } else {
                handle.abort();
                let _ = handle.await;
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct RouteManager {
    api: Arc<dyn MikrotikApi>,
    cfg: RouteManagerConfig,
    persistent_ips: AHashSet<String>,
    pub(super) domain_bindings: AHashMap<String, DomainBinding>,
    pub(super) routes: AHashMap<RouteKey, RouteEntry>,
    initialized: bool,
}

impl RouteManager {
    pub(super) fn new(api: Arc<dyn MikrotikApi>, cfg: RouteManagerConfig) -> Self {
        Self {
            api,
            persistent_ips: cfg.persistent_ips.clone(),
            cfg,
            domain_bindings: AHashMap::new(),
            routes: AHashMap::new(),
            initialized: false,
        }
    }

    async fn ensure_initialized(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        // One-time bootstrap:
        // 1) transport healthcheck
        // 2) validate configured gateways against RouterOS
        // 3) seed persistent routes
        // 4) reconcile local state from RouterOS
        self.api.healthcheck().await?;
        self.validate_gateways().await?;
        self.ensure_persistent_routes(unix_now());
        self.reconcile_from_router().await?;
        self.initialized = true;
        Ok(())
    }

    pub(super) async fn initialize_on_startup(&mut self) -> Result<()> {
        self.ensure_initialized().await
    }

    #[inline]
    fn clamp_ttl(&self, ttl_secs: u32) -> u32 {
        if let Some(ttl) = self.cfg.fixed_ttl {
            return ttl;
        }
        ttl_secs.clamp(self.cfg.min_ttl, self.cfg.max_ttl)
    }

    #[inline]
    fn gateway_for(&self, family: RouteFamily) -> Option<&str> {
        match family {
            RouteFamily::Ipv4 => self.cfg.gateway4.as_deref(),
            RouteFamily::Ipv6 => self.cfg.gateway6.as_deref(),
        }
    }

    async fn validate_gateways(&self) -> Result<()> {
        if let Some(gateway) = self.cfg.gateway4.as_deref() {
            let nonce = validation_nonce();
            let key =
                validation_route_key(RouteFamily::Ipv4, self.cfg.routing_table.as_str(), nonce);
            let comment = validation_comment(
                self.cfg.comment_prefix.as_str(),
                self.cfg.plugin_tag.as_str(),
                RouteFamily::Ipv4,
                nonce,
            );
            self.api
                .validate_route_config(&key, gateway, self.cfg.distance, &comment)
                .await
                .map_err(|e| {
                    DnsError::plugin(format!(
                        "mikrotik gateway4 validation failed for '{gateway}': {e}"
                    ))
                })?;
        }

        if let Some(gateway) = self.cfg.gateway6.as_deref() {
            let nonce = validation_nonce();
            let key =
                validation_route_key(RouteFamily::Ipv6, self.cfg.routing_table.as_str(), nonce);
            let comment = validation_comment(
                self.cfg.comment_prefix.as_str(),
                self.cfg.plugin_tag.as_str(),
                RouteFamily::Ipv6,
                nonce,
            );
            self.api
                .validate_route_config(&key, gateway, self.cfg.distance, &comment)
                .await
                .map_err(|e| {
                    DnsError::plugin(format!(
                        "mikrotik gateway6 validation failed for '{gateway}': {e}"
                    ))
                })?;
        }

        Ok(())
    }

    fn ensure_persistent_routes(&mut self, now: u64) {
        // Persistent IPs are represented as a synthetic anchor domain so they
        // naturally fit existing ref-count and expiration aggregation logic.
        let anchor = PERSISTENT_ANCHOR_DOMAIN.to_string();
        let mut desired_keys = AHashSet::new();
        let persistent_ips = self.persistent_ips.iter().cloned().collect::<Vec<_>>();
        for cidr in persistent_ips {
            let Some((ip, prefix)) = parse_dst_address(&cidr) else {
                warn!(
                    plugin = %self.cfg.plugin_tag,
                    route = %cidr,
                    "mikrotik persistent route parse failed, skipping"
                );
                continue;
            };
            let family = RouteFamily::from_ip(ip);
            if !family.is_valid_prefix(prefix) {
                warn!(
                    plugin = %self.cfg.plugin_tag,
                    route = %cidr,
                    "mikrotik persistent route prefix is invalid for family, skipping"
                );
                continue;
            }
            let Some(gateway) = self.gateway_for(family).map(str::to_string) else {
                continue;
            };
            let Some(key) = RouteKey::new_with_prefix(ip, prefix, self.cfg.routing_table.clone())
            else {
                continue;
            };
            desired_keys.insert(key.clone());

            if let Some(entry) = self.routes.get_mut(&key) {
                let mut changed = false;

                if entry.domains.insert(anchor.clone()) {
                    entry.ref_count = entry.ref_count.saturating_add(1);
                    changed = true;
                }
                if entry.ref_count == 0 {
                    entry.ref_count = 1;
                    changed = true;
                }
                if entry
                    .domain_expiries
                    .insert(anchor.clone(), PERSISTENT_EXPIRES_AT_UNIX)
                    != Some(PERSISTENT_EXPIRES_AT_UNIX)
                {
                    changed = true;
                }
                if entry.expires_at_unix != PERSISTENT_EXPIRES_AT_UNIX {
                    entry.expires_at_unix = PERSISTENT_EXPIRES_AT_UNIX;
                    changed = true;
                }
                if entry.gateway != gateway {
                    entry.gateway = gateway.clone();
                    changed = true;
                }
                if entry.distance != self.cfg.distance {
                    entry.distance = self.cfg.distance;
                    changed = true;
                }

                if entry.router_id.is_none() {
                    if !matches!(entry.sync_state, SyncState::PendingCreate) {
                        entry.sync_state = SyncState::PendingCreate;
                        changed = true;
                    }
                } else if matches!(entry.sync_state, SyncState::PendingDelete)
                    || (changed && matches!(entry.sync_state, SyncState::Synced))
                {
                    entry.sync_state = SyncState::Dirty;
                    changed = true;
                }

                if changed {
                    entry.last_refresh_unix = now;
                }
                continue;
            }

            let mut domains = AHashSet::new();
            domains.insert(PERSISTENT_ANCHOR_DOMAIN.to_string());
            let mut domain_expiries = AHashMap::new();
            domain_expiries.insert(
                PERSISTENT_ANCHOR_DOMAIN.to_string(),
                PERSISTENT_EXPIRES_AT_UNIX,
            );
            self.routes.insert(
                key.clone(),
                RouteEntry {
                    key,
                    family,
                    gateway,
                    distance: self.cfg.distance,
                    domains,
                    comment_domain: "persistent".to_string(),
                    domain_expiries,
                    ref_count: 1,
                    expires_at_unix: PERSISTENT_EXPIRES_AT_UNIX,
                    last_refresh_unix: now,
                    router_id: None,
                    recovered_from_comment: false,
                    sync_state: SyncState::PendingCreate,
                },
            );
        }

        // Remove persistent anchor from routes that are no longer configured by
        // persistent IP sources (e.g. file content changed).
        let anchored_keys = self
            .routes
            .iter()
            .filter_map(|(key, entry)| {
                if entry.domains.contains(PERSISTENT_ANCHOR_DOMAIN) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for key in anchored_keys {
            if desired_keys.contains(&key) {
                continue;
            }
            let Some(entry) = self.routes.get_mut(&key) else {
                continue;
            };
            if !entry.domains.remove(PERSISTENT_ANCHOR_DOMAIN) {
                continue;
            }
            entry.domain_expiries.remove(PERSISTENT_ANCHOR_DOMAIN);
            entry.ref_count = entry.ref_count.saturating_sub(1);
            entry.last_refresh_unix = now;

            if entry.ref_count == 0 {
                entry.expires_at_unix = now;
                entry.sync_state = SyncState::PendingDelete;
            } else {
                entry.expires_at_unix =
                    entry.domain_expiries.values().copied().max().unwrap_or(now);
                if matches!(entry.sync_state, SyncState::Synced) {
                    entry.sync_state = SyncState::Dirty;
                }
            }
        }
    }

    fn apply_observation(
        &mut self,
        domain: String,
        addrs: Vec<ObservedAddr>,
        now: u64,
    ) -> Vec<RouteKey> {
        let mut touched_keys = AHashSet::new();
        // Deduplicate answer IPs and keep max ttl per IP for this observation.
        let mut dedup_expiries = AHashMap::<IpAddr, u64>::new();
        for observed in addrs {
            let family = RouteFamily::from_ip(observed.addr);
            if self.gateway_for(family).is_none() {
                continue;
            }
            let ttl = self.clamp_ttl(observed.ttl_secs.max(1));
            let expires_at_unix = now.saturating_add(ttl as u64);
            dedup_expiries
                .entry(observed.addr)
                .and_modify(|existing| *existing = (*existing).max(expires_at_unix))
                .or_insert(expires_at_unix);
        }
        if dedup_expiries.is_empty() {
            return Vec::new();
        }

        let removed_ips = self
            .domain_bindings
            .get(&domain)
            .map(|binding| {
                binding
                    .ips
                    .iter()
                    .filter(|ip| !dedup_expiries.contains_key(ip))
                    .copied()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for ip in removed_ips {
            if let Some(key) = self.detach_domain_from_route(&domain, ip, now) {
                touched_keys.insert(key);
            }
        }

        let mut new_ips = AHashSet::with_capacity(dedup_expiries.len());
        for (ip, expiry) in &dedup_expiries {
            new_ips.insert(*ip);
            if let Some(key) = self.attach_or_refresh_route(&domain, *ip, *expiry, now) {
                touched_keys.insert(key);
            }
        }

        let expires_at_unix = dedup_expiries.values().copied().max().unwrap_or(now);
        self.domain_bindings.insert(
            domain.clone(),
            DomainBinding {
                domain,
                ips: new_ips,
                ip_expiries: dedup_expiries,
                expires_at_unix,
                last_refresh_unix: now,
            },
        );

        touched_keys.into_iter().collect()
    }

    fn attach_or_refresh_route(
        &mut self,
        domain: &str,
        ip: IpAddr,
        expires_at: u64,
        now: u64,
    ) -> Option<RouteKey> {
        let key = RouteKey::new(ip, self.cfg.routing_table.clone());
        if let Some(entry) = self.routes.get_mut(&key) {
            let inserted = entry.domains.insert(domain.to_string());
            if inserted
                && domain != PERSISTENT_ANCHOR_DOMAIN
                && (entry.ref_count == 0 || entry.comment_domain.is_empty())
            {
                entry.comment_domain = domain.to_string();
            }
            if inserted {
                entry.ref_count = entry.ref_count.saturating_add(1);
            }
            entry.domain_expiries.insert(domain.to_string(), expires_at);
            entry.expires_at_unix = entry
                .domain_expiries
                .values()
                .copied()
                .max()
                .unwrap_or(expires_at);
            entry.last_refresh_unix = now;
            entry.recovered_from_comment = false;

            if entry.router_id.is_none() {
                entry.sync_state = SyncState::PendingCreate;
            } else if matches!(
                entry.sync_state,
                SyncState::Synced | SyncState::PendingDelete
            ) {
                entry.sync_state = SyncState::Dirty;
            }
            return Some(key);
        }

        let family = RouteFamily::from_ip(ip);
        let Some(gateway) = self.gateway_for(family).map(str::to_string) else {
            return None;
        };
        let mut domains = AHashSet::new();
        domains.insert(domain.to_string());
        let mut domain_expiries = AHashMap::new();
        domain_expiries.insert(domain.to_string(), expires_at);

        self.routes.insert(
            key.clone(),
            RouteEntry {
                key: key.clone(),
                family,
                gateway,
                distance: self.cfg.distance,
                domains,
                comment_domain: domain.to_string(),
                domain_expiries,
                ref_count: 1,
                expires_at_unix: expires_at,
                last_refresh_unix: now,
                router_id: None,
                recovered_from_comment: false,
                sync_state: SyncState::PendingCreate,
            },
        );
        Some(key)
    }

    fn detach_domain_from_route(&mut self, domain: &str, ip: IpAddr, now: u64) -> Option<RouteKey> {
        let key = RouteKey::new(ip, self.cfg.routing_table.clone());
        let Some(entry) = self.routes.get_mut(&key) else {
            return None;
        };

        if !entry.domains.remove(domain) {
            return None;
        }

        entry.domain_expiries.remove(domain);
        entry.ref_count = entry.ref_count.saturating_sub(1);
        entry.last_refresh_unix = now;
        if entry.comment_domain == domain || entry.comment_domain.is_empty() {
            entry.comment_domain = select_comment_domain(&entry.domains);
        }

        if entry.ref_count == 0 {
            entry.expires_at_unix = now;
            entry.sync_state = SyncState::PendingDelete;
        } else {
            entry.expires_at_unix = entry.domain_expiries.values().copied().max().unwrap_or(now);
            if matches!(entry.sync_state, SyncState::Synced) {
                entry.sync_state = SyncState::Dirty;
            }
        }
        Some(key)
    }

    fn expire_domain_bindings(&mut self, now: u64) {
        let domains = self.domain_bindings.keys().cloned().collect::<Vec<_>>();
        for domain in domains {
            let mut to_remove = Vec::new();
            let mut remove_binding = false;

            if let Some(binding) = self.domain_bindings.get_mut(&domain) {
                if binding.expires_at_unix <= now {
                    to_remove.extend(binding.ips.iter().copied());
                } else {
                    for (ip, exp) in &binding.ip_expiries {
                        if *exp <= now {
                            to_remove.push(*ip);
                        }
                    }
                }

                for ip in &to_remove {
                    binding.ips.remove(ip);
                    binding.ip_expiries.remove(ip);
                }
                binding.expires_at_unix = binding.ip_expiries.values().copied().max().unwrap_or(0);
                remove_binding = binding.ips.is_empty();
            }

            for ip in &to_remove {
                self.detach_domain_from_route(&domain, *ip, now);
            }
            if remove_binding {
                self.domain_bindings.remove(&domain);
            }
        }
    }

    fn update_route_expiration(&mut self, now: u64) {
        for route in self.routes.values_mut() {
            if route.ref_count == 0 {
                if route.expires_at_unix <= now {
                    route.sync_state = SyncState::PendingDelete;
                }
                continue;
            }

            let max_exp = route.domain_expiries.values().copied().max().unwrap_or(now);
            if max_exp != route.expires_at_unix {
                route.expires_at_unix = max_exp;
                if matches!(route.sync_state, SyncState::Synced) {
                    route.sync_state = SyncState::Dirty;
                }
            }
        }
    }

    async fn sync_routes(&mut self, now: u64) -> Result<()> {
        let keys = self.routes.keys().cloned().collect::<Vec<_>>();
        self.sync_route_keys(keys, now).await
    }

    async fn sync_route_keys(&mut self, keys: Vec<RouteKey>, now: u64) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        // Snapshot-first loop avoids borrow conflicts and keeps each key operation atomic.
        for key in keys {
            let entry_snapshot =
                self.routes.get(&key).cloned().ok_or_else(|| {
                    DnsError::plugin("mikrotik route state disappeared during sync")
                })?;

            match entry_snapshot.sync_state {
                SyncState::PendingCreate | SyncState::Dirty if entry_snapshot.ref_count > 0 => {
                    // Upsert route with latest gateway/comment metadata.
                    let comment = RouteCommentCodec::encode(
                        &self.cfg.comment_prefix,
                        &self.cfg.plugin_tag,
                        &entry_snapshot,
                    );
                    let route_id = self
                        .api
                        .upsert_host_route(
                            &entry_snapshot.key,
                            &entry_snapshot.gateway,
                            entry_snapshot.distance,
                            &comment,
                            &self.cfg.comment_prefix,
                            &self.cfg.plugin_tag,
                        )
                        .await?;
                    if let Some(route) = self.routes.get_mut(&key) {
                        route.router_id = Some(route_id);
                        route.recovered_from_comment = false;
                        route.sync_state = SyncState::Synced;
                        route.last_refresh_unix = now;
                    }
                }
                SyncState::PendingDelete => {
                    // Delete by known id first; fallback to find-by-key for crash-recovery cases.
                    if let Some(id) = entry_snapshot.router_id.as_deref() {
                        self.api
                            .delete_route_by_id(id, entry_snapshot.family)
                            .await?;
                    } else if let Some(found) = self
                        .api
                        .find_route(
                            &entry_snapshot.key,
                            &self.cfg.comment_prefix,
                            &self.cfg.plugin_tag,
                        )
                        .await?
                    {
                        self.api.delete_route_by_id(&found.id, found.family).await?;
                    }
                    self.routes.remove(&key);
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn reconcile_from_router(&mut self) -> Result<()> {
        // Reconcile algorithm:
        // 1) scan RouterOS rows in target table
        // 2) recover managed rows by comment metadata
        // 3) mark missing local entries as create/delete candidates
        // 4) execute one sync pass
        let now = unix_now();
        let rows = self
            .api
            .list_managed_routes(&self.cfg.routing_table)
            .await?;
        let mut seen_keys = AHashSet::new();

        for route in rows {
            if is_default_route_dst(&route.dst_address) {
                continue;
            }

            let Some((ip, prefix)) = parse_dst_address(&route.dst_address) else {
                continue;
            };
            let family = RouteFamily::from_ip(ip);
            if !family.is_valid_prefix(prefix) {
                continue;
            }

            let Some(comment) = route.comment.as_deref() else {
                continue;
            };
            let meta = match RouteCommentCodec::decode(
                &self.cfg.comment_prefix,
                &self.cfg.plugin_tag,
                route.family,
                &route.dst_address,
                comment,
            ) {
                Ok(Some(meta)) => meta,
                Ok(None) => continue,
                Err(e) => {
                    warn!(
                        plugin = %self.cfg.plugin_tag,
                        route_id = %route.id,
                        err = %e,
                        "mikrotik route comment parse failed, treating as unknown residue"
                    );
                    continue;
                }
            };
            if meta.family != family || meta.ip != ip {
                warn!(
                    plugin = %self.cfg.plugin_tag,
                    route_id = %route.id,
                    dst = %route.dst_address,
                    "mikrotik route comment metadata mismatches route dst, skipping recovery"
                );
                continue;
            }

            let Some(key) = RouteKey::new_with_prefix(ip, prefix, self.cfg.routing_table.clone())
            else {
                continue;
            };
            seen_keys.insert(key.clone());

            if let Some(existing) = self.routes.get_mut(&key) {
                existing.router_id = Some(route.id.clone());
                if existing.ref_count == 0 {
                    existing.comment_domain = meta.comment_domain.clone();
                    existing.expires_at_unix = meta.expires_at_unix;
                    existing.last_refresh_unix = meta.last_refresh_unix;
                    existing.sync_state = if meta.expires_at_unix <= now {
                        SyncState::PendingDelete
                    } else {
                        SyncState::Synced
                    };
                    let gateway_drift = route.gateway.as_deref() != Some(existing.gateway.as_str());
                    let distance_drift = route.distance != Some(existing.distance);
                    let expected_comment = RouteCommentCodec::encode(
                        &self.cfg.comment_prefix,
                        &self.cfg.plugin_tag,
                        existing,
                    );
                    let comment_drift = route.comment.as_deref() != Some(expected_comment.as_str());
                    if gateway_drift || distance_drift || comment_drift {
                        existing.sync_state = SyncState::Dirty;
                    }
                } else {
                    let gateway_drift = route.gateway.as_deref() != Some(existing.gateway.as_str());
                    let distance_drift = route.distance != Some(existing.distance);
                    let expected_comment = RouteCommentCodec::encode(
                        &self.cfg.comment_prefix,
                        &self.cfg.plugin_tag,
                        existing,
                    );
                    let comment_drift = route.comment.as_deref() != Some(expected_comment.as_str());
                    if gateway_drift
                        || distance_drift
                        || comment_drift
                        || matches!(existing.sync_state, SyncState::PendingCreate)
                    {
                        existing.sync_state = SyncState::Dirty;
                    }
                }
                continue;
            }

            let Some(gateway) = self.gateway_for(family).map(str::to_string) else {
                continue;
            };
            let mut entry = RouteEntry {
                key: key.clone(),
                family,
                gateway,
                distance: self.cfg.distance,
                domains: AHashSet::new(),
                comment_domain: meta.comment_domain,
                domain_expiries: AHashMap::new(),
                ref_count: 0,
                expires_at_unix: meta.expires_at_unix,
                last_refresh_unix: meta.last_refresh_unix,
                router_id: Some(route.id.clone()),
                recovered_from_comment: true,
                sync_state: if meta.expires_at_unix <= now {
                    SyncState::PendingDelete
                } else {
                    SyncState::Synced
                },
            };
            if !matches!(entry.sync_state, SyncState::PendingDelete) {
                let gateway_drift = route.gateway.as_deref() != Some(entry.gateway.as_str());
                let distance_drift = route.distance != Some(entry.distance);
                let expected_comment = RouteCommentCodec::encode(
                    &self.cfg.comment_prefix,
                    &self.cfg.plugin_tag,
                    &entry,
                );
                let comment_drift = route.comment.as_deref() != Some(expected_comment.as_str());
                if gateway_drift || distance_drift || comment_drift {
                    entry.sync_state = SyncState::Dirty;
                }
            }
            self.routes.insert(key.clone(), entry);
        }

        let keys = self.routes.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            if seen_keys.contains(&key) {
                continue;
            }
            let Some(route) = self.routes.get_mut(&key) else {
                continue;
            };
            if route.ref_count > 0 {
                route.router_id = None;
                route.sync_state = SyncState::PendingCreate;
            } else {
                route.sync_state = SyncState::PendingDelete;
            }
        }

        self.sync_routes(now).await?;
        Ok(())
    }

    pub(super) async fn observe_domain(
        &mut self,
        domain: String,
        addrs: Vec<ObservedAddr>,
    ) -> Result<()> {
        self.ensure_initialized().await?;
        let now = unix_now();
        let touched = self.apply_observation(domain, addrs, now);
        self.sync_route_keys(touched, now).await
    }

    pub(super) async fn sweep(&mut self) -> Result<()> {
        self.ensure_initialized().await?;
        let now = unix_now();
        self.ensure_persistent_routes(now);
        self.expire_domain_bindings(now);
        self.update_route_expiration(now);
        self.sync_routes(now).await
    }

    pub(super) async fn update_persistent_ips(&mut self, ips: AHashSet<String>) -> Result<()> {
        self.ensure_initialized().await?;
        self.persistent_ips = ips;
        let now = unix_now();
        self.ensure_persistent_routes(now);
        self.update_route_expiration(now);
        self.sync_routes(now).await
    }

    pub(super) async fn reconcile(&mut self) -> Result<()> {
        self.ensure_initialized().await?;
        self.ensure_persistent_routes(unix_now());
        self.reconcile_from_router().await?;
        Ok(())
    }

    pub(super) async fn shutdown(&mut self, cleanup: bool) -> Result<()> {
        if !cleanup {
            return Ok(());
        }
        self.ensure_initialized().await?;
        let routes = self
            .api
            .list_managed_routes(&self.cfg.routing_table)
            .await?;
        for route in routes {
            if comment_matches_prefix(route.comment.as_deref(), &self.cfg.comment_prefix) {
                self.api.delete_route_by_id(&route.id, route.family).await?;
            }
        }
        self.routes.clear();
        self.domain_bindings.clear();
        Ok(())
    }
}

fn comment_matches_prefix(comment: Option<&str>, prefix: &str) -> bool {
    let Some(comment) = comment else {
        return false;
    };
    if prefix.is_empty() {
        return true;
    }
    comment.starts_with(prefix) && comment.as_bytes().get(prefix.len()) == Some(&b';')
}

fn validation_nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn validation_route_key(family: RouteFamily, table: &str, nonce: u128) -> RouteKey {
    let ip = match family {
        RouteFamily::Ipv4 => {
            let third = ((nonce >> 8) & 0xff) as u8;
            let fourth = match (nonce & 0xff) as u8 {
                0 => 1,
                value => value,
            };
            IpAddr::V4(Ipv4Addr::new(198, 18, third, fourth))
        }
        RouteFamily::Ipv6 => {
            let seg5 = ((nonce >> 32) & 0xffff) as u16;
            let seg6 = ((nonce >> 16) & 0xffff) as u16;
            let seg7 = (nonce & 0xffff) as u16;
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, seg5, seg6, seg7, 1))
        }
    };
    RouteKey::new(ip, table.to_string())
}

fn validation_comment(prefix: &str, plugin_tag: &str, _family: RouteFamily, nonce: u128) -> String {
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
        out.push(';');
    }
    out.push_str("plugin=");
    out.push_str(plugin_tag);
    out.push_str(";kind=gateway-check");
    out.push_str(";nonce=");
    out.push_str(&nonce.to_string());
    out
}

fn select_comment_domain(domains: &AHashSet<String>) -> String {
    domains
        .iter()
        .filter(|domain| domain.as_str() != PERSISTENT_ANCHOR_DOMAIN)
        .min()
        .cloned()
        .unwrap_or_default()
}

async fn run_manager_worker(
    tag: String,
    mut manager: RouteManager,
    mut rx: mpsc::Receiver<ManagerCommand>,
) {
    // Single-owner event loop for route state.
    // All cross-map updates are serialized here to keep transitions deterministic.
    while let Some(command) = rx.recv().await {
        match command {
            ManagerCommand::ObserveDomain {
                domain,
                addrs,
                wait,
            } => {
                let result = manager.observe_domain(domain, addrs).await;
                match (wait, result) {
                    (Some(ch), outcome) => {
                        let _ = ch.send(outcome);
                    }
                    (None, Ok(())) => {}
                    (None, Err(e)) => {
                        warn!(
                            plugin = %tag,
                            err = %e,
                            "mikrotik observe failed in async mode"
                        );
                    }
                }
            }
            ManagerCommand::Sweep => {
                if let Err(e) = manager.sweep().await {
                    warn!(
                        plugin = %tag,
                        err = %e,
                        "mikrotik periodic sweep failed"
                    );
                }
            }
            ManagerCommand::UpdatePersistentIps { ips } => {
                if let Err(e) = manager.update_persistent_ips(ips).await {
                    warn!(
                        plugin = %tag,
                        err = %e,
                        "mikrotik persistent route maintenance failed"
                    );
                }
            }
            ManagerCommand::Reconcile => {
                if let Err(e) = manager.reconcile().await {
                    warn!(
                        plugin = %tag,
                        err = %e,
                        "mikrotik periodic reconcile failed"
                    );
                } else {
                    debug!(plugin = %tag, "mikrotik reconcile completed");
                }
            }
            ManagerCommand::Shutdown { cleanup, done } => {
                if let Err(e) = manager.shutdown(cleanup).await {
                    warn!(plugin = %tag, err = %e, "mikrotik shutdown cleanup failed");
                }
                let _ = done.send(());
                break;
            }
        }
    }

    debug!(plugin = %tag, "mikrotik manager worker exited");
}

fn parse_dst_address(dst: &str) -> Option<(IpAddr, u8)> {
    let (ip_raw, prefix_raw) = dst.split_once('/')?;
    let ip = ip_raw.parse::<IpAddr>().ok()?;
    let prefix = prefix_raw.parse::<u8>().ok()?;
    Some((ip, prefix))
}

pub(super) fn is_default_route_dst(dst: &str) -> bool {
    dst == ROUTE_DEFAULT_V4 || dst == ROUTE_DEFAULT_V6
}

#[inline]
fn unix_now() -> u64 {
    let start_unix = START_UNIX_SECS.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    start_unix.saturating_add(AppClock::elapsed_millis() / 1000)
}
