//! Address-list manager state machine for mikrotik executor.
//!
//! Responsibilities:
//! - maintain desired persistent address-list entries
//! - upsert dynamic address-list entries from observed DNS answers
//! - keep ownership metadata in RouterOS comments
//! - execute idempotent create/update/delete through [`MikrotikApi`]
//!
//! Design notes:
//! - RouterOS remains the authority for dynamic expiration via native `timeout`.
//! - local state is intentionally lightweight and only suppresses redundant
//!   refresh writes; it does not attempt to mirror full remote state.
//! - persistent items are reconciled as a desired set and never enter the
//!   dynamic refresh cache.

use super::api::MikrotikApi;
use crate::core::app_clock::AppClock;
use crate::core::error::Result;
use crate::core::task_center;
use ahash::{AHashMap, AHashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Host prefix used for normalized IPv4 single-address entries.
const HOST_PREFIX_V4: u8 = 32;
/// Host prefix used for normalized IPv6 single-address entries.
const HOST_PREFIX_V6: u8 = 128;
/// Capacity of the manager command channel.
const MANAGER_QUEUE_SIZE: usize = 1024;
/// Periodic interval for persistent desired-set reconciliation.
const RECONCILE_INTERVAL_SECS: u64 = 180;
/// Periodic interval for reloading persistent item files.
const PERSISTENT_RELOAD_INTERVAL_SECS: u64 = 60;
/// Periodic interval for local dynamic-cache pruning.
const DYNAMIC_CACHE_PRUNE_INTERVAL_SECS: u64 = 60;
/// Maximum time allowed for graceful manager shutdown coordination.
const SHUTDOWN_TIMEOUT_SECS: u64 = 8;
/// Hard upper bound for locally cached dynamic refresh states.
const MAX_DYNAMIC_CACHE_ENTRIES: usize = 65_536;
/// Maximum time a dynamic key can go without a refresh attempt under steady traffic.
const MAX_DYNAMIC_REFRESH_SUPPRESS_MS: u64 = 60_000;
/// Minimum refresh lead time before estimated RouterOS timeout expiry.
const MIN_DYNAMIC_REFRESH_LEAD_MS: u64 = 1_000;
/// Maximum refresh lead time before estimated RouterOS timeout expiry.
const MAX_DYNAMIC_REFRESH_LEAD_MS: u64 = 60_000;

/// Comment field storing the owning plugin tag.
const COMMENT_FIELD_PLUGIN: &str = "pg";
/// Comment field storing entry kind metadata.
const COMMENT_FIELD_KIND: &str = "kind";
/// Comment field storing the observed domain for dynamic entries.
const COMMENT_FIELD_DOMAIN: &str = "dm";
/// Compact comment marker for dynamic entries.
const COMMENT_KIND_DYNAMIC: &str = "D";
/// Compact comment marker for persistent entries.
const COMMENT_KIND_PERSISTENT: &str = "P";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(super) enum AddressListFamily {
    Ipv4,
    Ipv6,
}

impl AddressListFamily {
    #[inline]
    pub(super) fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    #[inline]
    pub(super) fn host_prefix(self) -> u8 {
        match self {
            Self::Ipv4 => HOST_PREFIX_V4,
            Self::Ipv6 => HOST_PREFIX_V6,
        }
    }

    #[inline]
    pub(super) fn is_valid_prefix(self, prefix: u8) -> bool {
        match self {
            Self::Ipv4 => prefix <= HOST_PREFIX_V4,
            Self::Ipv6 => prefix <= HOST_PREFIX_V6,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct AddressListKey {
    pub(super) family: AddressListFamily,
    pub(super) list: String,
    pub(super) address: IpAddr,
    pub(super) prefix: u8,
}

impl AddressListKey {
    pub(super) fn new(ip: IpAddr, list: String) -> Self {
        let family = AddressListFamily::from_ip(ip);
        Self {
            family,
            list,
            address: ip,
            prefix: family.host_prefix(),
        }
    }

    pub(super) fn new_with_prefix(ip: IpAddr, prefix: u8, list: String) -> Option<Self> {
        let family = AddressListFamily::from_ip(ip);
        if !family.is_valid_prefix(prefix) {
            return None;
        }
        Some(Self {
            family,
            list,
            address: normalize_network_ip(ip, prefix),
            prefix,
        })
    }

    #[inline]
    pub(super) fn normalized_value(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }

    #[inline]
    pub(super) fn router_value(&self) -> String {
        if self.prefix == self.family.host_prefix() {
            self.address.to_string()
        } else {
            self.normalized_value()
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum OwnedCommentKind {
    Dynamic,
    Persistent,
}

impl OwnedCommentKind {
    #[inline]
    fn as_str(self) -> &'static str {
        match self {
            Self::Dynamic => COMMENT_KIND_DYNAMIC,
            Self::Persistent => COMMENT_KIND_PERSISTENT,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct OwnedCommentMeta {
    pub(super) kind: OwnedCommentKind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DynamicRefreshState {
    /// Timeout value written on the last successful RouterOS update.
    written_timeout_ms: u64,
    /// Local estimate of when the remote timeout will naturally expire.
    expires_at_ms: u64,
    /// Earliest local time when another refresh is worth sending.
    next_refresh_at_ms: u64,
}

impl DynamicRefreshState {
    /// Build a suppression window after a successful dynamic write.
    ///
    /// The cache deliberately refreshes before the estimated remote expiry so
    /// periodic DNS traffic can extend entries without waiting for RouterOS to
    /// drop them first. At the same time, the suppress window is capped so very
    /// long TTLs do not completely stop background refreshes.
    fn from_write(now_ms: u64, timeout_secs: u32) -> Self {
        let timeout_ms = u64::from(timeout_secs).saturating_mul(1000);
        let expires_at_ms = now_ms.saturating_add(timeout_ms);
        let refresh_lead_ms = dynamic_refresh_lead_ms(timeout_ms);
        let near_expiry_refresh_at_ms = expires_at_ms.saturating_sub(refresh_lead_ms);
        let max_skip_refresh_at_ms = now_ms.saturating_add(MAX_DYNAMIC_REFRESH_SUPPRESS_MS);
        Self {
            written_timeout_ms: timeout_ms,
            expires_at_ms,
            next_refresh_at_ms: near_expiry_refresh_at_ms.min(max_skip_refresh_at_ms),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct AddressListManagerConfig {
    /// Plugin tag reused in RouterOS comments for ownership checks.
    pub(super) plugin_tag: String,
    /// IPv4 address-list name managed by this plugin.
    pub(super) address_list4: Option<String>,
    /// IPv6 address-list name managed by this plugin.
    pub(super) address_list6: Option<String>,
    /// Desired persistent set at startup.
    pub(super) persistent_items: AHashSet<AddressListKey>,
    /// Comment prefix used as an ownership fast-path.
    pub(super) comment_prefix: String,
    /// Minimum TTL clamp for dynamic observations.
    pub(super) min_ttl: u32,
    /// Maximum TTL clamp for dynamic observations.
    pub(super) max_ttl: u32,
    /// Optional fixed TTL override for dynamic observations.
    pub(super) fixed_ttl: Option<u32>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct ObservedAddr {
    /// Observed A/AAAA answer IP.
    pub(super) addr: IpAddr,
    /// Raw TTL extracted from the DNS response before clamping.
    pub(super) ttl_secs: u32,
}

#[derive(Debug)]
pub(super) enum ManagerCommand {
    ObserveDomain {
        domain: String,
        addrs: Vec<ObservedAddr>,
        wait: Option<oneshot::Sender<Result<()>>>,
    },
    UpdatePersistentItems {
        items: AHashSet<AddressListKey>,
    },
    Reconcile,
    PruneDynamicCache,
    Shutdown {
        cleanup: bool,
        done: oneshot::Sender<()>,
    },
}

#[derive(Debug, Clone)]
pub(super) struct PersistentReloadConfig {
    /// Inline-only persistent set that never changes after startup.
    pub(super) inline_items: AHashSet<AddressListKey>,
    /// File sources periodically reloaded in the background.
    pub(super) files: Vec<String>,
    /// IPv4 target list needed to bind reloaded file items.
    pub(super) address_list4: Option<String>,
    /// IPv6 target list needed to bind reloaded file items.
    pub(super) address_list6: Option<String>,
    /// Initial merged desired set used to suppress redundant reload updates.
    pub(super) initial_items: AHashSet<AddressListKey>,
}

#[derive(Debug)]
pub(super) struct AddressListManagerRuntime {
    /// Command channel used by with-next execution and background tasks.
    tx: mpsc::Sender<ManagerCommand>,
    /// Single-owner worker task that serializes all local state transitions.
    worker_handle: Option<JoinHandle<()>>,
    /// Local-memory cache prune loop.
    prune_task_id: Option<u64>,
    /// Periodic persistent reconcile loop.
    reconcile_task_id: Option<u64>,
    /// Periodic persistent file reload loop.
    persistent_reload_task_id: Option<u64>,
}

impl AddressListManagerRuntime {
    pub(super) fn start(
        tag: String,
        manager: AddressListManager,
        persistent_reload: Option<PersistentReloadConfig>,
    ) -> Self {
        // All mutable state lives behind one worker to avoid cross-map locking
        // or request-path synchronization in the DNS hot path.
        let (tx, rx) = mpsc::channel::<ManagerCommand>(MANAGER_QUEUE_SIZE);

        let worker_tag = tag.clone();
        let worker_handle = Some(tokio::spawn(async move {
            run_manager_worker(worker_tag, manager, rx).await;
        }));

        // Pruning is local-memory only. It never talks to RouterOS and exists
        // solely to keep the write-suppression cache bounded.
        let prune_tx = tx.clone();
        let prune_task_id = Some(task_center::spawn_fixed(
            format!("mikrotik:{tag}:dynamic_cache_prune"),
            Duration::from_secs(DYNAMIC_CACHE_PRUNE_INTERVAL_SECS),
            move || {
                let prune_tx = prune_tx.clone();
                async move {
                    let _ = prune_tx.send(ManagerCommand::PruneDynamicCache).await;
                }
            },
        ));

        // Reconcile is only useful when persistent behavior is configured.
        let reconcile_enabled = persistent_reload
            .as_ref()
            .is_some_and(|cfg| !cfg.initial_items.is_empty() || !cfg.files.is_empty());
        let reconcile_task_id = reconcile_enabled.then(|| {
            let reconcile_tx = tx.clone();
            task_center::spawn_fixed(
                format!("mikrotik:{tag}:reconcile"),
                Duration::from_secs(RECONCILE_INTERVAL_SECS),
                move || {
                    let reconcile_tx = reconcile_tx.clone();
                    async move {
                        let _ = reconcile_tx.send(ManagerCommand::Reconcile).await;
                    }
                },
            )
        });

        let persistent_reload_task_id = persistent_reload.and_then(|reload_cfg| {
            if reload_cfg.files.is_empty() {
                return None;
            }

            // File reload re-parses source files in the background and only
            // sends a manager update when the merged desired set actually changes.
            let maintain_tx = tx.clone();
            let maintain_tag = tag.clone();
            let last_loaded_items =
                Arc::new(tokio::sync::Mutex::new(reload_cfg.initial_items.clone()));
            Some(task_center::spawn_fixed(
                format!("mikrotik:{maintain_tag}:persistent_reload"),
                Duration::from_secs(PERSISTENT_RELOAD_INTERVAL_SECS),
                move || {
                    let maintain_tx = maintain_tx.clone();
                    let maintain_tag = maintain_tag.clone();
                    let last_loaded_items = last_loaded_items.clone();
                    let reload_cfg = reload_cfg.clone();
                    async move {
                        match super::load_persistent_items_from_files_async(
                            reload_cfg.files.as_slice(),
                            reload_cfg.address_list4.as_deref(),
                            reload_cfg.address_list6.as_deref(),
                        )
                        .await
                        {
                            Ok((file_items, ignored_by_family)) => {
                                if ignored_by_family > 0 {
                                    debug!(
                                        plugin = %maintain_tag,
                                        ignored = ignored_by_family,
                                        "mikrotik persistent file reload ignored entries without corresponding address list family"
                                    );
                                }

                                let mut desired_items = reload_cfg.inline_items.clone();
                                desired_items.extend(file_items);

                                let mut last_loaded_guard = last_loaded_items.lock().await;
                                if desired_items != *last_loaded_guard {
                                    *last_loaded_guard = desired_items.clone();
                                    if maintain_tx
                                        .send(ManagerCommand::UpdatePersistentItems {
                                            items: desired_items,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                }

                                let _ = maintain_tx.send(ManagerCommand::Reconcile).await;
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
                },
            ))
        });

        Self {
            tx,
            worker_handle,
            prune_task_id,
            reconcile_task_id,
            persistent_reload_task_id,
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

        if let Some(task_id) = self.prune_task_id.take() {
            task_center::stop_task(task_id).await;
        }
        if let Some(task_id) = self.reconcile_task_id.take() {
            task_center::stop_task(task_id).await;
        }
        if let Some(task_id) = self.persistent_reload_task_id.take() {
            task_center::stop_task(task_id).await;
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
pub(super) struct AddressListManager {
    /// RouterOS API abstraction used by the single-owner worker.
    api: Arc<dyn MikrotikApi>,
    /// Immutable config shared across runtime decisions.
    cfg: AddressListManagerConfig,
    /// Current desired persistent set.
    persistent_items: AHashSet<AddressListKey>,
    /// Lightweight local cache that suppresses redundant dynamic refresh writes.
    dynamic_refresh_cache: AHashMap<AddressListKey, DynamicRefreshState>,
    /// One-time startup guard.
    initialized: bool,
}

impl AddressListManager {
    pub(super) fn new(api: Arc<dyn MikrotikApi>, cfg: AddressListManagerConfig) -> Self {
        Self {
            api,
            persistent_items: cfg.persistent_items.clone(),
            dynamic_refresh_cache: AHashMap::new(),
            cfg,
            initialized: false,
        }
    }

    async fn ensure_initialized(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        // Startup intentionally validates connectivity and repairs persistent
        // state before the first observed DNS answer is processed.
        self.api.healthcheck().await?;
        self.reconcile_persistent_inner().await?;
        self.initialized = true;
        Ok(())
    }

    pub(super) async fn initialize_on_startup(&mut self) -> Result<()> {
        self.ensure_initialized().await
    }

    #[inline]
    fn clamp_ttl(&self, ttl_secs: u32) -> u32 {
        // TTL policy is centralized here so dynamic observations and tests use
        // identical clamping semantics.
        if let Some(ttl) = self.cfg.fixed_ttl {
            return ttl;
        }
        ttl_secs.clamp(self.cfg.min_ttl, self.cfg.max_ttl)
    }

    #[inline]
    fn list_name_for(&self, family: AddressListFamily) -> Option<&str> {
        match family {
            AddressListFamily::Ipv4 => self.cfg.address_list4.as_deref(),
            AddressListFamily::Ipv6 => self.cfg.address_list6.as_deref(),
        }
    }

    #[inline]
    fn comment_for_dynamic(&self, domain: &str) -> String {
        encode_comment(
            self.cfg.comment_prefix.as_str(),
            self.cfg.plugin_tag.as_str(),
            OwnedCommentKind::Dynamic,
            Some(domain),
        )
    }

    #[inline]
    fn comment_for_persistent(&self) -> String {
        encode_comment(
            self.cfg.comment_prefix.as_str(),
            self.cfg.plugin_tag.as_str(),
            OwnedCommentKind::Persistent,
            None,
        )
    }

    fn should_refresh_dynamic_entry(
        &self,
        key: &AddressListKey,
        timeout_secs: u32,
        now_ms: u64,
    ) -> bool {
        // Missing or expired cache means we have no recent successful remote write
        // to rely on, so the entry must be refreshed immediately.
        let Some(state) = self.dynamic_refresh_cache.get(key) else {
            return true;
        };
        if now_ms >= state.expires_at_ms {
            return true;
        }

        // A longer TTL is always worth pushing immediately. Shorter TTLs are
        // intentionally ignored until the normal refresh window to avoid
        // excessive rewrite churn on frequently queried names.
        let timeout_ms = u64::from(timeout_secs).saturating_mul(1000);
        timeout_ms > state.written_timeout_ms || now_ms >= state.next_refresh_at_ms
    }

    fn prune_dynamic_cache(&mut self, now_ms: u64) {
        // Step 1: drop obviously stale or now-persistent entries.
        self.dynamic_refresh_cache.retain(|key, state| {
            state.expires_at_ms > now_ms && !self.persistent_items.contains(key)
        });

        if self.dynamic_refresh_cache.len() <= MAX_DYNAMIC_CACHE_ENTRIES {
            return;
        }

        // Step 2: if the cache still exceeds the hard cap, evict entries that
        // will expire the soonest because they provide the least suppression value.
        let overflow = self
            .dynamic_refresh_cache
            .len()
            .saturating_sub(MAX_DYNAMIC_CACHE_ENTRIES);
        let mut eviction_order = self
            .dynamic_refresh_cache
            .iter()
            .map(|(key, state)| (key.clone(), state.expires_at_ms))
            .collect::<Vec<_>>();
        eviction_order.sort_by_key(|(_, expires_at_ms)| *expires_at_ms);
        for (key, _) in eviction_order.into_iter().take(overflow) {
            self.dynamic_refresh_cache.remove(&key);
        }
    }

    async fn reconcile_persistent_inner(&mut self) -> Result<()> {
        // Persistent reconcile treats RouterOS as a converged desired-set target:
        // ensure every configured persistent item exists, then remove stale owned
        // persistent entries that are no longer desired.
        let existing = self
            .api
            .list_entries(
                self.cfg.address_list4.as_deref(),
                self.cfg.address_list6.as_deref(),
            )
            .await?;

        let desired_comment = self.comment_for_persistent();
        for key in &self.persistent_items {
            match self
                .api
                .upsert_owned_entry(
                    key,
                    None,
                    desired_comment.as_str(),
                    self.cfg.comment_prefix.as_str(),
                    self.cfg.plugin_tag.as_str(),
                    false,
                )
                .await?
            {
                Some(_) => {}
                None => {
                    warn!(
                        plugin = %self.cfg.plugin_tag,
                        list = %key.list,
                        address = %key.normalized_value(),
                        "mikrotik persistent entry conflicts with foreign address-list entry, skipping"
                    );
                }
            }
        }

        for entry in existing {
            let Some(meta) = decode_owned_comment(
                self.cfg.comment_prefix.as_str(),
                self.cfg.plugin_tag.as_str(),
                entry.comment.as_deref(),
            ) else {
                continue;
            };
            if meta.kind != OwnedCommentKind::Persistent {
                continue;
            }
            if self.persistent_items.contains(&entry.key) {
                continue;
            }
            self.api
                .delete_entry_by_id(&entry.id, entry.key.family)
                .await?;
        }

        Ok(())
    }

    async fn observe_domain_inner(
        &mut self,
        domain: String,
        addrs: Vec<ObservedAddr>,
        now_ms: u64,
    ) -> Result<()> {
        // Keep the local suppression cache healthy before evaluating refreshes.
        let mut dedup = AHashMap::<AddressListKey, u32>::new();
        for observed in addrs {
            let family = AddressListFamily::from_ip(observed.addr);
            let Some(list) = self.list_name_for(family) else {
                continue;
            };
            let key = AddressListKey::new(observed.addr, list.to_string());
            if self.persistent_items.contains(&key) {
                continue;
            }
            let ttl = self.clamp_ttl(observed.ttl_secs.max(1));
            dedup
                .entry(key)
                .and_modify(|existing| *existing = (*existing).max(ttl))
                .or_insert(ttl);
        }

        if dedup.is_empty() {
            return Ok(());
        }

        // One response can contain duplicate IPs. We already reduced that to one
        // key with the strongest TTL, so each key below represents at most one
        // remote write decision for this DNS observation.
        let comment = self.comment_for_dynamic(domain.as_str());
        for (key, ttl) in dedup {
            if !self.should_refresh_dynamic_entry(&key, ttl, now_ms) {
                continue;
            }
            let timeout = format!("{ttl}s");
            let upsert_result = self
                .api
                .upsert_owned_entry(
                    &key,
                    Some(timeout.as_str()),
                    comment.as_str(),
                    self.cfg.comment_prefix.as_str(),
                    self.cfg.plugin_tag.as_str(),
                    true,
                )
                .await;
            match upsert_result {
                Ok(Some(_)) => {
                    // Only successful remote writes advance the suppression cache.
                    self.dynamic_refresh_cache
                        .insert(key.clone(), DynamicRefreshState::from_write(now_ms, ttl));
                }
                Ok(None) => {
                    // Foreign ownership conflict: drop any local cache so future
                    // observations do not keep assuming we control the entry.
                    self.dynamic_refresh_cache.remove(&key);
                    warn!(
                        plugin = %self.cfg.plugin_tag,
                        list = %key.list,
                        address = %key.normalized_value(),
                        "mikrotik dynamic entry conflicts with foreign address-list entry, skipping"
                    );
                }
                Err(err) => {
                    // Error path also drops the local cache so the next
                    // observation retries immediately instead of being suppressed.
                    self.dynamic_refresh_cache.remove(&key);
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    pub(super) async fn observe_domain(
        &mut self,
        domain: String,
        addrs: Vec<ObservedAddr>,
    ) -> Result<()> {
        self.ensure_initialized().await?;
        self.observe_domain_inner(domain, addrs, now_millis()).await
    }

    pub(super) async fn update_persistent_items(
        &mut self,
        items: AHashSet<AddressListKey>,
    ) -> Result<()> {
        self.ensure_initialized().await?;
        // Persistent ownership takes precedence over any cached dynamic state.
        self.persistent_items = items;
        self.prune_dynamic_cache(now_millis());
        self.reconcile_persistent_inner().await
    }

    pub(super) async fn reconcile(&mut self) -> Result<()> {
        self.ensure_initialized().await?;
        self.prune_dynamic_cache(now_millis());
        self.reconcile_persistent_inner().await
    }

    pub(super) async fn prune_dynamic_cache_now(&mut self) -> Result<()> {
        self.ensure_initialized().await?;
        self.prune_dynamic_cache(now_millis());
        Ok(())
    }

    pub(super) async fn shutdown(&mut self, cleanup: bool) -> Result<()> {
        if !cleanup {
            self.dynamic_refresh_cache.clear();
            return Ok(());
        }

        // Cleanup only touches entries that match this plugin's comment ownership.
        self.ensure_initialized().await?;
        let entries = self
            .api
            .list_entries(
                self.cfg.address_list4.as_deref(),
                self.cfg.address_list6.as_deref(),
            )
            .await?;
        for entry in entries {
            if decode_owned_comment(
                self.cfg.comment_prefix.as_str(),
                self.cfg.plugin_tag.as_str(),
                entry.comment.as_deref(),
            )
            .is_some()
            {
                self.api
                    .delete_entry_by_id(&entry.id, entry.key.family)
                    .await?;
            }
        }
        self.dynamic_refresh_cache.clear();
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn dynamic_cache_len(&self) -> usize {
        self.dynamic_refresh_cache.len()
    }

    #[cfg(test)]
    pub(super) async fn observe_domain_at_for_test(
        &mut self,
        domain: String,
        addrs: Vec<ObservedAddr>,
        now_ms: u64,
    ) -> Result<()> {
        self.ensure_initialized().await?;
        self.observe_domain_inner(domain, addrs, now_ms).await
    }

    #[cfg(test)]
    pub(super) async fn prune_dynamic_cache_at_for_test(&mut self, now_ms: u64) -> Result<()> {
        self.ensure_initialized().await?;
        self.prune_dynamic_cache(now_ms);
        Ok(())
    }
}

pub(super) fn encode_comment(
    prefix: &str,
    plugin_tag: &str,
    kind: OwnedCommentKind,
    domain: Option<&str>,
) -> String {
    // Comments intentionally stay compact because they live on RouterOS objects
    // and are parsed frequently during reconciliation and cleanup.
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
        out.push(';');
    }
    out.push_str(COMMENT_FIELD_PLUGIN);
    out.push('=');
    out.push_str(plugin_tag);
    out.push(';');
    out.push_str(COMMENT_FIELD_KIND);
    out.push('=');
    out.push_str(kind.as_str());
    if let Some(domain) = domain {
        out.push(';');
        out.push_str(COMMENT_FIELD_DOMAIN);
        out.push('=');
        out.push_str(domain);
    }
    out
}

pub(super) fn decode_owned_comment(
    prefix: &str,
    plugin_tag: &str,
    comment: Option<&str>,
) -> Option<OwnedCommentMeta> {
    // Prefix and plugin-tag checks provide a fast ownership filter before the
    // caller considers deleting or modifying an entry.
    let comment = comment?;
    if !prefix.is_empty() {
        if !comment.starts_with(prefix) {
            return None;
        }
        if comment.as_bytes().get(prefix.len()) != Some(&b';') {
            return None;
        }
    }

    let mut plugin_matches = false;
    let mut kind = None;
    for token in comment.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key.trim() {
            COMMENT_FIELD_PLUGIN if value.trim() == plugin_tag => plugin_matches = true,
            COMMENT_FIELD_KIND => {
                kind = match value.trim() {
                    COMMENT_KIND_DYNAMIC => Some(OwnedCommentKind::Dynamic),
                    COMMENT_KIND_PERSISTENT => Some(OwnedCommentKind::Persistent),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    if plugin_matches {
        kind.map(|kind| OwnedCommentMeta { kind })
    } else {
        None
    }
}

async fn run_manager_worker(
    tag: String,
    mut manager: AddressListManager,
    mut rx: mpsc::Receiver<ManagerCommand>,
) {
    // Every state transition is serialized here. Request-path code only pushes
    // commands into the channel and never mutates manager state directly.
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
            ManagerCommand::UpdatePersistentItems { items } => {
                if let Err(e) = manager.update_persistent_items(items).await {
                    warn!(
                        plugin = %tag,
                        err = %e,
                        "mikrotik persistent address-list maintenance failed"
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
            ManagerCommand::PruneDynamicCache => {
                if let Err(e) = manager.prune_dynamic_cache_now().await {
                    warn!(
                        plugin = %tag,
                        err = %e,
                        "mikrotik dynamic cache prune failed"
                    );
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

fn dynamic_refresh_lead_ms(timeout_ms: u64) -> u64 {
    // Refresh slightly ahead of the estimated remote expiry while keeping both
    // extremely short and extremely long TTLs within practical bounds.
    (timeout_ms / 4)
        .max(MIN_DYNAMIC_REFRESH_LEAD_MS)
        .min(MAX_DYNAMIC_REFRESH_LEAD_MS)
}

fn now_millis() -> u64 {
    // The app clock avoids repeated syscalls on hot paths and is already used
    // elsewhere in ForgeDNS for lightweight time reads.
    AppClock::elapsed_millis()
}

fn normalize_network_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(addr) => {
            let raw = u32::from(addr);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (HOST_PREFIX_V4 - prefix)
            };
            IpAddr::V4((raw & mask).into())
        }
        IpAddr::V6(addr) => {
            let raw = u128::from(addr);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (HOST_PREFIX_V6 - prefix)
            };
            IpAddr::V6((raw & mask).into())
        }
    }
}

pub(super) fn parse_router_address(family: AddressListFamily, raw: &str) -> Option<(IpAddr, u8)> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if let Some((ip_raw, prefix_raw)) = value.split_once('/') {
        let ip = ip_raw.parse::<IpAddr>().ok()?;
        let prefix = prefix_raw.parse::<u8>().ok()?;
        if AddressListFamily::from_ip(ip) != family || !family.is_valid_prefix(prefix) {
            return None;
        }
        return Some((normalize_network_ip(ip, prefix), prefix));
    }

    let ip = value.parse::<IpAddr>().ok()?;
    if AddressListFamily::from_ip(ip) != family {
        return None;
    }
    Some((ip, family.host_prefix()))
}
