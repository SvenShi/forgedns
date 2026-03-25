//! RouterOS API adapter for mikrotik executor.
//!
//! This module isolates all RouterOS address-list command paths and response
//! decoding so manager logic does not depend on `mikrotik-rs` protocol details.
//! The business layer only sees normalized address-list keys, ownership-aware
//! upsert behavior, and stable plugin errors.

use super::manager::{
    AddressListFamily, AddressListKey, decode_owned_comment, parse_router_address,
};
use crate::core::error::{DnsError, Result};
use async_trait::async_trait;
use mikrotik_rs::MikrotikDevice;
use mikrotik_rs::protocol::CommandResponse;
use mikrotik_rs::protocol::command::CommandBuilder;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

/// RouterOS field containing the internal row id.
const ADDRESS_ID_FIELD: &str = ".id";
/// RouterOS field containing the address-list name.
const ADDRESS_LIST_FIELD: &str = "list";
/// RouterOS field containing the IP or CIDR value.
const ADDRESS_FIELD: &str = "address";
/// RouterOS field containing the native timeout string.
const TIMEOUT_FIELD: &str = "timeout";
/// RouterOS field containing ownership metadata.
const COMMENT_FIELD: &str = "comment";

/// Cheap command used for API health checks during startup.
const COMMAND_SYSTEM_IDENTITY_PRINT: &str = "/system/identity/print";

/// RouterOS command for listing IPv4 firewall address-list rows.
const COMMAND_IP_ADDRESS_LIST_PRINT: &str = "/ip/firewall/address-list/print";
/// RouterOS command for creating IPv4 firewall address-list rows.
const COMMAND_IP_ADDRESS_LIST_ADD: &str = "/ip/firewall/address-list/add";
/// RouterOS command for updating IPv4 firewall address-list rows.
const COMMAND_IP_ADDRESS_LIST_SET: &str = "/ip/firewall/address-list/set";
/// RouterOS command for deleting IPv4 firewall address-list rows.
const COMMAND_IP_ADDRESS_LIST_REMOVE: &str = "/ip/firewall/address-list/remove";

/// RouterOS command for listing IPv6 firewall address-list rows.
const COMMAND_IPV6_ADDRESS_LIST_PRINT: &str = "/ipv6/firewall/address-list/print";
/// RouterOS command for creating IPv6 firewall address-list rows.
const COMMAND_IPV6_ADDRESS_LIST_ADD: &str = "/ipv6/firewall/address-list/add";
/// RouterOS command for updating IPv6 firewall address-list rows.
const COMMAND_IPV6_ADDRESS_LIST_SET: &str = "/ipv6/firewall/address-list/set";
/// RouterOS command for deleting IPv6 firewall address-list rows.
const COMMAND_IPV6_ADDRESS_LIST_REMOVE: &str = "/ipv6/firewall/address-list/remove";

/// Timeout for establishing a RouterOS API connection.
const CONNECT_TIMEOUT_SECS: u64 = 5;
/// Timeout for sending one RouterOS API command.
const SEND_TIMEOUT_SECS: u64 = 5;
/// Timeout for receiving one chunk of RouterOS API response data.
const RECV_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub(super) struct RouterListEntry {
    /// RouterOS internal row id (for example `*123`).
    pub(super) id: String,
    /// Normalized key reconstructed from RouterOS list/address fields.
    pub(super) key: AddressListKey,
    /// Timeout string returned by RouterOS when present.
    pub(super) timeout: Option<String>,
    /// Comment field used for ownership checks and diagnostics.
    pub(super) comment: Option<String>,
}

#[async_trait]
pub(super) trait MikrotikApi: Debug + Send + Sync {
    /// List all entries from the configured IPv4/IPv6 address lists.
    async fn list_entries(
        &self,
        list4: Option<&str>,
        list6: Option<&str>,
    ) -> Result<Vec<RouterListEntry>>;
    /// Upsert one plugin-owned address-list entry.
    ///
    /// Returning `Ok(None)` means a foreign entry already occupies the same
    /// `(family, list, address)` key and the caller must not overwrite it.
    async fn upsert_owned_entry(
        &self,
        key: &AddressListKey,
        timeout: Option<&str>,
        comment: &str,
        comment_prefix: &str,
        plugin_tag: &str,
        refresh_timeout: bool,
    ) -> Result<Option<String>>;
    /// Delete one row by RouterOS internal id.
    async fn delete_entry_by_id(&self, id: &str, family: AddressListFamily) -> Result<()>;
    /// Cheap connectivity check used during startup.
    async fn healthcheck(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
struct RouterReply {
    attributes: HashMap<String, Option<String>>,
}

impl RouterReply {
    #[inline]
    fn get(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(|v| v.as_deref())
    }

    fn require(&self, key: &str, action: &str) -> Result<String> {
        self.get(key)
            .map(str::to_string)
            .ok_or_else(|| DnsError::plugin(format!("mikrotik {action} response missing '{key}'")))
    }
}

pub(super) struct MikrotikRsClient {
    /// RouterOS API endpoint, usually `<host>:8728`.
    address: String,
    /// Login username.
    username: String,
    /// Login password.
    password: String,
    /// Lazily initialized shared connection reused across commands.
    connection: tokio::sync::Mutex<Option<MikrotikDevice>>,
}

impl Debug for MikrotikRsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MikrotikRsClient")
            .field("address", &self.address)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl MikrotikRsClient {
    pub(super) fn new(address: String, username: String, password: String) -> Self {
        Self {
            address,
            username,
            password,
            connection: tokio::sync::Mutex::new(None),
        }
    }

    async fn invalidate_connection(&self) {
        // Any protocol-level failure drops the cached connection so the next
        // call performs a clean reconnect.
        let mut guard = self.connection.lock().await;
        *guard = None;
    }

    async fn get_or_connect(&self) -> Result<MikrotikDevice> {
        // Keep connection reuse entirely inside the API layer. Callers should not
        // need to care whether a command hits an existing session or reconnects.
        {
            let guard = self.connection.lock().await;
            if let Some(device) = guard.as_ref() {
                return Ok(device.clone());
            }
        }

        let password = if self.password.is_empty() {
            None
        } else {
            Some(self.password.as_str())
        };

        let connect_result = tokio::time::timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            MikrotikDevice::connect(self.address.as_str(), &self.username, password),
        )
        .await;
        let device = match connect_result {
            Ok(Ok(device)) => device,
            Ok(Err(e)) => {
                return Err(DnsError::plugin(format!(
                    "mikrotik connect failed to {}: {}",
                    self.address, e
                )));
            }
            Err(_) => {
                return Err(DnsError::plugin(format!(
                    "mikrotik connect timeout after {}s to {}",
                    CONNECT_TIMEOUT_SECS, self.address
                )));
            }
        };

        let mut guard = self.connection.lock().await;
        *guard = Some(device.clone());
        Ok(device)
    }

    async fn send_rows(
        &self,
        action: &str,
        command: mikrotik_rs::protocol::command::Command,
    ) -> Result<Vec<RouterReply>> {
        // All network/protocol details are normalized into `DnsError::plugin`
        // here so the manager only sees semantic success/failure.
        let device = self.get_or_connect().await?;
        let send_result = tokio::time::timeout(
            Duration::from_secs(SEND_TIMEOUT_SECS),
            device.send_command(command),
        )
        .await;
        let mut rx = match send_result {
            Ok(Ok(rx)) => rx,
            Ok(Err(e)) => {
                self.invalidate_connection().await;
                return Err(DnsError::plugin(format!(
                    "mikrotik {action} send failed: {e}"
                )));
            }
            Err(_) => {
                self.invalidate_connection().await;
                return Err(DnsError::plugin(format!(
                    "mikrotik {action} send timeout after {}s",
                    SEND_TIMEOUT_SECS
                )));
            }
        };

        let mut rows = Vec::new();
        loop {
            let recv_result =
                tokio::time::timeout(Duration::from_secs(RECV_TIMEOUT_SECS), rx.recv()).await;
            let Some(item) = (match recv_result {
                Ok(item) => item,
                Err(_) => {
                    self.invalidate_connection().await;
                    return Err(DnsError::plugin(format!(
                        "mikrotik {action} receive timeout after {}s",
                        RECV_TIMEOUT_SECS
                    )));
                }
            }) else {
                break;
            };

            let response = match item {
                Ok(resp) => resp,
                Err(e) => {
                    self.invalidate_connection().await;
                    return Err(DnsError::plugin(format!(
                        "mikrotik {action} receive failed: {e}"
                    )));
                }
            };

            match response {
                CommandResponse::Reply(reply) => rows.push(RouterReply {
                    attributes: reply.attributes,
                }),
                CommandResponse::Done(_) | CommandResponse::Empty(_) => {}
                CommandResponse::Trap(trap) => {
                    return Err(DnsError::plugin(format!(
                        "mikrotik {action} trap: {}",
                        trap.message
                    )));
                }
                CommandResponse::Fatal(reason) => {
                    self.invalidate_connection().await;
                    return Err(DnsError::plugin(format!(
                        "mikrotik {action} fatal: {reason}"
                    )));
                }
            }
        }

        Ok(rows)
    }

    async fn find_entries_by_key(&self, key: &AddressListKey) -> Result<Vec<RouterListEntry>> {
        // RouterOS separates IPv4 and IPv6 address-lists into different command
        // namespaces, but the manager uses one normalized key type.
        let print = CommandBuilder::new()
            .command(address_list_command(key.family, ListOp::Print))
            .query_equal(ADDRESS_LIST_FIELD, key.list.as_str())
            .query_equal(ADDRESS_FIELD, key.router_value().as_str())
            .build();
        let rows = self.send_rows("find address-list entries", print).await?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(parse_router_list_entry(
                "find address-list entries parse",
                key.family,
                &row,
                Some(key.list.as_str()),
            )?);
        }
        Ok(entries)
    }

    async fn add_entry(
        &self,
        key: &AddressListKey,
        timeout: Option<&str>,
        comment: &str,
    ) -> Result<String> {
        // Add is followed by a re-query because RouterOS does not always return
        // the created row id directly in a stable shape.
        let mut add = CommandBuilder::new()
            .command(address_list_command(key.family, ListOp::Add))
            .attribute(ADDRESS_LIST_FIELD, Some(key.list.as_str()))
            .attribute(ADDRESS_FIELD, Some(key.router_value().as_str()))
            .attribute(COMMENT_FIELD, Some(comment));
        if let Some(timeout) = timeout {
            add = add.attribute(TIMEOUT_FIELD, Some(timeout));
        }
        let _ = self
            .send_rows("add address-list entry", add.build())
            .await?;

        let mut created = self.find_entries_by_key(key).await?;
        created.retain(|entry| entry.comment.as_deref() == Some(comment));
        created
            .into_iter()
            .map(|entry| entry.id)
            .next()
            .ok_or_else(|| {
                DnsError::plugin("mikrotik add address-list entry succeeded but entry id not found")
            })
    }
}

#[derive(Debug, Clone, Copy)]
enum ListOp {
    Print,
    Add,
    Set,
    Remove,
}

/// Map a normalized family/op pair to the RouterOS command namespace.
fn address_list_command(family: AddressListFamily, op: ListOp) -> &'static str {
    match (family, op) {
        (AddressListFamily::Ipv4, ListOp::Print) => COMMAND_IP_ADDRESS_LIST_PRINT,
        (AddressListFamily::Ipv4, ListOp::Add) => COMMAND_IP_ADDRESS_LIST_ADD,
        (AddressListFamily::Ipv4, ListOp::Set) => COMMAND_IP_ADDRESS_LIST_SET,
        (AddressListFamily::Ipv4, ListOp::Remove) => COMMAND_IP_ADDRESS_LIST_REMOVE,
        (AddressListFamily::Ipv6, ListOp::Print) => COMMAND_IPV6_ADDRESS_LIST_PRINT,
        (AddressListFamily::Ipv6, ListOp::Add) => COMMAND_IPV6_ADDRESS_LIST_ADD,
        (AddressListFamily::Ipv6, ListOp::Set) => COMMAND_IPV6_ADDRESS_LIST_SET,
        (AddressListFamily::Ipv6, ListOp::Remove) => COMMAND_IPV6_ADDRESS_LIST_REMOVE,
    }
}

fn parse_router_list_entry(
    action: &str,
    family: AddressListFamily,
    reply: &RouterReply,
    fallback_list: Option<&str>,
) -> Result<RouterListEntry> {
    // RouterOS may omit the list name in some filtered query paths, so callers
    // can provide the already-known list as a fallback.
    let id = reply.require(ADDRESS_ID_FIELD, action)?;
    let list = reply
        .get(ADDRESS_LIST_FIELD)
        .map(str::to_string)
        .or_else(|| fallback_list.map(str::to_string))
        .ok_or_else(|| {
            DnsError::plugin(format!(
                "mikrotik {action} response missing '{ADDRESS_LIST_FIELD}'"
            ))
        })?;
    let address_raw = reply.require(ADDRESS_FIELD, action)?;
    let (address, prefix) =
        parse_router_address(family, address_raw.as_str()).ok_or_else(|| {
            DnsError::plugin(format!(
                "mikrotik {action} response has invalid '{ADDRESS_FIELD}' value '{address_raw}'"
            ))
        })?;
    let key = AddressListKey::new_with_prefix(address, prefix, list).ok_or_else(|| {
        DnsError::plugin(format!(
            "mikrotik {action} response has invalid normalized address '{address_raw}'"
        ))
    })?;
    let timeout = reply.get(TIMEOUT_FIELD).map(str::to_string);
    let comment = reply.get(COMMENT_FIELD).map(str::to_string);
    Ok(RouterListEntry {
        id,
        key,
        timeout,
        comment,
    })
}

#[async_trait]
impl MikrotikApi for MikrotikRsClient {
    async fn list_entries(
        &self,
        list4: Option<&str>,
        list6: Option<&str>,
    ) -> Result<Vec<RouterListEntry>> {
        // The manager asks for a full list scan only on relatively cold paths:
        // persistent reconcile, startup repair, and cleanup.
        let mut entries = Vec::new();

        if let Some(list4) = list4 {
            let print = CommandBuilder::new()
                .command(address_list_command(AddressListFamily::Ipv4, ListOp::Print))
                .query_equal(ADDRESS_LIST_FIELD, list4)
                .build();
            for row in self
                .send_rows("print ipv4 address-list entries", print)
                .await?
            {
                entries.push(parse_router_list_entry(
                    "parse ipv4 address-list entry",
                    AddressListFamily::Ipv4,
                    &row,
                    Some(list4),
                )?);
            }
        }

        if let Some(list6) = list6 {
            let print = CommandBuilder::new()
                .command(address_list_command(AddressListFamily::Ipv6, ListOp::Print))
                .query_equal(ADDRESS_LIST_FIELD, list6)
                .build();
            for row in self
                .send_rows("print ipv6 address-list entries", print)
                .await?
            {
                entries.push(parse_router_list_entry(
                    "parse ipv6 address-list entry",
                    AddressListFamily::Ipv6,
                    &row,
                    Some(list6),
                )?);
            }
        }

        Ok(entries)
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
        // Upsert policy:
        // 1) query all rows for the exact `(family, list, address)` key
        // 2) refuse overwrite when only foreign rows exist
        // 3) deduplicate multiple owned rows down to one canonical row
        // 4) update the canonical row in place when safe
        // 5) recreate when switching between timed and persistent forms
        let entries = self.find_entries_by_key(key).await?;
        let mut owned = Vec::new();
        let mut has_foreign = false;
        for entry in entries {
            if decode_owned_comment(comment_prefix, plugin_tag, entry.comment.as_deref()).is_some()
            {
                owned.push(entry);
            } else {
                has_foreign = true;
            }
        }

        if owned.is_empty() && has_foreign {
            return Ok(None);
        }

        let mut iter = owned.into_iter();
        let mut canonical = iter.next();
        for extra in iter {
            self.delete_entry_by_id(&extra.id, extra.key.family).await?;
        }

        if let Some(existing) = canonical.take() {
            // RouterOS timed and timeless rows are different enough that the
            // safest transition is delete-and-add when the timeout kind changes.
            let timeout_kind_changed = existing.timeout.is_some() != timeout.is_some();
            if timeout_kind_changed {
                self.delete_entry_by_id(&existing.id, existing.key.family)
                    .await?;
                let id = self.add_entry(key, timeout, comment).await?;
                return Ok(Some(id));
            }

            // `refresh_timeout` lets callers force a timeout rewrite even when
            // the string looks unchanged, which keeps the remote timer alive.
            let timeout_changed = existing.timeout.as_deref() != timeout;
            let comment_changed = existing.comment.as_deref() != Some(comment);
            if refresh_timeout || timeout_changed || comment_changed {
                let mut set = CommandBuilder::new()
                    .command(address_list_command(key.family, ListOp::Set))
                    .attribute(ADDRESS_ID_FIELD, Some(existing.id.as_str()))
                    .attribute(COMMENT_FIELD, Some(comment));
                if let Some(timeout) = timeout {
                    set = set.attribute(TIMEOUT_FIELD, Some(timeout));
                }
                let _ = self
                    .send_rows("set address-list entry", set.build())
                    .await?;
            }
            return Ok(Some(existing.id));
        }

        let id = self.add_entry(key, timeout, comment).await?;
        Ok(Some(id))
    }

    async fn delete_entry_by_id(&self, id: &str, family: AddressListFamily) -> Result<()> {
        let remove = CommandBuilder::new()
            .command(address_list_command(family, ListOp::Remove))
            .attribute(ADDRESS_ID_FIELD, Some(id))
            .build();
        match self.send_rows("remove address-list entry", remove).await {
            Ok(_) => Ok(()),
            Err(e) if is_not_found_error(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn healthcheck(&self) -> Result<()> {
        // `/system/identity/print` is cheap and available on RouterOS targets
        // that support the API used by this plugin.
        let command = CommandBuilder::new()
            .command(COMMAND_SYSTEM_IDENTITY_PRINT)
            .build();
        let _ = self.send_rows("healthcheck", command).await?;
        Ok(())
    }
}

fn is_not_found_error(err: &DnsError) -> bool {
    // RouterOS error text is not strongly typed. Treat common "already gone"
    // variants as successful delete semantics.
    let lower = err.to_string().to_ascii_lowercase();
    lower.contains("no such item")
        || lower.contains("not found")
        || lower.contains("does not exist")
}
