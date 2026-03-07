//! RouterOS API adapter for mikrotik executor.
//!
//! This module isolates all RouterOS command paths and response decoding so
//! manager logic does not depend on `mikrotik-rs` protocol details.
//! Business layer only sees strongly-typed route snapshots and idempotent APIs.

use super::manager::{RouteFamily, RouteKey};
use crate::core::error::{DnsError, Result};
use async_trait::async_trait;
use mikrotik_rs::MikrotikDevice;
use mikrotik_rs::protocol::CommandResponse;
use mikrotik_rs::protocol::command::CommandBuilder;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

const ROUTER_ID_FIELD: &str = ".id";
const ROUTE_DST_FIELD: &str = "dst-address";
const ROUTE_TABLE_FIELD: &str = "routing-table";
const ROUTE_GATEWAY_FIELD: &str = "gateway";
const ROUTE_COMMENT_FIELD: &str = "comment";
const COMMENT_FIELD_PLUGIN: &str = "plugin";

const COMMAND_SYSTEM_IDENTITY_PRINT: &str = "/system/identity/print";

const COMMAND_IP_ROUTE_PRINT: &str = "/ip/route/print";
const COMMAND_IP_ROUTE_ADD: &str = "/ip/route/add";
const COMMAND_IP_ROUTE_SET: &str = "/ip/route/set";
const COMMAND_IP_ROUTE_REMOVE: &str = "/ip/route/remove";

const COMMAND_IPV6_ROUTE_PRINT: &str = "/ipv6/route/print";
const COMMAND_IPV6_ROUTE_ADD: &str = "/ipv6/route/add";
const COMMAND_IPV6_ROUTE_SET: &str = "/ipv6/route/set";
const COMMAND_IPV6_ROUTE_REMOVE: &str = "/ipv6/route/remove";

const CONNECT_TIMEOUT_SECS: u64 = 5;
const SEND_TIMEOUT_SECS: u64 = 5;
const RECV_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub(super) struct RouterRoute {
    /// RouterOS internal route identifier (e.g. `*123`).
    pub(super) id: String,
    /// Address family inferred by command namespace (`/ip/route` or `/ipv6/route`).
    pub(super) family: RouteFamily,
    /// Destination address in RouterOS format (`a.b.c.d/32` or `x::y/128`).
    pub(super) dst_address: String,
    /// Routing table name where the route lives.
    pub(super) routing_table: String,
    /// Optional gateway string from RouterOS.
    pub(super) gateway: Option<String>,
    /// Optional comment field from RouterOS.
    pub(super) comment: Option<String>,
}

#[async_trait]
pub(super) trait MikrotikApi: Debug + Send + Sync {
    /// List all routes in target table that can be considered by manager reconciliation.
    async fn list_managed_routes(&self, table: &str) -> Result<Vec<RouterRoute>>;
    /// Find one route by route key (family + table + destination).
    async fn find_route(
        &self,
        key: &RouteKey,
        comment_prefix: &str,
        plugin_tag: &str,
    ) -> Result<Option<RouterRoute>>;
    /// Create or update one host route and return its RouterOS internal id.
    async fn upsert_host_route(
        &self,
        key: &RouteKey,
        gateway: &str,
        comment: &str,
        comment_prefix: &str,
        plugin_tag: &str,
    ) -> Result<String>;
    /// Delete route by internal id.
    async fn delete_route_by_id(&self, id: &str, family: RouteFamily) -> Result<()>;
    /// Lightweight command that verifies RouterOS API availability.
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
    address: String,
    username: String,
    password: String,
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
        let mut guard = self.connection.lock().await;
        *guard = None;
    }

    async fn get_or_connect(&self) -> Result<MikrotikDevice> {
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
        // All low-level transport/protocol errors are translated into plugin errors here.
        // Manager sees stable semantic errors and does not handle stream-level details.
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

    async fn find_route_by_exact_comment(
        &self,
        key: &RouteKey,
        comment: &str,
    ) -> Result<Option<RouterRoute>> {
        let print = CommandBuilder::new()
            .command(route_command(key.family(), RouteOp::Print))
            .query_equal(ROUTE_TABLE_FIELD, &key.table)
            .query_equal(ROUTE_DST_FIELD, &key.dst_address())
            .query_equal(ROUTE_COMMENT_FIELD, comment)
            .build();
        let rows = self.send_rows("find route by comment", print).await?;
        for row in rows {
            let mut route =
                parse_router_route_from_reply("find route by comment parse", key.family(), &row)?;
            if route.routing_table.is_empty() {
                route.routing_table = key.table.clone();
            }
            return Ok(Some(route));
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy)]
enum RouteOp {
    Print,
    Add,
    Set,
    Remove,
}

/// Map logical route operation to RouterOS command path by address family.
fn route_command(family: RouteFamily, op: RouteOp) -> &'static str {
    match (family, op) {
        (RouteFamily::Ipv4, RouteOp::Print) => COMMAND_IP_ROUTE_PRINT,
        (RouteFamily::Ipv4, RouteOp::Add) => COMMAND_IP_ROUTE_ADD,
        (RouteFamily::Ipv4, RouteOp::Set) => COMMAND_IP_ROUTE_SET,
        (RouteFamily::Ipv4, RouteOp::Remove) => COMMAND_IP_ROUTE_REMOVE,
        (RouteFamily::Ipv6, RouteOp::Print) => COMMAND_IPV6_ROUTE_PRINT,
        (RouteFamily::Ipv6, RouteOp::Add) => COMMAND_IPV6_ROUTE_ADD,
        (RouteFamily::Ipv6, RouteOp::Set) => COMMAND_IPV6_ROUTE_SET,
        (RouteFamily::Ipv6, RouteOp::Remove) => COMMAND_IPV6_ROUTE_REMOVE,
    }
}

/// Decode one RouterOS reply row into stable business route snapshot.
fn parse_router_route_from_reply(
    action: &str,
    family: RouteFamily,
    reply: &RouterReply,
) -> Result<RouterRoute> {
    let id = reply.require(ROUTER_ID_FIELD, action)?;
    let dst_address = reply.require(ROUTE_DST_FIELD, action)?;
    let routing_table = reply
        .get(ROUTE_TABLE_FIELD)
        .map(str::to_string)
        .unwrap_or_default();
    let gateway = reply.get(ROUTE_GATEWAY_FIELD).map(str::to_string);
    let comment = reply.get(ROUTE_COMMENT_FIELD).map(str::to_string);

    Ok(RouterRoute {
        id,
        family,
        dst_address,
        routing_table,
        gateway,
        comment,
    })
}

fn comment_matches_prefix(comment: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    comment.starts_with(prefix) && comment.as_bytes().get(prefix.len()) == Some(&b';')
}

fn comment_field<'a>(comment: &'a str, key: &str) -> Option<&'a str> {
    for token in comment.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let Some((k, v)) = token.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            return Some(v.trim());
        }
    }
    None
}

fn route_owned_by_plugin(route: &RouterRoute, comment_prefix: &str, plugin_tag: &str) -> bool {
    let Some(comment) = route.comment.as_deref() else {
        return false;
    };
    if !comment_matches_prefix(comment, comment_prefix) {
        return false;
    }
    comment_field(comment, COMMENT_FIELD_PLUGIN) == Some(plugin_tag)
}

#[async_trait]
impl MikrotikApi for MikrotikRsClient {
    async fn list_managed_routes(&self, table: &str) -> Result<Vec<RouterRoute>> {
        // RouterOS IPv4/IPv6 routes live in different namespaces.
        let mut routes = Vec::new();

        let v4_print = CommandBuilder::new()
            .command(route_command(RouteFamily::Ipv4, RouteOp::Print))
            .query_equal(ROUTE_TABLE_FIELD, table)
            .build();
        let rows_v4 = self.send_rows("print ipv4 routes", v4_print).await?;
        for row in &rows_v4 {
            let mut route =
                parse_router_route_from_reply("parse ipv4 route", RouteFamily::Ipv4, row)?;
            if route.routing_table.is_empty() {
                route.routing_table = table.to_string();
            }
            routes.push(route);
        }

        let v6_print = CommandBuilder::new()
            .command(route_command(RouteFamily::Ipv6, RouteOp::Print))
            .query_equal(ROUTE_TABLE_FIELD, table)
            .build();
        let rows_v6 = self.send_rows("print ipv6 routes", v6_print).await?;
        for row in &rows_v6 {
            let mut route =
                parse_router_route_from_reply("parse ipv6 route", RouteFamily::Ipv6, row)?;
            if route.routing_table.is_empty() {
                route.routing_table = table.to_string();
            }
            routes.push(route);
        }

        Ok(routes)
    }

    async fn find_route(
        &self,
        key: &RouteKey,
        comment_prefix: &str,
        plugin_tag: &str,
    ) -> Result<Option<RouterRoute>> {
        let print = CommandBuilder::new()
            .command(route_command(key.family(), RouteOp::Print))
            .query_equal(ROUTE_TABLE_FIELD, &key.table)
            .query_equal(ROUTE_DST_FIELD, &key.dst_address())
            .build();
        let rows = self.send_rows("find route", print).await?;
        for row in rows {
            let mut route = parse_router_route_from_reply("find route parse", key.family(), &row)?;
            if route.routing_table.is_empty() {
                route.routing_table = key.table.clone();
            }
            if route_owned_by_plugin(&route, comment_prefix, plugin_tag) {
                return Ok(Some(route));
            }
        }
        Ok(None)
    }

    async fn upsert_host_route(
        &self,
        key: &RouteKey,
        gateway: &str,
        comment: &str,
        comment_prefix: &str,
        plugin_tag: &str,
    ) -> Result<String> {
        // Upsert strategy:
        // 1) find existing by key
        // 2) update only changed fields (gateway/comment)
        // 3) otherwise add and then resolve id by re-query
        if let Some(existing) = self.find_route(key, comment_prefix, plugin_tag).await? {
            let gateway_changed = existing.gateway.as_deref() != Some(gateway);
            let comment_changed = existing.comment.as_deref() != Some(comment);
            if gateway_changed || comment_changed {
                let mut set_builder = CommandBuilder::new()
                    .command(route_command(key.family(), RouteOp::Set))
                    .attribute(ROUTER_ID_FIELD, Some(existing.id.as_str()));
                if gateway_changed {
                    set_builder = set_builder.attribute(ROUTE_GATEWAY_FIELD, Some(gateway));
                }
                if comment_changed {
                    set_builder = set_builder.attribute(ROUTE_COMMENT_FIELD, Some(comment));
                }
                set_builder = set_builder.attribute("disabled", Some("no"));
                let _ = self
                    .send_rows("set host route", set_builder.build())
                    .await?;
            }
            return Ok(existing.id);
        }

        let add = CommandBuilder::new()
            .command(route_command(key.family(), RouteOp::Add))
            .attribute(ROUTE_DST_FIELD, Some(&key.dst_address()))
            .attribute(ROUTE_TABLE_FIELD, Some(&key.table))
            .attribute(ROUTE_GATEWAY_FIELD, Some(gateway))
            .attribute(ROUTE_COMMENT_FIELD, Some(comment))
            .attribute("disabled", Some("no"))
            .build();
        let _ = self.send_rows("add host route", add).await?;

        let created = if let Some(route) = self.find_route_by_exact_comment(key, comment).await? {
            route
        } else {
            self.find_route(key, comment_prefix, plugin_tag)
                .await?
                .ok_or_else(|| {
                    DnsError::plugin("mikrotik upsert route succeeded but route id not found")
                })?
        };
        Ok(created.id)
    }

    async fn delete_route_by_id(&self, id: &str, family: RouteFamily) -> Result<()> {
        let remove = CommandBuilder::new()
            .command(route_command(family, RouteOp::Remove))
            .attribute(ROUTER_ID_FIELD, Some(id))
            .build();
        match self.send_rows("remove route", remove).await {
            Ok(_) => Ok(()),
            Err(e) if is_not_found_error(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn healthcheck(&self) -> Result<()> {
        // Identity print is cheap and available on all RouterOS v7 targets.
        let command = CommandBuilder::new()
            .command(COMMAND_SYSTEM_IDENTITY_PRINT)
            .build();
        let _ = self.send_rows("healthcheck", command).await?;
        Ok(())
    }
}

fn is_not_found_error(err: &DnsError) -> bool {
    let lower = err.to_string().to_ascii_lowercase();
    lower.contains("no such item")
        || lower.contains("not found")
        || lower.contains("does not exist")
}
