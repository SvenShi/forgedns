/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! UDP DNS server plugin
//!
//! Listens for DNS queries over UDP and processes them through a configured
//! entry plugin executor. Handles concurrent requests efficiently and manages
//! task spawning with automatic cleanup.

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::plugin::server::{RequestHandle, Server};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use async_trait::async_trait;

use crate::network::transport::udp_transport::UdpTransport;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Error;
use std::net::SocketAddr;
use std::net::UdpSocket as StdUdpSocket;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// UDP server configuration
#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// Entry executor plugin tag to process incoming requests.
    ///
    /// - Must reference an existing executor plugin registered in `PluginRegistry`.
    /// - All UDP-based DNS queries will be forwarded to this executor.
    entry: String,

    /// UDP listen address in `ip:port` format (e.g., "0.0.0.0:53").
    ///
    /// - Must be a valid `SocketAddr` string or validation will fail.
    /// - Ensure the port is not occupied by other UDP listeners.
    listen: String,
}

/// UDP DNS server plugin
#[allow(unused)]
#[derive(Debug)]
pub struct UdpServer {
    tag: String,
    listen: String,
    request_handle: Arc<RequestHandle>,
}

#[async_trait]
impl Plugin for UdpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        self.run();
    }

    async fn destroy(&mut self) {}
}

impl Server for UdpServer {
    fn run(&self) {
        let listen = self.listen.clone();
        let addr = listen.clone();

        info!("Starting UDP server on {}", listen);
        tokio::spawn(run_server(addr, self.request_handle.clone()));
        info!("UDP server listening on {}", listen);
    }
}

/// Main UDP server loop
///
/// Creates a UDP stream, listens for incoming DNS queries, and spawns
/// handler tasks for each request. Performs periodic cleanup of finished tasks.
async fn run_server(addr: String, handler: Arc<RequestHandle>) {
    let socket = match build_udp_socket(&addr) {
        Ok(s) => UdpSocket::from_std(s).unwrap(),
        Err(e) => {
            error!("Failed to bind UDP socket to {}: {}", addr, e);
            return;
        }
    };

    debug!("UDP server event loop started on {}", addr);

    let transport = Arc::new(UdpTransport::new(socket));
    let mut buf = [0u8; 4096];
    loop {
        match transport.read_message_from(&mut buf).await {
            Ok((msg, src_addr)) => {
                let handler = handler.clone();
                let transport = transport.clone();
                tokio::spawn(async move {
                    let response = handler.handle_request(msg, src_addr).await;
                    if let Err(e) = transport.write_message_to(&response, src_addr).await {
                        warn!("Failed to send response to {}: {}", src_addr, e);
                    }
                });
            }
            Err(e) => {
                warn!("Error receiving message on UDP socket: {}", e);
                continue;
            }
        }
    }
}

/// Build a UDP socket with reuse_address and reuse_port options
///
/// Creates a socket optimized for DNS server workloads with port reuse enabled.
pub fn build_udp_socket(addr: &str) -> Result<StdUdpSocket> {
    let addr = SocketAddr::from_str(addr).map_err(|e| {
        Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid address {}: {}", addr, e),
        )
    })?;

    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);
    #[cfg(not(target_os = "windows"))]
    let _ = sock.set_reuse_port(true);

    sock.bind(&addr.into())?;

    Ok(sock.into())
}

/// Factory for creating UDP server plugin instances
#[derive(Debug)]
pub struct UdpServerFactory {}

#[async_trait]
impl PluginFactory for UdpServerFactory {
    fn create(
        &self,
        plugin_info: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let udp_config = serde_yml::from_value::<UdpServerConfig>(
            plugin_info
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("UDP Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse UDP Server config: {}", e)))?;

        // Look up the entry plugin using the registry
        let entry = registry.get_plugin(&udp_config.entry).ok_or_else(|| {
            DnsError::plugin(format!(
                "UDP Server [{}] entry plugin [{}] not found",
                plugin_info.tag, udp_config.entry
            ))
        })?;

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            UdpServer {
                tag: plugin_info.tag.clone(),
                listen: udp_config.listen,
                request_handle: Arc::new(RequestHandle {
                    entry_executor: entry.to_executor().clone(),
                    registry,
                }),
            },
        )))
    }

    /// Validate UDP server configuration
    fn validate_config(&self, plugin_info: &PluginConfig) -> Result<()> {
        use std::net::SocketAddr;
        use std::str::FromStr;

        // Parse and validate UDP-specific configuration
        let udp_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<UdpServerConfig>(args).map_err(|e| {
                DnsError::plugin(format!("UDP Server config parsing failed: {}", e))
            })?,
            None => {
                return Err(DnsError::plugin(
                    "UDP Server must configure 'listen' and 'entry' in config file",
                ));
            }
        };

        // Validate listen address format
        if SocketAddr::from_str(&udp_config.listen).is_err() {
            return Err(DnsError::plugin(format!(
                "Invalid listen address: {}",
                udp_config.listen
            )));
        }

        // Validate entry is not empty
        if udp_config.entry.is_empty() {
            return Err(DnsError::plugin("UDP Server 'entry' field cannot be empty"));
        }

        Ok(())
    }

    /// Get dependencies (the entry executor plugin)
    fn get_dependencies(&self, plugin_info: &PluginConfig) -> Vec<String> {
        if let Some(args) = &plugin_info.args {
            if let Ok(config) = serde_yml::from_value::<UdpServerConfig>(args.clone()) {
                return vec![config.entry];
            }
        }
        vec![]
    }
}
