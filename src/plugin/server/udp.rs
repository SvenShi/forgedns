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
use futures::StreamExt;
use hickory_proto::DnsStreamHandle;
use hickory_proto::op::Message;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::udp::UdpStream;
use hickory_proto::xfer::SerialMessage;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// UDP server configuration
#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// Entry executor plugin tag to process incoming requests
    entry: String,

    /// UDP listen address (e.g., "0.0.0.0:53")
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
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket to {}: {}", addr, e);
            return;
        }
    };

    let (mut stream, stream_handle) =
        UdpStream::<TokioRuntimeProvider>::with_bound(socket, ([127, 255, 255, 254], 0).into());

    let stream_handle = Arc::new(stream_handle);

    debug!("UDP server event loop started on {}", addr);

    loop {
        let message = match stream.next().await {
            None => break,
            Some(message) => message,
        };

        let message = match message {
            Err(error) => {
                warn!(%error, "Error receiving message on UDP socket");
                continue;
            }
            Ok(message) => message,
        };

        // Spawn handler task for this request (non-blocking)
        let handler = handler.clone();
        let stream_handle = stream_handle.clone();
        tokio::spawn(async move {
            let (msg, src_addr) = message.into_parts();
            if let Ok(msg) = Message::from_bytes(msg.as_slice()) {
                let response = handler.handle_request(msg, src_addr).await;
                if let Ok(bytes) = response.to_bytes() {
                    if let Err(e) = stream_handle
                        .with_remote_addr(src_addr)
                        .send(SerialMessage::new(bytes, src_addr))
                    {
                        warn!("Failed to send response to {}: {}", src_addr, e);
                    }
                } else {
                    warn!("Failed to serialize response for {}", src_addr);
                }
            }
        });
    }
}

/// Build a UDP socket with reuse_address and reuse_port options
///
/// Creates a socket optimized for DNS server workloads with port reuse enabled.
fn build_udp_socket(addr: &str) -> std::result::Result<UdpSocket, Error> {
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

    UdpSocket::from_std(sock.into())
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
