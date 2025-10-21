/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! UDP DNS server plugin
//!
//! Listens for DNS queries over UDP and processes them through a configured
//! entry plugin executor. Handles concurrent requests efficiently and manages
//! task spawning with automatic cleanup.

use crate::config::config::PluginConfig;
use crate::core::context::DnsContext;
use crate::plugin::{Plugin, PluginFactory, PluginInfo, PluginMainType, PluginRegistry};
use async_trait::async_trait;
use futures::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::udp::UdpStream;
use hickory_proto::xfer::SerialMessage;
use hickory_proto::{BufDnsStreamHandle, DnsStreamHandle};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tracing::{Level, debug, error, event_enabled, info, warn};

/// UDP server configuration
#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// Entry executor plugin tag to process incoming requests
    pub entry: String,

    /// UDP listen address (e.g., "0.0.0.0:53")
    pub listen: String,
}

/// UDP DNS server plugin
#[allow(unused)]
pub struct UdpServer {
    pub tag: String,
    pub entry: Arc<PluginInfo>,
    pub listen: String,
    pub registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for UdpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        let listen = self.listen.clone();
        let addr = listen.clone();
        let entry_executor = self.entry.clone();
        let registry = self.registry.clone();

        info!(
            "Starting UDP server on {} (entry: {})",
            listen, entry_executor.tag
        );
        tokio::spawn(run_server(addr, entry_executor, registry));
        info!("UDP server listening on {}", listen);
    }

    async fn execute(&self, _: &mut DnsContext) {}

    fn main_type(&self) -> PluginMainType {
        PluginMainType::Server {
            tag: self.tag.to_string(),
            type_name: "UdpServer".to_string(),
        }
    }

    async fn destroy(&mut self) {}
}

/// Main UDP server loop
///
/// Creates a UDP stream, listens for incoming DNS queries, and spawns
/// handler tasks for each request. Performs periodic cleanup of finished tasks.
async fn run_server(
    addr: String,
    entry_executor: Arc<PluginInfo>,
    registry: Arc<PluginRegistry>,
) {
    let socket = match build_udp_socket(&addr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket to {}: {}", addr, e);
            return;
        }
    };

    let (mut stream, stream_handle) =
        UdpStream::<TokioRuntimeProvider>::with_bound(socket, ([127, 255, 255, 254], 0).into());

    let mut inner_join_set = JoinSet::new();
    let stream_handle = Arc::new(stream_handle);

    debug!("UDP server event loop started on {}", addr);

    loop {
        let message = tokio::select! {
            message = stream.next() => match message {
                None => break,
                Some(message) => message,
            },
        };

        let message = match message {
            Err(error) => {
                warn!(%error, "Error receiving message on UDP socket");
                continue;
            }
            Ok(message) => message,
        };

        // Spawn handler task for this request (non-blocking)
        inner_join_set.spawn(handler_message(
            entry_executor.clone(),
            stream_handle.clone(),
            message,
            registry.clone(),
        ));

        // Clean up completed tasks (non-blocking)
        reap_tasks(&mut inner_join_set);
    }
}

/// Handle a single DNS query message
///
/// Parses the incoming message, creates a context, executes the entry plugin,
/// and sends the response back to the client.
async fn handler_message(
    entry_executor: Arc<PluginInfo>,
    stream_handle: Arc<BufDnsStreamHandle>,
    message: SerialMessage,
    registry: Arc<PluginRegistry>,
) {
    let (message, src_addr) = message.into_parts();

    // Parse DNS message
    if let Ok(msg) = Message::from_bytes(message.as_slice()) {
        let mut context = DnsContext {
            src_addr,
            request: msg,
            response: None,
            mark: Vec::new(),
            attributes: HashMap::new(),
            registry,
        };

        // Log request details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "DNS request from {}, queries: {:?}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.queries(),
                context.request.extensions(),
                context.request.name_servers()
            );
        }

        // Execute entry plugin to process the request
        entry_executor.plugin.execute(&mut context).await;

        // Construct response message
        let mut response;
        match context.response {
            None => {
                debug!("No response received from entry plugin");
                response = Message::new();
                response.set_id(context.request.id());
                response.set_op_code(OpCode::Query);
                response.set_message_type(MessageType::Query);
            }
            Some(res) => {
                response = Message::from(res);
            }
        }

        // Log response details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "Sending response to {}, queries: {:?}, id: {}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.queries(),
                context.request.id(),
                response.extensions(),
                response.name_servers()
            );
        }

        // Send response back to client
        stream_handle
            .with_remote_addr(src_addr)
            .send(SerialMessage::new(response.to_bytes().unwrap(), src_addr))
            .unwrap();
    }
}

/// Reap completed tasks from the join set
///
/// Non-blocking cleanup of finished handler tasks
fn reap_tasks(join_set: &mut JoinSet<()>) {
    while join_set.try_join_next().is_some() {}
}

/// Build a UDP socket with reuse_address and reuse_port options
///
/// Creates a socket optimized for DNS server workloads with port reuse enabled.
fn build_udp_socket(addr: &str) -> Result<UdpSocket, Error> {
    let addr = SocketAddr::from_str(addr).unwrap();

    let sock = if addr.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?
    } else {
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?
    };

    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);
    #[cfg(not(target_os = "windows"))]
    let _ = sock.set_reuse_port(true);

    sock.bind(&addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Factory for creating UDP server plugin instances
pub struct UdpServerFactory {}

#[async_trait]
impl PluginFactory for UdpServerFactory {
    fn create(
        &self,
        plugin_info: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<Box<dyn Plugin>, String> {
        let udp_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<UdpServerConfig>(args)
                .map_err(|e| format!("UDP Server config parsing failed: {}", e))?,
            None => {
                return Err("UDP Server must configure 'listen' and 'entry' in config file".to_string());
            }
        };

        // Look up the entry plugin using the registry
        let entry = registry.get_plugin(&udp_config.entry).ok_or_else(|| {
            format!(
                "UDP Server [{}] entry plugin [{}] not found",
                plugin_info.tag, udp_config.entry
            )
        })?;

        Ok(Box::new(UdpServer {
            tag: plugin_info.tag.clone(),
            entry: entry.clone(),
            listen: udp_config.listen,
            registry,
        }))
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Server {
            tag: tag.to_string(),
            type_name: "udp".to_string(),
        }
    }
    
    /// Validate UDP server configuration
    fn validate_config(&self, plugin_info: &PluginConfig) -> Result<(), String> {
        use std::net::SocketAddr;
        use std::str::FromStr;
        
        // Parse and validate UDP-specific configuration
        let udp_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<UdpServerConfig>(args)
                .map_err(|e| format!("UDP Server config parsing failed: {}", e))?,
            None => {
                return Err("UDP Server must configure 'listen' and 'entry' in config file".to_string());
            }
        };
        
        // Validate listen address format
        if SocketAddr::from_str(&udp_config.listen).is_err() {
            return Err(format!("Invalid listen address: {}", udp_config.listen));
        }
        
        // Validate entry is not empty
        if udp_config.entry.is_empty() {
            return Err("UDP Server 'entry' field cannot be empty".to_string());
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
