// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! UDP DNS server plugin
//!
//! Listens for DNS queries over UDP and processes them through a configured
//! entry plugin executor. Handles concurrent requests efficiently and manages
//! task spawning with automatic cleanup.

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::config::types::PluginConfig;
use crate::core::context::RequestMeta;
use crate::core::error::{DnsError, Result};
use crate::network::transport::udp_transport::UdpTransport;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::server::{RequestHandle, Server, parse_listen_addr};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use crate::register_plugin_factory;

const UDP_RECV_BUFFER_SIZE: usize = 65_535;
const UDP_SOCKET_BUFFER_SIZE: usize = 64 * 1024;

/// UDP server configuration
#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// Entry executor plugin tag to process incoming requests.
    ///
    /// - Must reference an existing executor plugin registered in
    ///   `PluginRegistry`.
    /// - All UDP-based DNS queries will be forwarded to this executor.
    entry: String,

    /// UDP listen address in `ip:port` or `:port` format (e.g., "0.0.0.0:53",
    /// ":53").
    ///
    /// - `:port` binds on `0.0.0.0:port`.
    /// - Must be a valid listen address or validation will fail.
    /// - Ensure the port is not occupied by other UDP listeners.
    listen: String,
}

/// UDP DNS server plugin
#[allow(unused)]
pub struct UdpServer {
    tag: String,
    listen: SocketAddr,
    request_handle: Arc<RequestHandle>,
    shutdown_tx: watch::Sender<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for UdpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpServer")
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .finish()
    }
}

impl UdpServer {
    fn spawn_server_task(
        &self,
        startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
    ) -> Result<()> {
        let mut task_slot = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("UDP server task lock poisoned"))?;

        if task_slot.is_some() {
            if let Some(startup_tx) = startup_tx {
                let _ = startup_tx.send(Ok(()));
            }
            return Ok(());
        }

        let addr = self.listen;
        let handler = self.request_handle.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        *task_slot = Some(tokio::spawn(run_server(
            addr,
            handler,
            shutdown_rx,
            startup_tx,
        )));
        Ok(())
    }
}

#[async_trait]
impl Plugin for UdpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) -> Result<()> {
        let (startup_tx, startup_rx) = oneshot::channel();
        self.spawn_server_task(Some(startup_tx))?;
        match startup_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(DnsError::plugin(e)),
            Err(_) => Err(DnsError::plugin(
                "UDP server startup channel closed unexpectedly",
            )),
        }
    }

    async fn destroy(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        let handle = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("UDP server task lock poisoned"))?
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl Server for UdpServer {
    fn run(&self) {
        debug!(listen = %self.listen, "Spawning UDP server task");
        if let Err(e) = self.spawn_server_task(None) {
            error!(plugin = %self.tag, error = %e, "Failed to spawn UDP server task");
        }
    }
}

/// Main UDP server loop
///
/// Creates a UDP stream, listens for incoming DNS queries, and spawns
/// handler tasks for each request. Uses a task tracker to manage request
/// lifetimes without polling completed tasks from the hot path.
#[hotpath::measure]
async fn run_server(
    addr: SocketAddr,
    handler: Arc<RequestHandle>,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    let socket = match build_udp_socket(addr) {
        Ok(s) => UdpSocket::from_std(s).unwrap(),
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!("Failed to bind UDP socket to {}: {}", addr, e)));
            }
            error!("Failed to bind UDP socket to {}: {}", addr, e);
            return;
        }
    };

    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }
    info!(listen = %addr, "UDP server listening");
    debug!("UDP server event loop started on {}", addr);

    let transport = Arc::new(UdpTransport::new(socket));
    let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
    let tasks = TaskTracker::new();
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            recv = transport.read_message_from(&mut buf) => {
                match recv {
                    Ok((msg, src_addr)) => {
                        let max_payload = msg.max_payload();
                        let handler = handler.clone();
                        let transport = transport.clone();
                        tasks.spawn(async move {
                            let response = handler.handle_request(msg, src_addr, RequestMeta{server_name: None, url_path: None}).await;
                            // Use requester-advertised UDP payload limit (EDNS) when encoding
                            // response so oversize replies become TC=1 DNS messages, not raw truncation.
                            if let Err(e) =
                                transport.write_message_to(&response.response, src_addr, max_payload).await
                            {
                                warn!("Failed to send response to {}: {}", src_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Error receiving message on UDP socket: {}", e);
                    }
                }
            }
        }
    }

    tasks.close();
    tasks.wait().await;
    info!(listen = %addr, "UDP server stopped");
}

/// Build a UDP socket with reuse_address and reuse_port options when available
///
/// Creates a socket optimized for DNS server workloads with port reuse enabled.
pub fn build_udp_socket(addr: SocketAddr) -> Result<StdUdpSocket> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);
    #[cfg(all(
        unix,
        not(any(
            target_os = "solaris",
            target_os = "illumos",
            target_os = "cygwin",
            target_os = "wasi"
        ))
    ))]
    let _ = sock.set_reuse_port(true);
    let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);

    sock.bind(&addr.into())?;

    Ok(sock.into())
}

/// Factory for creating UDP server plugin instances
#[derive(Debug)]
pub struct UdpServerFactory {}

register_plugin_factory!("udp_server", UdpServerFactory {});

#[async_trait]
impl PluginFactory for UdpServerFactory {
    /// Get dependencies (the entry executor plugin)
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        if let Some(args) = &plugin_config.args
            && let Ok(config) = serde_yaml_ng::from_value::<UdpServerConfig>(args.clone())
        {
            return vec![DependencySpec::executor("args.entry", config.entry)];
        }
        vec![]
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let udp_config = serde_yaml_ng::from_value::<UdpServerConfig>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("UDP Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse UDP Server config: {}", e)))?;
        let listen = parse_listen_addr(&udp_config.listen).map_err(|e| {
            DnsError::plugin(format!(
                "Invalid UDP listen address '{}': {}",
                udp_config.listen, e
            ))
        })?;

        // Resolve and type-check the entry executor using contextual diagnostics.
        let entry_executor = registry.get_executor_dependency(
            &plugin_config.tag,
            "args.entry",
            &udp_config.entry,
        )?;

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            UdpServer {
                tag: plugin_config.tag.clone(),
                listen,
                request_handle: Arc::new(RequestHandle {
                    entry_executor,
                    registry,
                }),
                shutdown_tx: watch::channel(false).0,
                task_handle: Mutex::new(None),
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::plugin::test_utils::{plugin_config, test_registry};

    #[test]
    fn test_udp_factory_requires_args() {
        let factory = UdpServerFactory {};
        let cfg = plugin_config("udp", "udp_server", None);
        assert!(
            factory
                .create(&cfg, test_registry(), &Default::default())
                .is_err()
        );
    }

    #[test]
    fn test_build_udp_socket_accepts_port_only_shorthand() {
        let socket = build_udp_socket(parse_listen_addr(":0").unwrap())
            .expect("port-only shorthand should bind");
        let addr = socket
            .local_addr()
            .expect("socket should expose local address");

        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_ne!(addr.port(), 0);
    }
}
