/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! TCP DNS server plugin
//!
//! Listens for DNS queries over TCP (with optional TLS support) and processes
//! them through a configured entry plugin executor. Handles concurrent requests
//! efficiently and manages task spawning with automatic cleanup.
//!
//! ## TLS Support
//!
//! The server supports optional TLS encryption. To enable TLS, provide both
//! `cert` and `key` configuration options pointing to PEM-encoded certificate
//! and private key files.

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::network::tls_config::load_tls_config;
use crate::network::transport::tcp_transport::TcpTransport;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::server::{
    ConnectionGuard, RequestHandle, RequestMeta, Server, normalize_listen_addr, parse_listen_addr,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use crate::proto::Message;
use crate::register_plugin_factory;

use async_trait::async_trait;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

const DEFAULT_IDLE_TIMEOUT: u64 = 10;

/// TCP server configuration
#[derive(Deserialize)]
pub struct TcpServerConfig {
    /// Entry executor plugin tag to process incoming requests.
    ///
    /// - Must reference an existing executor plugin registered in `PluginRegistry`.
    /// - All TCP/TLS DNS queries will be forwarded to this executor.
    entry: String,

    /// TCP listen address in `ip:port` or `:port` format.
    ///
    /// - Example: "0.0.0.0:53" (DNS over TCP), ":853" (DNS over TLS/DoT)
    /// - `:port` binds on `0.0.0.0:port`.
    /// - Must be a valid listen address or validation will fail.
    listen: String,

    /// Path to TLS certificate file (PEM format, optional).
    ///
    /// - When both `cert` and `key` are provided, TLS will be enabled (DoT on port 853).
    /// - When either is missing, server runs in plain TCP mode.
    cert: Option<String>,

    /// Path to TLS private key file (PEM format, optional).
    ///
    /// - Supports common key formats (PKCS#8/RSA/EC) via `rustls-pemfile`.
    key: Option<String>,

    /// TCP connection idle timeout in seconds.
    ///
    /// - Default: 10 seconds if omitted.
    /// - Applied as TCP keepalive interval for long-lived connections.
    idle_timeout: Option<u64>,
}

/// TCP DNS server plugin
#[allow(unused)]
pub struct TcpServer {
    tag: String,
    listen: String,
    request_handle: Arc<RequestHandle>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    idle_timeout: Option<u64>,
    shutdown_tx: watch::Sender<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for TcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpServer")
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("has_tls", &self.tls_acceptor.is_some())
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

impl TcpServer {
    fn spawn_server_task(
        &self,
        startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
    ) -> Result<()> {
        let mut task_slot = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("TCP server task lock poisoned"))?;

        if task_slot.is_some() {
            if let Some(startup_tx) = startup_tx {
                let _ = startup_tx.send(Ok(()));
            }
            return Ok(());
        }

        let addr = self.listen.clone();
        let handler = self.request_handle.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let idle_timeout = self.idle_timeout;
        let shutdown_rx = self.shutdown_tx.subscribe();
        *task_slot = Some(tokio::spawn(run_server(
            addr,
            handler,
            tls_acceptor,
            idle_timeout,
            shutdown_rx,
            startup_tx,
        )));
        Ok(())
    }
}

#[async_trait]
impl Plugin for TcpServer {
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
                "TCP server startup channel closed unexpectedly",
            )),
        }
    }

    async fn destroy(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        let handle = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("TCP server task lock poisoned"))?
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl Server for TcpServer {
    fn run(&self) {
        let tls_mode = self.tls_acceptor.is_some();

        debug!(listen = %self.listen, tls = tls_mode, "Spawning TCP server task");
        if let Err(e) = self.spawn_server_task(None) {
            error!(plugin = %self.tag, error = %e, "Failed to spawn TCP server task");
        }
    }
}

/// Main TCP server loop
///
/// Creates a TCP stream, listens for incoming DNS queries, and spawns
/// handler tasks for each request. Uses a task tracker and cancellation token
/// to manage active connections without polling completed tasks from the
/// accept loop.
async fn run_server(
    addr: String,
    handler: Arc<RequestHandle>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    idle_timeout: Option<u64>,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    let timeout = Duration::from_secs(idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT));
    let listener = match build_tcp_listener(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!("Failed to bind TCP socket to {}: {}", addr, e)));
            }
            error!("Failed to bind TCP socket to {}: {}", addr, e);
            return;
        }
    };

    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }
    info!(
        listen = %addr,
        idle_timeout_secs = timeout.as_secs(),
        tls = %tls_acceptor.is_some(),
        "TCP server bound successfully"
    );

    let tasks = TaskTracker::new();
    let shutdown_token = CancellationToken::new();
    let active_connections = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            // Accept new connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, src)) => {
                        let handler = handler.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let task_shutdown = shutdown_token.clone();
                        let active_connections = active_connections.clone();

                        let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        debug!("New connection from {} (active: {})", src, active);
                        tasks.spawn(async move {
                            let _connection_guard =
                                ConnectionGuard::new(active_connections.clone(), src, "TCP");
                            tokio::select! {
                                _ = task_shutdown.cancelled() => {}
                                _ = async move {
                                    // Handle TLS handshake if TLS is enabled
                                    if let Some(acceptor) = tls_acceptor {
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                let server_name = tls_stream
                                                    .get_ref()
                                                    .1
                                                    .server_name()
                                                    .map(Arc::from);
                                                debug!("TLS handshake completed for client {}", src);
                                                handle_dns_stream(tls_stream, src, handler, server_name)
                                                    .await;
                                            }
                                            Err(e) => {
                                                warn!("TLS handshake failed for {}: {}", src, e);
                                            }
                                        }
                                    } else {
                                        // Plain TCP connection
                                        debug!("TCP server connected to client {}", src);
                                        handle_dns_stream(stream, src, handler, None).await;
                                    }
                                } => {}
                            }
                        });
                    }
                    Err(e) => {
                        debug!(%e, listen = %addr, "Error accepting TCP connection");
                    }
                }
            }
        }
    }

    shutdown_token.cancel();
    tasks.close();
    tasks.wait().await;
    info!(listen = %addr, "TCP server stopped");
}

/// Handle DNS messages over a TCP stream (works for both TLS and plain TCP)
async fn handle_dns_stream<S>(
    stream: S,
    src: SocketAddr,
    handler: Arc<RequestHandle>,
    server_name: Option<Arc<str>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    let transport = TcpTransport::new(stream);
    let (mut reader, mut writer) = transport.into_split();

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Message>(128);

    let handle = tokio::spawn(async move {
        loop {
            if let Some(response) = receiver.recv().await
                && let Err(e) = writer.write_message(&response).await
            {
                warn!("Failed to write TCP response to {}: {}", src, e);
            }
        }
    });

    let sender = Arc::new(sender);

    loop {
        let handler = handler.clone();
        let sender = sender.clone();
        let server_name = server_name.clone();
        match reader.read_message().await {
            Ok(req_msg) => tokio::spawn(async move {
                let response = handler
                    .handle_request(
                        req_msg,
                        src,
                        RequestMeta {
                            server_name,
                            url_path: None,
                        },
                    )
                    .await;
                if let Err(e) = sender.send(response.response).await {
                    warn!("Failed to write TCP response to {}: {}", src, e);
                }
            }),
            Err(e) => {
                debug!("TCP client {} disconnected or read error: {}", src, e);
                break;
            }
        };
    }
    handle.abort();
}

/// Build a TCP socket with reuse_address and reuse_port options
///
/// Creates a socket optimized for DNS server workloads with port reuse enabled.
pub fn build_tcp_listener(addr: &str, idle_timeout: Duration) -> Result<TcpListener> {
    let addr = parse_listen_addr(addr)?;

    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;

    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_tcp_nodelay(true);
    let keepalive = TcpKeepalive::new().with_interval(idle_timeout);
    let _ = sock.set_tcp_keepalive(&keepalive);
    #[cfg(not(target_os = "windows"))]
    let _ = sock.set_reuse_port(true);

    sock.bind(&addr.into())?;
    sock.listen(512)?;

    Ok(TcpListener::from_std(sock.into())?)
}

/// Factory for creating TCP server plugin instances
#[derive(Debug)]
pub struct TcpServerFactory {}

register_plugin_factory!("tcp_server", TcpServerFactory {});

#[async_trait]
impl PluginFactory for TcpServerFactory {
    /// Get dependencies (the entry executor plugin)
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        if let Some(args) = &plugin_config.args
            && let Ok(config) = serde_yaml_ng::from_value::<TcpServerConfig>(args.clone())
        {
            return vec![DependencySpec::executor("args.entry", config.entry)];
        }
        vec![]
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let tcp_config = serde_yaml_ng::from_value::<TcpServerConfig>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("TCP Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse TCP Server config: {}", e)))?;
        let listen = normalize_listen_addr(&tcp_config.listen).map_err(|e| {
            DnsError::plugin(format!(
                "Invalid TCP listen address '{}': {}",
                tcp_config.listen, e
            ))
        })?;

        // Resolve and type-check the entry executor using contextual diagnostics.
        let entry_executor = registry.get_executor_dependency(
            &plugin_config.tag,
            "args.entry",
            &tcp_config.entry,
        )?;

        // Load TLS configuration if cert and key are provided
        let tls_acceptor = match load_tls_config(&tcp_config.cert, &tcp_config.key) {
            None => None,
            Some(res) => {
                let mut config = res?;
                config.alpn_protocols = vec![b"dot".to_vec()];
                Some(Arc::new(TlsAcceptor::from(Arc::new(config))))
            }
        };

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            TcpServer {
                tag: plugin_config.tag.clone(),
                listen,
                request_handle: Arc::new(RequestHandle {
                    entry_executor,
                    registry,
                }),
                tls_acceptor,
                idle_timeout: tcp_config.idle_timeout,
                shutdown_tx: watch::channel(false).0,
                task_handle: Mutex::new(None),
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::{plugin_config, test_registry};
    use serde_yaml_ng::from_str;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::Duration;

    #[test]
    fn test_tcp_factory_requires_args() {
        let factory = TcpServerFactory {};
        let cfg = plugin_config("tcp", "tcp_server", None);
        assert!(factory.create(&cfg, test_registry()).is_err());
    }

    #[test]
    fn test_build_tcp_listener_rejects_invalid_address() {
        let listener = build_tcp_listener("not-an-address", Duration::from_secs(5));

        assert!(listener.is_err());
    }

    #[tokio::test]
    async fn test_build_tcp_listener_accepts_port_only_shorthand() {
        let listener = build_tcp_listener(":0", Duration::from_secs(5))
            .expect("port-only shorthand should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose local address");

        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn test_tcp_factory_reports_entry_dependency() {
        let factory = TcpServerFactory {};
        let args = from_str(
            r#"
entry: forward_main
listen: 127.0.0.1:53
"#,
        )
        .expect("yaml should parse");
        let cfg = plugin_config("tcp", "tcp_server", Some(args));

        let deps = factory.get_dependency_specs(&cfg);

        assert_eq!(
            deps,
            vec![DependencySpec::executor("args.entry", "forward_main")]
        );
    }
}
