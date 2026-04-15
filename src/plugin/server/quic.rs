/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! QUIC DNS server plugin
//!
//! Listens for DNS queries over QUIC and processes them through a configured
//! entry plugin executor. Handles concurrent requests efficiently and manages
//! task spawning with automatic cleanup.

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::network::tls_config::load_tls_config;
use crate::network::transport::quic_transport::{
    QuicTransport, QuicTransportReader, QuicTransportWriter,
};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::server::{
    ConnectionGuard, RequestHandle, RequestMeta, Server, normalize_listen_addr, udp,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use crate::register_plugin_factory;
use async_trait::async_trait;
use quinn::{Endpoint, EndpointConfig, IdleTimeout, TransportConfig};
use rustls::ServerConfig;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

/// QUIC server configuration
#[derive(Deserialize)]
pub struct QuicServerConfig {
    /// Entry executor plugin tag to process incoming requests.
    ///
    /// - Must reference an existing executor plugin registered in `PluginRegistry`.
    /// - All DoQ (DNS over QUIC) queries will be forwarded to this executor.
    entry: String,

    /// QUIC listen address in `ip:port` or `:port` format (e.g., "0.0.0.0:853", ":853").
    ///
    /// - `:port` binds on `0.0.0.0:port`.
    /// - Must be a valid listen address or validation will fail.
    /// - QUIC runs over UDP; ensure the port is not occupied by UDP listeners.
    listen: String,

    /// Path to TLS certificate file (PEM format).
    ///
    /// - DoQ requires TLS; both `cert` and `key` must be provided.
    /// - Certificate chain supported via `rustls-pemfile::certs`.
    cert: String,

    /// Path to TLS private key file (PEM format).
    ///
    /// - Supports common key formats (PKCS#8/RSA/EC) via `rustls-pemfile`.
    key: String,

    /// QUIC transport-level idle timeout in seconds (optional).
    ///
    /// - Applies to QUIC transport. When absent, quinn's default is used.
    idle_timeout: Option<u64>,
}

/// QUIC DNS server plugin
#[allow(unused)]
pub struct QuicServer {
    tag: String,
    listen: String,
    /// TLS acceptor for HTTPS support (None for plain HTTP)
    server_config: ServerConfig,
    idle_timeout: Option<u64>,

    request_handle: Arc<RequestHandle>,
    shutdown_tx: watch::Sender<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServer")
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

impl QuicServer {
    fn spawn_server_task(
        &self,
        startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
    ) -> Result<()> {
        let mut task_slot = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("QUIC server task lock poisoned"))?;

        if task_slot.is_some() {
            if let Some(startup_tx) = startup_tx {
                let _ = startup_tx.send(Ok(()));
            }
            return Ok(());
        }

        let addr = self.listen.clone();
        let handler = self.request_handle.clone();
        let server_config = self.server_config.clone();
        let idle_timeout = self.idle_timeout;
        let shutdown_rx = self.shutdown_tx.subscribe();
        *task_slot = Some(tokio::spawn(run_server(
            addr,
            handler,
            server_config,
            idle_timeout,
            shutdown_rx,
            startup_tx,
        )));
        Ok(())
    }
}

#[async_trait]
impl Plugin for QuicServer {
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
                "QUIC server startup channel closed unexpectedly",
            )),
        }
    }

    async fn destroy(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        let handle = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("QUIC server task lock poisoned"))?
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl Server for QuicServer {
    fn run(&self) {
        // Spawn the QUIC server loop. This call is non-blocking and returns immediately.
        // The event loop will accept incoming QUIC connections and process DoQ streams.
        debug!(listen = %self.listen, "Spawning QUIC server task");
        if let Err(e) = self.spawn_server_task(None) {
            error!(plugin = %self.tag, error = %e, "Failed to spawn QUIC server task");
        }
    }
}

async fn run_server(
    addr: String,
    handler: Arc<RequestHandle>,
    server_config: ServerConfig,
    idle_timeout: Option<u64>,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    let endpoint = match build_quic_endpoint(&addr, server_config, idle_timeout) {
        Ok(s) => s,
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!(
                    "Failed to bind QUIC endpoint to {}: {}",
                    addr, e
                )));
            }
            error!("Failed to bind QUIC endpoint to {}: {}", addr, e);
            return;
        }
    };
    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }
    info!(listen = %addr, "QUIC server listening");
    // QUIC endpoint created successfully; enter the accept loop.
    debug!("QUIC server event loop started on {}", addr);

    let tasks = TaskTracker::new();
    let shutdown_token = CancellationToken::new();
    let active_connections = Arc::new(AtomicU64::new(0));

    // Accept QUIC connections and spawn a task per connection.
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            maybe_connecting = endpoint.accept() => {
                match maybe_connecting {
                    Some(connecting) => {
                        let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        let handler_clone = handler.clone();
                        let task_shutdown = shutdown_token.clone();
                        let active_connections = active_connections.clone();
                        tasks.spawn(async move {
                            let _connection_guard =
                                ConnectionGuard::new(active_connections.clone(), connecting.remote_address(), "QUIC");
                            tokio::select! {
                                _ = task_shutdown.cancelled() => {}
                                _ = handle_quic_connection(connecting, handler_clone) => {}
                            }
                        });
                        debug!("New QUIC connection started (active: {})", active);
                    }
                    None => break,
                }
            }
        }
    }

    shutdown_token.cancel();
    tasks.close();
    tasks.wait().await;
    info!(listen = %addr, "QUIC server stopped");
}

/// Accept a QUIC connection and handle all bidirectional streams (DNS over QUIC).
/// Each bi-directional stream represents a single DNS query/response exchange.
async fn handle_quic_connection(connecting: quinn::Incoming, handler: Arc<RequestHandle>) {
    let remote_addr = connecting.remote_address();
    let connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            warn!("QUIC handshake failed for {}: {}", remote_addr, e);
            return;
        }
    };
    let server_name = extract_tls_server_name(&connection);

    debug!("QUIC connection established with {}", remote_addr);

    let transport = QuicTransport::new(connection);
    // Accept bi-directional streams on this QUIC connection until it is closed.
    let server_name = server_name.map(Arc::from);

    loop {
        match transport.accept_bi().await {
            Ok((reader, writer)) => {
                let handler = handler.clone();
                let server_name = server_name.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_doq_bi_stream(
                        reader,
                        writer,
                        handler.clone(),
                        remote_addr,
                        server_name,
                    )
                    .await
                    {
                        warn!("DoQ stream error ({}): {}", remote_addr, e);
                    }
                });
            }
            Err(e) => {
                debug!("QUIC connection closed by {}: {}", remote_addr, e);
                return;
            }
        }
    }
}

/// Handle a single DNS over QUIC (DoQ) bidirectional stream.
/// Format: 2-byte big-endian length prefix followed by the DNS message payload.
async fn handle_doq_bi_stream(
    mut reader: QuicTransportReader,
    mut writer: QuicTransportWriter,
    handler: Arc<RequestHandle>,
    remote_addr: std::net::SocketAddr,
    server_name: Option<Arc<str>>,
) -> Result<()> {
    match reader.read_message().await {
        Ok(request_msg) => {
            let response = handler
                .handle_request(
                    request_msg,
                    remote_addr,
                    RequestMeta {
                        server_name,
                        url_path: None,
                    },
                )
                .await;
            if let Err(e) = writer.write_message(&response.response).await {
                warn!("Failed to send DoQ response to {}: {}", remote_addr, e);
                return Ok(());
            }
            let _ = writer.finish();
        }
        Err(e) => {
            warn!("Failed to read DoQ request from {}: {}", remote_addr, e);
        }
    }
    Ok(())
}

#[inline]
fn extract_tls_server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name)
        .map(|name| name.to_ascii_lowercase())
}

pub fn build_quic_endpoint(
    addr: &str,
    server_config: ServerConfig,
    timeout: Option<u64>,
) -> Result<Endpoint> {
    let socket = udp::build_udp_socket(addr)?;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_config))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    if let Some(timeout) = timeout {
        let mut config = TransportConfig::default();
        let timeout = IdleTimeout::try_from(Duration::from_secs(timeout))?;
        config.max_idle_timeout(Some(timeout));
        server_config.transport = Arc::new(config);
    }

    Ok(Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}

/// Factory for creating QUIC server plugin instances
#[derive(Debug)]
pub struct QuicServerFactory {}

register_plugin_factory!("quic_server", QuicServerFactory {});

#[async_trait]
impl PluginFactory for QuicServerFactory {
    /// Get dependencies (the entry executor plugin)
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        if let Some(args) = &plugin_config.args
            && let Ok(config) = serde_yaml_ng::from_value::<QuicServerConfig>(args.clone())
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
        let quic_config = serde_yaml_ng::from_value::<QuicServerConfig>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("QUIC Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse QUIC Server config: {}", e)))?;
        let listen = normalize_listen_addr(&quic_config.listen).map_err(|e| {
            DnsError::plugin(format!(
                "Invalid QUIC listen address '{}': {}",
                quic_config.listen, e
            ))
        })?;

        // Resolve and type-check the entry executor using contextual diagnostics.
        let entry_executor = registry.get_executor_dependency(
            &plugin_config.tag,
            "args.entry",
            &quic_config.entry,
        )?;

        // Load TLS configuration if cert and key are provided
        let server_config =
            if let Some(res) = load_tls_config(&Some(quic_config.cert), &Some(quic_config.key)) {
                let mut config = res?;
                config.alpn_protocols = vec![b"doq".to_vec()];
                config
            } else {
                return Err("Failed to load TLS config".into());
            };

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            QuicServer {
                tag: plugin_config.tag.clone(),
                listen,
                server_config,
                idle_timeout: quic_config.idle_timeout,
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
    use super::*;
    use crate::plugin::test_utils::{plugin_config, test_registry};

    #[test]
    fn test_quic_factory_requires_args() {
        let factory = QuicServerFactory {};
        let cfg = plugin_config("quic", "quic_server", None);
        assert!(
            factory
                .create(&cfg, test_registry(), &Default::default())
                .is_err()
        );
    }
}
