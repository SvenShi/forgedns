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
use crate::plugin::server::{RequestHandle, RequestMeta, Server, udp};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use crate::register_plugin_factory;
use async_trait::async_trait;
use quinn::{Endpoint, EndpointConfig, IdleTimeout, TransportConfig};
use rustls::ServerConfig;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

/// QUIC server configuration
#[derive(Deserialize)]
pub struct QuicServerConfig {
    /// Entry executor plugin tag to process incoming requests.
    ///
    /// - Must reference an existing executor plugin registered in `PluginRegistry`.
    /// - All DoQ (DNS over QUIC) queries will be forwarded to this executor.
    entry: String,

    /// QUIC listen address in `ip:port` format (e.g., "0.0.0.0:853").
    ///
    /// - Must be a valid `SocketAddr` string or validation will fail.
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
#[derive(Debug)]
pub struct QuicServer {
    tag: String,
    listen: String,
    /// TLS acceptor for HTTPS support (None for plain HTTP)
    server_config: ServerConfig,
    idle_timeout: Option<u64>,

    request_handle: Arc<RequestHandle>,
}

#[async_trait]
impl Plugin for QuicServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        self.run();
    }

    async fn destroy(&self) {}
}

impl Server for QuicServer {
    fn run(&self) {
        let listen = self.listen.clone();
        let addr = listen.clone();

        // Spawn the QUIC server loop. This call is non-blocking and returns immediately.
        // The event loop will accept incoming QUIC connections and process DoQ streams.
        info!("Starting QUIC server on {}", listen);
        tokio::spawn(run_server(
            addr,
            self.request_handle.clone(),
            self.server_config.clone(),
            self.idle_timeout,
        ));
        info!("QUIC server listening on {}", listen);
    }
}

async fn run_server(
    addr: String,
    handler: Arc<RequestHandle>,
    server_config: ServerConfig,
    idle_timeout: Option<u64>,
) {
    let endpoint = match build_quic_endpoint(&addr, server_config, idle_timeout) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind QUIC endpoint to {}: {}", addr, e);
            return;
        }
    };
    // QUIC endpoint created successfully; enter the accept loop.
    debug!("QUIC server event loop started on {}", addr);

    // Track all active connection tasks
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut active_connections = 0u64;

    // Accept QUIC connections and spawn a task per connection.
    loop {
        tokio::select! {
            maybe_connecting = endpoint.accept() => {
                match maybe_connecting {
                    Some(connecting) => {
                        active_connections += 1;
                        let handler_clone = handler.clone();
                        tasks.spawn(async move {
                            handle_quic_connection(connecting, handler_clone).await;
                        });
                        debug!("New QUIC connection started (active: {})", active_connections);
                    }
                    None => break,
                }
            }

            // Clean up finished tasks
            Some(result) = tasks.join_next() => {
                active_connections = active_connections.saturating_sub(1);
                if let Err(e) = result {
                    warn!("Connection task panicked: {:?}", e);
                }
                if active_connections % 10 == 0 && active_connections > 0 {
                    debug!("Active connections: {}", active_connections);
                }
            }
        }
    }
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
    server_name: Option<String>,
) -> Result<()> {
    match reader.read_message().await {
        Ok(request_msg) => {
            let response = handler
                .handle_request_with_meta(
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
    addr: &String,
    server_config: ServerConfig,
    timeout: Option<u64>,
) -> Result<Endpoint> {
    let socket = udp::build_udp_socket(&addr)?;

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
    /// Validate QUIC server configuration
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        use std::net::SocketAddr;
        use std::str::FromStr;

        // Parse and validate QUIC-specific configuration
        let quic_config = match plugin_config.args.clone() {
            Some(args) => serde_yml::from_value::<QuicServerConfig>(args).map_err(|e| {
                DnsError::plugin(format!("QUIC Server config parsing failed: {}", e))
            })?,
            None => {
                return Err(DnsError::plugin(
                    "QUIC Server must configure 'listen' and 'entry' in config file",
                ));
            }
        };

        // Validate listen address format
        if SocketAddr::from_str(&quic_config.listen).is_err() {
            return Err(DnsError::plugin(format!(
                "Invalid listen address: {}",
                quic_config.listen
            )));
        }

        // Validate entry is not empty
        if quic_config.entry.is_empty() {
            return Err(DnsError::plugin(
                "QUIC Server 'entry' field cannot be empty",
            ));
        }

        Ok(())
    }

    /// Get dependencies (the entry executor plugin)
    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        if let Some(args) = &plugin_config.args {
            if let Ok(config) = serde_yml::from_value::<QuicServerConfig>(args.clone()) {
                return vec![config.entry];
            }
        }
        vec![]
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let quic_config = serde_yml::from_value::<QuicServerConfig>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("QUIC Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse QUIC Server config: {}", e)))?;

        // Look up the entry plugin using the registry
        let entry = registry.get_plugin(&quic_config.entry).ok_or_else(|| {
            DnsError::plugin(format!(
                "QUIC Server [{}] entry plugin [{}] not found",
                plugin_config.tag, quic_config.entry
            ))
        })?;

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
                listen: quic_config.listen,
                server_config,
                idle_timeout: quic_config.idle_timeout,
                request_handle: Arc::new(RequestHandle {
                    entry_executor: entry.to_executor().clone(),
                    registry,
                }),
            },
        )))
    }
}
