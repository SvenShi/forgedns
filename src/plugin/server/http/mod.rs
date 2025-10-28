/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! HTTP DNS server plugin
//!
//! Listens for DNS queries over HTTP (with optional TLS support) and processes
//! them through a configured entry plugin executor. Handles concurrent requests
//! efficiently and manages task spawning with automatic cleanup.
//!
//! ## TLS Support
//!
//! The server supports optional TLS encryption. To enable TLS, provide both
//! `cert` and `key` configuration options pointing to PEM-encoded certificate
//! and private key files.

mod http2_server;
mod http3_server;
mod http_dispatcher;

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::plugin::server::http::http_dispatcher::{DnsGetHandler, DnsPostHandler, HttpDispatcher};
use crate::plugin::server::{RequestHandle, Server, load_tls_config};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use async_trait::async_trait;
use http::Method;
use rustls::ServerConfig;
use serde::Deserialize;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub(crate) const DEFAULT_IDLE_TIMEOUT: u64 = 30;

/// HTTP server configuration
#[derive(Deserialize)]
pub struct HttpServerConfig {
    /// DoH route entries mapping HTTP paths to executor plugins.
    ///
    /// - Each route defines a `path` (e.g., "/dns-query") and an executor `exec` tag.
    /// - Requests are routed by HTTP method and path via `HttpDispatcher`.
    entries: Vec<Entry>,

    /// HTTP listen address in `ip:port` format (e.g., "0.0.0.0:443").
    ///
    /// - Must be a valid `SocketAddr` string or validation will fail.
    /// - When TLS is configured, server runs HTTPS (HTTP/2) and optional HTTP/3.
    listen: String,

    /// HTTP header name to extract real client IP (optional).
    ///
    /// - Common values: "X-Real-IP", "X-Forwarded-For".
    /// - Useful when running behind reverse proxies; falls back to TCP source IP if absent.
    src_ip_header: Option<String>,

    /// Path to TLS certificate file (PEM format, optional).
    ///
    /// - When both `cert` and `key` are provided, HTTPS is enabled.
    /// - Required for enabling HTTP/3.
    cert: Option<String>,

    /// Path to TLS private key file (PEM format, optional).
    ///
    /// - Supports common key formats (PKCS#8/RSA/EC) via `rustls-pemfile`.
    key: Option<String>,

    /// HTTP connection idle timeout in seconds.
    ///
    /// - Default: 30 seconds if omitted.
    /// - Applies to HTTP/2 connections; HTTP/3 uses QUIC transport idle timeout.
    idle_timeout: Option<u64>,

    /// Enable HTTP/3 (QUIC) for DoH connections.
    ///
    /// - Requires TLS to be configured (`cert` + `key`).
    /// - Reuses the same `listen` address via QUIC endpoint.
    enable_http3: Option<bool>,
}

/// HTTP route entry configuration
///
/// Maps an HTTP path to a DNS executor plugin
#[derive(Deserialize, Debug)]
pub struct Entry {
    /// HTTP path (e.g., "/dns-query").
    ///
    /// - Must start with '/'.
    /// - Combined with HTTP method for routing in `HttpDispatcher`.
    pub path: String,
    /// Executor plugin tag to handle DNS queries for this path.
    ///
    /// - Must reference an existing executor plugin in `PluginRegistry`.
    pub exec: String,
}

/// HTTP DNS server plugin
///
/// Implements DNS over HTTPS (DoH) RFC 8484 server functionality.
/// Supports both HTTP and HTTPS (TLS) with flexible routing to multiple
/// DNS executors based on request paths.
pub struct HttpServer {
    /// Plugin identifier
    tag: String,
    /// Route configurations mapping paths to executors
    entries: Vec<Entry>,
    /// Listen address (e.g., "0.0.0.0:443")
    listen: String,
    /// HTTP header name to extract real client IP from reverse proxy
    src_ip_header: Option<String>,
    /// HTTP request dispatcher for routing
    dispatcher: Arc<HttpDispatcher>,
    /// TLS acceptor for HTTPS support (None for plain HTTP)
    server_config: Option<ServerConfig>,
    /// Connection idle timeout in seconds
    idle_timeout: Option<u64>,
    /// Enable HTTP/3 for DoH connections
    enable_http3: Option<bool>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("tag", &self.tag)
            .field("entries", &self.entries)
            .field("src_ip_header", &self.src_ip_header)
            .field("listen", &self.listen)
            .field("has_dispatcher", &true)
            .field("has_tls", &self.server_config.is_some())
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

#[async_trait]
impl Plugin for HttpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        self.run();
    }

    async fn destroy(&mut self) {}
}

impl Server for HttpServer {
    fn run(&self) {
        let listen = self.listen.clone();
        let tls_mode = self.server_config.is_some();

        // Start HTTP/2 server (over TCP)
        tokio::spawn(http2_server::run_server(
            listen.clone(),
            self.dispatcher.clone(),
            self.server_config.clone(),
            self.idle_timeout,
            self.src_ip_header.clone(),
        ));

        if tls_mode {
            info!("HTTPS (HTTP/2) server listening on {}", listen);
        } else {
            info!("HTTP (HTTP/2) server listening on {}", listen);
        }

        if self.enable_http3.unwrap_or(false) {
            match self.server_config.clone() {
                Some(cfg) => {
                    info!("HTTP/3 server listening on {}", listen);
                    tokio::spawn(http3_server::run_server(
                        listen.clone(),
                        self.dispatcher.clone(),
                        cfg,
                        self.idle_timeout,
                        self.src_ip_header.clone(),
                    ));
                }
                None => {
                    error!("HTTP/3 requires TLS; server_config is missing");
                }
            };
        }
    }
}

/// Factory for creating HTTP server plugin instances
#[derive(Debug)]
pub struct HttpServerFactory {}

#[async_trait]
impl PluginFactory for HttpServerFactory {
    fn create(
        &self,
        plugin_info: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let http_config = serde_yml::from_value::<HttpServerConfig>(
            plugin_info
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("HTTP Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse HTTP Server config: {}", e)))?;

        // Create HTTP dispatcher for routing requests
        let mut dispatcher = HttpDispatcher::new();

        // Register routes for each configured entry
        // Each entry maps a path to an executor that processes DNS queries
        for entry in &http_config.entries {
            // Look up the executor plugin by its tag
            let executor = registry.get_plugin(&entry.exec).ok_or_else(|| {
                DnsError::plugin(format!(
                    "HTTP Server [{}] executor plugin [{}] not found",
                    plugin_info.tag, entry.exec
                ))
            })?;

            // Create request handle that wraps the executor
            let request_handle = Arc::new(RequestHandle {
                entry_executor: executor.to_executor().clone(),
                registry: registry.clone(),
            });

            // Register GET route (DoH RFC 8484: DNS query in URL parameter)
            info!(
                "Registering HTTP route: GET {} -> {}",
                entry.path, entry.exec
            );
            dispatcher.register_route(
                Method::GET,
                entry.path.clone(),
                Box::new(DnsGetHandler::new(request_handle.clone())),
            );

            // Register POST route (DoH RFC 8484: DNS query in request body)
            info!(
                "Registering HTTP route: POST {} -> {}",
                entry.path, entry.exec
            );
            dispatcher.register_route(
                Method::POST,
                entry.path.clone(),
                Box::new(DnsPostHandler::new(request_handle.clone())),
            );
        }

        // Load TLS configuration if cert and key are provided
        let server_config = match load_tls_config(&http_config.cert, &http_config.key) {
            None => None,
            Some(res) => Some(res?),
        };

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            HttpServer {
                tag: plugin_info.tag.clone(),
                entries: http_config.entries,
                listen: http_config.listen,
                src_ip_header: http_config.src_ip_header,
                dispatcher: Arc::new(dispatcher),
                server_config,
                idle_timeout: http_config.idle_timeout,
                enable_http3: http_config.enable_http3,
            },
        )))
    }

    /// Validate HTTP server configuration
    fn validate_config(&self, plugin_info: &PluginConfig) -> Result<()> {
        use std::net::SocketAddr;
        use std::str::FromStr;

        // Parse and validate HTTP-specific configuration
        let http_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<HttpServerConfig>(args).map_err(|e| {
                DnsError::plugin(format!("HTTP Server config parsing failed: {}", e))
            })?,
            None => {
                return Err(DnsError::plugin(
                    "HTTP Server must configure 'listen' and 'entry' in config file",
                ));
            }
        };

        // Validate listen address format
        if SocketAddr::from_str(&http_config.listen).is_err() {
            return Err(DnsError::plugin(format!(
                "Invalid listen address: {}",
                http_config.listen
            )));
        }

        // Validate entry is not empty
        if http_config.entries.is_empty() {
            return Err(DnsError::plugin(
                "HTTP Server 'entry' field cannot be empty",
            ));
        }

        Ok(())
    }

    /// Get dependencies (the entry executor plugins)
    fn get_dependencies(&self, plugin_info: &PluginConfig) -> Vec<String> {
        let http_config = match plugin_info.args.clone() {
            Some(args) => match serde_yml::from_value::<HttpServerConfig>(args) {
                Ok(config) => config,
                Err(_) => return vec![],
            },
            None => return vec![],
        };

        // Return all entry executors as dependencies
        // This ensures executors are initialized before the HTTP server
        http_config.entries.iter().map(|e| e.exec.clone()).collect()
    }
}

/// Extract real client IP address from HTTP headers
///
/// When running behind a reverse proxy (e.g., Nginx, HAProxy), the TCP source
/// address will be the proxy's IP, not the actual client's IP. This function
/// attempts to extract the real client IP from configured HTTP headers.
///
/// Supports common headers:
/// - X-Real-IP: Single IP address from the client
/// - X-Forwarded-For: Comma-separated list of IPs (takes the first one)
/// - Custom headers as configured
///
/// Returns the TCP source address if header is not configured or parsing fails.
pub fn extract_client_ip(
    headers: &http::HeaderMap,
    src_ip_header: &Option<String>,
    tcp_src: SocketAddr,
) -> SocketAddr {
    if let Some(header_name) = src_ip_header {
        if let Some(header_value) = headers.get(header_name.as_str()) {
            if let Ok(ip_str) = header_value.to_str() {
                // Try to parse as complete SocketAddr (IP:Port)
                if let Ok(addr) = SocketAddr::from_str(ip_str) {
                    debug!("Extracted real IP: {} (from header {})", addr, header_name);
                    return addr;
                }
                // Try to parse as IP only, use TCP port
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    let addr = SocketAddr::new(ip, tcp_src.port());
                    debug!(
                        "Extracted real IP: {} (from header {}, port from TCP)",
                        addr, header_name
                    );
                    return addr;
                }
                // X-Forwarded-For may contain multiple IPs, take the first one (original client)
                if let Some(first_ip) = ip_str.split(',').next() {
                    let first_ip = first_ip.trim();
                    if let Ok(ip) = first_ip.parse::<std::net::IpAddr>() {
                        let addr = SocketAddr::new(ip, tcp_src.port());
                        debug!(
                            "Extracted real IP: {} (from header {}, first in X-Forwarded-For)",
                            addr, header_name
                        );
                        return addr;
                    }
                }
                warn!("Failed to parse IP from header {}: {}", header_name, ip_str);
            }
        }
    }
    tcp_src
}
