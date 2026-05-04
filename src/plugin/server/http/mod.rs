// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

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

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderValue, Method};
use rustls::ServerConfig;
use serde::Deserialize;
use tokio::sync::{oneshot, watch};
use tracing::{debug, error, info, warn};

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::deserialize_duration_option;
use crate::network::tls_config::load_tls_config;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::server::http::http_dispatcher::{DnsGetHandler, DnsPostHandler, HttpDispatcher};
use crate::plugin::server::{RequestHandle, Server, parse_listen_addr};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use crate::register_plugin_factory;

mod http2_server;
mod http3_server;
mod http_dispatcher;

pub(crate) const DEFAULT_SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP server configuration
#[derive(Deserialize)]
pub struct HttpServerConfig {
    /// DoH route entries mapping HTTP paths to executor plugins.
    ///
    /// - Each route defines a `path` (e.g., "/dns-query") and an executor
    ///   `exec` tag.
    /// - Requests are routed by HTTP method and path via `HttpDispatcher`.
    entries: Vec<Entry>,

    /// HTTP listen address in `ip:port` or `:port` format (e.g., "0.0.0.0:443",
    /// ":443").
    ///
    /// - `:port` binds on `0.0.0.0:port`.
    /// - Must be a valid listen address or validation will fail.
    /// - When TLS is configured, server runs HTTPS (HTTP/2) and optional
    ///   HTTP/3.
    listen: String,

    /// HTTP header name to extract real client IP (optional).
    ///
    /// - Common values: "X-Real-IP", "X-Forwarded-For".
    /// - Useful when running behind reverse proxies; falls back to TCP source
    ///   IP if absent.
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
    /// - Applies to HTTP/2 connections; HTTP/3 uses QUIC transport idle
    ///   timeout.
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    idle_timeout: Option<Duration>,

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
    listen: SocketAddr,
    /// HTTP header name to extract real client IP from reverse proxy
    src_ip_header: Option<String>,
    /// HTTP request dispatcher for routing
    dispatcher: Arc<HttpDispatcher>,
    /// TLS acceptor for HTTPS support (None for plain HTTP)
    server_config: Option<ServerConfig>,
    /// Connection idle timeout in seconds
    idle_timeout: Duration,
    /// Enable HTTP/3 for DoH connections
    enable_http3: Option<bool>,
    /// Prebuilt Alt-Svc header for HTTP/2 responses when HTTP/3 is enabled
    http2_alt_svc: Option<HeaderValue>,
    /// Shared shutdown signal for HTTP/2 and HTTP/3 tasks
    shutdown_tx: watch::Sender<bool>,
    /// Spawned top-level server task handles
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
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

impl HttpServer {
    fn spawn_server_tasks(
        &self,
        h2_startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
        h3_startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
    ) -> Result<()> {
        let mut task_handles = self
            .task_handles
            .lock()
            .map_err(|_| DnsError::runtime("HTTP server task lock poisoned"))?;

        if !task_handles.is_empty() {
            if let Some(tx) = h2_startup_tx {
                let _ = tx.send(Ok(()));
            }
            if let Some(tx) = h3_startup_tx {
                let _ = tx.send(Ok(()));
            }
            return Ok(());
        }

        let listen = self.listen;
        let tls_mode = self.server_config.is_some();
        debug!(
            listen = %listen,
            tls = tls_mode,
            http3 = self.enable_http3.unwrap_or(false),
            "Spawning HTTP server tasks"
        );

        task_handles.push(tokio::spawn(http2_server::run_server(
            listen,
            self.dispatcher.clone(),
            self.server_config.clone(),
            self.http2_alt_svc.clone(),
            self.idle_timeout,
            self.src_ip_header.clone(),
            self.shutdown_tx.subscribe(),
            h2_startup_tx,
        )));

        if self.enable_http3.unwrap_or(false) {
            match self.server_config.clone() {
                Some(cfg) => {
                    task_handles.push(tokio::spawn(http3_server::run_server(
                        listen,
                        self.dispatcher.clone(),
                        cfg,
                        self.idle_timeout,
                        self.src_ip_header.clone(),
                        self.shutdown_tx.subscribe(),
                        h3_startup_tx,
                    )));
                }
                None => {
                    if let Some(tx) = h3_startup_tx {
                        let _ = tx.send(Err("HTTP/3 requires TLS".to_string()));
                    }
                    return Err(DnsError::plugin(
                        "HTTP/3 requires TLS; cert/key are missing",
                    ));
                }
            };
        } else if let Some(tx) = h3_startup_tx {
            let _ = tx.send(Ok(()));
        }

        Ok(())
    }
}

#[async_trait]
impl Plugin for HttpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) -> Result<()> {
        let (h2_tx, h2_rx) = oneshot::channel();
        let (h3_tx, h3_rx) = if self.enable_http3.unwrap_or(false) {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        self.spawn_server_tasks(Some(h2_tx), h3_tx)?;

        match h2_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(DnsError::plugin(e)),
            Err(_) => {
                return Err(DnsError::plugin(
                    "HTTP/2 server startup channel closed unexpectedly",
                ));
            }
        }

        if let Some(h3_rx) = h3_rx {
            match h3_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(DnsError::plugin(e)),
                Err(_) => {
                    return Err(DnsError::plugin(
                        "HTTP/3 server startup channel closed unexpectedly",
                    ));
                }
            }
        }

        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(true);
        let handles = {
            let mut task_handles = self
                .task_handles
                .lock()
                .map_err(|_| DnsError::runtime("HTTP server task lock poisoned"))?;
            std::mem::take(&mut *task_handles)
        };
        for handle in handles {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl Server for HttpServer {
    fn run(&self) {
        if let Err(e) = self.spawn_server_tasks(None, None) {
            error!(plugin = %self.tag, error = %e, "Failed to spawn HTTP server task");
        }
    }
}

/// Factory for creating HTTP server plugin instances
#[derive(Debug)]
pub struct HttpServerFactory {}

register_plugin_factory!("http_server", HttpServerFactory {});

#[async_trait]
impl PluginFactory for HttpServerFactory {
    /// Get dependencies (the entry executor plugins)
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let http_config = match plugin_config.args.clone() {
            Some(args) => match serde_yaml_ng::from_value::<HttpServerConfig>(args) {
                Ok(config) => config,
                Err(_) => return vec![],
            },
            None => return vec![],
        };

        // Return all entry executors as dependencies
        // This ensures executors are initialized before the HTTP server
        http_config
            .entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                DependencySpec::executor(format!("args.entries[{}].exec", idx), entry.exec.clone())
            })
            .collect()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let http_config = serde_yaml_ng::from_value::<HttpServerConfig>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("HTTP Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse HTTP Server config: {}", e)))?;
        let listen = parse_listen_addr(&http_config.listen).map_err(|e| {
            DnsError::plugin(format!(
                "Invalid HTTP listen address '{}': {}",
                http_config.listen, e
            ))
        })?;

        // Create HTTP dispatcher for routing requests
        let mut dispatcher = HttpDispatcher::new();

        // Register routes for each configured entry
        // Each entry maps a path to an executor that processes DNS queries
        for (idx, entry) in http_config.entries.iter().enumerate() {
            let field = format!("args.entries[{}].exec", idx);
            // Resolve and type-check executor with field context.
            let executor =
                registry.get_executor_dependency(&plugin_config.tag, &field, &entry.exec)?;

            // Create request handle that wraps the executor
            let request_handle = Arc::new(RequestHandle {
                entry_executor: executor,
                registry: registry.clone(),
            });

            // Register GET route (DoH RFC 8484: DNS query in URL parameter)
            info!(
                "Registering HTTP route: GET {} -> {}",
                entry.path, entry.exec
            );
            dispatcher.register_route(
                Method::GET,
                Arc::from(entry.path.clone()),
                Box::new(DnsGetHandler::new(request_handle.clone())),
            );

            // Register POST route (DoH RFC 8484: DNS query in request body)
            info!(
                "Registering HTTP route: POST {} -> {}",
                entry.path, entry.exec
            );
            dispatcher.register_route(
                Method::POST,
                Arc::from(entry.path.clone()),
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
                tag: plugin_config.tag.clone(),
                entries: http_config.entries,
                listen,
                src_ip_header: http_config.src_ip_header,
                dispatcher: Arc::new(dispatcher),
                server_config,
                idle_timeout: http_config
                    .idle_timeout
                    .unwrap_or(DEFAULT_SERVER_IDLE_TIMEOUT),
                enable_http3: http_config.enable_http3,
                http2_alt_svc: http2_alt_svc_for_config(http_config.enable_http3, listen)?,
                shutdown_tx: watch::channel(false).0,
                task_handles: Mutex::new(Vec::new()),
            },
        )))
    }
}

fn http2_alt_svc_for_config(
    enable_http3: Option<bool>,
    listen: SocketAddr,
) -> Result<Option<HeaderValue>> {
    enable_http3
        .unwrap_or(false)
        .then(|| http3_alt_svc_header(listen))
        .transpose()
}

fn http3_alt_svc_header(listen: SocketAddr) -> Result<HeaderValue> {
    let value = format!("h3=\":{}\"; ma=86400", listen.port());
    HeaderValue::from_str(&value)
        .map_err(|e| DnsError::plugin(format!("Failed to build HTTP/3 Alt-Svc header: {}", e)))
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
    src_ip_header: &Option<Arc<str>>,
    tcp_src: SocketAddr,
) -> SocketAddr {
    if let Some(header_name) = src_ip_header
        && let Some(header_value) = headers.get(header_name.as_ref())
        && let Ok(ip_str) = header_value.to_str()
    {
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
        // X-Forwarded-For may contain multiple IPs, take the first one (original
        // client)
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
    tcp_src
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use http::HeaderMap;
    use serde_yaml_ng::from_str;

    use super::*;
    use crate::plugin::test_utils::{plugin_config, test_registry};

    #[test]
    fn test_http_factory_requires_args() {
        let factory = HttpServerFactory {};
        let cfg = plugin_config("http", "http_server", None);
        assert!(
            factory
                .create(&cfg, test_registry(), &Default::default())
                .is_err()
        );
    }

    #[test]
    fn test_http_factory_reports_all_executor_dependencies() {
        let factory = HttpServerFactory {};
        let args = from_str(
            r#"
entries:
  - path: /dns-query
    exec: exec_a
  - path: /dns-alt
    exec: exec_b
listen: 127.0.0.1:443
"#,
        )
        .expect("yaml should parse");
        let cfg = plugin_config("http", "http_server", Some(args));

        let deps = factory.get_dependency_specs(&cfg);

        assert_eq!(deps.len(), 2);
        assert_eq!(
            deps[0],
            DependencySpec::executor("args.entries[0].exec", "exec_a")
        );
        assert_eq!(
            deps[1],
            DependencySpec::executor("args.entries[1].exec", "exec_b")
        );
    }

    #[test]
    fn test_extract_client_ip_prefers_socket_addr_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-real-ip",
            "198.51.100.10:8443".parse().expect("header should parse"),
        );
        let src = SocketAddr::from(([127, 0, 0, 1], 443));

        let client = extract_client_ip(&headers, &Some(Arc::from("x-real-ip")), src);

        assert_eq!(client, SocketAddr::from(([198, 51, 100, 10], 8443)));
    }

    #[test]
    fn test_http2_alt_svc_is_initialized_when_http3_is_enabled() {
        let value = http2_alt_svc_for_config(Some(true), SocketAddr::from(([127, 0, 0, 1], 9443)))
            .expect("Alt-Svc header should build")
            .expect("HTTP/3 enabled should create Alt-Svc");

        assert_eq!(value, "h3=\":9443\"; ma=86400");
    }

    #[test]
    fn test_http2_alt_svc_is_absent_when_http3_is_disabled() {
        let value = http2_alt_svc_for_config(Some(false), SocketAddr::from(([127, 0, 0, 1], 9443)))
            .expect("Alt-Svc initialization should succeed");

        assert!(value.is_none());
    }

    #[test]
    fn test_extract_client_ip_uses_ip_only_header_with_tcp_port() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-real-ip",
            "198.51.100.11".parse().expect("header should parse"),
        );
        let src = SocketAddr::from(([127, 0, 0, 1], 443));

        let client = extract_client_ip(&headers, &Some(Arc::from("x-real-ip")), src);

        assert_eq!(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)), 443)
        );
    }

    #[test]
    fn test_extract_client_ip_uses_first_forwarded_for_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.10, 198.51.100.20"
                .parse()
                .expect("header should parse"),
        );
        let src = SocketAddr::from(([127, 0, 0, 1], 443));

        let client = extract_client_ip(&headers, &Some(Arc::from("x-forwarded-for")), src);

        assert_eq!(client, SocketAddr::from(([203, 0, 113, 10], 443)));
    }

    #[test]
    fn test_extract_client_ip_falls_back_to_tcp_source_on_invalid_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-real-ip",
            "not-an-ip".parse().expect("header should parse"),
        );
        let src = SocketAddr::from(([127, 0, 0, 1], 443));

        let client = extract_client_ip(&headers, &Some(Arc::from("x-real-ip")), src);

        assert_eq!(client, src);
    }
}
