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

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::network::server::http_dispatcher::{DnsGetHandler, DnsPostHandler, HttpDispatcher};
use crate::plugin::server::{RequestHandle, Server, load_tls_config};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry};
use async_trait::async_trait;
use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::io::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

const DEFAULT_IDLE_TIMEOUT: u64 = 30;

/// HTTP server configuration
#[derive(Deserialize)]
pub struct HttpServerConfig {
    /// Entry executor plugin tag to process incoming requests
    entries: Vec<Entry>,

    /// HTTP listen address (e.g., "0.0.0.0:443")
    listen: String,

    /// HTTP header name to extract real client IP (e.g., "X-Real-IP", "X-Forwarded-For")
    /// Used when running behind a reverse proxy
    src_ip_header: Option<String>,

    /// Path to TLS certificate file (PEM format, optional)
    cert: Option<String>,

    /// Path to TLS private key file (PEM format, optional)
    key: Option<String>,

    /// HTTP connection idle timeout in seconds (default: 30)
    idle_timeout: Option<u64>,
}

/// HTTP route entry configuration
///
/// Maps an HTTP path to a DNS executor plugin
#[derive(Deserialize, Debug)]
pub struct Entry {
    /// HTTP path (e.g., "/dns-query")
    pub path: String,
    /// Executor plugin tag to handle DNS queries for this path
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
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    /// Connection idle timeout in seconds
    idle_timeout: Option<u64>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("tag", &self.tag)
            .field("entries", &self.entries)
            .field("src_ip_header", &self.src_ip_header)
            .field("listen", &self.listen)
            .field("has_dispatcher", &true)
            .field("has_tls", &self.tls_acceptor.is_some())
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
        let tls_mode = self.tls_acceptor.is_some();

        // Start HTTP/2 server (over TCP)
        tokio::spawn(run_http2_server(
            listen.clone(),
            self.dispatcher.clone(),
            self.tls_acceptor.clone(),
            self.idle_timeout,
            self.src_ip_header.clone(),
        ));

        if tls_mode {
            info!("HTTPS (HTTP/2) server listening on {}", listen);
        } else {
            info!("HTTP server listening on {}", listen);
        }
    }
}

/// Main HTTP/2 server loop (over TCP)
///
/// Creates an HTTP/2 stream, listens for incoming DNS queries, and spawns
/// handler tasks for each request. Uses JoinSet to track and manage active
/// connections, enabling graceful cleanup and resource management.
///
/// # Architecture
/// - Accepts TCP connections (with optional TLS handshake)
/// - Performs HTTP/2 handshake
/// - Spawns a task per connection to handle HTTP/2 multiplexed requests
/// - Each request is further spawned into its own task for maximum concurrency
///
/// # Parameters
/// - `addr`: Listen address
/// - `dispatcher`: HTTP request dispatcher for routing
/// - `tls_acceptor`: Optional TLS acceptor for HTTPS
/// - `idle_timeout`: Connection idle timeout in seconds
/// - `src_ip_header`: HTTP header name to extract real client IP
async fn run_http2_server(
    addr: String,
    dispatcher: Arc<HttpDispatcher>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    idle_timeout: Option<u64>,
    src_ip_header: Option<String>,
) {
    let timeout = Duration::from_secs(idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT));
    let listener = match build_tcp_listener(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind HTTP socket to {}: {}", addr, e);
            return;
        }
    };

    // JoinSet to track all active connection tasks
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut active_connections = 0u64;

    loop {
        tokio::select! {
            // Accept new connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, src)) => {
                        let dispatcher = dispatcher.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let src_ip_header = src_ip_header.clone();

                        active_connections += 1;
                        debug!("New connection from {} (active: {})", src, active_connections);

                        tasks.spawn(async move {
                            // Handle TLS handshake if TLS is enabled
                            if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        debug!("TLS handshake completed for client {}", src);
                                        handle_http_stream(tls_stream, src, dispatcher, src_ip_header.clone()).await;
                                    }
                                    Err(e) => {
                                        warn!("TLS handshake failed for {}: {}", src, e);
                                    }
                                }
                            } else {
                                // Plain HTTP connection
                                debug!("HTTP server connected to client {}", src);
                                handle_http_stream(stream, src, dispatcher, src_ip_header.clone()).await;
                            }
                        });
                    }
                    Err(e) => {
                        debug!(%e, "Error accepting HTTP connection");
                    }
                }
            }

            // Clean up finished tasks
            Some(result) = tasks.join_next() => {
                active_connections = active_connections.saturating_sub(1);

                if let Err(e) = result {
                    warn!("Connection task panicked: {:?}", e);
                }

                // Log when connection count changes significantly
                if active_connections % 10 == 0 && active_connections > 0 {
                    debug!("Active connections: {}", active_connections);
                }
            }
        }
    }
}

/// Handle HTTP/2 requests over a stream (works for both TLS and plain HTTP)
///
/// This function:
/// 1. Performs HTTP/2 handshake
/// 2. Accepts HTTP/2 requests in a loop (multiplexed over single connection)
/// 3. Spawns a task for each request to process it asynchronously
/// 4. Extracts real client IP from HTTP headers if configured
/// 5. Reads request body with flow control
/// 6. Dispatches to appropriate handler
/// 7. Returns HTTP response
///
/// # Type Parameters
/// - `S`: Stream type implementing AsyncRead + AsyncWrite (e.g., TcpStream, TlsStream)
async fn handle_http_stream<S>(
    stream: S,
    src: SocketAddr,
    dispatcher: Arc<HttpDispatcher>,
    src_ip_header: Option<String>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Start the HTTP/2.0 connection handshake
    let mut h2 = match h2::server::handshake(stream).await {
        Ok(h2) => h2,
        Err(err) => {
            warn!("HTTP/2 handshake error from {}: {}", src, err);
            return;
        }
    };

    debug!("HTTP/2 connection established with {}", src);

    // Process HTTP/2 requests
    loop {
        let (request, mut respond) = match h2.accept().await {
            Some(Ok(next_request)) => next_request,
            Some(Err(err)) => {
                warn!("Error accepting HTTP/2 request from {}: {}", src, err);
                return;
            }
            None => {
                debug!("HTTP/2 connection closed by {}", src);
                return;
            }
        };

        let dispatcher = dispatcher.clone();
        let src_ip_header_clone = src_ip_header.clone();

        // Spawn a task to handle this request (non-blocking)
        // Each request is processed in its own task for maximum concurrency
        tokio::spawn(async move {
            // Extract request metadata
            let method = request.method().clone();
            let uri = request.uri().clone();
            let path = uri.path().to_string();
            let query = uri.query().map(|s| s.to_string());
            let headers = request.headers();

            // Try to extract real client IP from HTTP headers (e.g., X-Real-IP, X-Forwarded-For)
            // This is essential when running behind a reverse proxy
            let client_addr = extract_client_ip(headers, &src_ip_header_clone, src);

            debug!("Received {} {} from {} (real: {})", method, path, src, client_addr);

            // Read request body from h2::RecvStream
            // HTTP/2 streams data in chunks for flow control
            let mut recv_stream = request.into_body();
            let mut body_bytes = Vec::new();

            while let Some(chunk_result) = recv_stream.data().await {
                match chunk_result {
                    Ok(chunk) => {
                        body_bytes.extend_from_slice(&chunk);
                        // MUST call flow_control().release_capacity() to release flow control window
                        // This allows the sender to continue sending more data
                        let _ = recv_stream.flow_control().release_capacity(chunk.len());
                    }
                    Err(e) => {
                        warn!("Failed to read request body chunk from {}: {}", src, e);
                        break;
                    }
                }
            }

            let body = Bytes::from(body_bytes);

            // Dispatch request to appropriate handler (using real client IP for logging and filtering)
            let response = dispatcher
                .handle_request(method, path, query, body, client_addr)
                .await;

            // Convert response to HTTP/2 format
            let (parts, response_body) = response.into_parts();
            let response_bytes = match response_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    warn!("Failed to collect response body from {}: {}", src, e);
                    return;
                }
            };

            // Build HTTP/2 response with empty body (body sent separately)
            let h2_response = match http::Response::builder()
                .status(parts.status)
                .version(parts.version)
                .body(())
            {
                Ok(mut resp) => {
                    *resp.headers_mut() = parts.headers;
                    resp
                }
                Err(e) => {
                    warn!("Failed to build HTTP/2 response: {}", e);
                    return;
                }
            };

            // Send response headers
            let mut send_stream = match respond.send_response(h2_response, false) {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("Failed to send HTTP/2 response headers to {}: {}", src, e);
                    return;
                }
            };

            // Send response body (end_stream=true to close the stream)
            if let Err(e) = send_stream.send_data(response_bytes, true) {
                warn!("Failed to send HTTP/2 response body to {}: {}", src, e);
                return;
            }

            debug!("Response sent to {}", src);
        });
    }
}

/// Build a TCP socket with reuse_address and reuse_port options
///
/// Creates a socket optimized for DNS server workloads with port reuse enabled.
/// This allows multiple server instances to bind to the same port for load balancing.
///
/// Socket options configured:
/// - `SO_REUSEADDR`: Allow binding to addresses in TIME_WAIT state
/// - `SO_REUSEPORT`: Allow multiple sockets to bind to the same port (Linux/Unix)
/// - `TCP_NODELAY`: Disable Nagle's algorithm for low latency
/// - `TCP_KEEPALIVE`: Keep connections alive with periodic probes
///
/// # Parameters
/// - `addr`: Listen address (e.g., "0.0.0.0:443")
/// - `idle_timeout`: TCP keepalive interval
fn build_tcp_listener(addr: &str, idle_timeout: Duration) -> Result<TcpListener> {
    let addr = SocketAddr::from_str(addr).map_err(|e| {
        Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid address {}: {}", addr, e),
        )
    })?;

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
fn extract_client_ip(
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
                    debug!("Extracted real IP: {} (from header {}, port from TCP)", addr, header_name);
                    return addr;
                }
                // X-Forwarded-For may contain multiple IPs, take the first one (original client)
                if let Some(first_ip) = ip_str.split(',').next() {
                    let first_ip = first_ip.trim();
                    if let Ok(ip) = first_ip.parse::<std::net::IpAddr>() {
                        let addr = SocketAddr::new(ip, tcp_src.port());
                        debug!("Extracted real IP: {} (from header {}, first in X-Forwarded-For)", addr, header_name);
                        return addr;
                    }
                }
                warn!("Failed to parse IP from header {}: {}", header_name, ip_str);
            }
        }
    }
    tcp_src
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
        let tls_acceptor = match (&http_config.cert, &http_config.key) {
            (Some(cert), Some(key)) => {
                info!(
                    "Loading TLS configuration for HTTP server [{}]: cert={}, key={}",
                    plugin_info.tag, cert, key
                );
                Some(Arc::new(load_tls_config(cert, key)?))
            }
            (Some(_), None) => {
                return Err(DnsError::plugin(format!(
                    "HTTP Server [{}]: cert specified but key is missing",
                    plugin_info.tag
                )));
            }
            (None, Some(_)) => {
                return Err(DnsError::plugin(format!(
                    "HTTP Server [{}]: key specified but cert is missing",
                    plugin_info.tag
                )));
            }
            (None, None) => None,
        };

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            HttpServer {
                tag: plugin_info.tag.clone(),
                entries: http_config.entries,
                listen: http_config.listen,
                src_ip_header: http_config.src_ip_header,
                dispatcher: Arc::new(dispatcher),
                tls_acceptor,
                idle_timeout: http_config.idle_timeout,
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
