/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::http::{extract_client_ip, DEFAULT_IDLE_TIMEOUT};
use crate::plugin::server::tcp;
use bytes::Bytes;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, warn};

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
///
pub async fn run_server(
    addr: String,
    dispatcher: Arc<HttpDispatcher>,
    server_config: Option<Box<ServerConfig>>,
    idle_timeout: Option<u64>,
    src_ip_header: Option<String>,
) {
    let timeout = Duration::from_secs(idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT));
    let listener = match tcp::build_tcp_listener(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind HTTP socket to {}: {}", addr, e);
            return;
        }
    };

    // Wrap header name in Arc to avoid cloning Strings per request
    let src_ip_header = Arc::new(src_ip_header);

    // JoinSet to track all active connection tasks
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut active_connections = 0u64;
    let tls_acceptor = if let Some(server_config) = server_config {
        Some(Arc::new(TlsAcceptor::from(Arc::from(server_config))))
    } else {
        None
    };

    loop {
        tokio::select! {
            // Accept new connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, src)) => {
                        let dispatcher = dispatcher.clone();
                        let src_ip_header = src_ip_header.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        active_connections += 1;
                        debug!("New connection from {} (active: {})", src, active_connections);

                        tasks.spawn(async move {
                            // Handle TLS handshake if TLS is enabled
                            if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        debug!("TLS handshake completed for client {}", src);
                                        handle_http_stream(tls_stream, src, dispatcher, src_ip_header).await;
                                    }
                                    Err(e) => {
                                        warn!("TLS handshake failed for {}: {}", src, e);
                                    }
                                }
                            } else {
                                // Plain HTTP connection
                                debug!("HTTP server connected to client {}", src);
                                handle_http_stream(stream, src, dispatcher, src_ip_header).await;
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
    src_ip_header: Arc<Option<String>>,
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
            let client_addr = extract_client_ip(headers, &*src_ip_header_clone, src);

            debug!(
                "Received {} {} from {} (real: {})",
                method, path, src, client_addr
            );

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
            let (parts, response_bytes) = response.into_parts();

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
