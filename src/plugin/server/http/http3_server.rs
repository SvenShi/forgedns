/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::http::{DEFAULT_IDLE_TIMEOUT, extract_client_ip};
use crate::plugin::server::quic;
use bytes::Buf;
use bytes::Bytes;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{debug, error, warn};

/// Main HTTP/3 server loop (over QUIC)
///
/// Creates an HTTP/3 endpoint, accepts QUIC connections, and spawns
/// handler tasks for each connection and per-stream request. Uses JoinSet to
/// track and manage active connections, enabling graceful cleanup and
/// resource management.
///
/// # Architecture
/// - Binds a UDP socket for QUIC
/// - Requires TLS configuration (HTTP/3 mandates TLS over QUIC)
/// - Accepts QUIC connections and performs HTTP/3 handshake
/// - Spawns a task per connection and per request for concurrency
///
/// # Parameters
/// - `addr`: Listen address
/// - `dispatcher`: HTTP request dispatcher for routing
/// - `server_config`: TLS server config (required for HTTP/3)
/// - `idle_timeout`: Connection idle timeout in seconds (transport-level)
/// - `src_ip_header`: HTTP header name to extract real client IP
pub async fn run_server(
    addr: String,
    dispatcher: Arc<HttpDispatcher>,
    mut server_config: ServerConfig,
    idle_timeout: Option<u64>,
    src_ip_header: Option<String>,
) {
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = match quic::build_quic_endpoint(&addr, server_config, idle_timeout) {
        Ok(value) => value,
        Err(e) => {
            error!("QUIC endpoint build failed: {}", e);
            return;
        }
    };

    debug!(
        listen = %addr,
        idle_timeout_secs = idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT),
        "HTTP/3 QUIC endpoint bound successfully"
    );

    // Wrap header name in Arc to avoid cloning Strings per request
    let src_ip_header = Arc::new(src_ip_header);

    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut active_connections = 0u64;
    loop {
        // Accept new connections
        tokio::select! {
            accept_result = endpoint.accept()  => {
                match accept_result {
                    Some(connecting) => {
                        active_connections += 1;
                        let dispatcher = dispatcher.clone();
                        let src_ip_header = src_ip_header.clone();
                        tasks.spawn(async move {
                            handle_h3_connection(connecting, dispatcher, src_ip_header).await;
                        });
                        debug!("New QUIC connection started (active: {})", active_connections);
                    }
                    _ => {}
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

/// Handle a single QUIC connection and all its HTTP/3 request streams
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dispatcher: Arc<HttpDispatcher>,
    src_ip_header: Arc<Option<String>>,
) {
    let src = connecting.remote_address();
    let connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            warn!("QUIC handshake failed for {}: {}", src, e);
            return;
        }
    };
    let server_name = extract_tls_server_name(&connection);
    debug!("HTTP/3 connection established with {}", src);

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("HTTP/3 handshake error from {}: {}", src, e);
                return;
            }
        };

    loop {
        let (request, stream) = match h3_conn.accept().await {
            Ok(Some(request)) => match request.resolve_request().await {
                Ok(resolved) => resolved,
                Err(e) => {
                    warn!("Failed to resolve HTTP/3 request from {}: {}", src, e);
                    continue;
                }
            },
            Ok(None) => {
                debug!("HTTP/3 connection closed by {}", src);
                return;
            }
            Err(e) => {
                warn!("Error accepting HTTP/3 request from {}: {}", src, e);
                continue;
            }
        };

        let dispatcher = dispatcher.clone();
        let src_ip_header_clone = src_ip_header.clone();
        let server_name = server_name.clone();
        tokio::spawn(async move {
            handle_h3_request(
                request,
                stream,
                dispatcher,
                src,
                src_ip_header_clone,
                server_name,
            )
            .await;
        });
    }
}

/// Handle a single HTTP/3 request stream
async fn handle_h3_request(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    dispatcher: Arc<HttpDispatcher>,
    src: SocketAddr,
    src_ip_header: Arc<Option<String>>,
    server_name: Option<String>,
) {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().map(|s| s.to_string());
    let headers = request.headers();

    let client_addr = extract_client_ip(headers, &*src_ip_header, src);
    debug!(
        "Received {} {} from {} (real: {})",
        method, path, src, client_addr
    );

    let mut body_bytes = Vec::new();
    while let Ok(chunk_result) = stream.recv_data().await {
        match chunk_result {
            Some(chunk) => {
                body_bytes.extend_from_slice(chunk.chunk());
            }
            _ => {
                warn!("Failed to read request body chunk from {}", src);
                break;
            }
        }
    }

    let body = Bytes::from(body_bytes);
    let response = dispatcher
        .handle_request(method, path, query, body, client_addr, server_name)
        .await;

    let (parts, response_bytes) = response.into_parts();

    let h3_response = match http::Response::builder()
        .status(parts.status)
        .version(parts.version)
        .body(())
    {
        Ok(mut resp) => {
            *resp.headers_mut() = parts.headers;
            resp
        }
        Err(e) => {
            warn!("Failed to build HTTP/3 response: {}", e);
            return;
        }
    };

    if let Err(e) = stream.send_response(h3_response).await {
        warn!("Failed to send HTTP/3 response headers to {}: {}", src, e);
        return;
    }

    if let Err(e) = stream.send_data(response_bytes).await {
        warn!("Failed to send HTTP/3 response body to {}: {}", src, e);
        return;
    }

    debug!("Response sent to {}", src);
}

#[inline]
fn extract_tls_server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name)
        .map(|name| name.to_ascii_lowercase())
}
