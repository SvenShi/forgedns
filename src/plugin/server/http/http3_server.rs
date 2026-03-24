/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::plugin::server::ConnectionGuard;
use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::http::{DEFAULT_IDLE_TIMEOUT, extract_client_ip};
use crate::plugin::server::quic;
use bytes::{BufMut, Bytes, BytesMut};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

const MAX_HTTP3_BODY_SIZE: usize = 64 * 1024;

/// Main HTTP/3 server loop (over QUIC)
///
/// Creates an HTTP/3 endpoint, accepts QUIC connections, and spawns
/// handler tasks for each connection and per-stream request. Uses a task
/// tracker and cancellation token to manage active connections without
/// polling completed tasks from the accept loop.
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
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    server_config.alpn_protocols = vec![b"h3".to_vec()];

    let endpoint = match quic::build_quic_endpoint(&addr, server_config, idle_timeout) {
        Ok(value) => value,
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!("QUIC endpoint build failed: {}", e)));
            }
            error!("QUIC endpoint build failed: {}", e);
            return;
        }
    };

    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }

    info!(
        listen = %addr,
        idle_timeout_secs = idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT),
        "HTTP/3 server listening"
    );

    // Wrap header name in Arc to avoid cloning Strings per request
    let src_ip_header = src_ip_header.map(Arc::from);

    let tasks = TaskTracker::new();
    let shutdown_token = CancellationToken::new();
    let active_connections = Arc::new(AtomicU64::new(0));
    loop {
        // Accept new connections
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            accept_result = endpoint.accept() => {
                match accept_result {
                    Some(connecting) => {
                        let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        let dispatcher = dispatcher.clone();
                        let src_ip_header = src_ip_header.clone();
                        let task_shutdown = shutdown_token.clone();
                        let active_connections = active_connections.clone();
                        tasks.spawn(async move {
                            let _connection_guard =
                                ConnectionGuard::new(active_connections.clone(), connecting.remote_address(), "HTTP/3");
                            tokio::select! {
                                _ = task_shutdown.cancelled() => {}
                                _ = handle_h3_connection(connecting, dispatcher, src_ip_header) => {}
                            }
                        });
                        debug!("New QUIC connection started (active: {})", active);
                    }
                    _ => {}
                }
            }
        }
    }

    shutdown_token.cancel();
    tasks.close();
    tasks.wait().await;
    info!(listen = %addr, "HTTP/3 server stopped");
}

/// Handle a single QUIC connection and all its HTTP/3 request streams
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dispatcher: Arc<HttpDispatcher>,
    src_ip_header: Option<Arc<str>>,
) {
    let src = connecting.remote_address();

    let connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            warn!("QUIC handshake failed for {}: {}", src, e);
            return;
        }
    };

    let server_name = extract_tls_server_name(&connection).map(Arc::<str>::from);

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
        let src_ip_header = src_ip_header.clone();
        let server_name = server_name.clone();

        tokio::spawn(async move {
            handle_h3_request(request, stream, dispatcher, src, src_ip_header, server_name).await;
        });
    }
}

/// Handle a single HTTP/3 request stream
async fn handle_h3_request(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    dispatcher: Arc<HttpDispatcher>,
    src: SocketAddr,
    src_ip_header: Option<Arc<str>>,
    server_name: Option<Arc<str>>,
) {
    let method = request.method().clone();
    let uri = request.uri();
    let path = Arc::from(uri.path());
    let query = uri.query().map(Arc::from);
    let headers = request.headers();

    let client_addr = extract_client_ip(headers, &src_ip_header, src);

    debug!(
        "Received {} {} from {} (real: {})",
        method, path, src, client_addr
    );

    let body = match read_h3_body(&mut stream, src).await {
        Ok(body) => body,
        Err(status) => {
            let _ = send_h3_error_response(&mut stream, status, src).await;
            return;
        }
    };

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
            let _ =
                send_h3_error_response(&mut stream, http::StatusCode::INTERNAL_SERVER_ERROR, src)
                    .await;
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

    if let Err(e) = stream.finish().await {
        warn!("Failed to finish HTTP/3 response stream to {}: {}", src, e);
        return;
    }

    debug!("Response sent to {}", src);
}

#[inline]
async fn read_h3_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    src: SocketAddr,
) -> Result<Bytes, http::StatusCode> {
    let mut buf = BytesMut::with_capacity(2048);

    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                buf.put(chunk);
                if buf.len() > MAX_HTTP3_BODY_SIZE {
                    warn!(
                        "HTTP/3 request body too large from {}: {} bytes",
                        src,
                        buf.len()
                    );
                    return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
            Ok(None) => return Ok(buf.freeze()),
            Err(e) => {
                warn!("Failed to read HTTP/3 request body from {}: {}", src, e);
                return Err(http::StatusCode::BAD_REQUEST);
            }
        }
    }
}

#[inline]
async fn send_h3_error_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: http::StatusCode,
    src: SocketAddr,
) -> Result<(), ()> {
    let response = match http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to build HTTP/3 error response for {}: {}", src, e);
            return Err(());
        }
    };

    if let Err(e) = stream.send_response(response).await {
        warn!(
            "Failed to send HTTP/3 error response headers to {}: {}",
            src, e
        );
        return Err(());
    }

    if let Err(e) = stream.finish().await {
        warn!(
            "Failed to finish HTTP/3 error response stream to {}: {}",
            src, e
        );
        return Err(());
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use std::fmt::{Debug, Formatter};

    struct RejectingResolver;

    impl Debug for RejectingResolver {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("RejectingResolver")
        }
    }

    impl ResolvesServerCert for RejectingResolver {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    fn dummy_server_config() -> ServerConfig {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RejectingResolver))
    }

    #[tokio::test]
    async fn test_run_server_reports_startup_error_for_invalid_address() {
        let dispatcher = Arc::new(HttpDispatcher::new());
        let server_config = dummy_server_config();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (startup_tx, startup_rx) = oneshot::channel();

        run_server(
            "invalid-addr".to_string(),
            dispatcher,
            server_config,
            None,
            None,
            shutdown_rx,
            Some(startup_tx),
        )
        .await;

        let startup = startup_rx
            .await
            .expect("startup sender should not be dropped");
        assert!(startup.is_err());
    }
}
