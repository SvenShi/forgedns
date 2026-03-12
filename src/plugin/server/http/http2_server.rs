/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::http::{DEFAULT_IDLE_TIMEOUT, extract_client_ip};
use crate::plugin::server::tcp;
use bytes::Bytes;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

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
    server_config: Option<ServerConfig>,
    idle_timeout: Option<u64>,
    src_ip_header: Option<String>,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    let timeout = Duration::from_secs(idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT));
    let listener = match tcp::build_tcp_listener(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!(
                    "Failed to bind HTTP socket to {}: {}",
                    addr, e
                )));
            }
            error!("Failed to bind HTTP socket to {}: {}", addr, e);
            return;
        }
    };
    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }

    info!(
        listen = %addr,
        idle_timeout_secs = timeout.as_secs(),
        has_tls = %server_config.is_some(),
        "HTTP/2 server listening"
    );

    // Wrap header name in Arc to avoid cloning Strings per request
    let src_ip_header = Arc::new(src_ip_header);

    // JoinSet to track all active connection tasks
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut active_connections = 0u64;
    let tls_acceptor = if let Some(mut server_config) = server_config {
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        Some(Arc::new(TlsAcceptor::from(Arc::new(server_config))))
    } else {
        None
    };

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
                                        let server_name = tls_stream
                                            .get_ref()
                                            .1
                                            .server_name()
                                            .map(str::to_ascii_lowercase);
                                        debug!("TLS handshake completed for client {}", src);
                                        handle_http_stream(
                                            tls_stream,
                                            src,
                                            dispatcher,
                                            src_ip_header,
                                            server_name,
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        warn!("TLS handshake failed for {}: {}", src, e);
                                    }
                                }
                            } else {
                                // Plain HTTP connection
                                debug!("HTTP server connected to client {}", src);
                                handle_http_stream(stream, src, dispatcher, src_ip_header, None)
                                    .await;
                            }
                        });
                    }
                    Err(e) => {
                        debug!(%e, listen = %addr, "Error accepting HTTP connection");
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

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    info!(listen = %addr, "HTTP/2 server stopped");
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
    tls_server_name: Option<String>,
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
        let server_name = tls_server_name.clone();

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
                .handle_request(method, path, query, body, client_addr, server_name)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::core::dns_utils::build_response_from_request;
    use crate::core::error::Result;
    use crate::message::{Message, Question, ResponseCode};
    use crate::message::{Name, RecordType};
    use crate::plugin::Plugin;
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::server::RequestHandle;
    use crate::plugin::server::http::http_dispatcher::DnsPostHandler;
    use crate::plugin::test_utils::test_registry;
    use async_trait::async_trait;
    use bytes::Bytes;
    use http::Request;
    use std::sync::{Arc, Mutex};
    use tokio::io::duplex;
    use tokio::time::{Duration, timeout};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedRequest {
        src_addr: SocketAddr,
        server_name: Option<String>,
        url_path: Option<String>,
    }

    #[derive(Debug)]
    struct CaptureAndRespondExecutor {
        observed: Arc<Mutex<Option<ObservedRequest>>>,
    }

    #[async_trait]
    impl Plugin for CaptureAndRespondExecutor {
        fn tag(&self) -> &str {
            "capture_and_respond"
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for CaptureAndRespondExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            self.observed
                .lock()
                .expect("capture lock should not be poisoned")
                .replace(ObservedRequest {
                    src_addr: context.peer_addr(),
                    server_name: context.server_name().map(str::to_string),
                    url_path: context.url_path().map(str::to_string),
                });
            context.response.set_message(build_response_from_request(
                &context.request,
                ResponseCode::NoError,
            ));
            Ok(ExecStep::Stop)
        }
    }

    fn make_request_handle(observed: Arc<Mutex<Option<ObservedRequest>>>) -> Arc<RequestHandle> {
        Arc::new(RequestHandle {
            entry_executor: Arc::new(CaptureAndRespondExecutor { observed }),
            registry: test_registry(),
        })
    }

    fn make_dns_query(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should be valid"),
            RecordType::A,
        ));
        message
    }

    #[tokio::test]
    async fn test_handle_http_stream_processes_post_request_and_forwards_meta() {
        let observed = Arc::new(Mutex::new(None));
        let request_handle = make_request_handle(observed.clone());
        let mut dispatcher = HttpDispatcher::new();
        dispatcher.register_route(
            http::Method::POST,
            "/dns-query".to_string(),
            Box::new(DnsPostHandler::new(request_handle)),
        );
        let dispatcher = Arc::new(dispatcher);
        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(handle_http_stream(
            server,
            SocketAddr::from(([127, 0, 0, 1], 443)),
            dispatcher,
            Arc::new(Some("x-real-ip".to_string())),
            Some("resolver.example".to_string()),
        ));

        let (mut sender, connection) = h2::client::handshake(client)
            .await
            .expect("client handshake should succeed");
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let dns_query = make_dns_query(55);
        let dns_bytes = dns_query
            .to_bytes()
            .expect("dns query should serialize successfully");
        let request = Request::builder()
            .method("POST")
            .uri("/dns-query")
            .header("x-real-ip", "198.51.100.77")
            .body(())
            .expect("http request should build");

        let (response_future, mut send_stream) = sender
            .send_request(request, false)
            .expect("send_request should succeed");
        send_stream
            .send_data(Bytes::from(dns_bytes), true)
            .expect("request body send should succeed");

        let response = response_future
            .await
            .expect("response future should resolve");
        let mut body = response.into_body();
        let mut response_bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("response chunk should be readable");
            response_bytes.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        let dns_response = Message::from_bytes(&response_bytes)
            .expect("response bytes should decode as DNS message");

        assert_eq!(dns_response.id(), 55);
        assert_eq!(dns_response.response_code(), ResponseCode::NoError);
        assert_eq!(
            observed
                .lock()
                .expect("capture lock should not be poisoned")
                .clone(),
            Some(ObservedRequest {
                src_addr: SocketAddr::from(([198, 51, 100, 77], 443)),
                server_name: Some("resolver.example".to_string()),
                url_path: Some("/dns-query".to_string()),
            })
        );

        drop(sender);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn test_run_server_reports_startup_error_for_invalid_address() {
        let dispatcher = Arc::new(HttpDispatcher::new());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (startup_tx, startup_rx) = oneshot::channel();

        run_server(
            "invalid-addr".to_string(),
            dispatcher,
            None,
            None,
            None,
            shutdown_rx,
            Some(startup_tx),
        )
        .await;

        let startup = timeout(Duration::from_secs(1), startup_rx)
            .await
            .expect("startup channel should resolve")
            .expect("startup sender should not be dropped");
        assert!(startup.is_err());
    }
}
