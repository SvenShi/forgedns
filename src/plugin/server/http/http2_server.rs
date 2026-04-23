/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::plugin::server::ConnectionGuard;
use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::http::{DEFAULT_IDLE_TIMEOUT, extract_client_ip};
use crate::plugin::server::tcp;
use bytes::{BufMut, Bytes, BytesMut};
use http::header::{ALT_SVC, CONTENT_LENGTH};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

/// Main HTTP/2 server loop (over TCP)
///
/// Creates an HTTP/2 stream, listens for incoming DNS queries, and spawns
/// handler tasks for each request. Uses a task tracker and cancellation token
/// to manage active connections without polling completed tasks from the
/// accept loop.
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
/// - `server_config`: Optional TLS server config for HTTPS
/// - `idle_timeout`: Connection idle timeout in seconds
/// - `src_ip_header`: HTTP header name to extract real client IP
#[hotpath::measure]
#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    addr: SocketAddr,
    dispatcher: Arc<HttpDispatcher>,
    server_config: Option<ServerConfig>,
    alt_svc: Option<http::HeaderValue>,
    idle_timeout: Option<u64>,
    src_ip_header: Option<String>,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    let timeout = Duration::from_secs(idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT));

    let listener = match tcp::build_tcp_listener(addr, timeout) {
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
        alt_svc = alt_svc.as_ref().and_then(|value| value.to_str().ok()),
        "HTTP/2 server listening"
    );

    // Wrap header name in Arc to avoid cloning Strings per request
    let src_ip_header = src_ip_header.map(Arc::from);
    let alt_svc = alt_svc.map(Arc::new);

    let tasks = TaskTracker::new();
    let shutdown_token = CancellationToken::new();
    let active_connections = Arc::new(AtomicU64::new(0));
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
                        let alt_svc = alt_svc.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let task_shutdown = shutdown_token.clone();
                        let active_connections = active_connections.clone();

                        let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        debug!("New connection from {} (active: {})", src, active);

                        tasks.spawn(async move {
                            let _connection_guard =
                                ConnectionGuard::new(active_connections.clone(), src, "HTTP/2");
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
                                                    .map(Arc::<str>::from);
                                                debug!("TLS handshake completed for client {}", src);
                                                handle_http_stream(
                                                    tls_stream,
                                                    src,
                                                    dispatcher,
                                                    src_ip_header,
                                                    server_name,
                                                    alt_svc,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                debug!("TLS handshake failed for {}: {}", src, e);
                                            }
                                        }
                                    } else {
                                        // Plain HTTP connection
                                        debug!("HTTP server connected to client {}", src);
                                        handle_http_stream(stream, src, dispatcher, src_ip_header, None, alt_svc)
                                            .await;
                                    }
                                } => {}
                            }
                        });
                    }
                    Err(e) => {
                        debug!(%e, listen = %addr, "Error accepting HTTP connection");
                    }
                }
            }
        }
    }

    shutdown_token.cancel();
    tasks.close();
    tasks.wait().await;
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
#[hotpath::measure]
async fn handle_http_stream<S>(
    stream: S,
    src: SocketAddr,
    dispatcher: Arc<HttpDispatcher>,
    src_ip_header: Option<Arc<str>>,
    tls_server_name: Option<Arc<str>>,
    alt_svc: Option<Arc<http::HeaderValue>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Start the HTTP/2.0 connection handshake
    let mut h2 = match h2::server::handshake(stream).await {
        Ok(h2) => h2,
        Err(err) => {
            debug!("HTTP/2 handshake error from {}: {}", src, err);
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
        let src_ip_header = src_ip_header.clone();
        let server_name = tls_server_name.clone();
        let alt_svc = alt_svc.clone();
        // Spawn a task to handle this request (non-blocking)
        // Each request is processed in its own task for maximum concurrency
        tokio::spawn(async move {
            // Extract request metadata
            let method = request.method().clone();
            let uri = request.uri().clone();
            let path = Arc::from(uri.path());
            let query = uri.query().map(Arc::from);
            let headers = request.headers();

            // Try to extract real client IP from HTTP headers (e.g., X-Real-IP, X-Forwarded-For)
            // This is essential when running behind a reverse proxy
            let client_addr = extract_client_ip(headers, &src_ip_header, src);

            debug!(
                "Received {} {} from {} (real: {})",
                method, path, src, client_addr
            );

            let body = match read_h2_body(request.into_body(), src).await {
                Ok(body) => body,
                Err(status) => {
                    let _ = send_h2_error_response(&mut respond, status, src, alt_svc.as_deref());
                    return;
                }
            };

            let response = dispatcher
                .handle_request(method, path, query, body, client_addr, server_name)
                .await;

            let (mut parts, response_bytes) = response.into_parts();
            insert_alt_svc_header(&mut parts.headers, alt_svc.as_deref());

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
                    let _ = send_h2_error_response(
                        &mut respond,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        src,
                        alt_svc.as_deref(),
                    );
                    return;
                }
            };

            let mut send_stream = match respond.send_response(h2_response, false) {
                Ok(stream) => stream,
                Err(e) => {
                    debug!("Failed to send HTTP/2 response headers to {}: {}", src, e);
                    return;
                }
            };

            if let Err(e) = send_stream.send_data(response_bytes, true) {
                debug!("Failed to send HTTP/2 response body to {}: {}", src, e);
                return;
            }

            debug!("Response sent to {}", src);
        });
    }
}

const MAX_HTTP_BODY: usize = 64 * 1024;
const INITIAL_HTTP_BODY_CAPACITY: usize = 2048;

#[inline]
async fn read_h2_body(
    mut recv_stream: h2::RecvStream,
    src: SocketAddr,
) -> Result<Bytes, http::StatusCode> {
    let mut buf = BytesMut::with_capacity(INITIAL_HTTP_BODY_CAPACITY);

    while let Some(chunk_result) = recv_stream.data().await {
        match chunk_result {
            Ok(chunk) => {
                if buf.len() + chunk.len() > MAX_HTTP_BODY {
                    warn!(
                        "HTTP/2 request body too large from {}: {}+{} bytes",
                        src,
                        buf.len(),
                        chunk.len()
                    );
                    return Err(http::StatusCode::PAYLOAD_TOO_LARGE);
                }

                buf.put_slice(&chunk);

                if let Err(e) = recv_stream.flow_control().release_capacity(chunk.len()) {
                    debug!(
                        "Failed to release HTTP/2 flow control capacity for {}: {}",
                        src, e
                    );
                }
            }
            Err(e) => {
                warn!("Failed to read request body chunk from {}: {}", src, e);
                return Err(http::StatusCode::BAD_REQUEST);
            }
        }
    }

    Ok(buf.freeze())
}

#[inline]
fn send_h2_error_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: http::StatusCode,
    src: SocketAddr,
    alt_svc: Option<&http::HeaderValue>,
) -> Result<(), ()> {
    let response = match http::Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, 0)
        .body(())
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to build HTTP/2 error response for {}: {}", src, e);
            return Err(());
        }
    };
    let mut response = response;
    insert_alt_svc_header(response.headers_mut(), alt_svc);

    if let Err(e) = respond.send_response(response, true) {
        warn!("Failed to send HTTP/2 error response to {}: {}", src, e);
        return Err(());
    }

    Ok(())
}

#[inline]
fn insert_alt_svc_header(headers: &mut http::HeaderMap, alt_svc: Option<&http::HeaderValue>) {
    if let Some(alt_svc) = alt_svc {
        headers.insert(ALT_SVC, alt_svc.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::core::error::Result;
    use crate::plugin::Plugin;
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::server::RequestHandle;
    use crate::plugin::server::http::http_dispatcher::DnsPostHandler;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{Message, Question, Rcode};
    use crate::proto::{Name, RecordType};
    use async_trait::async_trait;
    use bytes::Bytes;
    use http::Request;
    use std::sync::{Arc, Mutex};
    use tokio::io::duplex;

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
            context.set_response(context.request.response(Rcode::NoError));
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
            crate::proto::DNSClass::IN,
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
            Arc::from("/dns-query"),
            Box::new(DnsPostHandler::new(request_handle)),
        );
        let dispatcher = Arc::new(dispatcher);

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(handle_http_stream(
            server,
            SocketAddr::from(([127, 0, 0, 1], 443)),
            dispatcher,
            Some(Arc::from("x-real-ip")),
            Some(Arc::from("resolver.example")),
            Some(Arc::new(http::HeaderValue::from_static(
                "h3=\":443\"; ma=86400",
            ))),
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
        assert_eq!(response.headers()["alt-svc"], "h3=\":443\"; ma=86400");

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
        assert_eq!(dns_response.rcode(), Rcode::NoError);
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
}
