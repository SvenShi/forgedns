/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::ConnectionBuilder;
use crate::pkg::upstream::pool::utils::{connect_quic, connect_tls};
use crate::pkg::upstream::{ConnectInfo, ConnectType, Connection, DEFAULT_TIMEOUT};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bytes::{BufMut, Bytes, BytesMut};
use futures::SinkExt;
use futures::TryFutureExt;
use futures::future::poll_fn;
use h2::client::{ResponseFuture, SendRequest as H2SendRequest};
use h3::client::{RequestStream, SendRequest as H3SendRequest};
use h3_quinn::{BidiStream, OpenStreams};
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, Response, Version, header};
use std::cell::RefCell;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::oneshot::{Receiver, Sender, channel};
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct DoHConnection {
    id: u16,
    sender: Mutex<Box<dyn HttpsSender + Send + Sync>>,
    using_count: AtomicU16,
    closed: AtomicBool,
    last_used: AtomicU64,
    timeout: std::time::Duration,
    request_uri: String,
    close_notify: Notify,
}

const DNS_HEADER_VALUE_STR: &str = "application/dns-message";

const DNS_HEADER_VALUE: HeaderValue = HeaderValue::from_static(DNS_HEADER_VALUE_STR);

#[async_trait::async_trait]
impl Connection for DoHConnection {
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        debug!(conn_id = self.id, "Closing DoH connection");
        self.close_notify.notify_waiters();
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(ProtoError::from("DoH connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        self.last_used
            .store(AppClock::run_millis(), Ordering::Relaxed);

        let raw_id = request.id();
        request.set_id(0);
        let body_bytes = request.to_bytes()?;

        // 构造 GET 请求（DoH over GET）
        let uri = self.request_uri.clone() + &BASE64_URL_SAFE_NO_PAD.encode(body_bytes);
        let request = http::Request::builder()
            .header(header::CONTENT_TYPE, DNS_HEADER_VALUE)
            .method(Method::GET)
            .uri(uri)
            .body(())
            .unwrap();

        // 通过统一 sender 发送并等待 receiver 读取 body
        let mut sender_guard = self.sender.lock().await;
        let receiver = match sender_guard.send(request).await {
            Ok(mut r) => r,
            Err(e) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                warn!(conn_id = self.id, raw_id, ?e, "DoH send error");
                return Err(e);
            }
        };
        drop(sender_guard);

        let result = match timeout(self.timeout, receiver).await {
            Ok(Ok(bytes)) => {
                let vec = bytes.map_err(ProtoError::from)?;
                let mut resp = DnsResponse::from_buffer(vec)?;
                resp.set_id(raw_id);
                debug!(conn_id = self.id, raw_id, "Received DoH response");
                Ok(resp)
            }
            Ok(Err(e)) => {
                warn!(conn_id = self.id, raw_id, ?e, "DoH request error");
                Err("DoH request error".into())
            }
            Err(_) => {
                warn!(conn_id = self.id, raw_id, "DoH request timeout");
                Err(ProtoError::from("dns query timeout"))
            }
        };

        self.using_count.fetch_sub(1, Ordering::Relaxed);
        result
    }

    fn using_count(&self) -> u16 {
        self.using_count.load(Ordering::Relaxed)
    }

    fn available(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

/// Builder
#[derive(Debug)]
pub struct DoHConnectionBuilder {
    pub bind_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub timeout: std::time::Duration,
    pub server_name: String,
    pub request_uri: String,
    pub insecure_skip_verify: bool,
    pub enable_http3: bool,
}

impl DoHConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            bind_addr: connect_info.get_bind_socket_addr(),
            remote_addr: connect_info.get_full_remote_socket_addr(),
            timeout: connect_info.timeout,
            server_name: connect_info.host.clone(),
            request_uri: if connect_info.port != ConnectType::DoH.default_port() {
                format!(
                    "https://{}{}:{}?dns=",
                    connect_info.host, connect_info.port, connect_info.path
                )
            } else {
                format!("https://{}{}?dns=", connect_info.host, connect_info.path)
            },
            insecure_skip_verify: connect_info.insecure_skip_verify,
            enable_http3: connect_info.enable_http3,
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<DoHConnection> for DoHConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<DoHConnection>, ProtoError> {
        if self.enable_http3 {
            self.build_h3_connection(conn_id).await
        } else {
            self.build_h2_connection(conn_id).await
        }
    }
}

impl DoHConnectionBuilder {
    async fn build_h2_connection(&self, conn_id: u16) -> Result<Arc<DoHConnection>, ProtoError> {
        // 建立 TCP -> TLS -> H2
        let stream = TcpStream::connect(self.remote_addr)
            .await
            .map_err(|e| ProtoError::from(format!("Unable to connect to doh remote tcp: {}", e)))?;

        let tls_stream = connect_tls(
            stream,
            self.insecure_skip_verify,
            self.server_name.clone(),
            DEFAULT_TIMEOUT,
        )
        .await?;

        let (sender, connection) = h2::client::Builder::new()
            .handshake(tls_stream)
            .await
            .map_err(|e| ProtoError::from(format!("H2 handshake error: {}", e)))?;

        let doh_conn = Arc::new(DoHConnection {
            id: conn_id,
            sender: Mutex::new(Box::new(H2Sender { sender })),
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::run_millis()),
            using_count: AtomicU16::new(0),
            timeout: self.timeout,
            request_uri: self.request_uri.clone(),
            close_notify: Notify::new(),
        });

        let _conn = doh_conn.clone();
        tokio::spawn(async move {
            select! {
                res = connection => {
                    if let Err(e) = res {
                        _conn.close();
                        debug!(conn_id, ?e, "H2 connection error");
                    }
                }
                _ = _conn.close_notify.notified() => {
                    debug!(conn_id, "H2 connection closed by notify");
                }
            }
        });

        Ok(doh_conn)
    }

    async fn build_h3_connection(&self, conn_id: u16) -> Result<Arc<DoHConnection>, ProtoError> {
        let quic_conn = connect_quic(
            self.bind_addr,
            self.remote_addr,
            self.insecure_skip_verify,
            self.server_name.clone(),
            DEFAULT_TIMEOUT,
        )
        .await?;

        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let (mut driver, send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| ProtoError::from(format!("h3 connection failed: {e}")))?;

        let doh_conn = Arc::new(DoHConnection {
            id: conn_id,
            sender: Mutex::new(Box::new(H3Sender {
                sender: send_request,
            })),
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::run_millis()),
            using_count: AtomicU16::new(0),
            timeout: self.timeout,
            request_uri: self.request_uri.clone(),
            close_notify: Notify::new(),
        });

        let _conn = doh_conn.clone();

        let _driver_handle = tokio::spawn(async move {
            select! {
                _ = poll_fn(|cx| driver.poll_close(cx)) => {
                    debug!(conn_id, "H3 connection poll closed");
                }
                _ = _conn.close_notify.notified()=>{
                    debug!(conn_id, "H3 connection closed by notify");
                }
            }
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(doh_conn)
    }
}

#[async_trait::async_trait]
trait HttpsSender: Send + Sync + Debug {
    async fn send(
        &mut self,
        request: Request<()>,
    ) -> Result<Receiver<Result<Vec<u8>, ProtoError>>, ProtoError>;
}

/// ---------------- H2 实现 ----------------
#[derive(Debug)]
struct H2Sender {
    sender: H2SendRequest<Bytes>,
}

#[async_trait::async_trait]
impl HttpsSender for H2Sender {
    async fn send(
        &mut self,
        mut request: Request<()>,
    ) -> Result<Receiver<Result<Vec<u8>, ProtoError>>, ProtoError> {
        *request.version_mut() = Version::HTTP_2;
        let (response_future, _send_stream) = self
            .sender
            .send_request(request, false)
            .map_err(|e| ProtoError::from(format!("H2 send_request error: {e}")))?;
        let (sender, receiver) = channel();
        tokio::spawn(async move {
            let _ = sender.send(Self::recv(response_future).await);
        });
        Ok(receiver)
    }
}

impl H2Sender {
    async fn recv(response_future: ResponseFuture) -> Result<Vec<u8>, ProtoError> {
        let mut response = response_future
            .await
            .map_err(|e| ProtoError::from(format!("H3 response error: {}", e)))?;

        let status_code = response.status();
        let is_success = status_code.is_success();

        let mut body = response.into_body();
        let mut response_bytes = BytesMut::with_capacity(4096);

        while let Some(Ok(partial_bytes)) = body.data().await {
            response_bytes.put(partial_bytes);
        }
        // Was it a successful request?
        if !is_success {
            let error_string = String::from_utf8_lossy(response_bytes.as_ref());
            Err(ProtoError::from(format!(
                "http unsuccessful code: {}, message: {}",
                status_code, error_string
            )))
        } else {
            Ok(response_bytes.to_vec())
        }
    }
}

/// ---------------- H3 实现 ----------------
struct H3Sender {
    sender: H3SendRequest<OpenStreams, Bytes>,
}

impl Debug for H3Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "H3Sender")
    }
}

#[async_trait::async_trait]
impl HttpsSender for H3Sender {
    async fn send(
        &mut self,
        mut request: Request<()>,
    ) -> Result<Receiver<Result<Vec<u8>, ProtoError>>, ProtoError> {
        *request.version_mut() = Version::HTTP_3;
        let (sender, receiver) = channel();
        let send_res = self
            .sender
            .send_request(request)
            .await
            .map_err(|e| ProtoError::from(format!("H3 send_request error: {e}")))?;
        tokio::spawn(async move {
            let _ = sender.send(Self::recv(send_res).await);
        });
        Ok(receiver)
    }
}

impl H3Sender {
    async fn recv(
        mut request_stream: RequestStream<BidiStream<Bytes>, Bytes>,
    ) -> Result<Vec<u8>, ProtoError> {
        let response = request_stream
            .recv_response()
            .await
            .map_err(|e| ProtoError::from(format!("H3 response error: {}", e)))?;

        let mut response_bytes = BytesMut::with_capacity(4096);

        while let Some(partial_bytes) = request_stream
            .recv_data()
            .await
            .map_err(|e| ProtoError::from(format!("h3 recv_data error: {e}")))?
        {
            response_bytes.put(partial_bytes);
        }

        // Was it a successful request?
        if !response.status().is_success() {
            let error_string = String::from_utf8_lossy(response_bytes.as_ref());

            Err(ProtoError::from(format!(
                "http unsuccessful code: {}, message: {}",
                response.status(),
                error_string
            )))
        } else {
            Ok(response_bytes.to_vec())
        }
    }
}
