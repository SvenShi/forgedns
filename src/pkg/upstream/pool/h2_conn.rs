/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::utils::{build_dns_get_request, connect_tls, get_buf_from_res};
use crate::pkg::upstream::pool::ConnectionBuilder;
use crate::pkg::upstream::{ConnectInfo, ConnectType, Connection, DEFAULT_TIMEOUT};
use bytes::{BufMut, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use http::Version;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct H2Connection {
    id: u16,
    sender: SendRequest<Bytes>,
    using_count: AtomicU16,
    closed: AtomicBool,
    last_used: AtomicU64,
    timeout: std::time::Duration,
    request_uri: String,
    close_notify: Notify,
}

#[async_trait::async_trait]
impl Connection for H2Connection {
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

        let request = build_dns_get_request(self.request_uri.clone(), body_bytes, Version::HTTP_2);

        let (response_future, _send_stream) =
            self.sender.clone().send_request(request, false).map_err(|e| {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                ProtoError::from(format!("H2 send_request error: {e}"))
            })?;

        let result = match timeout(self.timeout, recv(response_future)).await {
            Ok(Ok(bytes)) => {
                let mut resp = DnsResponse::from_buffer(bytes.to_vec())?;
                resp.set_id(raw_id);
                debug!(conn_id = self.id, raw_id, "Received H2 response");
                Ok(resp)
            }
            Ok(Err(e)) => {
                warn!(conn_id = self.id, raw_id, ?e, "H2 request error");
                Err(e)
            }
            Err(_) => {
                warn!(conn_id = self.id, raw_id, "H2 request timeout");
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
pub struct H2ConnectionBuilder {
    pub remote_addr: SocketAddr,
    pub timeout: std::time::Duration,
    pub server_name: String,
    pub request_uri: String,
    pub insecure_skip_verify: bool,
}

impl H2ConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
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
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<H2Connection> for H2ConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<H2Connection>, ProtoError> {
        // 建立 TCP -> TLS -> H2
        let stream = TcpStream::connect(self.remote_addr)
            .await
            .map_err(|e| ProtoError::from(format!("Unable to connect to H2 remote tcp: {}", e)))?;

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

        let h2_conn = Arc::new(H2Connection {
            id: conn_id,
            sender,
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::run_millis()),
            using_count: AtomicU16::new(0),
            timeout: self.timeout,
            request_uri: self.request_uri.clone(),
            close_notify: Notify::new(),
        });

        let _conn = h2_conn.clone();
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

        Ok(h2_conn)
    }
}

async fn recv(response_future: ResponseFuture) -> Result<Bytes, ProtoError> {
    let mut response = response_future
        .await
        .map_err(|e| ProtoError::from(format!("H3 response error: {}", e)))?;

    let status_code = response.status();
    let mut response_bytes = get_buf_from_res(&mut response);
    let mut body = response.into_body();

    while let Some(Ok(partial_bytes)) = body.data().await {
        response_bytes.put(partial_bytes);
    }

    if !status_code.is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());
        Err(ProtoError::from(format!(
            "http unsuccessful code: {}, message: {}",
            status_code, error_string
        )))
    } else {
        Ok(response_bytes.freeze())
    }
}
