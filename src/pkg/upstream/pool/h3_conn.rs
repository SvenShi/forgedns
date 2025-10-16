/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::utils::{build_dns_get_request, connect_quic, get_buf_from_res};
use crate::pkg::upstream::pool::ConnectionBuilder;
use crate::pkg::upstream::{ConnectInfo, ConnectType, Connection, DEFAULT_TIMEOUT};
use bytes::{BufMut, Bytes};
use futures::future::poll_fn;
use h3::client::{RequestStream, SendRequest};
use h3_quinn::{BidiStream, OpenStreams};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use http::Version;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::select;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, warn};

pub struct H3Connection {
    id: u16,
    sender: Mutex<SendRequest<OpenStreams, Bytes>>,
    using_count: AtomicU16,
    closed: AtomicBool,
    last_used: AtomicU64,
    timeout: std::time::Duration,
    request_uri: String,
    close_notify: Notify,
}
impl Debug for H3Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3Connection")
    }
}

#[async_trait::async_trait]
impl Connection for H3Connection {
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        debug!(conn_id = self.id, "Closing H3 connection");
        self.close_notify.notify_waiters();
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(ProtoError::from("H3 connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        self.last_used
            .store(AppClock::run_millis(), Ordering::Relaxed);

        let raw_id = request.id();
        request.set_id(0);
        let body_bytes = request.to_bytes()?;

        let request = build_dns_get_request(self.request_uri.clone(), body_bytes, Version::HTTP_3);

        let mut sender_guard = self.sender.lock().await;
        let request_stream = sender_guard.send_request(request).await.map_err(|e| {
            self.using_count.fetch_sub(1, Ordering::Relaxed);
            ProtoError::from(format!("H3 send_request error: {e}"))
        })?;
        drop(sender_guard);

        let result = match timeout(self.timeout, recv(request_stream)).await {
            Ok(Ok(bytes)) => {
                let mut resp = DnsResponse::from_buffer(bytes.to_vec())?;
                resp.set_id(raw_id);
                debug!(conn_id = self.id, raw_id, "Received H3 response");
                Ok(resp)
            }
            Ok(Err(e)) => {
                warn!(conn_id = self.id, raw_id, ?e, "H3 request error");
                Err(e)
            }
            Err(_) => {
                warn!(conn_id = self.id, raw_id, "H3 request timeout");
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
pub struct H3ConnectionBuilder {
    pub bind_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub timeout: std::time::Duration,
    pub server_name: String,
    pub request_uri: String,
    pub insecure_skip_verify: bool,
}

impl H3ConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            bind_addr: connect_info.get_bind_socket_addr(),
            remote_addr: connect_info.get_full_remote_socket_addr(),
            timeout: connect_info.timeout,
            server_name: connect_info.host.clone(),
            request_uri: if connect_info.port != ConnectType::DoH.default_port() {
                let mut uri = format!(
                    "https://{}{}:{}?dns=",
                    connect_info.host, connect_info.port, connect_info.path
                );
                uri.reserve(512);
                uri
            } else {
                let mut uri = format!("https://{}{}?dns=", connect_info.host, connect_info.path);
                uri.reserve(512);
                uri
            },
            insecure_skip_verify: connect_info.insecure_skip_verify,
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<H3Connection> for H3ConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<H3Connection>, ProtoError> {
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

        let h3_conn = Arc::new(H3Connection {
            id: conn_id,
            sender: Mutex::new(send_request),
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::run_millis()),
            using_count: AtomicU16::new(0),
            timeout: self.timeout,
            request_uri: self.request_uri.clone(),
            close_notify: Notify::new(),
        });

        let _conn = h3_conn.clone();

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

        Ok(h3_conn)
    }
}

async fn recv(
    mut request_stream: RequestStream<BidiStream<Bytes>, Bytes>,
) -> Result<Bytes, ProtoError> {
    let mut response = request_stream
        .recv_response()
        .await
        .map_err(|e| ProtoError::from(format!("H3 response error: {}", e)))?;

    let mut response_bytes = get_buf_from_res(&mut response);

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
        Ok(response_bytes.freeze())
    }
}
