/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::request_map::RequestMap;
use crate::pkg::upstream::pool::utils::connect_tls;
use crate::pkg::upstream::pool::ConnectionBuilder;
use crate::pkg::upstream::{ConnectInfo, Connection, DEFAULT_TIMEOUT};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use h2::client::SendRequest;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use http::Version;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, warn};

/// HTTP/2 DoH 连接
#[derive(Debug)]
pub struct DoHConnection {
    id: u16,
    sender: Mutex<SendRequest<Bytes>>,
    request_map: RequestMap,
    closed: AtomicBool,
    last_used: AtomicU64,
    close_notify: Notify,
    timeout: std::time::Duration,
    request_uri: String,
}

#[async_trait::async_trait]
impl Connection for DoHConnection {
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        debug!(conn_id = self.id, "Closing H2 connection");
        self.close_notify.notify_waiters();
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(ProtoError::from("H2 connection closed"));
        }

        let (tx, rx) = oneshot::channel();
        let query_id = self.request_map.store(tx);

        let raw_id = request.id();
        request.set_id(query_id);
        let body_bytes = request.to_bytes()?;

        let request = http::Request::builder()
            .version(Version::HTTP_2)
            .header("content-type", "application/dns-message")
            .method("GET")
            .uri(format!(
                "{}?dns={}",
                self.request_uri.clone(),
                BASE64_URL_SAFE_NO_PAD.encode(body_bytes)
            ))
            .body(())
            .unwrap();

        // 打开一个新的 stream 发送请求
        let (response_future, _) = self
            .sender
            .lock()
            .await
            .send_request(request, false)
            .map_err(|e| ProtoError::from(format!("H2 send_request error: {e}")))?;

        // 异步等待响应
        match timeout(self.timeout, async {
            let response = response_future
                .await
                .map_err(|e| ProtoError::from(e.to_string()))?;
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                bytes.extend_from_slice(&chunk);
            }
            DnsResponse::from_buffer(bytes)
        })
        .await
        {
            Ok(Ok(mut resp)) => {
                resp.set_id(raw_id);
                debug!(conn_id = self.id, query_id, "Received H2 DoH response");
                Ok(resp)
            }
            Ok(Err(e)) => {
                self.request_map.take(query_id);
                warn!(conn_id = self.id, query_id, ?e, "H2 DoH request error");
                Err(e)
            }
            Err(_) => {
                self.request_map.take(query_id);
                warn!(conn_id = self.id, query_id, "H2 DoH request timeout");
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    fn using_count(&self) -> u16 {
        self.request_map.size()
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
    pub remote_addr: SocketAddr,
    pub timeout: std::time::Duration,
    pub server_name: String,
    pub request_uri: String,
    pub insecure_skip_verify: bool,
}

impl DoHConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            remote_addr: connect_info.get_full_remote_socket_addr(),
            timeout: connect_info.timeout,
            server_name: connect_info.host.clone(),
            request_uri: connect_info.raw_addr.clone(),
            insecure_skip_verify: connect_info.insecure_skip_verify,
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<DoHConnection> for DoHConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<DoHConnection>, ProtoError> {
        let stream = match TcpStream::connect(self.remote_addr).await {
            Ok(stream) => stream,
            Err(_) => {
                return Err(ProtoError::from("Unable to connect to doh connection"));
            }
        };

        let tls_stream = connect_tls(
            stream,
            self.insecure_skip_verify,
            self.server_name.clone(),
            DEFAULT_TIMEOUT,
        )
        .await?;

        match h2::client::Builder::new().handshake(tls_stream).await {
            Ok((sender, connection)) => {
                tokio::spawn(connection);

                Ok(Arc::new(DoHConnection {
                    id: conn_id,
                    sender: Mutex::new(sender),
                    request_map: RequestMap::new(),
                    closed: AtomicBool::new(false),
                    last_used: AtomicU64::new(AppClock::run_millis()),
                    close_notify: Notify::new(),
                    timeout: self.timeout,
                    request_uri: self.request_uri.clone(),
                }))
            }
            Err(e) => Err(ProtoError::from(format!("H2 handshake error: {}", e))),
        }
    }
}
