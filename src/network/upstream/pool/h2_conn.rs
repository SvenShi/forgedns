/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::network::upstream::pool::ConnectionBuilder;
use crate::network::upstream::utils::{
    build_dns_get_request, build_doh_request_uri, connect_stream, connect_tls, get_buf_from_res,
};
use crate::network::upstream::{Connection, ConnectionInfo, DEFAULT_TIMEOUT};
use bytes::{BufMut, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use http::Version;
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::Notify;
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
    async fn query(&self, mut request: Message) -> Result<DnsResponse> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(DnsError::protocol("DoH connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        self.last_used
            .store(AppClock::elapsed_millis(), Ordering::Relaxed);

        let raw_id = request.id();
        request.set_id(0);
        let body_bytes = request.to_bytes()?;

        let request = build_dns_get_request(self.request_uri.clone(), body_bytes, Version::HTTP_2);

        let (response_future, _send_stream) = self
            .sender
            .clone()
            .send_request(request, false)
            .map_err(|e| {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                DnsError::protocol(format!("H2 send_request error: {e}"))
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
                Err(DnsError::protocol("dns query timeout"))
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
    remote_ip: Option<IpAddr>,
    port: u16,
    timeout: std::time::Duration,
    server_name: String,
    request_uri: String,
    insecure_skip_verify: bool,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
}

impl H2ConnectionBuilder {
    pub fn new(connection_info: &ConnectionInfo) -> Self {
        Self {
            remote_ip: connection_info.remote_ip,
            port: connection_info.port,
            timeout: connection_info.timeout,
            server_name: connection_info.server_name.clone(),
            request_uri: build_doh_request_uri(connection_info),
            insecure_skip_verify: connection_info.insecure_skip_verify,
            so_mark: connection_info.so_mark,
            bind_to_device: connection_info.bind_to_device.clone(),
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<H2Connection> for H2ConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn create_connection(&self, conn_id: u16) -> Result<Arc<H2Connection>> {
        let stream = connect_stream(
            self.remote_ip,
            self.server_name.clone(),
            self.port,
            self.so_mark,
            self.bind_to_device.clone(),
        )?;

        let tls_stream = connect_tls(
            TcpStream::from_std(stream)?,
            self.insecure_skip_verify,
            self.server_name.clone(),
            DEFAULT_TIMEOUT,
        )
        .await?;

        let (sender, connection) = h2::client::Builder::new()
            .handshake(tls_stream)
            .await
            .map_err(|e| DnsError::protocol(format!("H2 handshake error: {}", e)))?;

        let h2_conn = Arc::new(H2Connection {
            id: conn_id,
            sender,
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
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

async fn recv(response_future: ResponseFuture) -> Result<Bytes> {
    let mut response = response_future
        .await
        .map_err(|e| DnsError::protocol(format!("H2 response error: {}", e)))?;

    let status_code = response.status();
    let mut response_bytes = get_buf_from_res(&mut response);
    let mut body = response.into_body();

    while let Some(Ok(partial_bytes)) = body.data().await {
        response_bytes.put(partial_bytes);
    }

    if !status_code.is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());
        Err(DnsError::protocol(format!(
            "http unsuccessful code: {}, message: {}",
            status_code, error_string
        )))
    } else {
        Ok(response_bytes.freeze())
    }
}
