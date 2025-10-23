/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::network::upstream::pool::ConnectionBuilder;
use crate::network::upstream::utils::{
    build_dns_get_request, build_doh_request_uri, connect_quic, connect_socket, get_buf_from_res,
};
use crate::network::upstream::{Connection, ConnectionInfo};
use bytes::{BufMut, Bytes};
use futures::future::poll_fn;
use h3::client::{RequestStream, SendRequest};
use h3_quinn::{BidiStream, OpenStreams};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use http::Version;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::select;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, warn};

pub struct H3Connection {
    id: u16,
    sender: SendRequest<OpenStreams, Bytes>,
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
    async fn query(&self, mut request: Message) -> Result<DnsResponse> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(DnsError::protocol("H3 connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        self.last_used
            .store(AppClock::elapsed_millis(), Ordering::Relaxed);

        let raw_id = request.id();
        request.set_id(0);
        let body_bytes = request.to_bytes()?;

        let request = build_dns_get_request(self.request_uri.clone(), body_bytes, Version::HTTP_3);

        let mut request_stream = self
            .sender
            .clone()
            .send_request(request)
            .await
            .map_err(|e| {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                DnsError::protocol(format!("H3 send_request error: {e}"))
            })?;

        request_stream
            .finish()
            .await
            .map_err(|err| DnsError::protocol(format!("H3 received a stream error: {err}")))?;

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
pub struct H3ConnectionBuilder {
    remote_ip: Option<IpAddr>,
    port: u16,
    timeout: std::time::Duration,
    server_name: String,
    request_uri: String,
    insecure_skip_verify: bool,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
}

impl H3ConnectionBuilder {
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
impl ConnectionBuilder<H3Connection> for H3ConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn create_connection(&self, conn_id: u16) -> Result<Arc<H3Connection>> {
        let socket = connect_socket(
            self.remote_ip,
            self.server_name.clone(),
            self.port,
            self.so_mark,
            self.bind_to_device.clone(),
        )?;

        let quic_conn = connect_quic(
            socket,
            self.insecure_skip_verify,
            self.server_name.clone(),
            self.timeout,
        )
        .await?;

        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let (mut driver, send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| DnsError::protocol(format!("h3 connection failed: {e}")))?;

        let h3_conn = Arc::new(H3Connection {
            id: conn_id,
            sender: send_request,
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
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

async fn recv(mut request_stream: RequestStream<BidiStream<Bytes>, Bytes>) -> Result<Bytes> {
    let mut response = request_stream
        .recv_response()
        .await
        .map_err(|e| DnsError::protocol(format!("H3 response error: {}", e)))?;

    let mut response_bytes = get_buf_from_res(&mut response);

    while let Some(partial_bytes) = request_stream
        .recv_data()
        .await
        .map_err(|e| DnsError::protocol(format!("h3 recv_data error: {e}")))?
    {
        response_bytes.put(partial_bytes);
    }

    // Was it a successful request?
    if !response.status().is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());

        Err(DnsError::protocol(format!(
            "http unsuccessful code: {}, message: {}",
            response.status(),
            error_string
        )))
    } else {
        Ok(response_bytes.freeze())
    }
}
