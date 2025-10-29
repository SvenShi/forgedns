/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::network::upstream::pool::ConnectionBuilder;
use crate::network::upstream::utils::{connect_quic, connect_socket};
use crate::network::upstream::{Connection, ConnectionInfo};
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

use crate::network::transport::quic_transport::QuicTransport;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::select;

use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub struct QuicConnection {
    id: u16,
    transport: QuicTransport,
    using_count: AtomicU16,
    closed: AtomicBool,
    last_used: AtomicU64,
    timeout: std::time::Duration,
    close_notify: Notify,
}

impl Debug for QuicConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuicConnection")
    }
}

#[async_trait::async_trait]
impl Connection for QuicConnection {
    /// Gracefully close the QUIC connection
    ///
    /// Sends QUIC CONNECTION_CLOSE frame to peer and notifies background tasks.
    /// This is idempotent - multiple calls are safe.
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return; // Already closed
        }
        debug!(
            conn_id = self.id,
            "Closing QUIC connection, sending CONNECTION_CLOSE frame"
        );
        // Gracefully close the underlying QUIC connection with error code 0 (no error)
        self.transport.close(b"closing");
        self.close_notify.notify_waiters();
    }

    /// Send a DNS query over QUIC (DoQ - DNS over QUIC, RFC 9250)
    ///
    /// # Arguments
    /// * `request` - DNS query message to send
    ///
    /// # Returns
    /// - `Ok(DnsResponse)` if response received within timeout
    /// - `Err(DnsError)` if connection closed, stream open fails, or timeout occurs
    ///
    /// # Protocol
    /// Each DNS query uses a new bidirectional QUIC stream:
    /// - 2-byte big-endian length prefix
    /// - DNS message body
    /// - Stream is closed after message sent/received
    ///
    /// This follows RFC 9250 (DNS over Dedicated QUIC Connections)
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(DnsError::protocol("Cannot query on closed QUIC connection"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);

        // Open a new bidirectional stream (reader/writer) via connection wrapper
        let (mut reader, mut writer) = match timeout(self.timeout, self.transport.open_bi()).await {
            Ok(Ok((reader, writer))) => (reader, writer),
            Ok(Err(e)) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                self.close();
                return Err(DnsError::protocol(format!(
                    "Failed to open QUIC bidirectional stream: {}",
                    e
                )));
            }
            Err(_) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                return Err(DnsError::protocol(
                    "Timeout opening QUIC bidirectional stream",
                ));
            }
        };

        let raw_id = request.id();
        request.set_id(0); // RFC 9250: query ID SHOULD be set to 0

        if let Err(e) = writer.write_message(&request).await {
            self.using_count.fetch_sub(1, Ordering::Relaxed);
            return Err(DnsError::protocol(format!(
                "Failed to write DNS query to QUIC stream: {}",
                e
            )));
        }
        if let Err(e) = writer.finish() {
            warn!(
                conn_id = self.id,
                error = ?e,
                "Failed to finish QUIC send stream (half-close)"
            );
        }

        let result = match timeout(self.timeout, reader.read_message()).await {
            Ok(Ok(msg)) => match DnsResponse::from_message(msg) {
                Ok(mut resp) => {
                    resp.set_id(raw_id);
                    debug!(
                        conn_id = self.id,
                        query_id = raw_id,
                        "Successfully received DNS response over QUIC"
                    );
                    Ok(resp)
                }
                Err(e) => {
                    warn!(
                        conn_id = self.id,
                        query_id = raw_id,
                        error = ?e,
                        "Failed to convert Message to DnsResponse"
                    );
                    Err(DnsError::protocol(format!(
                        "Failed to convert Message: {}",
                        e
                    )))
                }
            },
            Ok(Err(e)) => {
                warn!(
                    conn_id = self.id,
                    query_id = raw_id,
                    error = ?e,
                    "QUIC DNS query failed"
                );
                Err(e)
            }
            Err(_) => {
                warn!(
                    conn_id = self.id,
                    query_id = raw_id,
                    timeout_ms = ?self.timeout.as_millis(),
                    "QUIC DNS query timeout"
                );
                Err(DnsError::protocol("dns query timeout"))
            }
        };

        self.last_used
            .store(AppClock::elapsed_millis(), Ordering::Relaxed);
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
pub struct QuicConnectionBuilder {
    remote_ip: Option<IpAddr>,
    port: u16,
    timeout: std::time::Duration,
    server_name: String,
    insecure_skip_verify: bool,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
}

impl QuicConnectionBuilder {
    pub fn new(connection_info: &ConnectionInfo) -> Self {
        Self {
            remote_ip: connection_info.remote_ip,
            port: connection_info.port,
            timeout: connection_info.timeout,
            server_name: connection_info.server_name.clone(),
            insecure_skip_verify: connection_info.insecure_skip_verify,
            so_mark: connection_info.so_mark,
            bind_to_device: connection_info.bind_to_device.clone(),
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<QuicConnection> for QuicConnectionBuilder {
    /// Establish a new QUIC connection for DNS over QUIC (DoQ)
    ///
    /// # Returns
    /// Arc-wrapped QuicConnection with background monitoring task spawned
    ///
    /// # Protocol
    /// - Uses QUIC with TLS 1.3 (per RFC 9250)
    /// - Each DNS query uses a new bidirectional stream
    /// - Connection can be reused for multiple queries
    ///
    /// # Performance
    /// - 0-RTT support for resumed connections
    /// - Multiplexed streams avoid head-of-line blocking
    /// - Native congestion control and loss recovery
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn create_connection(&self, conn_id: u16) -> Result<Arc<QuicConnection>> {
        let socket = connect_socket(
            self.remote_ip,
            self.server_name.clone(),
            self.port,
            self.so_mark,
            self.bind_to_device.clone(),
        )?;

        // Establish QUIC connection (includes TLS 1.3 handshake)
        let quic_conn = connect_quic(
            socket,
            self.insecure_skip_verify,
            self.server_name.clone(),
            self.timeout,
        )
        .await?;

        info!(
            conn_id,
            server_name = %self.server_name,
            remote_addr = ?quic_conn.remote_address(),
            "Established QUIC connection for DoQ (DNS over QUIC)"
        );

        let quic_conn = Arc::new(QuicConnection {
            id: conn_id,
            transport: QuicTransport::new(quic_conn),
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            using_count: AtomicU16::new(0),
            timeout: self.timeout,
            close_notify: Notify::new(),
        });

        // Spawn background task to monitor connection health
        let _conn = quic_conn.clone();
        tokio::spawn(async move {
            select! {
                _ = _conn.transport.closed() => {
                    debug!(
                        conn_id,
                        "QUIC connection closed by remote peer or network error"
                    );
                }
                _ = _conn.close_notify.notified() => {
                    debug!(
                        conn_id,
                        "QUIC connection closed by local request"
                    );
                }
            }
            // Ensure the underlying QUIC connection is properly closed
            let _ = _conn.transport.close(b"driver task ending");
        });

        Ok(quic_conn)
    }
}
