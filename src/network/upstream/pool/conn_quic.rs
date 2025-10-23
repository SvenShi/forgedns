/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::network::upstream::pool::ConnectionBuilder;
use crate::network::upstream::utils::{connect_quic, connect_socket};
use crate::network::upstream::{Connection, ConnectionInfo};
use bytes::{Bytes, BytesMut};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use quinn::{SendStream, VarInt};
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use tokio::select;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub struct QuicConnection {
    id: u16,
    conn: quinn::Connection,
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
        self.conn.close(0u32.into(), b"closing");
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

        // Open a new bidirectional stream for this DNS query
        let (mut send, mut recv) = match timeout(self.timeout, self.conn.open_bi()).await {
            Ok(Ok(bi)) => bi,
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
        let body_bytes = Bytes::from(request.to_bytes()?); // DNS wire format

        // Validate message size (RFC 9250: max 65535 bytes)
        let bytes_len = u16::try_from(body_bytes.len()).map_err(|_e| {
            DnsError::protocol(format!(
                "DNS message too large for DoQ: {} bytes (max: 65535)",
                body_bytes.len()
            ))
        })?;

        // Prepare 2-byte big-endian length prefix
        let len = bytes_len.to_be_bytes().to_vec();
        let len = Bytes::from(len);

        // Send length-prefixed DNS message over QUIC stream
        match send.write_all_chunks(&mut [len, body_bytes]).await {
            Ok(_) => {}
            Err(e) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                return Err(DnsError::protocol(format!(
                    "Failed to write DNS query to QUIC stream: {}",
                    e
                )));
            }
        };

        // Close send side of stream (half-close, can still receive)
        if let Err(e) = send.finish() {
            // Not fatal - we can still try to read the response, but log the issue
            warn!(
                conn_id = self.id,
                error = ?e,
                "Failed to finish QUIC send stream (half-close)"
            );
        }

        // Receive length-prefixed DNS response
        let result = match timeout(self.timeout, recv_dns_response(&mut recv, send)).await {
            Ok(Ok(bytes)) => {
                let mut resp = DnsResponse::from_buffer(bytes.to_vec())?;
                resp.set_id(raw_id); // Restore original query ID
                debug!(
                    conn_id = self.id,
                    query_id = raw_id,
                    response_bytes = bytes.len(),
                    "Successfully received DNS response over QUIC"
                );
                Ok(resp)
            }
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
            conn: quic_conn,
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
                _ = _conn.conn.closed() => {
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
            let _ = _conn.conn.close(0u32.into(), b"driver task ending");
        });

        Ok(quic_conn)
    }
}

/// Read a length-prefixed (2-byte BE) DNS response from a QUIC receive stream
///
/// # Arguments
/// * `recv` - QUIC receive stream to read from
/// * `send` - QUIC send stream (used for error signaling if needed)
///
/// # Returns
/// - `Ok(Bytes)` containing the DNS response message
/// - `Err(DnsError)` if read fails or protocol violation detected
///
/// # Protocol
/// Per RFC 9250 Section 4.2:
/// - First 2 bytes: message length in big-endian format
/// - Following bytes: DNS message (max 65535 bytes)
async fn recv_dns_response(recv: &mut quinn::RecvStream, send: SendStream) -> Result<Bytes> {
    // Read 2-byte big-endian length prefix
    let mut len = [0u8; 2];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to read DoQ length prefix: {}", e)))?;
    let len = u16::from_be_bytes(len) as usize;

    // RFC 9250: DNS messages are restricted to a maximum size of 65535 bytes
    // This restriction is consistent with DNS over TCP (RFC 1035) and DoT (RFC 7858)
    let mut bytes = BytesMut::with_capacity(len);
    bytes.resize(len, 0);

    if let Err(e) = recv.read_exact(&mut bytes[..len]).await {
        debug!(
            expected_len = len,
            actual_bytes = ?bytes.len(),
            "Failed to read complete DoQ DNS message"
        );

        // Signal protocol error to peer via stream reset
        reset(send, DoqErrorCode::ProtocolError)
            .map_err(|_| debug!("QUIC stream already closed, cannot reset"))
            .ok();
        return Err(DnsError::protocol(format!(
            "Failed to read DoQ DNS message body: {}",
            e
        )));
    }

    debug!(
        message_len = len,
        message_hex = ?&bytes[..len.min(64)], // Log first 64 bytes for debugging
        "Received complete DoQ DNS message"
    );
    Ok(bytes.freeze())
}

/// Reset a QUIC send stream with a DoQ error code
///
/// Signals to the peer that an error occurred using QUIC RESET_STREAM frame
///
/// # Arguments
/// * `send` - QUIC send stream to reset
/// * `code` - DoQ-specific error code (RFC 9250 Section 7.3)
fn reset(mut send: SendStream, code: DoqErrorCode) -> Result<()> {
    send.reset(code.into()).map_err(|_| {
        DnsError::protocol("Failed to reset QUIC stream (stream may already be closed)")
    })
}

/// DoQ (DNS over QUIC) error codes as defined in RFC 9250 Section 7.3
///
/// These error codes are used in QUIC RESET_STREAM and CONNECTION_CLOSE frames
/// to signal protocol-level errors to the peer.
#[derive(Clone, Copy)]
pub enum DoqErrorCode {
    /// No error (0x0)
    /// Used when the connection or stream needs to be closed normally
    NoError,
    /// Internal error (0x1)
    /// The DoQ implementation encountered an internal error and cannot continue
    InternalError,
    /// Protocol error (0x2)
    /// The DoQ implementation detected a protocol violation and is aborting
    ProtocolError,
    /// Request cancelled (0x3)
    /// A DoQ client is canceling an outstanding transaction
    RequestCancelled,
    /// Excessive load (0x4)
    /// A DoQ server is closing the connection due to resource constraints
    ExcessiveLoad,
    /// Reserved error code (0xd098ea5e)
    /// Alternative error code for testing purposes
    ErrorReserved,
    /// Unknown error code
    /// Represents any error code not defined in RFC 9250
    Unknown(u32),
}

// not using repr(u32) above because of the Unknown
const NO_ERROR: u32 = 0x0;
const INTERNAL_ERROR: u32 = 0x1;
const PROTOCOL_ERROR: u32 = 0x2;
const REQUEST_CANCELLED: u32 = 0x3;
const EXCESSIVE_LOAD: u32 = 0x4;
const ERROR_RESERVED: u32 = 0xd098ea5e;

impl From<DoqErrorCode> for VarInt {
    fn from(doq_error: DoqErrorCode) -> Self {
        use DoqErrorCode::*;

        match doq_error {
            NoError => Self::from_u32(NO_ERROR),
            InternalError => Self::from_u32(INTERNAL_ERROR),
            ProtocolError => Self::from_u32(PROTOCOL_ERROR),
            RequestCancelled => Self::from_u32(REQUEST_CANCELLED),
            ExcessiveLoad => Self::from_u32(EXCESSIVE_LOAD),
            ErrorReserved => Self::from_u32(ERROR_RESERVED),
            Unknown(code) => Self::from_u32(code),
        }
    }
}

impl From<VarInt> for DoqErrorCode {
    fn from(doq_error: VarInt) -> Self {
        let code: u32 = if let Ok(code) = doq_error.into_inner().try_into() {
            code
        } else {
            return Self::ProtocolError;
        };

        match code {
            NO_ERROR => Self::NoError,
            INTERNAL_ERROR => Self::InternalError,
            PROTOCOL_ERROR => Self::ProtocolError,
            REQUEST_CANCELLED => Self::RequestCancelled,
            EXCESSIVE_LOAD => Self::ExcessiveLoad,
            ERROR_RESERVED => Self::ErrorReserved,
            _ => Self::Unknown(code),
        }
    }
}
