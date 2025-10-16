/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::utils::connect_quic;
use crate::pkg::upstream::pool::ConnectionBuilder;
use crate::pkg::upstream::{ConnectInfo, Connection, DEFAULT_TIMEOUT};
use bytes::{Bytes, BytesMut};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::{ProtoError, ProtoErrorKind};
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use quinn::{SendStream, VarInt};
use tokio::select;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, warn};

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
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        debug!(conn_id = self.id, "Closing QUIC connection");
        // close the underlying quinn connection gracefully
        self.conn.close(0u32.into(), b"closing");
        self.close_notify.notify_waiters();
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(ProtoError::from("QUIC connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        // open a bidirectional stream and send
        let (mut send, mut recv) = match timeout(self.timeout, self.conn.open_bi()).await {
            Ok(Ok(bi)) => bi,
            Ok(Err(e)) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                return Err(ProtoError::from(format!("quic open_bi error: {e}")));
            }
            Err(_) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                return Err(ProtoError::from("quic open_bi timeout"));
            }
        };

        let raw_id = request.id();
        request.set_id(0);
        let body_bytes = Bytes::from(request.to_bytes()?); // DNS wire format
        let bytes_len = u16::try_from(body_bytes.len())
            .map_err(|_e| ProtoErrorKind::MaxBufferSizeExceeded(body_bytes.len()))?;
        let len = bytes_len.to_be_bytes().to_vec();
        let len = Bytes::from(len);

        match send.write_all_chunks(&mut [len, body_bytes]).await {
            Ok(_) => {}
            Err(e) => {
                self.using_count.fetch_sub(1, Ordering::Relaxed);
                return Err(ProtoError::from(format!("quic send err: {e}")));
            }
        };

        // finish/close the send side
        if let Err(e) = send.finish() {
            // not fatal — continue to try to read, but warn
            warn!(conn_id = self.id, ?e, "quic send finish error");
        }

        // receive length-prefixed response
        let result = match timeout(self.timeout, recv_dns_response(&mut recv, send)).await {
            Ok(Ok(bytes)) => {
                let mut resp = DnsResponse::from_buffer(bytes.to_vec())?;
                resp.set_id(raw_id);
                debug!(conn_id = self.id, raw_id, "Received QUIC response");
                Ok(resp)
            }
            Ok(Err(e)) => {
                warn!(conn_id = self.id, raw_id, ?e, "QUIC request error");
                Err(e)
            }
            Err(_) => {
                warn!(conn_id = self.id, raw_id, "QUIC request timeout");
                Err(ProtoError::from("dns query timeout"))
            }
        };
        self.last_used
            .store(AppClock::run_millis(), Ordering::Relaxed);
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
    pub bind_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub timeout: std::time::Duration,
    pub server_name: String,
    pub insecure_skip_verify: bool,
}

impl QuicConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            bind_addr: connect_info.get_bind_socket_addr(),
            remote_addr: connect_info.get_full_remote_socket_addr(),
            timeout: connect_info.timeout,
            server_name: connect_info.host.clone(),
            insecure_skip_verify: connect_info.insecure_skip_verify,
        }
    }
}

#[async_trait::async_trait]
impl ConnectionBuilder<QuicConnection> for QuicConnectionBuilder {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<QuicConnection>, ProtoError> {
        // connect_quic should return a `quinn::Connection`
        let quic_conn = connect_quic(
            self.bind_addr,
            self.remote_addr,
            self.insecure_skip_verify,
            self.server_name.clone(),
            DEFAULT_TIMEOUT,
        )
        .await?;

        let quic_conn = Arc::new(QuicConnection {
            id: conn_id,
            conn: quic_conn,
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::run_millis()),
            using_count: AtomicU16::new(0),
            timeout: self.timeout,
            close_notify: Notify::new(),
        });

        // spawn a driver task to monitor connection close or external notify
        let _conn = quic_conn.clone();
        tokio::spawn(async move {
            select! {
                _ = _conn.conn.closed() => {
                    debug!(conn_id, "QUIC connection closed by remote");
                }
                _ = _conn.close_notify.notified() => {
                    debug!(conn_id, "QUIC connection closed by notify");
                }
            }
            // ensure the underlying connection is closed
            let _ = _conn.conn.close(0u32.into(), b"driver ending");
        });

        Ok(quic_conn)
    }
}

/// Read a length-prefixed (2-byte BE) DNS response from a `quinn::RecvStream`.
async fn recv_dns_response(recv: &mut quinn::RecvStream, send: SendStream) -> Result<Bytes, ProtoError> {
    // following above, the data should be first the length, followed by the message(s)
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await.unwrap();
    let len = u16::from_be_bytes(len) as usize;

    // RFC: DoQ queries and responses are sent on QUIC streams, which in theory can carry up to
    // 2^62 bytes.  However, DNS messages are restricted in practice to a maximum size of 65535
    // bytes.  This maximum size is enforced by the use of a 2-octet message length field in DNS
    // over TCP [RFC1035] and DoT [RFC7858], and by the definition of the
    // "application/dns-message" for DoH [RFC8484].  DoQ enforces the same restriction.
    let mut bytes = BytesMut::with_capacity(len);
    bytes.resize(len, 0);
    if let Err(e) = recv.read_exact(&mut bytes[..len]).await {
        debug!("received bad packet len: {} bytes: {:?}", len, bytes);

        reset(send, DoqErrorCode::ProtocolError)
            .map_err(|_| debug!("stream already closed"))
            .ok();
        return Err(format!("received err {e}").into());
    }

    debug!("received packet len: {} bytes: {:x?}", len, bytes);
    Ok(bytes.freeze())
}

fn reset(mut send: SendStream, code: DoqErrorCode) -> Result<(), ProtoError> {
    send.reset(code.into())
        .map_err(|_| ProtoError::from("an unknown quic stream was used"))
}

#[derive(Clone, Copy)]
pub enum DoqErrorCode {
    /// No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
    NoError,
    /// The DoQ implementation encountered an internal error and is incapable of pursuing the transaction or the connection.
    InternalError,
    /// The DoQ implementation encountered a protocol error and is forcibly aborting the connection.
    ProtocolError,
    /// A DoQ client uses this to signal that it wants to cancel an outstanding transaction.
    RequestCancelled,
    /// A DoQ implementation uses this to signal when closing a connection due to excessive load.
    ExcessiveLoad,
    /// An alternative error code used for tests.
    ErrorReserved,
    /// Unknown Error code
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