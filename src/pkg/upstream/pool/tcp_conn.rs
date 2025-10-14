/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::request_map::RequestMap;
use crate::pkg::upstream::pool::{Connection, ConnectionBuilder};
use crate::pkg::upstream::tls_client_config::{insecure_client_config, secure_client_config};
use crate::pkg::upstream::{ConnectInfo, ConnectType, DEFAULT_TIMEOUT};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf,
};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::select;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
    Notify,
};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, warn};

/// Represents a single persistent TCP-based DNS connection.
/// Handles both plaintext TCP and TLS (DoT) connections, supporting
/// asynchronous DNS queries and concurrent request tracking.
#[derive(Debug)]
pub struct TcpConnection {
    /// Unique connection ID for logging/tracing.
    id: u16,
    /// Sender for the unbounded outgoing TCP message channel.
    sender: UnboundedSender<Bytes>,
    /// Notifier that signals connection closure to background tasks.
    close_notify: Notify,
    /// Map of active DNS queries (query_id → response channel sender).
    request_map: RequestMap,
    /// Timeout duration for each DNS query.
    timeout: Duration,
    /// Whether the connection is marked as closed.
    closed: AtomicBool,
    /// Indicates if the connection is currently writable.
    writeable: AtomicBool,
    /// Timestamp (ms) of last successful activity.
    last_used: AtomicU64,
}

#[async_trait]
impl Connection for TcpConnection {
    /// Gracefully close the TCP connection and notify background tasks.
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return; // already closed
        }
        debug!(conn_id = self.id, "Closing TCP connection");
        self.close_notify.notify_waiters();
    }

    /// Sends a DNS query and waits asynchronously for its corresponding response.
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(ProtoError::from(format!(
                "Connection id {} closed",
                self.id
            )));
        }

        let (tx, rx) = oneshot::channel();
        let query_id = self.request_map.store(tx);

        debug!(
            conn_id = self.id,
            query_id,
            active = self.using_count(),
            "Sending TCP DNS query"
        );

        // Prepare query buffer with TCP 2-byte length prefix
        let raw_id = request.id();
        request.set_id(query_id);
        let buf = request.to_bytes()?;
        let mut bytes_mut = BytesMut::with_capacity(2 + buf.len());
        bytes_mut.put_u16(buf.len() as u16);
        bytes_mut.put_slice(&buf);

        if let Err(e) = self.sender.send(bytes_mut.freeze()) {
            self.request_map.take(query_id);
            error!(conn_id = self.id, ?e, "Failed to queue TCP DNS query");
            return Err(ProtoError::from(e.to_string()));
        }

        // Await response or timeout
        match timeout(self.timeout, rx).await {
            Ok(Ok(mut res)) => {
                res.set_id(raw_id);
                debug!(conn_id = self.id, query_id, "Received TCP DNS response");
                Ok(res)
            }
            Ok(Err(_)) => {
                self.request_map.take(query_id);
                warn!(
                    conn_id = self.id,
                    query_id, "TCP DNS query canceled before response"
                );
                Err(ProtoError::from("request canceled"))
            }
            Err(_) => {
                self.request_map.take(query_id);
                warn!(conn_id = self.id, query_id, "TCP DNS query timed out");
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    fn using_count(&self) -> u16 {
        self.request_map.size()
    }

    fn available(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.writeable.load(Ordering::Relaxed)
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl TcpConnection {
    /// Create a new `TcpConnection` instance wrapping a socket writer.
    fn new(conn_id: u16, sender: UnboundedSender<Bytes>, timeout: Duration) -> Self {
        debug!(conn_id, "Creating new TCP connection wrapper");
        Self {
            id: conn_id,
            sender,
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout,
            closed: AtomicBool::new(false),
            writeable: AtomicBool::new(true),
            last_used: AtomicU64::new(AppClock::run_millis()),
        }
    }

    /// Background task: sends queued DNS requests through the TCP writer.
    async fn send_dns_request<T: AsyncWrite>(
        self: Arc<Self>,
        mut writer: WriteHalf<T>,
        mut receiver: UnboundedReceiver<Bytes>,
    ) {
        let mut closing = false;
        debug!(conn_id = self.id, "TCP sender task started");

        while !closing {
            select! {
                Some(packet) = receiver.recv() => {
                    if let Err(e) = writer.write_all(&packet).await {
                        error!(conn_id = self.id, ?e, "TCP write error");
                        self.writeable.store(false, Ordering::Relaxed);
                        self.close();
                    }
                }
                _ = self.close_notify.notified() => {
                    debug!(conn_id = self.id, "TCP sender received close signal");
                    let _ = writer.shutdown().await;
                    closing = true;
                }
            }
        }

        debug!(conn_id = self.id, "TCP sender task exiting");
    }

    /// Background task: reads DNS responses from the upstream TCP connection.
    async fn listen_dns_response<T: AsyncRead>(self: Arc<Self>, reader: ReadHalf<T>) {
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 16384];
        let mut start = 0;
        let mut closing = false;

        debug!(conn_id = self.id, "TCP listener task started");

        loop {
            if closing && self.request_map.is_empty() {
                debug!(conn_id = self.id, "TCP listener exiting (no more requests)");
                break;
            }
            if self.closed.load(Ordering::Relaxed) {
                debug!(conn_id = self.id, "TCP listener detected closed connection");
                break;
            }

            select! {
                res = reader.read(&mut buf[start..]) => {
                    match res {
                        Ok(0) => {
                            warn!(conn_id = self.id, "TCP connection closed by remote");
                            self.close();
                            break;
                        }
                        Ok(n) => {
                            let total = start + n;
                            let mut offset = 0;

                            // Parse length-prefixed DNS messages
                            while total - offset >= 2 {
                                let msg_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                                if total - offset < 2 + msg_len { break; }

                                let msg_body = &buf[offset + 2..offset + 2 + msg_len];
                                match DnsResponse::from_buffer(Vec::from(msg_body)) {
                                    Ok(msg) => {
                                        let id = msg.header().id();
                                        if let Some(sender) = self.request_map.take(id) {
                                            let _ = sender.send(msg);
                                            self.last_used.store(AppClock::run_millis(), Ordering::Relaxed);
                                            debug!(conn_id = self.id, id, "Delivered TCP DNS response");
                                        } else {
                                            debug!(conn_id = self.id, id, "Discarded unmatched TCP response");
                                        }
                                    }
                                    Err(e) => {
                                        warn!(conn_id = self.id, ?e, "Failed to decode TCP DNS response");
                                    }
                                }
                                offset += 2 + msg_len;
                            }

                            start = total - offset;
                            buf.copy_within(offset..total, 0);
                        }
                        Err(e) => {
                            error!(conn_id = self.id, ?e, "TCP DNS read error");
                            self.close();
                            break;
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    closing = true;
                    debug!(conn_id = self.id, "TCP listener received close signal");
                    continue;
                }
            }
        }

        warn!(conn_id = self.id, "TCP listener terminated");
    }
}

/// Builder that establishes new TCP or TLS (DoT) DNS connections.
#[derive(Debug)]
pub struct TcpConnectionBuilder {
    pub remote_addr: SocketAddr,
    pub timeout: Duration,
    pub tls_enabled: bool,
    pub server_name: String,
    pub insecure_skip_verify: bool,
    pub connect_type: ConnectType,
}

impl TcpConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            remote_addr: SocketAddr::new(
                connect_info
                    .remote_addr
                    .parse()
                    .expect("Invalid remote address"),
                connect_info.port,
            ),
            timeout: connect_info.timeout,
            tls_enabled: matches!(connect_info.connect_type, ConnectType::DoT),
            server_name: connect_info.host.clone(),
            insecure_skip_verify: connect_info.insecure_skip_verify,
            connect_type: connect_info.connect_type,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<TcpConnection> for TcpConnectionBuilder {
    /// Establish a new TCP or TLS connection to the DNS server.
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<TcpConnection>, ProtoError> {
        let remote = self.remote_addr;

        match TcpStream::connect(remote).await {
            Ok(stream) => {
                if let Err(e) = stream.set_nodelay(true) {
                    warn!(conn_id, ?e, "Failed to enable TCP_NODELAY");
                }

                debug!(
                    conn_id,
                    local = ?stream.local_addr(),
                    remote = ?stream.peer_addr(),
                    tls = self.tls_enabled,
                    "Established new {:?} connection",
                    self.connect_type
                );

                let (sender, receiver) = unbounded_channel();
                let connection = TcpConnection::new(conn_id, sender, self.timeout);
                let arc = Arc::new(connection);

                if self.tls_enabled {
                    let config = if self.insecure_skip_verify {
                        insecure_client_config()
                    } else {
                        secure_client_config()
                    };
                    let connector = TlsConnector::from(Arc::new(config));

                    let dns_name = ServerName::try_from(self.server_name.clone())
                        .map_err(|_| ProtoError::from("invalid dns server name"))?;

                    let stream =
                        match timeout(DEFAULT_TIMEOUT, connector.connect(dns_name, stream)).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                return Err(ProtoError::from(format!("tls connect error: {e}")));
                            }
                            Err(_) => return Err(ProtoError::from("TLS handshake timeout")),
                        };

                    let (reader, writer) = split(stream);
                    tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
                    tokio::spawn(TcpConnection::send_dns_request(
                        arc.clone(),
                        writer,
                        receiver,
                    ));
                } else {
                    let (reader, writer) = split(stream);
                    tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
                    tokio::spawn(TcpConnection::send_dns_request(
                        arc.clone(),
                        writer,
                        receiver,
                    ));
                }

                Ok(arc)
            }
            Err(e) => {
                error!(
                    conn_id,
                    ?remote,
                    ?e,
                    "Failed to connect to {:?} DNS server",
                    self.connect_type
                );
                Err(ProtoError::from(e))
            }
        }
    }
}
