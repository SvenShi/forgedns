/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::network::transport::tcp_transport::{
    TcpTransport, TcpTransportReader, TcpTransportWriter,
};
use crate::network::upstream::pool::request_map::RequestMap;
use crate::network::upstream::pool::{Connection, ConnectionBuilder};
use crate::network::upstream::utils::{connect_stream, connect_tls};
use crate::network::upstream::{ConnectionInfo, ConnectionType, Socks5Opt};
use async_trait::async_trait;
use hickory_proto::op::Message;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::select;
use tokio::sync::{
    Notify,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    oneshot,
};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Represents a single persistent TCP-based DNS connection.
/// Handles both plaintext TCP and TLS (DoT) connections, supporting
/// asynchronous DNS queries and concurrent request tracking.
#[derive(Debug)]
pub struct TcpConnection {
    /// Unique connection ID for logging/tracing.
    id: u16,
    /// Sender for the unbounded outgoing TCP message channel.
    sender: UnboundedSender<Message>,
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
    /// Gracefully close the TCP connection and notify background tasks
    ///
    /// This method is idempotent - multiple calls are safe and will only close once.
    /// Background read/write tasks will be notified and gracefully shut down.
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return; // Already closed, no-op
        }
        debug!(
            conn_id = self.id,
            "Initiating TCP connection close sequence"
        );
        self.close_notify.notify_waiters();
    }

    /// Sends a DNS query and waits asynchronously for its corresponding response
    ///
    /// # Arguments
    /// * `request` - DNS query message to send
    ///
    /// # Returns
    /// - `Ok(DnsResponse)` if response received within timeout
    /// - `Err(DnsError)` if connection closed, timeout occurs, or network error
    ///
    /// # Performance
    /// Uses TCP length-prefixed framing (2-byte BE length header) as per RFC 1035
    async fn query(&self, mut request: Message) -> Result<Message> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(DnsError::protocol(format!(
                "Cannot query on closed TCP connection (id={})",
                self.id
            )));
        }

        // Register query and get unique ID for request/response matching
        let (tx, rx) = oneshot::channel();
        let query_id = self.request_map.store(tx);

        debug!(
            conn_id = self.id,
            query_id,
            active_queries = self.using_count(),
            "Sending DNS query over TCP"
        );

        // Prepare query buffer with TCP 2-byte big-endian length prefix (RFC 1035 Section 4.2.2)
        let raw_id = request.id();
        request.set_id(query_id);

        // Queue Message for background sender task (TcpTransportWriter will frame it)
        if let Err(e) = self.sender.send(request) {
            self.request_map.take(query_id);
            error!(
                conn_id = self.id,
                query_id,
                error = ?e,
                "Failed to queue DNS query Message (sender channel closed)"
            );
            return Err(DnsError::protocol(e.to_string()));
        }

        // Await response or timeout
        match timeout(self.timeout, rx).await {
            Ok(Ok(mut res)) => {
                res.set_id(raw_id); // Restore original query ID
                debug!(
                    conn_id = self.id,
                    query_id, "Successfully received DNS response over TCP"
                );
                Ok(res)
            }
            Ok(Err(_)) => {
                self.request_map.take(query_id);
                warn!(
                    conn_id = self.id,
                    query_id, "DNS query canceled (response channel dropped)"
                );
                Err(DnsError::protocol("request canceled"))
            }
            Err(_) => {
                self.request_map.take(query_id);
                warn!(
                    conn_id = self.id,
                    query_id,
                    timeout_ms = ?self.timeout.as_millis(),
                    "DNS query timeout over TCP"
                );
                Err(DnsError::protocol("dns query timeout"))
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
    /// Create a new `TcpConnection` instance wrapping a socket writer
    ///
    /// # Arguments
    /// * `conn_id` - Unique connection identifier for logging and debugging
    /// * `sender` - Unbounded channel for queuing outbound DNS messages
    /// * `timeout` - Maximum time to wait for a DNS response
    fn new(conn_id: u16, sender: UnboundedSender<Message>, timeout: Duration) -> Self {
        debug!(
            conn_id,
            "Initialized TCP connection wrapper with async I/O tasks"
        );
        Self {
            id: conn_id,
            sender,
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout,
            closed: AtomicBool::new(false),
            writeable: AtomicBool::new(true),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
        }
    }

    /// Background task: sends queued DNS requests through the TCP writer
    ///
    /// Continuously drains the outbound message queue and writes to the TCP stream.
    /// Terminates gracefully when close notification is received.
    ///
    /// # Error Handling
    /// Write errors trigger connection closure and notify waiting queries
    async fn send_dns_request<S: AsyncWrite + Unpin>(
        self: Arc<Self>,
        mut writer: TcpTransportWriter<S>,
        mut receiver: UnboundedReceiver<Message>,
    ) {
        let mut closing = false;
        debug!(
            conn_id = self.id,
            "TCP sender task started, ready to transmit queued messages"
        );

        while !closing {
            select! {
                Some(msg) = receiver.recv() => {
                    if let Err(e) = writer.write_message(&msg).await {
                        error!(
                            conn_id = self.id,
                            error = ?e,
                            "TCP write failed, marking connection as non-writable"
                        );
                        self.writeable.store(false, Ordering::Relaxed);
                        self.close();
                    }
                }
                _ = self.close_notify.notified() => {
                    debug!(
                        conn_id = self.id,
                        "TCP sender received close notification, shutting down stream"
                    );
                    closing = true;
                }
            }
        }

        debug!(conn_id = self.id, "TCP sender task exiting");
    }

    /// Background task: reads DNS responses from the upstream TCP connection
    ///
    /// Implements TCP length-prefixed message framing (RFC 1035):
    /// - Reads 2-byte big-endian length prefix
    /// - Reads message body of specified length
    /// - Matches response to pending query by ID
    /// - Delivers response via oneshot channel
    ///
    /// # Buffer Management
    /// Uses a rolling buffer to handle partial reads and multiple messages per read
    async fn listen_dns_response<S: AsyncRead + Unpin>(
        self: Arc<Self>,
        mut reader: TcpTransportReader<S>,
    ) {
        let mut closing = false;
        debug!(
            conn_id = self.id,
            "TCP listener task started, waiting for DNS responses"
        );

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
                res = reader.read_message() => {
                    match res {
                        Ok(msg) => {
                            let id = msg.id();
                            if let Some(sender) = self.request_map.take(id) {
                                let _ = sender.send(msg);
                                self.last_used.store(AppClock::elapsed_millis(), Ordering::Relaxed);
                                debug!(
                                    conn_id = self.id,
                                    query_id = id,
                                    "Matched and delivered DNS response to waiting query"
                                );
                            } else {
                                debug!(
                                    conn_id = self.id,
                                    query_id = id,
                                    "Discarded DNS response (no matching query or already timed out)"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                conn_id = self.id,
                                error = ?e,
                                "TCP read error or EOF, closing connection"
                            );
                            self.close();
                            break;
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    closing = true;
                    debug!(
                        conn_id = self.id,
                        pending_queries = self.request_map.size(),
                        "TCP listener received close notification, draining remaining responses"
                    );
                    continue;
                }
            }
        }

        warn!(conn_id = self.id, "TCP listener task terminated");
    }
}

/// Builder that establishes new TCP or TLS (DoT) DNS connections.
#[derive(Debug)]
pub struct TcpConnectionBuilder {
    remote_ip: Option<IpAddr>,
    port: u16,
    timeout: Duration,
    tls_enabled: bool,
    server_name: String,
    insecure_skip_verify: bool,
    connection_type: ConnectionType,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
    socks5: Option<Socks5Opt>,
}

impl TcpConnectionBuilder {
    pub fn new(connection_info: &ConnectionInfo) -> Self {
        Self {
            remote_ip: connection_info.remote_ip,
            port: connection_info.port,
            timeout: connection_info.timeout,
            tls_enabled: matches!(connection_info.connection_type, ConnectionType::DoT),
            server_name: connection_info.server_name.clone(),
            insecure_skip_verify: connection_info.insecure_skip_verify,
            connection_type: connection_info.connection_type,
            so_mark: connection_info.so_mark,
            bind_to_device: connection_info.bind_to_device.clone(),
            socks5: connection_info.socks5.clone(),
        }
    }
}

#[async_trait]
impl ConnectionBuilder<TcpConnection> for TcpConnectionBuilder {
    /// Establish a new TCP or TLS connection to the DNS server
    ///
    /// # Returns
    /// Arc-wrapped TcpConnection with background I/O tasks spawned
    ///
    /// # Performance
    /// - TCP_NODELAY enabled for low-latency queries
    /// - Async I/O with separate reader/writer tasks
    /// - TLS handshake performed asynchronously if enabled
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn create_connection(&self, conn_id: u16) -> Result<Arc<TcpConnection>> {
        let stream = connect_stream(
            self.remote_ip,
            self.server_name.clone(),
            self.port,
            self.so_mark,
            self.bind_to_device.clone(),
            self.socks5.clone(),
        )
        .await?;

        info!(
            conn_id,
            connection_type = ?self.connection_type,
            remote = ?stream.peer_addr(),
            tls_enabled = self.tls_enabled,
            "Established TCP connection to DNS server"
        );

        let (sender, receiver) = unbounded_channel();
        let connection = TcpConnection::new(conn_id, sender, self.timeout);
        let arc = Arc::new(connection);

        if self.tls_enabled {
            let tls_stream = connect_tls(
                stream,
                self.insecure_skip_verify,
                self.server_name.clone(),
                self.timeout,
                vec![b"dot".to_vec()],
            )
            .await?;

            let transport = TcpTransport::new(tls_stream);
            let (reader, writer) = transport.into_split();
            tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
            tokio::spawn(TcpConnection::send_dns_request(
                arc.clone(),
                writer,
                receiver,
            ));
        } else {
            let transport = TcpTransport::new(stream);
            let (reader, writer) = transport.into_split();
            tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
            tokio::spawn(TcpConnection::send_dns_request(
                arc.clone(),
                writer,
                receiver,
            ));
        }

        Ok(arc)
    }
}
