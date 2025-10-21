/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::pkg::upstream::ConnectInfo;
use crate::pkg::upstream::pool::request_map::RequestMap;
use crate::pkg::upstream::pool::{Connection, ConnectionBuilder};
use async_trait::async_trait;
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Represents a single UDP connection used in DNS upstream queries.
/// Each connection manages its own socket and maintains a mapping
/// of request IDs to response channels for asynchronous query handling.
#[derive(Debug)]
pub struct UdpConnection {
    /// Unique connection ID (for debugging/tracing)
    id: u16,
    /// The underlying UDP socket bound to a local address
    socket: UdpSocket,
    /// Notifier used to signal connection closure
    close_notify: Notify,
    /// Mapping between DNS query IDs and response channels
    request_map: RequestMap,
    /// Timeout duration for a DNS query
    timeout: Duration,
    /// Timestamp of last activity (milliseconds)
    last_used: AtomicU64,
}

/// Retry delay for initial DNS query attempts
const RETRY_TIMEOUT: Duration = Duration::from_secs(1);

#[async_trait]
impl Connection for UdpConnection {
    /// Close this UDP connection and notify all waiting tasks.
    fn close(&self) {
        debug!(conn_id = self.id, "Closing UDP connection");
        self.close_notify.notify_waiters();
    }

    /// Send a DNS query and wait asynchronously for its response.
    /// Retries once with a shorter timeout, then uses the normal timeout.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        let raw_id = request.id();
        let mut current_timeout = RETRY_TIMEOUT;

        for attempt in 0..2 {
            let (tx, rx) = oneshot::channel();
            let query_id = self.request_map.store(tx);
            request.set_id(query_id);

            let msg = request.to_bytes()?;
            debug!(conn_id = self.id, attempt, query_id, "Sending DNS query");

            // Send request
            match self.socket.send(msg.as_slice()).await {
                Ok(_sent) => {}
                Err(e) => {
                    self.request_map.take(query_id);
                    return Err(ProtoError::from(e));
                }
            };

            // Wait for response or timeout
            match timeout(current_timeout, rx).await {
                Ok(Ok(mut response)) => {
                    response.set_id(raw_id);
                    debug!(conn_id = self.id, query_id, "Received DNS response");
                    self.last_used
                        .store(AppClock::run_millis(), Ordering::Relaxed);
                    return Ok(response);
                }
                Ok(Err(_)) => {
                    self.request_map.take(query_id);
                    return Err(ProtoError::from("request canceled"));
                }
                Err(_) => {
                    self.request_map.take(query_id);
                    warn!(
                        conn_id = self.id,
                        query_id, "Query timed out (will retry if possible)"
                    );
                }
            }

            current_timeout = self.timeout;
        }

        Err(ProtoError::from("dns query timeout"))
    }

    /// Return the number of active queries currently tracked by this connection.
    fn using_count(&self) -> u16 {
        self.request_map.size()
    }

    /// UDP connections are always considered available (no persistent state).
    fn available(&self) -> bool {
        true
    }

    /// Return the timestamp (in ms) of last successful activity.
    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl UdpConnection {
    /// Construct a new UDP connection with the given parameters.
    fn new(conn_id: u16, socket: UdpSocket, timeout: Duration) -> UdpConnection {
        Self {
            id: conn_id,
            socket,
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout,
            last_used: AtomicU64::new(AppClock::run_millis()),
        }
    }

    /// Asynchronously listen for DNS responses and deliver them to matching queries.
    /// This task runs per connection until all requests complete or the connection closes.
    async fn listen_dns_response(self: Arc<Self>) {
        let mut buf = [0u8; 4096];
        let mut closing = false;

        debug!(conn_id = self.id, "UDP connection listener started");

        loop {
            if closing && self.request_map.is_empty() {
                debug!(conn_id = self.id, "Listener exiting (connection dropped)");
                break;
            }

            select! {
                recv = self.socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((len, _addr)) => {
                            match DnsResponse::from_buffer(Vec::from(&buf[..len])) {
                                Ok(msg) => {
                                    let id = msg.header().id();
                                    if let Some(sender) = self.request_map.take(id) {
                                        let _ = sender.send(msg);
                                        self.last_used.store(AppClock::run_millis(), Ordering::Relaxed);
                                        debug!(conn_id = self.id, id, "Delivered DNS response to waiting query");
                                    } else {
                                        debug!(conn_id = self.id, id, "Discarded unmatched DNS response");
                                    }
                                }
                                Err(_) => {
                                    warn!(conn_id = self.id, "Failed to parse DNS response buffer");
                                }
                            }
                        }
                        Err(e) => {
                            error!(conn_id = self.id, ?e, "recv_from failed");
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    closing = true;
                    debug!(conn_id = self.id, "Received close notification");
                    continue;
                }
            }
        }
    }
}

/// Builder for creating new `UdpConnection` instances.
#[derive(Debug)]
pub struct UdpConnectionBuilder {
    /// Local address to bind UDP sockets to.
    bind_addr: SocketAddr,
    /// Upstream DNS server address.
    remote_addr: SocketAddr,
    /// Query timeout duration.
    timeout: Duration,
}

impl UdpConnectionBuilder {
    /// Initialize a new builder using upstream connection info.
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            bind_addr: connect_info.get_bind_socket_addr(),
            remote_addr: connect_info.get_full_remote_socket_addr(),
            timeout: connect_info.timeout,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<UdpConnection> for UdpConnectionBuilder {
    /// Create a new UDP connection, bind it locally, connect to remote server,
    /// and spawn a background listener task to handle responses.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<UdpConnection>, ProtoError> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        socket.connect(self.remote_addr).await?;

        info!("Established UDP connection (id={}, remote={})", conn_id, self.remote_addr);

        let connection = UdpConnection::new(conn_id, socket, self.timeout);
        let arc = Arc::new(connection);

        // Spawn background task for listening responses
        tokio::spawn(UdpConnection::listen_dns_response(arc.clone()));

        Ok(arc)
    }
}
