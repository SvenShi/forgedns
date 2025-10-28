/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::network::transport::{recv_message_from_udp, send_message_udp};
use crate::network::upstream::pool::request_map::RequestMap;
use crate::network::upstream::pool::{Connection, ConnectionBuilder};
use crate::network::upstream::utils::connect_socket;
use crate::network::upstream::ConnectionInfo;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;
use tracing::{debug, error, info};

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
    /// Connection closed flag (prevents use after closure and ensures idempotent close)
    closed: AtomicBool,
}

/// Retry delay for initial DNS query attempts
const RETRY_TIMEOUT: Duration = Duration::from_secs(1);

#[async_trait]
impl Connection for UdpConnection {
    /// Close this UDP connection and notify all waiting tasks
    ///
    /// UDP connections are stateless, so close mainly signals the listener task to exit.
    /// This method is idempotent - multiple calls are safe and will only execute once.
    fn close(&self) {
        // Atomically set closed flag and check previous value
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // Already closed, no-op
        }
        debug!(
            conn_id = self.id,
            "Closing UDP connection and signaling listener task"
        );
        self.close_notify.notify_waiters();
    }

    /// Send a DNS query and wait asynchronously for its response
    ///
    /// # Arguments
    /// * `request` - DNS query message to send
    ///
    /// # Returns
    /// - `Ok(DnsResponse)` if response received
    /// - `Err(DnsError)` if both attempts timeout or network error occurs
    ///
    /// # Retry Strategy
    /// - First attempt: 1 second timeout (quick retry on packet loss)
    /// - Second attempt: configured timeout (allows for slower network)
    ///
    /// This two-stage approach improves resilience against UDP packet loss
    /// while maintaining low latency for successful queries.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse> {
        let raw_id = request.id();
        let mut current_timeout = RETRY_TIMEOUT;

        for attempt in 0..2 {
            let (tx, rx) = oneshot::channel();
            let query_id = self.request_map.store(tx);
            request.set_id(query_id);

            debug!(
                conn_id = self.id,
                attempt,
                query_id,
                timeout_ms = current_timeout.as_millis(),
                "Sending DNS query over UDP"
            );

            // Send UDP datagram (no length prefix needed for UDP)
            match send_message_udp(&self.socket, &request).await {
                Ok(_sent) => {}
                Err(e) => {
                    self.request_map.take(query_id);
                    // Close connection on send failure (socket likely unusable)
                    self.close();
                    return Err(DnsError::protocol(format!("UDP send failed: {}", e)));
                }
            };

            // Wait for response or timeout
            match timeout(current_timeout, rx).await {
                Ok(Ok(mut response)) => {
                    response.set_id(raw_id); // Restore original query ID
                    debug!(
                        conn_id = self.id,
                        query_id, attempt, "Successfully received DNS response over UDP"
                    );
                    self.last_used
                        .store(AppClock::elapsed_millis(), Ordering::Relaxed);
                    return Ok(response);
                }
                Ok(Err(_)) => {
                    self.request_map.take(query_id);
                    return Err(DnsError::protocol("request canceled (channel dropped)"));
                }
                Err(_) => {
                    // Timeout on this attempt, will retry if attempts remain
                    self.request_map.take(query_id);
                    debug!(
                        conn_id = self.id,
                        query_id,
                        attempt,
                        timeout_ms = current_timeout.as_millis(),
                        "DNS query attempt timed out"
                    );
                }
            }

            // Use full timeout for second attempt
            current_timeout = self.timeout;
        }

        Err(DnsError::protocol(format!(
            "DNS query timeout after 2 attempts (total {}ms)",
            (RETRY_TIMEOUT + self.timeout).as_millis()
        )))
    }

    /// Return the number of active queries currently tracked by this connection.
    fn using_count(&self) -> u16 {
        self.request_map.size()
    }

    /// Check if the UDP connection is available for new queries
    ///
    /// Returns false if the connection has been closed (e.g., due to send failure)
    fn available(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    /// Return the timestamp (in ms) of last successful activity.
    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl UdpConnection {
    /// Construct a new UDP connection with the given parameters
    ///
    /// # Arguments
    /// * `conn_id` - Unique connection identifier for logging
    /// * `socket` - Pre-configured UDP socket connected to remote server
    /// * `timeout` - Query timeout duration
    fn new(conn_id: u16, socket: UdpSocket, timeout: Duration) -> UdpConnection {
        Self {
            id: conn_id,
            socket,
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout,
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            closed: AtomicBool::new(false), // Initially open
        }
    }

    /// Asynchronously listen for DNS responses and deliver them to matching queries
    ///
    /// Continuously receives UDP datagrams and matches them to pending queries by ID.
    /// This task runs per connection until all requests complete or the connection closes.
    ///
    /// # Buffer Size
    /// Uses 4KB buffer which is sufficient for most DNS responses.
    /// Larger responses would typically use TCP (with TC bit set).
    async fn listen_dns_response(self: Arc<Self>) {
        let mut buf = [0u8; 4096]; // Standard DNS UDP buffer size
        let mut closing = false;

        debug!(
            conn_id = self.id,
            "UDP listener task started, waiting for DNS responses"
        );

        loop {
            if closing && self.request_map.is_empty() {
                debug!(conn_id = self.id, "Listener exiting (connection dropped)");
                break;
            }

            select! {
                recv = recv_message_from_udp(&self.socket,&mut buf) => {
                    match recv {
                        Ok((msg, _addr)) => {
                            let id = msg.header().id();
                            if let Some(sender) = self.request_map.take(id) {
                                let _ = sender.send(DnsResponse::from_message(msg).unwrap());
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
                            error!(
                                conn_id = self.id,
                                error = ?e,
                                "UDP recv_from failed"
                            );
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    closing = true;
                    debug!(
                        conn_id = self.id,
                        pending_queries = self.request_map.size(),
                        "UDP listener received close notification, will drain remaining responses"
                    );
                    continue;
                }
            }
        }
    }
}

/// Builder for creating new `UdpConnection` instances.
#[derive(Debug)]
pub struct UdpConnectionBuilder {
    remote_ip: Option<IpAddr>,
    port: u16,
    server_name: String,
    /// Query timeout duration.
    timeout: Duration,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
}

impl UdpConnectionBuilder {
    /// Initialize a new builder using upstream connection info.
    pub fn new(connection_info: &ConnectionInfo) -> Self {
        Self {
            remote_ip: connection_info.remote_ip,
            port: connection_info.port,
            server_name: connection_info.server_name.clone(),
            timeout: connection_info.timeout,
            so_mark: connection_info.so_mark,
            bind_to_device: connection_info.bind_to_device.clone(),
        }
    }
}

#[async_trait]
impl ConnectionBuilder<UdpConnection> for UdpConnectionBuilder {
    /// Create a new UDP connection, bind it locally, connect to remote server,
    /// and spawn a background listener task to handle responses
    ///
    /// # Returns
    /// Arc-wrapped UdpConnection with background listener task spawned
    ///
    /// # Performance
    /// - Non-blocking socket I/O
    /// - Single listener task handles all responses for this connection
    /// - Zero-copy where possible (direct socket buffer to DNS parser)
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn create_connection(&self, conn_id: u16) -> Result<Arc<UdpConnection>> {
        let socket = connect_socket(
            self.remote_ip,
            self.server_name.clone(),
            self.port,
            self.so_mark,
            self.bind_to_device.clone(),
        )?;

        info!(
            conn_id,
            local_addr = ?socket.local_addr(),
            remote_addr = ?socket.peer_addr(),
            "Established UDP connection to DNS server"
        );

        let connection = UdpConnection::new(conn_id, UdpSocket::from_std(socket)?, self.timeout);
        let arc = Arc::new(connection);

        // Spawn background task for listening responses
        tokio::spawn(UdpConnection::listen_dns_response(arc.clone()));

        Ok(arc)
    }
}
