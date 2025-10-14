/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
use tracing::{debug, error, warn};

/// A single UDP connection in the pool
#[derive(Debug)]
pub struct UdpConnection {
    id: u16,
    /// Underlying UDP socket
    socket: UdpSocket,
    /// Notify waiters when the connection is closed
    close_notify: Notify,
    /// Mapping of query ID -> response channel sender
    request_map: RequestMap,
    /// Query timeout in seconds
    timeout: Duration,
    /// Last using time
    last_used: AtomicU64,
}

const RETRY_TIMEOUT: Duration = Duration::from_secs(1);

#[async_trait]
impl Connection for UdpConnection {
    fn close(&self) {
        debug!("Closing UDP connection");
        self.close_notify.notify_waiters();
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        let raw_id = request.id();

        let mut _timeout = RETRY_TIMEOUT;
        for _ in 0..2 {
            let (tx, rx) = oneshot::channel();
            let query_id = self.request_map.store(tx);
            request.set_id(query_id);
            let msg = request.to_bytes()?;
            match self.socket.send(msg.as_slice()).await {
                Ok(_sent) => {}
                Err(e) => {
                    self.request_map.take(query_id);
                    return Err(ProtoError::from(e));
                }
            };
            // first will retry timeout
            match timeout(_timeout, rx).await {
                Ok(Ok(mut response)) => {
                    response.set_id(raw_id);
                    return Ok(response);
                }
                Ok(Err(_canceled)) => {
                    self.request_map.take(query_id);
                    return Err(ProtoError::from("request canceled"));
                }
                Err(_elapsed) => {
                    self.request_map.take(query_id);
                }
            }
            _timeout = self.timeout;
        }
        Err(ProtoError::from("dns query timeout"))
    }

    fn using_count(&self) -> u16 {
        self.request_map.size()
    }

    fn available(&self) -> bool {
        true
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl UdpConnection {
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
    /// Listen for DNS responses from the remote server
    async fn listen_dns_response(self: Arc<Self>) {
        let mut buf = [0u8; 4096];
        let mut closing = false;
        loop {
            if closing && self.request_map.is_empty() {
                debug!("UDP connection listener exiting due to drop");
                break;
            }

            select! {
                res = self.socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, _)) => {
                            if let Ok(msg) = DnsResponse::from_buffer(Vec::from(&buf[..len])) {
                                let id = msg.header().id();
                                if let Some(sender) = self.request_map.take(id) {
                                    let _ = sender.send(msg);
                                    self.last_used
                                        .store(AppClock::run_millis(), Ordering::Relaxed);
                                } else {
                                    debug!("Discarded unmatched DNS response id={}", id);
                                }
                            } else {
                                warn!("Failed to parse DNS response");
                            }
                        },
                        Err(e) => {
                            error!("recv_from error: {:?}", e);
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    // back to the loop, recheck dropped flag
                    closing = true;
                    continue;
                }
            }
        }
    }
}
#[derive(Debug)]
pub struct UdpConnectionBuilder {
    /// Local bind address for UDP sockets
    bind_addr: SocketAddr,
    /// Upstream DNS server address
    remote_addr: SocketAddr,
    /// Query timeout in seconds
    timeout: Duration,
}

impl UdpConnectionBuilder {
    pub fn new(connect_info: &ConnectInfo) -> Self {
        Self {
            bind_addr: connect_info
                .bind_addr
                .parse()
                .expect("Invalid bind address"),
            remote_addr: SocketAddr::new(
                connect_info
                    .remote_addr
                    .parse()
                    .expect("Invalid remote address"),
                connect_info.port,
            ),
            timeout: connect_info.timeout,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<UdpConnection> for UdpConnectionBuilder {
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<UdpConnection>, ProtoError> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        socket.connect(self.remote_addr).await?;
        let connection = UdpConnection::new(conn_id, socket, self.timeout);
        let arc = Arc::new(connection);
        tokio::spawn(UdpConnection::listen_dns_response(arc.clone()));
        Ok(arc)
    }
}
