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
use crate::pkg::upstream::pool::{Connection, ConnectionBuilder};
use crate::pkg::upstream::request_map::RequestMap;
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use socket2::{Domain, Socket, Type};
use std::fmt::Debug;
use std::io::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// A single UDP connection in the pool
#[derive(Debug)]
pub struct UdpConnection {
    /// Underlying UDP socket
    socket: UdpSocket,
    /// Notify waiters when the connection is closed
    close_notify: Notify,
    /// Mapping of query ID -> response channel sender
    request_map: RequestMap,
    /// Query timeout in seconds
    timeout_secs: u64,
}

#[async_trait]
impl Connection for UdpConnection {
    fn close(&self) {
        debug!("Closing UDP connection");
        self.close_notify.notify_waiters();
    }

    async fn query(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        let (tx, rx) = oneshot::channel();
        let query_id = self.request_map.store(tx);
        let mut query_msg = Message::new(query_id, MessageType::Query, OpCode::Query);
        query_msg.add_query(query);

        match self
            .socket
            .send(query_msg.to_bytes().unwrap().as_slice())
            .await
        {
            Ok(_sent) => {}
            Err(e) => {
                self.request_map.remove(&query_id);
                return Err(ProtoError::from(e));
            }
        };

        match timeout(Duration::from_secs(self.timeout_secs), rx).await {
            Ok(Ok(message)) => {
                debug!("Received DNS response for id={}", query_id);
                let response = DnsResponse::from_message(message)?;
                self.request_map.remove(&query_id);
                Ok(response)
            }
            Ok(Err(_canceled)) => {
                self.request_map.remove(&query_id);
                Err(ProtoError::from("request canceled"))
            }
            Err(_elapsed) => {
                self.request_map.remove(&query_id);
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    fn using_count(&self) -> u16 {
        self.request_map.len() as u16
    }
}

impl UdpConnection {
    fn new(socket: UdpSocket, timeout_secs: u64) -> UdpConnection {
        Self {
            socket,
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout_secs,
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
                            if let Ok(msg) = Message::from_bytes(&buf[..len]) {
                                let id = msg.header().id();
                                if let Some((_, sender)) = self.request_map.remove(&id) {
                                    let _ = sender.send(msg);
                                    debug!("Received valid DNS response id={}", id);
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
    timeout_secs: u64,
}

impl UdpConnectionBuilder {
    pub fn new(bind_addr: SocketAddr, remote_addr: SocketAddr, timeout_secs: u64) -> Self {
        Self {
            bind_addr,
            remote_addr,
            timeout_secs,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<UdpConnection> for UdpConnectionBuilder {
   async fn new_conn(&self) -> Result<Arc<UdpConnection>, ProtoError> {
        let socket = connect_udp_socket(self.bind_addr, self.remote_addr).unwrap();
        let connection = UdpConnection::new(socket, self.timeout_secs);
        let arc = Arc::new(connection);
        tokio::spawn(UdpConnection::listen_dns_response(arc.clone()));
        Ok(arc)
    }
}

/// Create and bind a new UDP socket
#[inline]
fn connect_udp_socket(bind_addr: SocketAddr, remote_addr: SocketAddr) -> Result<UdpSocket, Error> {
    let sock = if bind_addr.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    sock.connect(&remote_addr.into())?;
    debug!(
        "Created UDP socket bind={:?} remote={:?}",
        bind_addr, remote_addr
    );
    UdpSocket::from_std(sock.into())
}
