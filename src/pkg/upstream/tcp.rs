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
use hickory_proto::ProtoError;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::xfer::DnsResponse;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, RwLock, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn, error};

/// Represents a single persistent TCP DNS connection
#[derive(Debug)]
pub struct TcpConnection {
    /// TCP writer half, protected by RwLock to allow concurrent reads
    writer: RwLock<OwnedWriteHalf>,
    /// Notifies listeners when the connection is closed
    close_notify: Notify,
    /// Map of query_id -> response sender
    request_map: RequestMap,
    /// Timeout duration for a single DNS query
    timeout: Duration,
}

#[async_trait]
impl Connection for TcpConnection {
    /// Close the TCP connection and notify all waiters
    fn close(&self) {
        debug!("Closing TCP connection");
        self.close_notify.notify_waiters();
    }

    /// Sends a DNS query over TCP and waits for the response
    async fn query(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        let (tx, rx) = oneshot::channel();

        // Generate and register a unique query ID
        let query_id = self.request_map.store(tx);
        debug!("Sending TCP DNS query id={}", query_id);

        // Build DNS message
        let mut msg = Message::new(query_id, MessageType::Query, OpCode::Query);
        msg.add_query(query);

        // Encode message with TCP 2-byte length prefix
        let buf = msg.to_bytes()?;
        let buf_length = (buf.len() as u16).to_be_bytes();
        let mut msg = Vec::with_capacity(2 + buf.len());
        msg.extend_from_slice(&buf_length);
        msg.extend_from_slice(&buf);

        // Send message to upstream DNS server
        {
            let mut writer = self.writer.write().await;
            if let Err(e) = writer.write_all(msg.as_slice()).await {
                self.request_map.remove(&query_id);
                error!("Failed to send TCP DNS query: {:?}", e);
                return Err(ProtoError::from(e));
            }
        }

        // Wait for response or timeout
        match timeout(self.timeout, rx).await {
            Ok(Ok(message)) => {
                debug!("Received TCP DNS response id={}", query_id);
                Ok(DnsResponse::from_message(message)?)
            }
            Ok(Err(_)) => {
                warn!("TCP DNS query id={} canceled", query_id);
                self.request_map.remove(&query_id);
                Err(ProtoError::from("request canceled"))
            }
            Err(_) => {
                warn!("TCP DNS query id={} timed out", query_id);
                self.request_map.remove(&query_id);
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    /// Returns the number of active queries using this connection
    fn using_count(&self) -> u16 {
        self.request_map.len() as u16
    }

    /// Check if the connection is writable (usable)
    async fn available(&self) -> bool {
        self.writer.read().await.writable().await.is_ok()
    }
}

impl TcpConnection {
    /// Create a new TCP connection wrapper
    fn new(writer: OwnedWriteHalf, timeout_secs: u64) -> Self {
        Self {
            writer: RwLock::new(writer),
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Background task: continuously reads responses from the upstream DNS server
    async fn listen_dns_response(self: Arc<Self>, reader: OwnedReadHalf) {
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 4096];
        let mut data = Vec::new();

        info!("Start listening for TCP DNS responses");

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    // EOF (connection closed)
                    warn!("TCP DNS connection closed by remote, canceling all pending requests");
                    break;
                }
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);

                    // Try to parse full DNS messages from the accumulated data
                    while data.len() >= 2 {
                        let msg_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                        if data.len() < 2 + msg_len {
                            // Not enough bytes for a full message yet
                            break;
                        }

                        // Extract one full message
                        let msg_bytes = data.drain(0..2 + msg_len).collect::<Vec<_>>();
                        let msg_body = &msg_bytes[2..];

                        match Message::from_bytes(msg_body) {
                            Ok(msg) => {
                                let id = msg.header().id();
                                if let Some((_, sender)) = self.request_map.remove(&id) {
                                    let _ = sender.send(msg);
                                    debug!("Delivered TCP DNS response id={}", id);
                                } else {
                                    debug!("Discarded unmatched TCP response id={}", id);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode TCP DNS response: {:?}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("TCP DNS read error: {:?}", e);
                    break;
                }
            }
        }

        warn!("TCP DNS listener terminated");
    }
}

/// Builder for creating TCP DNS connections
#[derive(Debug)]
pub struct TcpConnectionBuilder {
    /// Upstream DNS server address
    pub remote_addr: SocketAddr,
    /// Timeout duration for queries (seconds)
    pub timeout_secs: u64,
}

impl TcpConnectionBuilder {
    pub fn new(remote_addr: SocketAddr, timeout_secs: u64) -> Self {
        Self {
            remote_addr,
            timeout_secs,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<TcpConnection> for TcpConnectionBuilder {
    /// Establish a new TCP connection to the DNS server
    async fn new_conn(&self) -> Result<Arc<TcpConnection>, ProtoError> {
        let remote = self.remote_addr;
        let timeout = self.timeout_secs;

        info!("Connecting to TCP DNS server: {:?}", remote);

        match TcpStream::connect(remote).await {
            Ok(stream) => {
                info!("Connected to TCP DNS server: {:?}", remote);
                let (reader, writer) = stream.into_split();

                let connection = TcpConnection::new(writer, timeout);
                let arc = Arc::new(connection);

                // Spawn a background task to read responses
                tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));

                Ok(arc)
            }
            Err(e) => {
                error!("Failed to connect to TCP DNS server {:?}: {:?}", remote, e);
                Err(ProtoError::from(e))
            }
        }
    }
}
