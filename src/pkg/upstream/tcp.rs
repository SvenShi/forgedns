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
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Represents a single TCP DNS connection
#[derive(Debug)]
pub struct TcpConnection {
    /// The underlying TCP stream
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
    /// Notify listeners when closed
    close_notify: Notify,
    /// Mapping query_id -> response sender
    request_map: RequestMap,
    /// Query timeout (seconds)
    timeout_secs: u64,
}

#[async_trait]
impl Connection for TcpConnection {
    fn close(&self) {
        debug!("Closing TCP connection");
        self.close_notify.notify_waiters();
    }

    async fn query(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        let (tx, rx) = oneshot::channel();

        // Generate unique query ID
        let query_id = self.request_map.store(tx);

        let mut msg = Message::new(query_id, MessageType::Query, OpCode::Query);
        msg.add_query(query);

        // Encode DNS message with TCP length prefix
        let buf = msg.to_bytes()?;
        let buf_length = (buf.len() as u16).to_be_bytes();
        let mut msg = Vec::with_capacity(2 + buf.len());
        msg.extend_from_slice(&buf_length);
        msg.extend_from_slice(&buf);

        {
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(msg.as_slice()).await {
                self.request_map.remove(&query_id);
                return Err(ProtoError::from(e));
            }
        }

        // Wait for response or timeout
        match timeout(Duration::from_secs(self.timeout_secs), rx).await {
            Ok(Ok(message)) => {
                debug!("Received TCP DNS response id={}", query_id);
                Ok(DnsResponse::from_message(message).unwrap())
            }
            Ok(Err(_)) => {
                self.request_map.remove(&query_id);
                Err(ProtoError::from("request canceled"))
            }
            Err(_) => {
                self.request_map.remove(&query_id);
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    fn using_count(&self) -> u16 {
        self.request_map.len() as u16
    }
}

impl TcpConnection {
    fn new(stream: TcpStream, timeout_secs: u64) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            close_notify: Notify::new(),
            request_map: RequestMap::new(),
            timeout_secs,
        }
    }

    /// Start listening for incoming TCP DNS responses
    async fn listen_dns_response(self: Arc<Self>) {
        let mut closing = false;
        let mut reader = self.reader.lock().await;

        loop {
            if closing && self.request_map.is_empty() {
                debug!("TCP connection listener exiting due to close");
                break;
            }

            let mut len_buf = [0u8; 2];
            select! {
                res = reader.read_exact(&mut len_buf) => {
                    if let Err(e) = res {
                        if e.kind() == ErrorKind::UnexpectedEof {
                            warn!("TCP connection closed by remote");
                            break;
                        }
                        error!("TCP read error: {:?}", e);
                        continue;
                    }

                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];

                    if let Err(e) = reader.read_exact(&mut buf).await {
                        error!("Failed to read full DNS message: {:?}", e);
                        continue;
                    }

                    match Message::from_bytes(&buf) {
                        Ok(msg) => {
                            let id = msg.header().id();
                            if let Some((_, sender)) = self.request_map.remove(&id) {
                                let _ = sender.send(msg);
                            } else {
                                debug!("Discarded unmatched TCP response id={}", id);
                            }
                        }
                        Err(e) => warn!("Failed to decode DNS response: {:?}", e),
                    }
                },
                _ = self.close_notify.notified() => {
                    closing = true;
                    continue;
                }
            }
        }
    }
}

/// Builder for TcpConnection
#[derive(Debug)]
pub struct TcpConnectionBuilder {
    pub remote_addr: SocketAddr,
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
    async fn new_conn(&self) -> Result<Arc<TcpConnection>, ProtoError> {
        let remote = self.remote_addr;
        let timeout = self.timeout_secs;
        match TcpStream::connect(remote).await {
            Ok(stream) => {
                debug!("Connected to TCP DNS server: {:?}", remote);
                let connection = TcpConnection::new(stream, timeout);
                let arc = Arc::new(connection);
                tokio::spawn(TcpConnection::listen_dns_response(arc.clone()));
                Ok(arc)
            }
            Err(e) => Err(ProtoError::from(e)),
        }
    }
}
