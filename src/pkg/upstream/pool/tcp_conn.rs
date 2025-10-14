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
use bytes::{BufMut, Bytes, BytesMut};
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::DnsResponse;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Represents a single persistent TCP DNS connection
#[derive(Debug)]
pub struct TcpConnection {
    id: u16,
    /// TCP writer half, protected by RwLock to allow concurrent reads
    sender: UnboundedSender<Bytes>,
    /// Notifies listeners when the connection is closed
    close_notify: Notify,
    /// Map of query_id -> response sender
    request_map: RequestMap,
    /// Timeout duration for a single DNS query
    timeout: Duration,
    /// connection close mark
    closed: AtomicBool,

    writeable: AtomicBool,

    last_used: AtomicU64,
}

#[async_trait]
impl Connection for TcpConnection {
    /// Close the TCP connection and notify all waiters
    fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return; // already closed
        }

        self.close_notify.notify_waiters();
    }

    /// Sends a DNS query over TCP and waits for the response
    async fn query(&self, mut request: Message) -> Result<DnsResponse, ProtoError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(ProtoError::from(format!(
                "Connection id {} TCP connection closed",
                self.id
            )));
        }

        let (tx, rx) = oneshot::channel();

        // Generate and register a unique query ID
        let query_id = self.request_map.store(tx);
        debug!(
            "Connection id {} Sending TCP DNS query id={}, current requests count {}",
            self.id,
            query_id,
            self.using_count()
        );

        // Build DNS message
        let raw_id = request.id();
        request.set_id(query_id);
        // Encode message with TCP 2-byte length prefix
        let buf = request.to_bytes()?;
        let mut bytes_mut = BytesMut::with_capacity(2 + buf.len());
        bytes_mut.put_u16(buf.len() as u16);
        bytes_mut.put_slice(&buf);
        if let Err(e) = self.sender.send(bytes_mut.freeze()) {
            self.request_map.take(query_id);
            error!(
                "Connection id {} Failed to send TCP DNS query: {:?}",
                self.id, e
            );
            return Err(ProtoError::from(e.to_string()));
        }

        // Wait for response or timeout
        match timeout(self.timeout, rx).await {
            Ok(Ok(mut res)) => {
                res.set_id(raw_id);
                Ok(res)
            }
            Ok(Err(_)) => {
                self.request_map.take(query_id);
                Err(ProtoError::from(format!(
                    "Connection id {} request canceled",
                    self.id
                )))
            }
            Err(_) => {
                self.request_map.take(query_id);
                Err(ProtoError::from(format!(
                    "Connection id {} DNS query timeout",
                    self.id
                )))
            }
        }
    }

    /// Returns the number of active queries using this connection
    fn using_count(&self) -> u16 {
        self.request_map.size()
    }

    /// Check if the connection is writable (usable)
    fn available(&self) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            false
        } else {
            self.writeable.load(Ordering::Relaxed)
        }
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl TcpConnection {
    /// Create a new TCP connection wrapper
    fn new(conn_id: u16, sender: UnboundedSender<Bytes>, timeout: Duration) -> Self {
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

    async fn send_dns_request(
        self: Arc<Self>,
        mut writer: OwnedWriteHalf,
        mut receiver: UnboundedReceiver<Bytes>,
    ) {
        let mut closing = false;

        while !closing {
            select! {
                res = receiver.recv() => {
                    if let Some(res) = res {
                        if let Err(e) = writer.write_all(res.as_ref()).await {
                            error!("Write error: {:?}", e);
                            self.writeable.store(false, Ordering::Relaxed);
                            self.close();
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                   let _ = writer.shutdown().await;
                    closing = true;
                }
            }
        }
    }

    /// Background task: continuously reads responses from the upstream DNS server
    async fn listen_dns_response(self: Arc<Self>, reader: OwnedReadHalf) {
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 16384];
        let mut start = 0;

        let mut closing = false;
        loop {
            if closing && self.request_map.is_empty() {
                debug!(
                    "Connection id {} TCP connection listener exiting due to drop",
                    self.id
                );
                break;
            }
            if self.closed.load(Ordering::Relaxed) {
                debug!("Connection id {} TCP connection closed", self.id);
                break;
            }

            select! {
                res = reader.read(&mut buf[start..]) => {
                    match res {
                        Ok(0) => {
                            // EOF (connection closed)
                            warn!("Connection id {} TCP DNS connection closed by remote", self.id);
                            self.close();
                            break;
                        }
                        Ok(n) => {
                            let total = start + n;
                            let mut offset = 0;

                            while total - offset >= 2 {
                                   let msg_len = u16::from_be_bytes([buf[offset], buf[offset+1]]) as usize;
                                   if total - offset < 2 + msg_len { break; }

                                   let msg_body = &buf[offset+2..offset+2+msg_len];
                                match DnsResponse::from_buffer(Vec::from(msg_body)) {
                                    Ok(msg) => {
                                        let id = msg.header().id();
                                        if let Some(sender) = self.request_map.take(id) {
                                            let _ =  sender.send(msg);
                                            self.last_used
                                                .store(AppClock::run_millis(), Ordering::Relaxed);
                                        } else {
                                            debug!("Connection id {} Discarded unmatched TCP response id={}",self.id, id);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Connection id {} Failed to decode TCP DNS response: {:?}", self.id,e);
                                    }
                                }
                                   offset += 2 + msg_len;
                               }
                            start = total - offset;
                            buf.copy_within(offset..total, 0);
                        }
                        Err(e) => {
                            error!("Connection id {} TCP DNS read error: {:?}", self.id,e);
                            self.close();
                            break;
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

        warn!("Connection id {} TCP DNS listener terminated", self.id);
    }
}

/// Builder for creating TCP DNS connections
#[derive(Debug)]
pub struct TcpConnectionBuilder {
    /// Upstream DNS server address
    pub remote_addr: SocketAddr,
    /// Timeout duration for queries (seconds)
    pub timeout: Duration,
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
        }
    }
}

#[async_trait]
impl ConnectionBuilder<TcpConnection> for TcpConnectionBuilder {
    /// Establish a new TCP connection to the DNS server
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<TcpConnection>, ProtoError> {
        let remote = self.remote_addr;

        match TcpStream::connect(remote).await {
            Ok(stream) => {
                if let Err(e) = stream.set_nodelay(true) {
                    warn!(
                        "Connection id {} Failed to set TCP nodelay, reason: {e}",
                        conn_id
                    );
                }
                debug!(
                    "Connection id {} Connected to TCP DNS server: {:?}, Local addr: {:?}",
                    conn_id,
                    stream.peer_addr()?,
                    stream.local_addr()?
                );
                let (reader, writer) = stream.into_split();
                let (sender, receiver) = unbounded_channel();

                let connection = TcpConnection::new(conn_id, sender, self.timeout);
                let arc = Arc::new(connection);

                // Spawn a background task to read responses
                tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
                tokio::spawn(TcpConnection::send_dns_request(
                    arc.clone(),
                    writer,
                    receiver,
                ));

                Ok(arc)
            }
            Err(e) => {
                error!(
                    "Connection id {} Failed to connect to TCP DNS server {:?}: {:?}",
                    conn_id, remote, e
                );
                Err(ProtoError::from(e))
            }
        }
    }
}
