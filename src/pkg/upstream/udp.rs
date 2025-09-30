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
use crate::core::context::DnsContext;
use crate::pkg::upstream::{ConnectInfo, ConnectType, UpStream};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::{Message, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use socket2::{Domain, Socket, Type};
use std::io;
use std::io::Error;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::oneshot::Sender;
use tokio::sync::{oneshot, Notify, OnceCell};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// UDP-based upstream resolver implementation
pub struct UdpUpstream {
    pub current_id: AtomicU16,
    pub connect_info: ConnectInfo,
    pub pool: OnceCell<Arc<UdpPool>>,
}

#[async_trait]
impl UpStream for UdpUpstream {
    async fn connect(&self) {
        let addr = SocketAddr::new(
            IpAddr::from_str(&self.connect_info.addr).unwrap(),
            self.connect_info.port,
        );
        self.pool
            .set(UdpPool::new(
                SocketAddrV4::from_str("0.0.0.0:0").unwrap().into(),
                addr,
                1,
                64,
                3,
            ))
            .unwrap();
        info!("UdpUpstream connected to {}", addr);
    }

    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError> {
        let (query_msg, query_id) = self.build_query_message(&context);
        let vec = query_msg.to_bytes().unwrap();
        debug!("Sending DNS query with id={}", query_id);
        self.pool
            .get()
            .unwrap()
            .send(vec.as_slice(), query_id)
            .await
    }

    fn connect_type(&self) -> ConnectType {
        ConnectType::UDP
    }
}

impl UdpUpstream {
    /// Build a DNS query message and assign a unique ID that is not in use
    fn build_query_message(&self, context: &&mut DnsContext) -> (Message, u16) {
        let mut query_msg = Message::query();
        let info = &context.request_info;
        let mut query = Query::query(info.query.name().into(), info.query.query_type().clone());
        query.set_query_class(info.query.query_class().clone());
        query_msg.add_query(query);

        let mut header = info.header.clone();
        let query_id = loop {
            let id = self
                .current_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                    Some(id.wrapping_add(1))
                })
                .unwrap();

            if !self.pool.get().unwrap().requests.contains_key(&id) {
                break id;
            }
        };
        header.set_id(query_id);
        query_msg.set_header(header);

        debug!("Built DNS query message with id={}", query_id);
        (query_msg, query_id)
    }
}

/// A single UDP connection in the pool
#[derive(Debug)]
pub struct UdpConnection {
    use_count: Arc<AtomicU16>,
    socket: Arc<UdpSocket>,
    last_use: AtomicU64,
    dropped: AtomicBool,
    close_notify: Notify,
}

#[inline]
fn now_mono_ms() -> u64 {
    AppClock::run_millis()
}

impl UdpConnection {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            use_count: Arc::new(AtomicU16::new(0)),
            socket,
            last_use: AtomicU64::new(now_mono_ms()),
            dropped: AtomicBool::new(false),
            close_notify: Notify::new(),
        }
    }

    /// Mark this connection as closed and notify listeners
    pub fn close(&self) {
        if self.dropped.swap(true, Ordering::SeqCst) {
            return;
        }
        debug!("Closing UDP connection");
        self.close_notify.notify_waiters();
    }

    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf).await
    }

    #[inline]
    fn touch(&self) {
        self.last_use.store(now_mono_ms(), Ordering::Relaxed);
    }
}

/// A pool of UDP connections used for DNS queries
#[derive(Debug)]
pub struct UdpPool {
    remote_addr: SocketAddr,
    bind_addr: SocketAddr,
    index: AtomicUsize,
    connections: ArcSwap<Vec<Arc<UdpConnection>>>,
    max_size: usize,
    min_size: usize,
    max_load: u16,
    max_idle: Duration,
    requests: Arc<DashMap<u16, Sender<Message>>>,
    time_out_secs: u64,
}

impl UdpPool {
    pub fn new(
        bind: SocketAddr,
        remote: SocketAddr,
        min_size: usize,
        max_size: usize,
        time_out_secs: u64,
    ) -> Arc<Self> {
        info!(
            "Initializing UDP connection pool: bind={:?}, remote={:?}, min_size={}, max_size={}",
            &bind, &remote, min_size, max_size
        );
        let pool = Arc::new(Self {
            remote_addr: remote,
            bind_addr: bind,
            index: AtomicUsize::new(0),
            connections: ArcSwap::from_pointee(Vec::new()),
            max_size,
            min_size,
            time_out_secs,
            max_load: 64,
            max_idle: Duration::from_secs(60),
            requests: Arc::new(DashMap::with_capacity(65535)),
        });

        pool.clone().start_maintenance();

        if min_size > 0 {
            let arc = pool.clone();
            tokio::spawn(async move {
                arc.expand().await;
            });
        }
        pool
    }

    /// Send DNS request and wait for the response or timeout
    pub async fn send(&self, buf: &[u8], query_id: u16) -> Result<DnsResponse, ProtoError> {
        let (tx, rx) = oneshot::channel();
        self.requests.insert(query_id, tx);

        {
            let conn = self.get().await;
            conn.send(buf).await?;
        }

        match timeout(Duration::from_secs(self.time_out_secs), rx).await {
            Ok(Ok(message)) => {
                debug!("Received DNS response for id={}", query_id);
                DnsResponse::from_message(message)
            }
            Ok(Err(_canceled)) => {
                self.requests.remove(&query_id);
                warn!("DNS request canceled, id={}", query_id);
                Err(ProtoError::from("request canceled"))
            }
            Err(_elapsed) => {
                self.requests.remove(&query_id);
                warn!("DNS query timeout, id={}", query_id);
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    /// Get a connection from the pool with load balancing
    async fn get(&'_ self) -> ConnectionGuard<'_> {
        loop {
            let conns = self.connections.load();
            let len = conns.len();

            if len == 0 {
                warn!("No available UDP connections, expanding pool...");
                self.expand().await;
                continue;
            }

            let mut idx = self.index.fetch_add(1, Ordering::Relaxed) % len;

            for _ in 0..len {
                let conn = &conns[idx];
                if conn.use_count.load(Ordering::Relaxed) < self.max_load {
                    conn.use_count.fetch_add(1, Ordering::Relaxed);
                    conn.touch();
                    return ConnectionGuard {
                        connection: conn.clone(),
                        pool: self,
                    };
                }
                idx = (idx + 1) % len;
            }

            warn!("All UDP connections overloaded, attempting to expand pool...");
            self.expand().await;
        }
    }

    /// Release a connection back to the pool
    pub(crate) fn release(&self, connection: Arc<UdpConnection>) {
        if connection.use_count.load(Ordering::Acquire) == 0
            && connection.dropped.load(Ordering::Acquire)
        {
            connection.close();
            return;
        }
        connection.touch();
    }

    /// Expand the pool by creating new UDP connections
    pub async fn expand(&self) {
        let conns_len = self.connections.load().len();
        if conns_len >= self.max_size {
            debug!("Connection pool already at max size");
            return;
        }

        let new_conns_count = if conns_len >= self.min_size {
            1
        } else {
            self.min_size - conns_len
        };

        debug!(
            "Expanding connection pool by {} connections",
            new_conns_count
        );
        let mut new_conns = Vec::with_capacity(new_conns_count);

        for _ in 0..new_conns_count {
            let socket = connect_udp_socket(self.bind_addr, self.remote_addr).unwrap();
            let socket = Arc::new(socket);
            let inner_socket = socket.clone();
            let connection = UdpConnection::new(socket);
            let conn = Arc::new(connection);
            tokio::spawn(Self::listen_dns_response(
                inner_socket,
                self.requests.clone(),
                conn.clone(),
            ));
            new_conns.push(conn);
        }

        loop {
            let conns = self.connections.load().clone();
            let mut new_vec = (*conns).clone();
            new_vec.append(&mut new_conns);
            let new_len = new_vec.len();
            if Arc::ptr_eq(
                &conns,
                &self.connections.compare_and_swap(&conns, Arc::new(new_vec)),
            ) {
                info!("UDP connections pool expanded, new total: {}", new_len);
                break;
            }
        }
    }

    /// Listen for DNS responses from the remote server
    async fn listen_dns_response(
        inner_socket: Arc<UdpSocket>,
        requests: Arc<DashMap<u16, Sender<Message>>>,
        inner_conn: Arc<UdpConnection>,
    ) {
        let mut buf = [0u8; 4096];
        loop {
            if inner_conn.dropped.load(Ordering::Relaxed)
                && inner_conn.use_count.load(Ordering::Relaxed) == 0
            {
                debug!("UDP connection listener exiting due to drop");
                break;
            }

            select! {
                res = inner_socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, _)) => {
                            if let Ok(msg) = Message::from_bytes(&buf[..len]) {
                                let id = msg.header().id();
                                if let Some((_, sender)) = requests.remove(&id) {
                                    let _ = sender.send(msg);
                                    inner_conn.use_count.fetch_sub(1, Ordering::AcqRel);
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
                _ = inner_conn.close_notify.notified() => {
                  // back to the loop, recheck dropped flag
                  continue;
                }
            }
        }
    }

    /// Periodically remove idle connections
    fn start_maintenance(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                let now = now_mono_ms();
                let mut new_vec = Vec::new();
                let mut drop_vec = Vec::new();
                let conns = self.connections.load();

                for conn in conns.iter() {
                    let last_use = conn.last_use.load(Ordering::Relaxed);
                    let idle = now - last_use;
                    if idle < self.max_idle.as_millis() as u64 {
                        new_vec.push(conn.clone());
                    } else {
                        drop_vec.push(conn.clone());
                    }
                }

                while new_vec.len() < self.min_size {
                    if !drop_vec.is_empty() {
                        new_vec.push(drop_vec.pop().unwrap());
                    } else {
                        break;
                    }
                }

                let new_len = new_vec.len();

                if !Arc::ptr_eq(
                    &conns,
                    &self.connections.compare_and_swap(&conns, Arc::new(new_vec)),
                ) {
                    break;
                }

                drop_vec.iter().for_each(|conn| conn.close());

                info!(
                    "UDP connection pool maintenance: dropped {} idle connections, active={}",
                    drop_vec.len(),
                    new_len
                );
            }
        });
    }
}

/// Guard object for a borrowed UDP connection
pub struct ConnectionGuard<'a> {
    connection: Arc<UdpConnection>,
    pool: &'a UdpPool,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.pool.release(self.connection.clone());
    }
}

impl<'a> Deref for ConnectionGuard<'a> {
    type Target = UdpConnection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

/// Create and bind a new UDP socket
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
