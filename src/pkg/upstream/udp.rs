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
use hickory_proto::ProtoError;
use hickory_proto::op::{Message, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::xfer::DnsResponse;
use socket2::{Domain, Socket, Type};
use std::io;
use std::io::Error;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot::Sender;
use tokio::sync::{OnceCell, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::info;

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
                64,
            ))
            .unwrap();
    }

    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError> {
        let (query_msg, query_id) = self.build_query_message(&context);
        let vec = query_msg.to_bytes().unwrap();
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
        (query_msg, query_id)
    }
}

/// 单个 UDP 连接
#[derive(Debug)]
pub struct UdpConnection {
    use_count: AtomicU16,
    socket: Arc<UdpSocket>,
    last_use: AtomicU64,
    listen_handler: OnceCell<JoinHandle<()>>,
    dropped: AtomicBool,
}

#[inline]
fn now_mono_ms() -> u64 {
    AppClock::run_millis()
}

impl UdpConnection {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            use_count: AtomicU16::new(0),
            socket,
            last_use: AtomicU64::new(now_mono_ms()),
            listen_handler: OnceCell::new(),
            dropped: AtomicBool::new(false),
        }
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

#[derive(Debug)]
pub struct UdpPool {
    remote_addr: SocketAddr,
    bind_addr: SocketAddr,
    index: AtomicUsize,                            // round-robin 指针
    connections: ArcSwap<Vec<Arc<UdpConnection>>>, // 热切换连接集合
    max_size: usize,
    max_load: u16, // 单连接最大负载
    max_idle: Duration,
    requests: Arc<DashMap<u16, Sender<Message>>>,
}

impl UdpPool {
    pub fn new(bind: SocketAddr, remote: SocketAddr, max_size: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            remote_addr: remote,
            bind_addr: bind,
            index: AtomicUsize::new(0),
            connections: ArcSwap::from_pointee(Vec::new()),
            max_size,
            max_load: 128,
            max_idle: Duration::from_secs(60),
            requests: Arc::new(DashMap::with_capacity(65535)),
        });

        // 启动维护任务
        pool.clone().start_maintenance();
        pool
    }

    pub async fn send(&self, buf: &[u8], query_id: u16) -> Result<DnsResponse, ProtoError> {
        let (tx, rx) = oneshot::channel();
        self.requests.insert(query_id, tx);
        {
            let conn = self.get().await;
            conn.send(buf).await?;
        }
        match timeout(Duration::from_secs(3), rx).await {
            Ok(Ok(message)) => DnsResponse::from_message(message),
            Ok(Err(_canceled)) => {
                self.requests.remove(&query_id);
                Err(ProtoError::from("request canceled"))
            }
            Err(_elapsed) => {
                // 超时，清理 request_map 里的 key
                self.requests.remove(&query_id);
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    /// 获取一个连接（必要时扩容）
    async fn get(&'_ self) -> ConnectionGuard<'_> {
        loop {
            let conns = self.connections.load();
            if conns.is_empty() {
                self.expand().await;
                continue; // 扩容后重新尝试
            }

            let conns = self.connections.load();
            let len = conns.len();
            let mut idx = self.index.fetch_add(1, Ordering::Relaxed) % len;

            // 如果负载过高，尝试找下一个
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

            // 如果所有连接都超量，尝试扩容后再来一轮
            self.expand().await;
        }
    }

    pub(crate) fn release(&self, connection: Arc<UdpConnection>) {
        // 释放一个连接的占用，减少计数
        let prev = connection.use_count.fetch_sub(1, Ordering::Relaxed);

        if prev == 0 {
            if connection.dropped.load(Ordering::Relaxed) {
                //  the dropped connection
                match connection.listen_handler.get() {
                    None => {}
                    Some(handler) => handler.abort(),
                }
                drop(connection);
            } else {
                connection.use_count.store(0, Ordering::Relaxed);
                // update last_use time
                connection.touch();
            }
        } else {
            // update last_use time
            connection.touch();
        }
    }

    /// 扩容一个连接
    pub async fn expand(&self) {
        let conns = self.connections.load().clone();
        if conns.len() >= self.max_size {
            return;
        }

        let socket = connect_udp_socket(self.bind_addr, self.remote_addr).unwrap();
        let arc = Arc::new(socket);
        let inner_socket = arc.clone();
        let connection = UdpConnection::new(arc);
        let conn = Arc::new(connection);
        let requests = self.requests.clone();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (len, _) = match inner_socket.recv_from(&mut buf).await {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("recv_from error: {:?}", e);
                        continue;
                    }
                };

                if let Ok(msg) = Message::from_bytes(&buf[..len]) {
                    let id = msg.header().id();
                    let sender = requests.remove(&id).unwrap().1;
                    sender.send(msg).unwrap();
                }
            }
        });

        conn.listen_handler.set(handle).unwrap();

        let conns = self.connections.load().clone();
        let mut new_vec = (*conns).clone();
        new_vec.push(conn);
        self.connections.store(Arc::new(new_vec));
        info!("连接池扩容 现有连接数：{}", self.connections.load().len());
    }

    /// 定时清理长时间空闲的连接
    fn start_maintenance(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                let now = now_mono_ms();
                let conns = self.connections.load();
                let mut new_vec = Vec::new();
                let mut drop_vec = Vec::new();

                for conn in conns.iter() {
                    let last_use = conn.last_use.load(Ordering::Relaxed);
                    let idle = now - last_use;
                    if idle < self.max_idle.as_millis() as u64 {
                        new_vec.push(conn.clone());
                    } else {
                        drop_vec.push(conn.clone());
                    }
                }
                // switch and stop
                self.connections.store(Arc::new(new_vec));

                for conn in &drop_vec {
                    conn.dropped.store(true, Ordering::SeqCst);
                }
                info!(
                    "连接池过期连接扫描 本次丢弃连接数：{}, 现有连接数：{}",
                    drop_vec.len(),
                    self.connections.load().len()
                );
            }
        });
    }
}

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
    UdpSocket::from_std(sock.into())
}

#[cfg(test)]
mod test {
    use crate::pkg::upstream::{UpStreamBuilder, UpStreamConfig};

    #[tokio::test]
    async fn tcp_connect_test() {
        let stream_config = UpStreamConfig {
            addr: "tcp://223.5.5.5".to_string(),
            port: Some(53),
            socks5: None,
            bootstrap: None,
            dial_addr: None,
            insecure_skip_verify: None,
        };
        let upstream = UpStreamBuilder::with_upstream_config(&stream_config);
        upstream.connect().await;
        println!("connect success");
    }
}
