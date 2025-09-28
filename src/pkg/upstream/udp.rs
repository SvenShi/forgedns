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
use crate::core::context::DnsContext;
use crate::pkg::upstream::{ConnectInfo, ConnectType, UpStream};
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::ProtoError;
use hickory_proto::op::{Message, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::xfer::DnsResponse;
use socket2::{Domain, Socket, Type};
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot::Sender;
use tokio::sync::{Mutex, OnceCell, oneshot, RwLock};
use tokio::time::Instant;
use tokio::time::timeout;

pub struct UdpUpstream {
    pub current_id: AtomicU16,
    pub request_map: Arc<DashMap<u16, Sender<Message>>>,
    pub connect_info: ConnectInfo,
    pub connect: OnceCell<Vec<Arc<UdpSocket>>>,
}

#[async_trait]
impl UpStream for UdpUpstream {
    async fn connect(&self) {
        let addr = SocketAddr::new(
            IpAddr::from_str(&self.connect_info.addr).unwrap(),
            self.connect_info.port,
        );
        let mut sockets = Vec::new();
        for _ in 0..20 {
            let udp_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            udp_socket.connect(addr).await.unwrap();
            let arc = Arc::new(udp_socket);
            let connect = arc.clone();
            let request_map = self.request_map.clone();
            sockets.push(arc);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (len, _) = match connect.recv_from(&mut buf).await {
                        Ok(res) => res,
                        Err(e) => {
                            eprintln!("recv_from error: {:?}", e);
                            continue;
                        }
                    };
                    if let Ok(msg) = Message::from_bytes(&buf[..len]) {
                        let id = msg.header().id();
                        let sender = request_map.remove(&id).unwrap().1;
                        sender.send(msg).unwrap();
                    }
                }
            });
        }

        self.connect.set(sockets).expect("set error");
    }

    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError> {
        let mut query_msg = Message::query();
        let info = &context.request_info;
        let mut query = Query::query(info.query.name().into(), info.query.query_type().clone());
        query.set_query_class(info.query.query_class().clone());
        query_msg.add_query(query);
        let mut header = info.header.clone();
        let query_id = self.current_id.fetch_add(1, Ordering::Relaxed);
        header.set_id(query_id);
        query_msg.set_header(header);
        let vec = query_msg.to_bytes().unwrap();
        // let instant = Instant::now();
        let index = (query_id % 20) as usize;
        let connect = self.connect.get().unwrap().get(index).unwrap();
        connect.send(vec.as_slice()).await?;
        let (tx, rx) = oneshot::channel();
        self.request_map.insert(query_msg.header().id(), tx);

        match timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(message)) => DnsResponse::from_message(message),
            Ok(Err(_canceled)) => Err(ProtoError::from("request canceled")),
            Err(_elapsed) => {
                // 超时，清理 request_map 里的 key
                self.request_map.remove(&query_id);
                Err(ProtoError::from("dns query timeout"))
            }
        }
    }

    fn connect_type(&self) -> ConnectType {
        todo!()
    }
}

pub struct LazyUpdConnectPool {
    remote_addr: SocketAddr,
    bind_addr: SocketAddr,
    index: u16,
    size: u16,
    max_size: u16,
    connections: Vec<UdpConnection>,
}

pub struct UdpConnection {
    use_count: Arc<AtomicU16>,
    socket: UdpSocket,
    last_use: Instant,
}

impl LazyUpdConnectPool {
    pub fn new(
        max_pool_size: u16,
        bind_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Arc<RwLock<Self>> {
        let pool = Self {
            index: 0,
            size: 0,
            bind_addr,
            remote_addr,
            max_size: max_pool_size,
            connections: Vec::new(),
        };

        let pool = Arc::new(RwLock::new(pool));
        let arc_pool = pool.clone();
        tokio::spawn(async move {
            let read_guard = arc_pool.read().await;

        });

        pool.clone()
    }

    pub fn get(&mut self) -> &UdpConnection {
        if self.size == 0 {
            self.try_expand();
        }
        todo!()
    }
    fn try_expand(&mut self) {
        if self.size >= self.max_size {
            return;
        }
        let socket = connect_udp_socket(self.bind_addr, self.remote_addr).unwrap();
        let connection = UdpConnection::from(socket);
        self.size += 1;
        self.connections.push(connection);
    }
}

impl UdpConnection {
    pub fn from(socket: UdpSocket) -> Self {
        Self {
            use_count: Arc::new(AtomicU16::new(0)),
            socket,
            last_use: Instant::now(),
        }
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
