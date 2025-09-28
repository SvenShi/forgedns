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
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::{Message, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use socket2::{Domain, Socket, Type};
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot::Sender;
use tokio::sync::{oneshot, OnceCell};
use tokio::time::{timeout, Instant};

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
            Ok(Err(_canceled)) => {
                self.request_map.remove(&query_id);
                Err(ProtoError::from("request canceled"))
            }
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

/// 单个 UDP 连接
pub struct UdpConnection {
    pub use_count: AtomicU16,
    pub socket: Arc<UdpSocket>,
    pub last_use: parking_lot::Mutex<Instant>, // 更新 last_use
}

impl UdpConnection {
    fn new(socket: UdpSocket) -> Self {
        Self {
            use_count: AtomicU16::new(0),
            socket: Arc::new(socket),
            last_use: parking_lot::Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        *self.last_use.lock() = Instant::now();
    }
}


pub struct UdpPool {
    remote_addr: SocketAddr,
    bind_addr: SocketAddr,
    index: AtomicUsize,                     // round-robin 指针
    connections: ArcSwap<Vec<Arc<UdpConnection>>>, // 热切换连接集合
    max_size: usize,
    min_size: usize,
    max_load: u16, // 单连接最大负载
    max_idle: Duration,
}

impl UdpPool {
    pub fn new(bind: SocketAddr, remote: SocketAddr, min_size: usize, max_size: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
                  remote_addr: remote,
                  bind_addr: bind,
                  index: AtomicUsize::new(0),
                  connections: ArcSwap::from_pointee(Vec::new()),
                  max_size,
                  min_size,
                  max_load: 4096,
                  max_idle: Duration::from_secs(60),
              });

              // 启动维护任务
              pool.clone().start_maintenance();
              pool
    }


    /// 获取一个连接（必要时扩容）
      pub async fn get(&self) -> Arc<UdpConnection> {
          let conns = self.connections.load();
          if conns.is_empty() {
              self.expand().await;
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
                  return conn.clone();
              }
              idx = (idx + 1) % len;
          }

          // 如果所有连接都超量，尝试扩容
          self.expand().await;
          self.get().await
      }

    /// 扩容一个连接
     pub async fn expand(&self) {
         let conns = self.connections.load().clone();
         if conns.len() >= self.max_size {
             return;
         }

         let socket = UdpSocket::bind(self.bind_addr).await.unwrap();
         socket.connect(self.remote_addr).await.unwrap();
         let conn = Arc::new(UdpConnection::new(socket));

         let mut new_vec = (*conns).clone();
         new_vec.push(conn);
         self.connections.store(Arc::new(new_vec));
     }

     /// 定时清理长时间空闲的连接
     fn start_maintenance(self: Arc<Self>) {
         tokio::spawn(async move {
             loop {
                 tokio::time::sleep(Duration::from_secs(30)).await;

                 let now = Instant::now();
                 let conns = self.connections.load();
                 let mut new_vec = Vec::new();

                 for conn in conns.iter() {
                     let idle = now.duration_since(*conn.last_use.lock());
                     if idle < self.max_idle {
                         new_vec.push(conn.clone());
                     }
                 }

                 // 保留至少 min_size 个
                 while new_vec.len() < self.min_size {
                     if let Ok(socket) = UdpSocket::bind(self.bind_addr).await {
                         if socket.connect(self.remote_addr).await.is_ok() {
                             new_vec.push(Arc::new(UdpConnection::new(socket)));
                         }
                     }
                 }

                 self.connections.store(Arc::new(new_vec));
             }
         });
     }
}

pub struct ConnectionGuard<'a> {
    connection: &'a UdpConnection,
}

const LOAD_FACTOR: u16 = (4096f64 / 0.75) as u16;

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
