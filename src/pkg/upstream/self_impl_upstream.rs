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
use crate::pkg::upstream::upstream::{ConnectInfo, ConnectType, UpStream};
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::{Message, Query};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::future::err;
use hickory_proto::ProtoError;
use hickory_proto::xfer::DnsResponse;
use tokio::net::UdpSocket;
use tokio::sync::oneshot::Sender;
use tokio::sync::{oneshot, OnceCell};
use tokio::time::timeout;
use tracing::error;
use tracing::log::info;

pub(crate) struct SelfImplUpstream {
    pub(crate) current_id: AtomicU16,
    pub(crate) request_map: Arc<DashMap<u16, Sender<Message>>>,
    pub(crate) connect_info: ConnectInfo,
    pub(crate) connect: OnceCell<Vec<Arc<UdpSocket>>>,
}

#[async_trait]
impl UpStream for SelfImplUpstream {
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
                let mut buf = [0u8; 4096];
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
                Err(ProtoError::from("request canceled"))
            },
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

pub(crate) struct DnsConnect {
    udp_socket: UdpSocket,
}

impl DnsConnect {}
