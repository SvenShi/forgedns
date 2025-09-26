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
use crate::config::config::PluginConfig;
use crate::core::context::{DnsContext, RequestInfo};
use crate::core::handler::DnsRequestHandler;
use crate::plugin::{Plugin, PluginFactory, PluginMainType, get_plugin};
use async_trait::async_trait;
use futures::StreamExt;
use hickory_proto::op::{LowerQuery, Message, Query, UpdateMessage};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::udp::UdpStream;
use hickory_proto::xfer::{Protocol, SerialMessage};
use hickory_proto::{BufDnsStreamHandle, DnsStreamHandle, ProtoError, ProtoErrorKind};
use serde::Deserialize;
use socket2::{Domain, Socket, Type};
use std::collections::HashMap;
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::count;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info, warn};
use url::quirks::port;

#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// server执行入口
    pub entry: String,
    /// server监听地址
    pub listen: String,
}

#[allow(unused)]
pub struct UdpServer {
    tag: String,
    entry: Arc<RwLock<Box<dyn Plugin>>>,
    listen: String,
}

#[async_trait]
impl Plugin for UdpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        let listen = self.listen.clone();
        let addr = listen.clone();
        let entry_executor = self.entry.clone();
        tokio::spawn(run_server_stream(addr, entry_executor));
        info!("UDP Server started，listen:{listen}");
    }

    async fn execute(&self, _: &mut DnsContext) {}

    fn main_type(&self) -> PluginMainType {
        PluginMainType::Executor {
            tag: self.tag.to_string(),
            type_name: "UdpServer".to_string(),
        }
    }

    async fn destroy(&mut self) {}
}

async fn run_server(addr: String, entry_executor: Arc<RwLock<Box<dyn Plugin>>>) {
    let bind = UdpSocket::bind(addr);
    let udp_socket = Arc::new(bind.await.unwrap());

    let udp_socket_c = udp_socket.clone();
    let mut buf = [0u8; 4096];
    loop {
        let (len, source) = match udp_socket_c.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("recv_from error: {:?}", e);
                continue;
            }
        };
        // 解析 DNS 消息
        if let Ok(mut msg) = Message::from_bytes(&buf[..len]) {
            let entry_executor = entry_executor.clone();
            let udp_socket_c = udp_socket_c.clone();
            let _ = tokio::spawn(async move {
                let mut context = DnsContext {
                    request_info: RequestInfo {
                        src: source,
                        protocol: Protocol::Udp,
                        header: msg.header().clone(),
                        query: to_query(msg.queries()).unwrap(),
                    },
                    response: None,
                    mark: Vec::new(),
                    attributes: HashMap::new(),
                };

                info!("Handling request");
                if event_enabled!(Level::DEBUG) {
                    debug!(
                        "dns:request source:{}, query:{}, queryType:{}",
                        context.request_info.src,
                        context.request_info.query.name().to_string(),
                        context.request_info.query.query_type().to_string()
                    );
                }
                {
                    // 执行程序入口执行
                    entry_executor.read().await.execute(&mut context).await;
                }

                match context.response {
                    None => {
                        warn!("No response received");
                    }
                    Some(mut res) => {
                        // if event_enabled!(Level::DEBUG) {
                        //     debug!(
                        //         "Response received: source:{}, query:{}, answer:{:?}, sourceId: {}, responseId:{}",
                        //         context.request_info.src,
                        //         context.request_info.query.name().to_string(),
                        //         res.answers()
                        //     );
                        // }
                        msg.add_answers(res.take_answers());
                        msg.add_additionals(res.take_additionals());
                    }
                }

                let message = msg.to_response();
                info!(
                    "Response received: source:{}, query:{}, sourceId: {}, responseId: {}, dst: {}",
                    context.request_info.src,
                    context.request_info.query.name().to_string(),
                    msg.header().id(),
                    message.header().id(),
                    source.to_string()
                );
                udp_socket_c
                    .send_to(message.to_bytes().unwrap().as_slice(), source)
                    .await
                    .unwrap();
            });
        }
    }
}
async fn run_server_stream(addr: String, entry_executor: Arc<RwLock<Box<dyn Plugin>>>) {
    let (mut stream, stream_handle) = UdpStream::<TokioRuntimeProvider>::with_bound(
        build_udp_socket(&addr).unwrap(),
        ([127, 255, 255, 254], 0).into(),
    );

    let mut inner_join_set = JoinSet::new();
    loop {
        let message = tokio::select! {
            message = stream.next() => match message {
                None => break,
                Some(message) => message,
            },
        };

        let message = match message {
            Err(error) => {
                warn!(%error, "error receiving message on udp_socket");

                continue;
            }
            Ok(message) => message,
        };

        let src_addr = message.addr();
        debug!("received udp request from: {}", src_addr);

        let stream_handle = stream_handle.with_remote_addr(src_addr);
        let entry = entry_executor.clone();
        inner_join_set.spawn(async move {
            handle_raw_request(message, Protocol::Udp, stream_handle, entry).await;
        });

        reap_tasks(&mut inner_join_set);
    }
}

async fn handle_raw_request(
    message: SerialMessage,
    protocol: Protocol,
    mut response_handler: BufDnsStreamHandle,
    entry_executor: Arc<RwLock<Box<dyn Plugin>>>,
) {
    let (message, src_addr) = message.into_parts();

    // 解析 DNS 消息
    if let Ok(mut msg) = Message::from_bytes(message.as_slice()) {
        let _ = tokio::spawn(async move {
            let mut context = DnsContext {
                request_info: RequestInfo {
                    src: src_addr,
                    protocol: protocol,
                    header: msg.header().clone(),
                    query: to_query(msg.queries()).unwrap(),
                },
                response: None,
                mark: Vec::new(),
                attributes: HashMap::new(),
            };

            // info!("Handling request");
            if event_enabled!(Level::DEBUG) {
                debug!(
                    "dns:request source:{}, query:{}, queryType:{}",
                    context.request_info.src,
                    context.request_info.query.name().to_string(),
                    context.request_info.query.query_type().to_string()
                );
            }
            {
                // 执行程序入口执行
                entry_executor.read().await.execute(&mut context).await;
            }

            match context.response {
                None => {
                    warn!("No response received");
                }
                Some(mut res) => {
                    msg.add_answers(res.take_answers());
                    msg.add_additionals(res.take_additionals());
                }
            }

            let message = msg.to_response();
            // info!(
            //     "Response received: source:{}, query:{}, sourceId: {}, responseId: {}, dst: {}",
            //     context.request_info.src,
            //     context.request_info.query.name().to_string(),
            //     msg.header().id(),
            //     message.header().id(),
            //     src_addr.to_string()
            // );
            response_handler
                .send(SerialMessage::new(message.to_bytes().unwrap(), src_addr))
                .unwrap();
        });
    }
}

fn reap_tasks(join_set: &mut JoinSet<()>) {
    while join_set.try_join_next().is_some() {}
}
fn build_udp_socket(addr: &str) -> Result<UdpSocket, Error> {
    let addr = SocketAddr::from_str(addr).unwrap();

    let sock = if addr.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    sock.bind(&addr.into())?;

    UdpSocket::from_std(sock.into())
}

fn to_query(queries: &[Query]) -> Result<LowerQuery, ProtoError> {
    let i = queries.len();
    if i == 1 {
        Ok(queries[0].clone().into())
    } else {
        Err(ProtoErrorKind::BadQueryCount(i).into())
    }
}

pub struct UdpServerFactory {}

#[async_trait]
impl PluginFactory for UdpServerFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let udp_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<UdpServerConfig>(args)
                .unwrap_or_else(|e| panic!("UDP Server init failed, config error. Error:{}", e)),
            None => {
                panic!("UDP Server must set 'listen' and 'entry' in config file.)")
            }
        };

        let entry = get_plugin(&udp_config.entry).expect(
            format!(
                "UDP Server [{}] entry plugin [{}] not found",
                plugin_info.tag, udp_config.entry
            )
            .as_str(),
        );

        Box::new(UdpServer {
            tag: plugin_info.tag.clone(),
            entry: entry.plugin.clone(),
            listen: udp_config.listen,
        })
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Server {
            tag: tag.to_string(),
            type_name: "udp".to_string(),
        }
    }
}
