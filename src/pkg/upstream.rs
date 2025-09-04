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
use crate::plugin::executable::forward::UpStreamConfig;
use async_trait::async_trait;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::ProtoError;
use hickory_server::proto::xfer::DnsResponse;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::sync::RwLock;
use tokio::task::yield_now;
use tracing::info;
use url::Url;

/// 上游服务器连接类型
#[derive(Clone, Copy)]
pub enum ConnectType {
    UDP,
    TCP,
    DoT,
    DoQ,
    DoH,
}

#[allow(unused)]
impl ConnectType {
    pub fn default_port(&self) -> u16 {
        match self {
            ConnectType::UDP => 53,
            ConnectType::TCP => 53,
            ConnectType::DoT => 853,
            ConnectType::DoQ => 853,
            ConnectType::DoH => 853,
        }
    }

    pub fn schema(&self) -> Vec<&str> {
        match self {
            ConnectType::UDP => vec!["udp", ""],
            ConnectType::TCP => vec!["tcp"],
            ConnectType::DoT => vec!["tls"],
            ConnectType::DoQ => vec!["doq", "quic"],
            ConnectType::DoH => vec!["doh", "https"],
        }
    }
}

#[async_trait]
#[allow(unused)]
pub trait UpStream: Send + Sync {
    async fn connect(&self);

    async fn query(&self, context: &mut DnsContext<'_>) -> Result<DnsResponse, ProtoError>;

    fn connect_type(&self) -> ConnectType;
}

/// 公共的连接信息
#[derive(Clone)]
#[allow(unused)]
pub struct ConnectInfo {
    connect_type: ConnectType,
    addr: String,
    port: u16,
    socks5: Option<String>,
}

/// 连接状态
pub enum ConnectState {
    New,
    Connecting,
    Connected { client: Client },
    Failed(ProtoError),
}

#[async_trait]
impl UpStream for DefaultUpStream {
    async fn connect(&self) {
        loop {
            let state = { self.connect_state.read().await };
            match &*state {
                ConnectState::New => {
                    drop(state);
                    {
                        let mut state = self.connect_state.write().await;
                        *state = ConnectState::Connecting;
                    }
                    // 真正执行连接逻辑
                    match Self::do_connect(&self.connect_info).await {
                        Ok(client) => {
                            let mut state = self.connect_state.write().await;
                            *state = ConnectState::Connected { client };
                        }
                        Err(e) => {
                            let mut state = self.connect_state.write().await;
                            *state = ConnectState::Failed(e);
                        }
                    }
                    break;
                }
                ConnectState::Connecting => {
                    info!("state: Connecting");
                    yield_now().await;
                }
                ConnectState::Connected { .. } | ConnectState::Failed(_) => {
                    info!("state: Connected");
                    break;
                }
            }
        }
    }

    async fn query(&self, context: &mut DnsContext<'_>) -> Result<DnsResponse, ProtoError> {
        let query = context.request_info.query;
        let state = { self.connect_state.read().await };
        match &*state {
            ConnectState::New | ConnectState::Connecting => {
                self.connect().await;
                self.query(context).await
            }
            ConnectState::Connected { client, .. } => {
                let mut client = client.clone();
                client
                    .query(query.name().into(), query.query_class(), query.query_type())
                    .await
            }
            ConnectState::Failed(e) => Err(e.clone()),
        }
    }

    fn connect_type(&self) -> ConnectType {
        self.connect_info.connect_type
    }
}

impl DefaultUpStream {
    async fn do_connect(info: &ConnectInfo) -> Result<Client, ProtoError> {
        match info.connect_type {
            ConnectType::UDP => {
                let addr = IpAddr::from_str(&info.addr).unwrap();
                let socket_addr = SocketAddr::new(addr, info.port);
                let conn =
                    UdpClientStream::builder(socket_addr, TokioRuntimeProvider::default()).build();
                let (client, bg) = Client::connect(conn).await?;
                tokio::spawn(bg);
                info!("UDP Upstream connected to: {}:{}", info.addr, info.port);
                Ok(client)
            }
            ConnectType::TCP => {
                let addr = SocketAddr::new(IpAddr::from_str(&info.addr).unwrap(), info.port);
                let stream =
                    TcpClientStream::new(addr, None, None, TokioRuntimeProvider::default());
                let (client, bg) = Client::new(stream.0, stream.1, None).await?;
                tokio::spawn(bg);
                info!("TCP Upstream connected to: {}:{}", info.addr, info.port);
                Ok(client)
            }
            ConnectType::DoH => {
                // HttpsClientStreamBuilder::build()
                todo!("https is not yet implemented")
            }
            ConnectType::DoT => {
                todo!("tls is not yet implemented")
            }
            ConnectType::DoQ => {
                todo!("quic is not yet implemented")
            }
        }
    }
}

#[tokio::test]
async fn tcp_connect_test() {
    let stream_config = UpStreamConfig {
        addr: "tcp://223.5.5.5".to_string(),
        port: Some(53),
        socks5: None,
    };
    let upstream = UpStreamBuilder::build(&stream_config);
    upstream.connect().await;
    println!("connect success");
}

pub struct DefaultUpStream {
    pub connect_info: ConnectInfo,
    pub connect_state: RwLock<ConnectState>,
}

pub struct UpStreamBuilder;

impl UpStreamBuilder {
    pub fn build(up_stream_config: &UpStreamConfig) -> Box<dyn UpStream> {
        let (connect_type, addr, port) = Self::detect_connect_type(&up_stream_config.addr);
        let port = up_stream_config
            .port
            .or(port)
            .unwrap_or(connect_type.default_port());

        let connect_info = ConnectInfo {
            addr,
            port,
            socks5: up_stream_config.socks5.clone(),
            connect_type,
        };

        Box::new(DefaultUpStream {
            connect_info,
            connect_state: RwLock::new(ConnectState::New),
        })
    }

    fn detect_connect_type(addr: &str) -> (ConnectType, String, Option<u16>) {
        if !addr.contains("//") {
            return Self::detect_connect_type(&("udp://".to_owned() + addr));
        }
        let url = Url::parse(addr).expect("Invalid upstream url");
        let connect_type;
        let new_addr;
        match url.scheme() {
            "udp" => {
                connect_type = ConnectType::UDP;
                new_addr = url.host_str().unwrap().to_string();
            }
            "tcp" => {
                connect_type = ConnectType::TCP;
                new_addr = url.host_str().unwrap().to_string();
            }
            "tls" => {
                connect_type = ConnectType::DoT;
                new_addr = url.host_str().unwrap().to_string();
            }
            "quic" | "doq" => {
                connect_type = ConnectType::DoQ;
                new_addr = addr.to_string();
            }
            "https" | "doh" => {
                connect_type = ConnectType::DoH;
                new_addr = addr.to_string();
            }
            _ => {
                panic!("Invalid upstream url scheme");
            }
        };
        (connect_type, new_addr, url.port())
    }
}
