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
    HTTPS,
    TLS,
    QUIC,
    DOQ,
}

#[allow(unused)]
impl ConnectType {
    pub fn default_port(&self) -> u16 {
        match self {
            ConnectType::UDP => 53,
            ConnectType::TCP => 53,
            ConnectType::HTTPS => 443,
            ConnectType::TLS => 853,
            ConnectType::QUIC => 853,
            ConnectType::DOQ => 853,
        }
    }

    pub fn schema(&self) -> &str {
        match self {
            ConnectType::UDP => "udp",
            ConnectType::TCP => "tcp",
            ConnectType::HTTPS => "https",
            ConnectType::TLS => "tls",
            ConnectType::QUIC => "quic",
            ConnectType::DOQ => "doq",
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
                },
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
        let addr = IpAddr::from_str(&info.addr).unwrap();
        let socket_addr = SocketAddr::new(addr, 53);
        let conn = UdpClientStream::builder(socket_addr, TokioRuntimeProvider::default()).build();
        let (client, bg) = Client::connect(conn).await?;
        tokio::spawn(bg);
        Ok(client)
    }
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
        let url = Url::parse(addr).expect("invalid upstream url");
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
            "https" => {
                connect_type = ConnectType::HTTPS;
                new_addr = addr.to_string();
            }
            "tls" => {
                connect_type = ConnectType::TLS;
                new_addr = url.host_str().unwrap().to_string();
            }
            "quic" => {
                connect_type = ConnectType::QUIC;
                new_addr = addr.to_string();
            }
            "doq" => {
                connect_type = ConnectType::DOQ;
                new_addr = addr.to_string();
            }
            _ => {
                connect_type = ConnectType::UDP;
                new_addr = url.host_str().unwrap().to_string();
            }
        };
        (connect_type, new_addr, url.port())
    }
}
