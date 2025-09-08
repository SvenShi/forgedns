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
use crate::pkg::upstream::tls_client_config::{insecure_client_config, secure_client_config};
use async_trait::async_trait;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::ProtoError;
use hickory_client::proto::h2::HttpsClientStreamBuilder;
use hickory_client::proto::quic::QuicClientStream;
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::udp::UdpClientStream;
use hickory_server::proto::rustls::tls_client_connect;
use hickory_server::proto::xfer::DnsResponse;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
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
            ConnectType::DoQ => 784,
            ConnectType::DoH => 443,
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

#[derive(Deserialize)]
pub struct UpStreamConfig {
    /// 请求服务器地址
    pub addr: String,
    pub port: Option<u16>,
    pub socks5: Option<String>,
    pub bootstrap: Option<String>,
    pub dial_addr: Option<IpAddr>,
    pub insecure_skip_verify: Option<bool>,
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
    bootstrap: Option<String>,
    path: String,
    host: String,
    is_ip_host: bool,
    insecure_skip_verify: bool,
}

/// 连接状态
pub enum ConnectState {
    New,
    Connecting,
    Connected { client: Client },
    Failed(ProtoError),
}

pub struct IpAddrUpStream {
    pub connect_info: ConnectInfo,
    pub connect_state: RwLock<ConnectState>,
}

#[async_trait]
impl UpStream for IpAddrUpStream {
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

impl IpAddrUpStream {
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
                let addr = SocketAddr::new(IpAddr::from_str(&info.addr).unwrap(), info.port);
                let conn = HttpsClientStreamBuilder::with_client_config(
                    Arc::new(if info.insecure_skip_verify {
                        insecure_client_config()
                    } else {
                        secure_client_config()
                    }),
                    TokioRuntimeProvider::default(),
                )
                .build(
                    addr,
                    Arc::from(info.host.clone()),
                    Arc::from(info.path.clone()),
                );
                let (client, bg) = Client::connect(conn).await?;
                tokio::spawn(bg);
                info!("DoH Upstream connected to: {}:{}", info.addr, info.port);
                Ok(client)
            }
            ConnectType::DoT => {
                let addr = SocketAddr::new(IpAddr::from_str(&info.addr).unwrap(), info.port);
                let stream = tls_client_connect(
                    addr,
                    ServerName::try_from(info.host.clone()).unwrap(),
                    Arc::new(if info.insecure_skip_verify {
                        insecure_client_config()
                    } else {
                        secure_client_config()
                    }),
                    TokioRuntimeProvider::default(),
                );
                let (client, bg) = Client::new(stream.0, stream.1, None).await?;
                tokio::spawn(bg);
                info!("TLS Upstream connected to: {}:{}", info.addr, info.port);
                Ok(client)
            }
            ConnectType::DoQ => {
                let addr = SocketAddr::new(IpAddr::from_str(&info.addr).unwrap(), info.port);
                let conn = QuicClientStream::builder().build(addr, Arc::from(info.host.clone()));
                let (client, bg) = Client::connect(conn).await?;
                // fixme: 没有合适的quic 服务器 待测试
                tokio::spawn(bg);
                info!("DoQ Upstream connected to: {}:{}", info.addr, info.port);
                Ok(client)
            }
        }
    }
}
#[allow(unused)]
pub struct DomainUpStream {
    pub bootstrap: Option<Box<dyn UpStream>>,
    pub connect_info: ConnectInfo,
    pub connect_state: RwLock<ConnectState>,
}

#[async_trait]
#[allow(unused)]
impl UpStream for DomainUpStream {
    async fn connect(&self) {
        todo!()
    }

    async fn query(&self, context: &mut DnsContext<'_>) -> Result<DnsResponse, ProtoError> {
        todo!()
    }

    fn connect_type(&self) -> ConnectType {
        todo!()
    }
}

pub struct UpStreamBuilder;

impl UpStreamBuilder {
    pub fn build(up_stream_config: &UpStreamConfig) -> Box<dyn UpStream> {
        let (connect_type, host, port, path) = Self::detect_connect_type(&up_stream_config.addr);
        let port = up_stream_config
            .port
            .or(port)
            .unwrap_or(connect_type.default_port());
        let connect_info = ConnectInfo {
            addr: if up_stream_config.dial_addr.is_some() {
                up_stream_config.dial_addr.unwrap().to_string()
            } else {
                host.clone()
            },
            port,
            socks5: up_stream_config.socks5.clone(),
            connect_type,
            bootstrap: up_stream_config.bootstrap.clone(),
            path: path.clone(),
            host: host.clone(),
            is_ip_host: IpAddr::from_str(host.as_str()).is_ok(),
            insecure_skip_verify: up_stream_config.insecure_skip_verify.unwrap_or(false),
        };

        if up_stream_config.dial_addr.is_some() || connect_info.is_ip_host {
            Box::new(IpAddrUpStream {
                connect_info,
                connect_state: RwLock::new(ConnectState::New),
            })
        } else {
            todo!("new domain upstream")
        }
    }

    fn detect_connect_type(addr: &str) -> (ConnectType, String, Option<u16>, String) {
        if !addr.contains("//") {
            return Self::detect_connect_type(&("udp://".to_owned() + addr));
        }
        let url = Url::parse(addr).expect("Invalid upstream url");
        let connect_type;
        let host;
        match url.scheme() {
            "udp" => {
                connect_type = ConnectType::UDP;
                host = url.host_str().unwrap().to_string();
            }
            "tcp" => {
                connect_type = ConnectType::TCP;
                host = url.host_str().unwrap().to_string();
            }
            "tls" => {
                connect_type = ConnectType::DoT;
                host = url.host_str().unwrap().to_string();
            }
            "quic" | "doq" => {
                connect_type = ConnectType::DoQ;
                host = url.host_str().unwrap().to_string();
            }
            "https" | "doh" => {
                connect_type = ConnectType::DoH;
                host = url.host_str().unwrap().to_string();
            }
            _ => {
                panic!("Invalid upstream url scheme");
            }
        };
        (connect_type, host, url.port(), url.path().to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::pkg::upstream::upstream::{UpStreamBuilder, UpStreamConfig};

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
        let upstream = UpStreamBuilder::build(&stream_config);
        upstream.connect().await;
        println!("connect success");
    }
}
