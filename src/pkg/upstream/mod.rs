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
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU16;
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::ProtoError;
use hickory_proto::xfer::DnsResponse;
use serde::Deserialize;
use tokio::sync::OnceCell;
use url::Url;
use crate::core::context::DnsContext;
use crate::pkg::upstream::udp::UdpUpstream;

mod bootstrap;
mod tls_client_config;
pub mod udp;



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
    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError>;

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



pub struct UpStreamBuilder;

impl UpStreamBuilder {
    pub fn with_upstream_config(up_stream_config: &UpStreamConfig) -> Box<dyn UpStream> {
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
            // Box::new(IpAddrUpStream {
            //     connect_info,
            //     connect_state: RwLock::new(ConnectState::New),
            // })

            Box::new(UdpUpstream {
                current_id: AtomicU16::new(0),
                request_map: Arc::new(DashMap::new()),
                connect_info,
                connect: OnceCell::new(),
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
