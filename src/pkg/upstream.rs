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
use hickory_client::proto::ProtoError;
use hickory_server::proto::xfer::DnsResponse;
use url::Url;

/// 上游服务器连接类型
#[derive(Clone)]
enum ConnectType {
    UDP,
    TCP,
    HTTPS,
    TLS,
    QUIC,
    DOQ,
}
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
pub trait UpStream: Send + Sync {
    async fn query(&mut self, context: &mut DnsContext<'_>) -> Result<DnsResponse, ProtoError>;

    fn connect_type(&self) -> ConnectType;
}

pub struct DefaultUpStream {
    pub addr: String,
    pub port: u16,
    pub socks5: Option<String>,
    pub connect_type: ConnectType,
    client: Client,
}

#[async_trait]
impl UpStream for DefaultUpStream {
    async fn query(&mut self, context: &mut DnsContext<'_>) -> Result<DnsResponse, ProtoError> {
        let query = context.request_info.query;
        self.client
            .query(query.name().into(), query.query_class(), query.query_type())
            .await
    }

    fn connect_type(&self) -> ConnectType {
        self.connect_type.clone()
    }
}

pub struct UpStreamBuilder {}

impl UpStreamBuilder {
    pub fn build(up_stream_config: &UpStreamConfig) -> Box<dyn UpStream> {
        let url = Url::parse(&up_stream_config.addr).expect("invalid upstream url");
        let connect_type = match url.scheme() {
            "udp" => ConnectType::UDP,
            "tcp" => ConnectType::TCP,
            "https" => ConnectType::HTTPS,
            "tls" => ConnectType::TLS,
            "quic" => ConnectType::QUIC,
            "doq" => ConnectType::DOQ,
            _ => ConnectType::UDP,
        };

        Box::new(DefaultUpStream {
            addr: "".to_string(),
            port: 0,
            socks5: up_stream_config.socks5,
            connect_type,
            client: (),
        })
    }

}
