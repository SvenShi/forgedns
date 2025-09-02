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
use crate::core::context::DnsContext;
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use crate::pkg::upstream::UpStream;
use async_trait::async_trait;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use log::{debug, info};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use hickory_client::proto::h2::{HttpsClientStream, HttpsClientStreamBuilder};
use hickory_client::proto::tcp::TcpClientStream;
use tokio::sync::Mutex;

/// 单线程的dns转发器
pub struct SequentialDnsForwarder {
    pub tag: String,
    /// 发送dns请求的客户端
    pub client: Arc<Mutex<Client>>,

    pub upstream: UpStream,
}

#[async_trait]
impl Plugin for SequentialDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    fn init(&self) {}

    async fn execute(&self, context: &mut DnsContext<'_>) {
        let query = context.request_info.query;

        let response = self.client.lock().await.query(
            query.name().into(),
            query.query_class(),
            query.query_type(),
        );

        info!(
            "收到dns请求 source:{} , query:{}",
            context.request_info.src,
            query.name().to_string()
        );

        match response.await {
            Ok(res) => {
                context.response = Some(res);
            }
            Err(e) => {
                debug!("dns request has err: {e}");
                context.response = None;
            }
        }
    }

    fn main_type(&self) -> PluginMainType {
        PluginMainType::Executor {
            tag: self.tag.to_string(),
            type_name: "SequentialDnsForwarder".to_string(),
        }
    }

    fn destroy(&self) {}
}

#[derive(Deserialize)]
pub struct ForwardConfig {
    /// 转发线程数
    pub concurrent: Option<u32>,
    /// server监听地址
    pub upstreams: Vec<UpStreamConfig>,
}


#[derive(Deserialize)]
pub struct UpStreamConfig {
    /// 请求服务器地址
    pub addr: String,
    pub port: Option<u16>,
    pub socks5: Option<String>,
}

pub struct ForwardFactory;

#[async_trait]
impl PluginFactory for ForwardFactory {
    async fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let forward_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<ForwardConfig>(args)
                .unwrap_or_else(|e| panic!("初始化Forward时，读取配置异常。Error:{}", e)),
            None => {
                panic!("初始化Forward需要配置线程数(concurrent)以及上游地址(upstreams)")
            }
        };
        // 注意以后要根据上游地址的数量 拆分不同的实现类
        let addr = IpAddr::from_str(forward_config.upstreams[0].addr.as_str()).unwrap();
        let socket_addr = SocketAddr::new(addr, 53);
        let conn = UdpClientStream::builder(socket_addr, TokioRuntimeProvider::default()).build();
        let (client, bg) = Client::connect(conn).await.unwrap();
        tokio::spawn(bg);

        Box::new(SequentialDnsForwarder {
            tag: plugin_info.tag.clone(),
            client: Arc::new(Mutex::new(client)),
        })
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Executor {
            tag: tag.to_string(),
            type_name: "forward".to_string(),
        }
    }
}
