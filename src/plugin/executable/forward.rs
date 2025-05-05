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
use crate::plugin::executable::Executable;
use crate::plugin::server::udp::UdpServerConfig;
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use async_trait::async_trait;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use log::debug;
use serde::Deserialize;
use std::any::Any;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 单线程的dns转发器
pub struct SequentialDnsForwarder {
    /// 发送dns请求的客户端
    pub client: Arc<Mutex<Client>>,
}

impl Plugin for SequentialDnsForwarder {
    fn init(&self) {}

    fn destroy(&self) {}
}

#[derive(Deserialize)]
pub struct ForwardConfig {
    /// 转发线程数
    pub concurrent: u32,
    /// server监听地址
    pub upstreams: Vec<UpStreamConfig>,
}

#[derive(Deserialize)]
pub struct UpStreamConfig {
    /// 请求服务器地址
    pub addr: String,
}

pub struct ForwardFactory;

impl PluginFactory for ForwardFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let forward_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<ForwardConfig>(args)
                .unwrap_or_else(|e| panic!("初始化Forward时，读取配置异常。Error:{}", e)),
            None => {
                panic!("初始化Forward需要配置线程数(concurrent)以及上游地址(upstreams)")
            }
        };
        let addr = IpAddr::from_str(forward_config.upstreams[0].addr.as_str()).unwrap();
        let socket_addr = SocketAddr::new(addr, 53);
        let conn = UdpClientStream::builder(socket_addr, TokioRuntimeProvider::default()).build();
        let (client, bg) = Client::connect(conn).await.unwrap();
        tokio::spawn(bg);

        Box::new(SequentialDnsForwarder {
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

#[async_trait]
impl Executable for SequentialDnsForwarder {
    async fn execute(&self, context: &mut DnsContext<'_>) {
        let query = context.request_info.query;

        let response = self.client.lock().await.query(
            query.name().into(),
            query.query_class(),
            query.query_type(),
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
}
