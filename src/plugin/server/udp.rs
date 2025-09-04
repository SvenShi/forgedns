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
use crate::core::handler::DnsRequestHandler;
use crate::plugin::{Plugin, PluginFactory, PluginMainType, get_plugin};
use async_trait::async_trait;
use hickory_server::ServerFuture;
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::info;

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
        tokio::spawn(async move {
            let bind = UdpSocket::bind(addr);
            let udp_socket = bind.await.unwrap();
            let mut server_future = ServerFuture::new(DnsRequestHandler {
                executor: entry_executor,
            });
            server_future.register_socket(udp_socket);
            server_future
                .block_until_done()
                .await
                .unwrap_or_else(|e| panic!("UDP Server 启动失败。{}", e));
        });
        info!("UDP Server启动成功，监听地址：{listen}");
    }

    async fn execute(&self, _: &mut DnsContext<'_>) {}

    fn main_type(&self) -> PluginMainType {
        PluginMainType::Executor {
            tag: self.tag.to_string(),
            type_name: "UdpServer".to_string(),
        }
    }

    async fn destroy(&mut self) {}
}

pub struct UdpServerFactory {}

#[async_trait]
impl PluginFactory for UdpServerFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let udp_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<UdpServerConfig>(args)
                .unwrap_or_else(|e| panic!("初始化UDP Server时，读取配置异常。Error:{}", e)),
            None => {
                panic!("初始化UDP Server需要配置监听地址(listen)以及服务入口(entry)")
            }
        };

        let entry = get_plugin(&udp_config.entry).expect(
            format!(
                "请检查{} UDP Server的入口插件{}是否存在",
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
