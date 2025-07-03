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
use crate::core::handler::DnsRequestHandler;
use crate::plugin::executable::Executable;
use crate::plugin::server::Server;
use crate::plugin::{get_plugin, Plugin, PluginFactory, PluginMainType};
use async_trait::async_trait;
use hickory_server::ServerFuture;
use log::info;
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::core::context::DnsContext;

#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// server执行入口
    pub entry: String,
    /// server监听地址
    pub listen: String,
}

pub struct UdpServer {
    tag: String,
    entry: Arc<Box<dyn Executable>>,
    listen: String,
}

#[async_trait]
impl Plugin for UdpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn execute(&self, context: &mut DnsContext<'_>) {
    }

    fn init(&self) {
        self.run();
    }

    fn destroy(&self) {}
}

impl Server for UdpServer {
    fn run(&self) {
        let listen = self.listen.clone();
        let entry = self.entry.clone();
        let addr = listen.clone();
        tokio::spawn(async move {
            let bind = UdpSocket::bind(addr);
            let udp_socket = bind.await.unwrap();
            let mut server_future = ServerFuture::new(DnsRequestHandler { executor: entry });
            server_future.register_socket(udp_socket);
            server_future
                .block_until_done()
                .await
                .unwrap_or_else(|e| panic!("UDP Server 启动失败。{}", e));
        });
        info!("UDP Server启动成功，监听地址：{listen}");
    }
}

pub struct UdpServerFactory {}

#[async_trait]
impl PluginFactory for UdpServerFactory {
    async fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
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
        let plugin = entry.plugin.clone();

        let executable = unsafe_cast_to_executable(plugin);

        Box::new(UdpServer {
            tag: plugin_info.tag.clone(),
            entry: executable,
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


fn unsafe_cast_to_executable(plugin: Arc<Box<dyn Plugin>>) -> Arc<Box<dyn Executable>> {
    unsafe {
        let raw: *const Box<dyn Plugin> = Arc::into_raw(plugin);
        // 转为 *const Box<dyn Executable>
        let raw_exec = raw as *const Box<dyn Executable>;
        Arc::from_raw(raw_exec)
    }
}
