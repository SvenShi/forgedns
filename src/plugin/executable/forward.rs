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
use crate::pkg::upstream::{UpStream, UpStreamBuilder};
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use async_trait::async_trait;
use log::{debug, info};
use serde::Deserialize;

/// 单线程的dns转发器
#[allow(unused)]
pub struct SequentialDnsForwarder {
    pub tag: String,

    pub upstream: Box<dyn UpStream>,
}

#[async_trait]
impl Plugin for SequentialDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        self.upstream.connect().await;
    }

    async fn execute(&self, context: &mut DnsContext<'_>) {
        info!(
            "收到dns请求 source:{} , query:{}",
            context.request_info.src,
            context.request_info.query.name().to_string()
        );

        match self.upstream.query(context).await {
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

    async fn destroy(&mut self) {}
}

#[derive(Deserialize)]
#[allow(unused)]
pub struct ForwardConfig {
    /// 转发线程数
    #[allow(unused_variables)]
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

impl PluginFactory for ForwardFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let forward_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<ForwardConfig>(args)
                .unwrap_or_else(|e| panic!("初始化Forward时，读取配置异常。Error:{}", e)),
            None => {
                panic!("初始化Forward需要配置线程数(concurrent)以及上游地址(upstreams)")
            }
        };

        Box::new(SequentialDnsForwarder {
            tag: plugin_info.tag.clone(),
            upstream: UpStreamBuilder::build(&forward_config.upstreams[0]),
        })
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Executor {
            tag: tag.to_string(),
            type_name: "forward".to_string(),
        }
    }
}
