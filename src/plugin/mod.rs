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
use crate::config::config::{Config, PluginConfig};
use crate::core::context::DnsContext;
use crate::plugin::executable::forward::ForwardFactory;
use crate::plugin::server::udp::UdpServerFactory;
use async_trait::async_trait;
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::Deserialize;
use serde_yml::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tracing::info;

pub mod executable;
mod server;

lazy_static! {
    static ref FACTORIES: HashMap<&'static str, Box<dyn PluginFactory>> = {
        let mut m: HashMap<&str, Box<dyn PluginFactory>> = HashMap::new();
        m.insert("forward", Box::new(ForwardFactory {}));
        m.insert("udp_server", Box::new(UdpServerFactory {}));
        m
    };
    static ref PLUGINS: DashMap<String, Arc<PluginInfo>> = DashMap::new();
}

/// 初始化插件
pub async fn init(config: Config) {
    // 每种插件都要实现一个插件构造工厂，通过构造工厂来创造插件
    for plugin_config in config.plugins {
        let key = plugin_config.plugin_type.as_str();
        let factory = FACTORIES
            .get(key)
            .unwrap_or_else(|| panic!("Plugin {key} not found"));
        let mut plugin_info = PluginInfo::from(&plugin_config, &factory);

        info!("Plugin init {} start", plugin_info.plugin_type);
        plugin_info.plugin.as_mut().init().await;

        PLUGINS.insert(plugin_config.tag.to_owned(), Arc::new(plugin_info));
    }
}

pub fn get_plugin(tag: &str) -> Option<Arc<PluginInfo>> {
    Some(PLUGINS.get(tag)?.clone())
}

#[allow(unused)]
pub fn set_plugin(plugin_info: Arc<PluginInfo>) {
    PLUGINS.insert(plugin_info.tag.to_owned(), plugin_info);
}

#[derive(Clone, Debug, Deserialize)]
pub enum PluginMainType {
    /// 持续运行的服务插件
    Server { tag: String, type_name: String },
    /// 可执行的执行插件
    Executor { tag: String, type_name: String },
    /// 用于匹配某种规则的匹配器
    Matcher { tag: String, type_name: String },
    /// 用于提供数据的数据提供器
    DataProvider { tag: String, type_name: String },
}

impl PluginMainType {
    pub fn tag(&self) -> &str {
        match self {
            PluginMainType::Server { tag, .. }
            | PluginMainType::Executor { tag, .. }
            | PluginMainType::Matcher { tag, .. }
            | PluginMainType::DataProvider { tag, .. } => tag,
        }
    }

    pub fn type_name(&self) -> &str {
        match self {
            PluginMainType::Server { type_name, .. }
            | PluginMainType::Executor { type_name, .. }
            | PluginMainType::Matcher { type_name, .. }
            | PluginMainType::DataProvider { type_name, .. } => type_name,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            PluginMainType::Server { .. } => "Server",
            PluginMainType::Executor { .. } => "Executor",
            PluginMainType::Matcher { .. } => "Matcher",
            PluginMainType::DataProvider { .. } => "DataProvider",
        }
    }
}

impl Display for PluginMainType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.kind(), self.type_name(), self.tag())
    }
}

/// 插件
#[async_trait]
#[allow(unused)]
pub trait Plugin: Send + Sync + 'static {
    fn tag(&self) -> &str;

    async fn init(&mut self);

    async fn execute(&self, context: &mut DnsContext);

    fn main_type(&self) -> PluginMainType;

    async fn destroy(&mut self);
}

/// 插件构造工厂
#[async_trait]
pub trait PluginFactory: Send + Sync + 'static {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin>;

    fn plugin_type(&self, tag: &str) -> PluginMainType;
}

/// 插件信息
#[allow(unused)]
pub struct PluginInfo {
    /// 插件tag
    pub tag: String,
    /// 插件类型
    pub plugin_type: PluginMainType,
    /// 插件参数
    pub args: Option<Value>,
    ///插件
    pub plugin: Box<dyn Plugin>,
}

impl PluginInfo {
    pub fn from(config: &PluginConfig, factory: &Box<dyn PluginFactory>) -> PluginInfo {
        let plugin = factory.create(config);

        PluginInfo {
            tag: config.tag.clone(),
            plugin_type: factory.plugin_type(&config.tag),
            args: config.args.clone(),
            plugin,
        }
    }
}
