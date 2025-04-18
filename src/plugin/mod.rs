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
use crate::plugin::executable::forward::ForwardFactory;
use lazy_static::lazy_static;
use serde::Deserialize;
use serde_yml::Value;
use std::collections::HashMap;

pub mod executable;
mod server;

lazy_static! {
    static ref FACTORIES: HashMap<String, Box<dyn PluginFactory>> = {
        let mut m : HashMap<String, Box<dyn PluginFactory>> = HashMap::new();
        m.insert("forward".to_owned(), Box::new(ForwardFactory));
        m
    };
}


/// 初始化插件
pub fn init(config: Config) -> HashMap<String, PluginInfo> {
    let mut plugin_map = HashMap::new();

    for plugin_config in config.plugins {
        let key = plugin_config.plugin_type.as_str();
        let factory = FACTORIES.get(key).unwrap_or_else(|| panic!("plugin {key} not found"));
        plugin_map.insert(plugin_config.tag.clone(), PluginInfo::from(&plugin_config, &factory));
    }

    plugin_map
}


#[derive(Clone, Debug, Deserialize)]
pub enum PluginType {
    /// 持续运行的服务插件
    Server {
        tag: String,
    },
    /// 可执行的执行插件
    Executor {
        tag: String,
    },
    /// 用于匹配某种规则的匹配器
    Matcher {
        tag: String,
    },
    /// 用于提供数据的数据提供器
    DataProvider {
        tag: String,
    },
}


/// 插件
pub trait Plugin: Send + Sync + 'static {
    fn init(&self);

    fn destroy(&self);
}

/// 插件构造工厂
pub trait PluginFactory: Send + Sync + 'static {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin>;

    fn plugin_type(&self, tag: &str) -> PluginType;
}


/// 插件信息
pub struct PluginInfo {
    /// 插件tag
    pub tag: String,
    /// 插件类型
    pub plugin_type: PluginType,
    /// 插件分类
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
