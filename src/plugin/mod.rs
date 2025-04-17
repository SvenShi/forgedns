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
use std::collections::HashMap;
use crate::config::config::{Config, PluginConfig};
use serde::Deserialize;

pub mod executable;
mod server;


// todo 插件注册逻辑需要实现





pub fn init(config: Config) -> HashMap<String, PluginInfo> {
    // todo 插件初始化 需要提前将所有的插件注册到应用中
    todo!()
}


#[derive(Clone, Debug, Deserialize)]
pub enum PluginType {


}


/// 插件
pub trait Plugin: Send + Sync + 'static {

    fn init(&self);

    fn destroy(&self);

}

/// 插件构造工厂
pub trait PluginFactory {
    fn create(plugin_info: PluginConfig) -> Box<dyn Plugin>;
}


/// 插件信息
pub struct PluginInfo {
    /// 插件tag
    pub tag: String,
    /// 插件类型
    pub plugin_type: PluginType,
    /// 插件参数
    pub args: Vec<String>,
    ///插件
    pub plugin: Box<dyn Plugin>,
}
