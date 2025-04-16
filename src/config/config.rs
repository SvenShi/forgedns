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
use crate::plugin::PluginType;
use serde::Deserialize;
use serde_yml::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// log 配置
    #[serde(default)]
    pub log: LogConfig,
    /// 插件
    pub plugins: Vec<PluginConfig>,
}

/// 日志配置
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    ///等级 off trace debug info warn error
    #[serde(default = "default_level")]
    pub level: String,
    /// 日志是否保存到文件中
    pub file: Option<String>,
}

impl Default for LogConfig {
    fn default() -> LogConfig {
        LogConfig { level: default_level(), file: None }

    }
}

fn default_level() -> String {
    "info".to_string()
}


/// 插件配置
#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    /// 插件标识符
    pub tag: String,
    /// 插件类型
    #[serde(rename = "type")]
    pub plugin_type: PluginType,
    /// 插件参数
    pub args: Option<Value>,
}
