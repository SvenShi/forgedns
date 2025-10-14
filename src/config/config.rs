/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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
        LogConfig {
            level: default_level(),
            file: None,
        }
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
    pub plugin_type: String,
    /// 插件参数
    pub args: Option<Value>,
}
