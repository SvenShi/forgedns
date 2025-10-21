/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Configuration structure definitions
//!
//! Defines the schema for RustDNS configuration files (YAML format).

use serde::Deserialize;
use serde_yml::Value;

/// Main server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Logging configuration (level, file output)
    #[serde(default)]
    pub log: LogConfig,
    
    /// List of plugins to load and their configurations
    pub plugins: Vec<PluginConfig>,
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    /// Log level: off, trace, debug, info, warn, error
    #[serde(default = "default_level")]
    pub level: String,
    
    /// Optional file path for log output (in addition to console)
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

/// Default log level
fn default_level() -> String {
    "info".to_string()
}

/// Plugin configuration entry
#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    /// Unique identifier for this plugin instance
    pub tag: String,
    
    /// Plugin type (e.g., "udp_server", "forward")
    #[serde(rename = "type")]
    pub plugin_type: String,
    
    /// Plugin-specific arguments (parsed by plugin factory)
    pub args: Option<Value>,
}
