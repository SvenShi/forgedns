/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Configuration structure definitions
//!
//! Defines the schema for RustDNS configuration files (YAML format).

use serde::Deserialize;
use serde_yml::Value;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;

/// Configuration validation errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Plugin tag cannot be empty")]
    EmptyPluginTag,

    #[error("Invalid listen address: {0}")]
    InvalidListenAddr(String),

    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),

    #[error("Plugin type cannot be empty")]
    EmptyPluginType,
}

/// Main server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Logging configuration (level, file output)
    #[serde(default)]
    pub log: LogConfig,

    /// List of plugins to load and their configurations
    pub plugins: Vec<PluginConfig>,
}

impl Config {
    /// Validate configuration
    ///
    /// Checks for common configuration errors such as invalid log levels,
    /// empty plugin tags, and invalid listen addresses.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate log level
        match self.log.level.to_lowercase().as_str() {
            "off" | "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => return Err(ConfigError::InvalidLogLevel(self.log.level.clone())),
        }

        // Validate plugins
        for plugin in &self.plugins {
            // Check for empty tag
            if plugin.tag.is_empty() {
                return Err(ConfigError::EmptyPluginTag);
            }

            // Check for empty type
            if plugin.plugin_type.is_empty() {
                return Err(ConfigError::EmptyPluginType);
            }

            // Validate server plugin listen addresses
            if plugin.plugin_type == "udp_server" || plugin.plugin_type == "tcp_server" {
                if let Some(args) = &plugin.args {
                    if let Some(listen) = args.get("listen") {
                        if let Some(listen_str) = listen.as_str() {
                            if SocketAddr::from_str(listen_str).is_err() {
                                return Err(ConfigError::InvalidListenAddr(listen_str.to_string()));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
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

impl PluginConfig {
    /// Extract dependencies from plugin configuration
    ///
    /// Returns a list of plugin tags that this plugin depends on.
    /// Used for dependency resolution during initialization.
    pub fn get_dependencies(&self) -> Vec<String> {
        match self.plugin_type.as_str() {
            "udp_server" | "tcp_server" => {
                if let Some(args) = &self.args {
                    if let Some(entry) = args.get("entry") {
                        if let Some(entry_str) = entry.as_str() {
                            return vec![entry_str.to_string()];
                        }
                    }
                }
                vec![]
            }
            _ => vec![],
        }
    }
}
