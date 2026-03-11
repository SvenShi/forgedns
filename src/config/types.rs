/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Configuration structure definitions
//!
//! Defines the schema for ForgeDNS configuration files (YAML format).

use serde::Deserialize;
use serde_yml::Value;
use std::collections::HashMap;
use thiserror::Error;

/// Configuration validation errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Plugin tag cannot be empty")]
    EmptyPluginTag,

    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),

    #[error("Plugin type cannot be empty")]
    EmptyPluginType,

    #[error("runtime.worker_threads must be greater than 0")]
    InvalidRuntimeWorkerThreads,

    #[error(
        "Duplicate plugin tag '{tag}' found at plugins[{first_index}] and plugins[{duplicate_index}]"
    )]
    DuplicatePluginTag {
        tag: String,
        first_index: usize,
        duplicate_index: usize,
    },
}

/// Main server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Tokio runtime configuration.
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Logging configuration (level, file output)
    #[serde(default)]
    pub log: LogConfig,

    /// List of plugins to load and their configurations
    pub plugins: Vec<PluginConfig>,
}

impl Config {
    /// Validate configuration
    ///
    /// Validates the configuration structure (log level, plugin tags/types).
    /// Plugin-specific validation (e.g., listen addresses, upstreams) is delegated
    /// to each PluginFactory during plugin initialization.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if matches!(self.runtime.worker_threads, Some(0)) {
            return Err(ConfigError::InvalidRuntimeWorkerThreads);
        }

        // Validate log level
        match self.log.level.to_lowercase().as_str() {
            "off" | "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => return Err(ConfigError::InvalidLogLevel(self.log.level.clone())),
        }

        // Validate plugins - basic structure checks
        let mut seen_tags = HashMap::new();
        for (idx, plugin) in self.plugins.iter().enumerate() {
            // Check for empty tag
            if plugin.tag.is_empty() {
                return Err(ConfigError::EmptyPluginTag);
            }
            if let Some(prev_idx) = seen_tags.insert(plugin.tag.as_str(), idx) {
                return Err(ConfigError::DuplicatePluginTag {
                    tag: plugin.tag.clone(),
                    first_index: prev_idx,
                    duplicate_index: idx,
                });
            }

            // Check for empty type
            if plugin.plugin_type.is_empty() {
                return Err(ConfigError::EmptyPluginType);
            }
        }

        Ok(())
    }
}

/// Tokio runtime configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuntimeConfig {
    /// Number of Tokio worker threads for the multi-thread runtime.
    ///
    /// When omitted, ForgeDNS uses the system's available CPU parallelism.
    pub worker_threads: Option<usize>,
}

impl RuntimeConfig {
    /// Resolve the effective Tokio worker-thread count.
    pub fn effective_worker_threads(&self) -> usize {
        self.worker_threads.unwrap_or_else(default_worker_threads)
    }
}

fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(tag: &str, plugin_type: &str) -> PluginConfig {
        PluginConfig {
            tag: tag.to_string(),
            plugin_type: plugin_type.to_string(),
            args: None,
        }
    }

    #[test]
    fn test_validate_rejects_duplicate_plugin_tags() {
        let config = Config {
            runtime: RuntimeConfig::default(),
            log: LogConfig::default(),
            plugins: vec![plugin("dup", "debug_print"), plugin("dup", "ttl")],
        };

        let err = config
            .validate()
            .expect_err("should reject duplicate plugin tags");
        assert!(matches!(err, ConfigError::DuplicatePluginTag { .. }));
    }

    #[test]
    fn test_validate_rejects_empty_plugin_type() {
        let config = Config {
            runtime: RuntimeConfig::default(),
            log: LogConfig::default(),
            plugins: vec![plugin("test", "")],
        };

        let err = config
            .validate()
            .expect_err("should reject empty plugin type");
        assert!(matches!(err, ConfigError::EmptyPluginType));
    }

    #[test]
    fn test_validate_accepts_basic_valid_config() {
        let config = Config {
            runtime: RuntimeConfig::default(),
            log: LogConfig::default(),
            plugins: vec![plugin("ok", "debug_print")],
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_zero_runtime_worker_threads() {
        let config = Config {
            runtime: RuntimeConfig {
                worker_threads: Some(0),
            },
            log: LogConfig::default(),
            plugins: vec![plugin("ok", "debug_print")],
        };

        let err = config
            .validate()
            .expect_err("should reject zero runtime worker threads");
        assert!(matches!(err, ConfigError::InvalidRuntimeWorkerThreads));
    }

    #[test]
    fn test_runtime_worker_threads_default_to_available_parallelism() {
        let expected = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);

        assert_eq!(
            RuntimeConfig::default().effective_worker_threads(),
            expected
        );
    }
}
