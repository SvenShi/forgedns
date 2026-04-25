// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Configuration structure definitions
//!
//! Defines the schema for ForgeDNS configuration files (YAML format).

use std::collections::HashMap;

use serde::Deserialize;
use serde_yaml_ng::Value;
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

    #[error("api.http.listen cannot be empty")]
    EmptyApiHttpListen,

    #[error("api.http.auth.basic.username cannot be empty")]
    EmptyApiBasicAuthUsername,

    #[error("api.http.auth.basic.password cannot be empty")]
    EmptyApiBasicAuthPassword,

    #[error("api.http.ssl.cert and api.http.ssl.key must be configured together")]
    IncompleteApiTlsConfig,

    #[error("api.http.ssl.require_client_cert requires api.http.ssl.client_ca")]
    MissingApiTlsClientCa,

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

    /// Optional management API configuration.
    #[serde(default)]
    pub api: ApiConfig,

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
    /// Plugin-specific validation (e.g., listen addresses, upstreams) is
    /// delegated to each PluginFactory during plugin initialization.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if matches!(self.runtime.worker_threads, Some(0)) {
            return Err(ConfigError::InvalidRuntimeWorkerThreads);
        }

        // Validate log level
        match self.log.level.to_lowercase().as_str() {
            "off" | "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => return Err(ConfigError::InvalidLogLevel(self.log.level.clone())),
        }

        if let Some(http) = &self.api.http {
            let resolved = http.resolve();
            if resolved.listen.trim().is_empty() {
                return Err(ConfigError::EmptyApiHttpListen);
            }

            if let Some(ssl) = &resolved.ssl {
                let cert_present = ssl.cert.is_some();
                let key_present = ssl.key.is_some();
                if cert_present != key_present {
                    return Err(ConfigError::IncompleteApiTlsConfig);
                }
                if ssl.require_client_cert.unwrap_or(false) && ssl.client_ca.is_none() {
                    return Err(ConfigError::MissingApiTlsClientCa);
                }
            }

            if let Some(ApiAuthConfig::Basic { username, password }) = &resolved.auth {
                if username.trim().is_empty() {
                    return Err(ConfigError::EmptyApiBasicAuthUsername);
                }
                if password.trim().is_empty() {
                    return Err(ConfigError::EmptyApiBasicAuthPassword);
                }
            }
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

/// Management API configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiConfig {
    /// Optional HTTP management API configuration.
    pub http: Option<ApiHttpConfig>,
}

/// `api.http` supports shorthand string and detailed object forms.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ApiHttpConfig {
    Listen(String),
    Detailed(ApiHttpDetailedConfig),
}

impl ApiHttpConfig {
    /// Resolve user-facing config variants into one canonical structure.
    pub fn resolve(&self) -> ResolvedApiHttpConfig {
        match self {
            Self::Listen(listen) => ResolvedApiHttpConfig {
                listen: listen.clone(),
                ssl: None,
                auth: None,
            },
            Self::Detailed(config) => ResolvedApiHttpConfig {
                listen: config.listen.clone(),
                ssl: config.ssl.clone(),
                auth: config.auth.clone(),
            },
        }
    }
}

/// Expanded HTTP API configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiHttpDetailedConfig {
    pub listen: String,
    pub ssl: Option<ApiTlsConfig>,
    pub auth: Option<ApiAuthConfig>,
}

/// TLS settings for the management API.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiTlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
    pub client_ca: Option<String>,
    pub require_client_cert: Option<bool>,
}

/// Authentication settings for the management API.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiAuthConfig {
    Basic { username: String, password: String },
}

/// Canonical HTTP API configuration used at runtime.
#[derive(Debug, Clone)]
pub struct ResolvedApiHttpConfig {
    pub listen: String,
    pub ssl: Option<ApiTlsConfig>,
    pub auth: Option<ApiAuthConfig>,
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

    #[serde(default)]
    pub rotation: LogRotation,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogRotation {
    #[default]
    Never,
    Minutely {
        max_files: Option<usize>,
    },
    Hourly {
        max_files: Option<usize>,
    },
    Daily {
        max_files: Option<usize>,
    },
    Weekly {
        max_files: Option<usize>,
    },
}

impl LogRotation {
    #[inline]
    pub fn max_files(&self) -> Option<usize> {
        match self {
            LogRotation::Never => None,
            LogRotation::Minutely { max_files } => *max_files,
            LogRotation::Hourly { max_files } => *max_files,
            LogRotation::Daily { max_files } => *max_files,
            LogRotation::Weekly { max_files } => *max_files,
        }
    }

    #[inline]
    pub fn is_never(&self) -> bool {
        matches!(self, LogRotation::Never)
    }
}

impl Default for LogConfig {
    fn default() -> LogConfig {
        LogConfig {
            level: default_level(),
            file: None,
            rotation: LogRotation::Never,
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
            api: ApiConfig::default(),
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
            api: ApiConfig::default(),
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
            api: ApiConfig::default(),
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
            api: ApiConfig::default(),
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

    #[test]
    fn test_validate_accepts_api_http_string_shorthand() {
        let config = Config {
            runtime: RuntimeConfig::default(),
            api: ApiConfig {
                http: Some(ApiHttpConfig::Listen("0.0.0.0:8080".to_string())),
            },
            log: LogConfig::default(),
            plugins: vec![plugin("ok", "debug_print")],
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_api_mtls_without_client_ca() {
        let config = Config {
            runtime: RuntimeConfig::default(),
            api: ApiConfig {
                http: Some(ApiHttpConfig::Detailed(ApiHttpDetailedConfig {
                    listen: "127.0.0.1:9443".to_string(),
                    ssl: Some(ApiTlsConfig {
                        cert: Some("cert.pem".to_string()),
                        key: Some("key.pem".to_string()),
                        client_ca: None,
                        require_client_cert: Some(true),
                    }),
                    auth: None,
                })),
            },
            log: LogConfig::default(),
            plugins: vec![plugin("ok", "debug_print")],
        };

        let err = config
            .validate()
            .expect_err("should reject mtls config without client_ca");
        assert!(matches!(err, ConfigError::MissingApiTlsClientCa));
    }

    #[test]
    fn test_log_rotation_deserializes_minutely() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            rotation: LogRotation,
        }

        let config: Wrapper = serde_yaml_ng::from_str(
            r#"
rotation:
  type: minutely
  max_files: 7
"#,
        )
        .expect("parse minutely rotation");

        match config.rotation {
            LogRotation::Minutely { max_files } => assert_eq!(max_files, Some(7)),
            other => panic!("unexpected rotation: {other:?}"),
        }
    }

    #[test]
    fn test_log_rotation_deserializes_weekly() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            rotation: LogRotation,
        }

        let config: Wrapper = serde_yaml_ng::from_str(
            r#"
rotation:
  type: weekly
  max_files: 4
"#,
        )
        .expect("parse weekly rotation");

        match config.rotation {
            LogRotation::Weekly { max_files } => assert_eq!(max_files, Some(4)),
            other => panic!("unexpected rotation: {other:?}"),
        }
    }
}
