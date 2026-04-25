// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime configuration loading and validation entry points.
//!
//! ForgeDNS configuration is defined as YAML and deserialized into
//! [`types::Config`]. This module keeps the file-loading boundary small:
//!
//! - read the configuration file from disk;
//! - deserialize it into strongly typed Rust structures; and
//! - trigger semantic validation before the runtime starts.
//!
//! The detailed schema lives in [`types`]. Keeping I/O and schema definitions
//! separate makes it easier to reuse the same validation path from the CLI,
//! tests, and future embedding scenarios.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::types::Config;
use crate::core::error::Result;
use crate::plugin::DependencyGraphReport;

pub mod types;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValidationSummary {
    pub plugin_count: usize,
    pub dependency_graph: DependencyGraphReport,
}

/// Load and parse configuration from YAML file
///
/// # Errors
/// Returns an error if the file cannot be read, if YAML parsing fails, or if
/// validation fails.
pub fn init(file: &PathBuf) -> Result<Config> {
    // Using ? operator - errors are automatically converted via From trait
    let string = fs::read_to_string(file)?;
    let config: Config = serde_yaml_ng::from_str(&string)?;

    // Validate configuration - ConfigError is auto-converted to DnsError
    config.validate()?;
    Ok(config)
}

/// Validate configuration from an on-disk YAML file.
pub fn validate_file(path: &Path) -> Result<ConfigValidationSummary> {
    let config = init(&path.to_path_buf())?;
    let dependency_graph = crate::plugin::analyze_configuration(&config)?;
    Ok(ConfigValidationSummary {
        plugin_count: config.plugins.len(),
        dependency_graph,
    })
}

/// Validate configuration from YAML text.
pub fn validate_text(text: &str) -> Result<ConfigValidationSummary> {
    let config: Config = serde_yaml_ng::from_str(text)?;
    config.validate()?;
    let dependency_graph = crate::plugin::analyze_configuration(&config)?;
    Ok(ConfigValidationSummary {
        plugin_count: config.plugins.len(),
        dependency_graph,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    fn valid_config_yaml() -> &'static str {
        r#"
plugins:
  - tag: debug_main
    type: debug_print
"#
    }

    #[test]
    fn validate_file_accepts_valid_config() {
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");

        let summary = validate_file(temp.path()).expect("valid config should pass");
        assert_eq!(summary.plugin_count, 1);
        assert_eq!(
            summary.dependency_graph.init_order,
            vec!["debug_main".to_string()]
        );
    }

    #[test]
    fn validate_file_rejects_invalid_yaml() {
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), "plugins: [").expect("write config");

        assert!(validate_file(temp.path()).is_err());
    }

    #[test]
    fn validate_text_rejects_unknown_plugin_type() {
        let err = validate_text(
            r#"
plugins:
  - tag: bad
    type: missing_plugin
"#,
        )
        .expect_err("unknown plugin should fail");

        assert!(err.to_string().contains("Unknown plugin type"));
    }
}
