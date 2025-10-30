/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Configuration module
//!
//! Handles loading and parsing of YAML configuration files.
//! Defines the structure for server configuration including:
//! - Logging settings
//! - Plugin configurations

use crate::config::types::Config;
use crate::core::error::Result;
use std::fs;
use std::path::PathBuf;

pub mod types;

/// Load and parse configuration from YAML file
///
/// # Errors
/// Returns an error if the file cannot be read, if YAML parsing fails, or if validation fails.
pub fn init(file: &PathBuf) -> Result<Config> {
    // Using ? operator - errors are automatically converted via From trait
    let string = fs::read_to_string(file)?;
    let config: Config = serde_yml::from_str(&string)?;

    // Validate configuration - ConfigError is auto-converted to DnsError
    config.validate()?;

    eprintln!(
        "Configuration loaded and validated: {} plugin(s) configured",
        config.plugins.len()
    );
    Ok(config)
}
