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
use std::fs;
use std::path::PathBuf;

pub mod types;

/// Load and parse configuration from YAML file
///
/// # Panics
/// Panics if the file cannot be read, if YAML parsing fails, or if validation fails.
/// This is intentional as the server cannot operate without valid configuration.
pub fn init(file: &PathBuf) -> Config {
    let string = fs::read_to_string(file)
        .unwrap_or_else(|e| panic!("Failed to read config file {:?}: {}", file, e));

    let config: Config = serde_yml::from_str(&string)
        .unwrap_or_else(|e| panic!("Failed to parse config file {:?}: {}", file, e));

    // Validate configuration
    config
        .validate()
        .unwrap_or_else(|e| panic!("Configuration validation failed: {}", e));

    eprintln!(
        "Configuration loaded and validated: {} plugin(s) configured",
        config.plugins.len()
    );
    config
}
