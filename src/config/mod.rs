/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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
    Ok(config)
}
