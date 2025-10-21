/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Runtime configuration and command-line argument parsing

use clap::Parser;
use std::path::PathBuf;

/// Core runtime container holding parsed command-line options
pub struct Runtime {
    pub options: Options,
}

/// Command-line options for RustDNS server
///
/// Supports:
/// - Configuration file path (default: config.yaml)
/// - Log level override (overrides config file setting)
#[derive(Parser)]
#[clap(version = "1.0", author = "Sven <shiwei@vankeytech.com>")]
pub struct Options {
    /// Path to configuration file
    #[clap(short, long, default_value = "config.yaml")]
    pub config: PathBuf,
    
    /// Log level (overrides config file): off, trace, debug, info, warn, error
    #[clap(short, long)]
    pub log_level: Option<String>,
}
