/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::config::config::Config;
use std::fs;
use std::path::PathBuf;

pub mod config;

pub fn init(file: &PathBuf) -> Config {
    let string = fs::read_to_string(file).unwrap();
    let config: Config = serde_yml::from_str(&string).expect("Failed to parse config file");
    config
}
