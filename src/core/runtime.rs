/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use clap::Parser;
use std::path::PathBuf;

pub struct Runtime {
    pub options: Options,
}

#[derive(Parser)]
#[clap(version = "1.0", author = "Sven <shiwei@vankeytech.com>")]
pub struct Options {
    #[clap(short, long, default_value = "config.yaml")]
    pub config: PathBuf,
    #[clap(short, long)]
    pub log_level: Option<String>,
}
