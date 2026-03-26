/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! ForgeDNS CLI entry point.

use forgedns::app::cli::{self, Command};
use forgedns::core::error::Result;
use forgedns::{app, service};

fn main() -> Result<()> {
    match cli::parse_cli().command {
        Command::Start(start) => app::run(start),
        Command::Service(service_opts) => service::run(service_opts),
    }
}
