/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! ForgeDNS binary entry point.
//!
//! The binary is intentionally thin: it parses CLI arguments and delegates to
//! either foreground runtime startup or operating-system service management.

use forgedns::app::cli::{self, Command};
use forgedns::core::error::Result;
use forgedns::{app, service};

fn main() -> Result<()> {
    match cli::parse_cli().command {
        Command::Start(start) => app::run(start),
        Command::Check(check) => app::check(check),
        Command::ExportDat(export) => app::export_dat::run(export),
        Command::Service(service_opts) => service::run(service_opts),
    }
}
