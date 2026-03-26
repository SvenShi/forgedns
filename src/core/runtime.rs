/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Runtime configuration and command-line argument parsing.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;

/// Core runtime container holding parsed start options.
pub struct Runtime {
    pub options: StartOptions,
    /// Log worker guard to ensure logs are flushed on shutdown
    pub log_guard: Option<WorkerGuard>,
}

/// Top-level CLI definition.
#[derive(Parser, Clone, Debug)]
#[command(version = "1.0", author = "Sven Shi <isvenshi@gmail.com>")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported top-level commands.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Start ForgeDNS in the foreground.
    Start(StartOptions),
    /// Manage the operating system service.
    Service(ServiceOptions),
}

/// Foreground start options.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct StartOptions {
    /// Path to configuration file
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    pub config: PathBuf,

    /// Working directory for ForgeDNS
    #[arg(short = 'd', long = "working-dir")]
    pub working_dir: Option<PathBuf>,

    /// Log level override (overrides config file): off, trace, debug, info, warn, error
    #[arg(short = 'l', long = "log-level")]
    pub log_level: Option<String>,
}

/// Service command options.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct ServiceOptions {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

/// Supported service manager actions.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum ServiceCommand {
    /// Install the system service. Installation only registers auto-start, it does not start immediately.
    Install(ServiceInstallOptions),
    /// Start the installed service.
    Start,
    /// Stop the installed service.
    Stop,
    /// Uninstall the installed service.
    Uninstall,
}

/// Service installation options.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct ServiceInstallOptions {
    /// Absolute working directory for the installed service.
    #[arg(short = 'd', long = "working-dir")]
    pub working_dir: PathBuf,

    /// Path to configuration file used by the installed service.
    #[arg(short = 'c', long = "config")]
    pub config: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_start_command_with_explicit_flags() {
        let args = [
            "forgedns",
            "start",
            "-c",
            "custom.yaml",
            "-d",
            "/tmp/forgedns",
            "-l",
            "debug",
        ];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Start(StartOptions {
                config: PathBuf::from("custom.yaml"),
                working_dir: Some(PathBuf::from("/tmp/forgedns")),
                log_level: Some("debug".to_string()),
            })
        );
    }

    #[test]
    fn parse_start_command_uses_default_config() {
        let args = ["forgedns", "start"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Start(StartOptions {
                config: PathBuf::from("config.yaml"),
                working_dir: None,
                log_level: None,
            })
        );
    }

    #[test]
    fn parse_service_install_command() {
        let args = [
            "forgedns",
            "service",
            "install",
            "-d",
            "/opt/forgedns",
            "-c",
            "/etc/forgedns/config.yaml",
        ];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Service(ServiceOptions {
                command: ServiceCommand::Install(ServiceInstallOptions {
                    working_dir: PathBuf::from("/opt/forgedns"),
                    config: PathBuf::from("/etc/forgedns/config.yaml"),
                }),
            })
        );
    }

    #[test]
    fn parse_service_start_command() {
        let args = ["forgedns", "service", "start"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Service(ServiceOptions {
                command: ServiceCommand::Start,
            })
        );
    }

    #[test]
    fn parse_service_stop_command() {
        let args = ["forgedns", "service", "stop"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Service(ServiceOptions {
                command: ServiceCommand::Stop,
            })
        );
    }

    #[test]
    fn parse_service_uninstall_command() {
        let args = ["forgedns", "service", "uninstall"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Service(ServiceOptions {
                command: ServiceCommand::Uninstall,
            })
        );
    }
}
