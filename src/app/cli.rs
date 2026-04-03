/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Application CLI definition and startup options.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Top-level CLI definition.
#[derive(Parser, Clone, Debug)]
#[command(version, author = "Sven Shi <isvenshi@gmail.com>")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported top-level commands.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Start ForgeDNS in the foreground.
    Start(StartOptions),
    /// Check whether a configuration file is valid.
    Check(CheckOptions),
    /// Export selected rules from a dat file into text files.
    ExportDat(ExportDatOptions),
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

/// Static configuration check options.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct CheckOptions {
    /// Path to configuration file
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    pub config: PathBuf,

    /// Working directory for resolving relative paths
    #[arg(short = 'd', long = "working-dir")]
    pub working_dir: Option<PathBuf>,

    /// Print plugin dependency graph after validation succeeds
    #[arg(long = "graph", default_value_t = false)]
    pub graph: bool,
}

/// Dat export options.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct ExportDatOptions {
    /// Path to the source dat file
    #[arg(long = "file")]
    pub file: PathBuf,

    /// Explicit dat kind: auto, geosite, geoip
    #[arg(long = "kind", value_enum, default_value_t = DatKind::Auto)]
    pub kind: DatKind,

    /// Output text format: forgedns or original
    #[arg(long = "format", value_enum, default_value_t = ExportFormat::Forgedns)]
    pub format: ExportFormat,

    /// Selector to export; repeat this flag to export multiple selectors
    #[arg(long = "selector")]
    pub selectors: Vec<String>,

    /// Output directory for exported files
    #[arg(long = "out-dir")]
    pub out_dir: PathBuf,

    /// Optional merged output file name written inside --out-dir
    #[arg(long = "merged-file")]
    pub merged_file: Option<String>,

    /// Allow overwriting existing output files
    #[arg(long = "overwrite", default_value_t = false)]
    pub overwrite: bool,
}

/// Supported dat kinds.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatKind {
    Auto,
    Geosite,
    Geoip,
}

/// Supported export text formats.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Forgedns,
    Original,
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

/// Parse command-line options for ForgeDNS.
pub fn parse_cli() -> Cli {
    <Cli as clap::Parser>::parse()
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
    fn parse_check_command_uses_default_config() {
        let args = ["forgedns", "check"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Check(CheckOptions {
                config: PathBuf::from("config.yaml"),
                working_dir: None,
                graph: false,
            })
        );
    }

    #[test]
    fn parse_check_command_with_explicit_config() {
        let args = ["forgedns", "check", "-c", "custom.yaml"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Check(CheckOptions {
                config: PathBuf::from("custom.yaml"),
                working_dir: None,
                graph: false,
            })
        );
    }

    #[test]
    fn parse_check_command_with_working_dir() {
        let args = [
            "forgedns",
            "check",
            "-c",
            "custom.yaml",
            "-d",
            "/tmp/forgedns",
        ];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Check(CheckOptions {
                config: PathBuf::from("custom.yaml"),
                working_dir: Some(PathBuf::from("/tmp/forgedns")),
                graph: false,
            })
        );
    }

    #[test]
    fn parse_check_command_with_graph() {
        let args = ["forgedns", "check", "--graph"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Check(CheckOptions {
                config: PathBuf::from("config.yaml"),
                working_dir: None,
                graph: true,
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

    #[test]
    fn parse_export_dat_command() {
        let args = [
            "forgedns",
            "export-dat",
            "--file",
            "rules/geosite.dat",
            "--selector",
            "cn",
            "--selector",
            "geolocation-!cn",
            "--out-dir",
            "/tmp/out",
            "--kind",
            "geosite",
            "--format",
            "original",
            "--merged-file",
            "all.txt",
            "--overwrite",
        ];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::ExportDat(ExportDatOptions {
                file: PathBuf::from("rules/geosite.dat"),
                kind: DatKind::Geosite,
                format: ExportFormat::Original,
                selectors: vec!["cn".to_string(), "geolocation-!cn".to_string()],
                out_dir: PathBuf::from("/tmp/out"),
                merged_file: Some("all.txt".to_string()),
                overwrite: true,
            })
        );
    }

    #[test]
    fn parse_export_dat_command_without_selectors() {
        let args = [
            "forgedns",
            "export-dat",
            "--file",
            "rules/geoip.dat",
            "--out-dir",
            "/tmp/out",
        ];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::ExportDat(ExportDatOptions {
                file: PathBuf::from("rules/geoip.dat"),
                kind: DatKind::Auto,
                format: ExportFormat::Forgedns,
                selectors: Vec::new(),
                out_dir: PathBuf::from("/tmp/out"),
                merged_file: None,
                overwrite: false,
            })
        );
    }
}
