// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Application CLI definition and startup options.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde::Deserialize;

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
    /// Check, download, or apply ForgeDNS release upgrades.
    Upgrade(UpgradeOptions),
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

    /// Log level override (overrides config file): off, trace, debug, info,
    /// warn, error
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

/// Upgrade command options.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct UpgradeOptions {
    #[command(subcommand)]
    pub action: Option<UpgradeAction>,

    /// Release tag to use, or latest.
    #[arg(long = "target", default_value = "latest", global = true)]
    pub target: String,

    /// GitHub repository in owner/name form.
    #[arg(long = "repository", default_value = "SvenShi/forgedns", global = true)]
    pub repository: String,

    /// Release asset name, or auto for the current platform archive.
    #[arg(long = "asset", default_value = "auto", global = true)]
    pub asset: String,

    /// Directory used to cache downloaded release files.
    #[arg(long = "cache-dir", default_value = "./upgrade-cache", global = true)]
    pub cache_dir: PathBuf,

    /// Directory used to store binary backups before apply.
    #[arg(
        long = "backup-dir",
        default_value = "./upgrade-backups",
        global = true
    )]
    pub backup_dir: PathBuf,

    /// Restart strategy after a successful apply.
    #[arg(long = "restart", value_enum, default_value_t = RestartMode::None, global = true)]
    pub restart: RestartMode,

    /// Allow prerelease GitHub releases.
    #[arg(long = "allow-prerelease", default_value_t = false, global = true)]
    pub allow_prerelease: bool,

    /// Apply even when the selected release is not newer than the current
    /// version.
    #[arg(long = "force", default_value_t = false, global = true)]
    pub force: bool,

    /// Request timeout such as 30s, 2m, or 500ms.
    #[arg(long = "timeout", value_parser = parse_cli_duration, default_value = "30s", global = true)]
    pub timeout: Duration,

    /// Optional SOCKS5 proxy address.
    #[arg(long = "socks5", global = true)]
    pub socks5: Option<String>,

    /// Disable TLS certificate verification for upgrade downloads.
    #[arg(long = "insecure-skip-verify", default_value_t = false, global = true)]
    pub insecure_skip_verify: bool,
}

/// Upgrade subcommands.
#[derive(Subcommand, Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeAction {
    Check,
    Download,
    Apply,
}

/// Restart behavior after applying an upgrade.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartMode {
    None,
    Service,
}

fn parse_cli_duration(raw: &str) -> std::result::Result<Duration, String> {
    crate::core::system_utils::parse_simple_duration(raw)
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
    /// Install the system service. Installation only registers auto-start, it
    /// does not start immediately.
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
    use clap::Parser;

    use super::*;

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
    fn parse_upgrade_apply_with_options() {
        let args = [
            "forgedns",
            "upgrade",
            "apply",
            "--target",
            "v0.4.2",
            "--repository",
            "SvenShi/forgedns",
            "--asset",
            "forgedns-x86_64-unknown-linux-gnu.tar.gz",
            "--cache-dir",
            "./cache",
            "--backup-dir",
            "./backups",
            "--restart",
            "service",
            "--allow-prerelease",
            "--timeout",
            "2m",
            "--socks5",
            "127.0.0.1:1080",
            "--insecure-skip-verify",
        ];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Upgrade(UpgradeOptions {
                action: Some(UpgradeAction::Apply),
                target: "v0.4.2".to_string(),
                repository: "SvenShi/forgedns".to_string(),
                asset: "forgedns-x86_64-unknown-linux-gnu.tar.gz".to_string(),
                cache_dir: PathBuf::from("./cache"),
                backup_dir: PathBuf::from("./backups"),
                restart: RestartMode::Service,
                allow_prerelease: true,
                force: false,
                timeout: Duration::from_secs(120),
                socks5: Some("127.0.0.1:1080".to_string()),
                insecure_skip_verify: true,
            })
        );
    }

    #[test]
    fn parse_upgrade_defaults_to_apply_and_accepts_force() {
        let args = ["forgedns", "upgrade", "--force"];

        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.command,
            Command::Upgrade(UpgradeOptions {
                action: None,
                target: "latest".to_string(),
                repository: "SvenShi/forgedns".to_string(),
                asset: "auto".to_string(),
                cache_dir: PathBuf::from("./upgrade-cache"),
                backup_dir: PathBuf::from("./upgrade-backups"),
                restart: RestartMode::None,
                allow_prerelease: false,
                force: true,
                timeout: Duration::from_secs(30),
                socks5: None,
                insecure_skip_verify: false,
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
