// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Release upgrade support shared by the CLI and executor plugin.

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use http::header::{HeaderValue, USER_AGENT};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use tracing::info;

use crate::app::cli::{RestartMode, UpgradeAction, UpgradeOptions};
use crate::core::VERSION;
use crate::core::error::{DnsError, Result};
use crate::network::http_client::{
    DownloadProgress, HttpClient, HttpClientOptions, HttpRequestOptions,
};
use crate::network::upstream::parse_socks5_opt;
use crate::service;

const DEFAULT_REPOSITORY: &str = "SvenShi/forgedns";
const DEFAULT_TARGET: &str = "latest";
const DEFAULT_CACHE_DIR: &str = "./upgrade-cache";
const DEFAULT_BACKUP_DIR: &str = "./upgrade-backups";

const EXIT_RESTART_REQUIRED: i32 = 75;
const GITHUB_USER_AGENT: &str = "ForgeDNS";

#[derive(Debug, Clone)]
pub struct UpgradeConfig {
    pub target: String,
    pub repository: String,
    pub asset: String,
    pub cache_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub restart: RestartMode,
    pub allow_prerelease: bool,
    pub force: bool,
    pub cleanup_after_apply: bool,
    pub timeout: Duration,
    pub socks5: Option<String>,
    pub insecure_skip_verify: bool,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            target: DEFAULT_TARGET.to_string(),
            repository: DEFAULT_REPOSITORY.to_string(),
            asset: "auto".to_string(),
            cache_dir: PathBuf::from(DEFAULT_CACHE_DIR),
            backup_dir: PathBuf::from(DEFAULT_BACKUP_DIR),
            restart: RestartMode::None,
            allow_prerelease: false,
            force: false,
            cleanup_after_apply: false,
            timeout: Duration::from_secs(30),
            socks5: None,
            insecure_skip_verify: false,
        }
    }
}

impl UpgradeConfig {
    pub fn from_cli(options: &UpgradeOptions) -> Self {
        Self {
            target: options.target.clone(),
            repository: options.repository.clone(),
            asset: options.asset.clone(),
            cache_dir: options.cache_dir.clone(),
            backup_dir: options.backup_dir.clone(),
            restart: options.restart,
            allow_prerelease: options.allow_prerelease,
            force: options.force,
            cleanup_after_apply: false,
            timeout: options.timeout,
            socks5: options.socks5.clone(),
            insecure_skip_verify: options.insecure_skip_verify,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpgradeDownload {
    pub version: String,
    pub asset_name: String,
    pub archive_path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct UpgradeCheck {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub asset_name: String,
    pub release_url: String,
}

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub installed_version: String,
    pub asset_name: String,
    pub backup_path: PathBuf,
    pub binary_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeContext {
    Cli,
    Plugin,
}

pub fn run_cli(action: UpgradeAction, config: UpgradeConfig) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| DnsError::runtime(format!("failed to create upgrade runtime: {err}")))?;

    runtime.block_on(async move {
        match action {
            UpgradeAction::Check => {
                print_cli_plan("check", &config);
                println!("Checking GitHub release metadata...");
                let check = check(&config).await?;
                println!(
                    "Current: {}, release: {}, asset: {}, update_available: {}",
                    check.current_version,
                    check.latest_version,
                    check.asset_name,
                    check.update_available
                );
                println!("Release: {}", check.release_url);
            }
            UpgradeAction::Download => {
                print_cli_plan("download", &config);
                println!("Resolving release asset...");
                println!("Downloading archive without checking the current version...");
                let progress_reporter = UpgradeDownloadProgressReporter::new(UpgradeContext::Cli);
                let download = download(&config, move |progress| {
                    progress_reporter.report(progress);
                })
                .await?;
                println!(
                    "Downloaded {} as {}",
                    download.asset_name,
                    download.archive_path.display()
                );
                println!("SHA256: {}", download.sha256);
                println!("Archive verified successfully.");
            }
            UpgradeAction::Apply => {
                print_cli_plan("apply", &config);
                println!("Checking whether an upgrade is needed...");
                match should_apply(&config).await? {
                    ApplyDecision::Apply { check } => {
                        if config.force {
                            println!(
                                "Force enabled: applying release {} even if it is not newer than current {}.",
                                check.latest_version, check.current_version
                            );
                        } else {
                            println!(
                                "Update available: current {}, release {}, asset {}.",
                                check.current_version, check.latest_version, check.asset_name
                            );
                        }
                        println!("Downloading, verifying, and replacing the current binary...");
                        let outcome = apply_unchecked(&config, UpgradeContext::Cli).await?;
                        if config.restart == RestartMode::Service {
                            println!("Service restart completed.");
                        }
                        println!(
                            "Installed {} from {}",
                            outcome.installed_version, outcome.asset_name
                        );
                        println!("Binary: {}", outcome.binary_path.display());
                        println!("Backup: {}", outcome.backup_path.display());
                        if prompt_cleanup_after_apply()? {
                            match cleanup_upgrade_artifacts(&config) {
                                Ok(cleaned) => {
                                    if cleaned.is_empty() {
                                        println!("No backup or cache directories to clean.");
                                    } else {
                                        for path in cleaned {
                                            println!("Cleaned: {}", path.display());
                                        }
                                    }
                                }
                                Err(err) => {
                                    println!("Cleanup failed: {err}");
                                }
                            }
                        } else {
                            println!("Cleanup skipped.");
                        }
                    }
                    ApplyDecision::Skip { check } => {
                        println!(
                            "No update available: current {}, release {}, asset {}",
                            check.current_version, check.latest_version, check.asset_name
                        );
                    }
                }
            }
        }
        Ok(())
    })
}

fn print_cli_plan(action: &str, config: &UpgradeConfig) {
    println!("ForgeDNS upgrade {action}");
    println!("Repository: {}", config.repository);
    println!("Target: {}", config.target);
    println!("Asset: {}", config.asset);
    println!("Cache: {}", config.cache_dir.display());
    if action == "apply" {
        println!("Backup: {}", config.backup_dir.display());
        println!("Restart: {:?}", config.restart);
        println!("Force: {}", config.force);
    }
    println!("Timeout: {:?}", config.timeout);
    if let Some(socks5) = config.socks5.as_deref() {
        println!("SOCKS5: {}", socks5);
    }
    if config.insecure_skip_verify {
        println!("TLS verification: disabled");
    }
}

pub async fn check(config: &UpgradeConfig) -> Result<UpgradeCheck> {
    let release = fetch_release(config).await?;
    let asset = select_asset(config, &release)?;
    let current_version = VERSION.to_string();
    let latest_version = release.version_string();
    let update_available = is_newer_version(&latest_version, &current_version);
    Ok(UpgradeCheck {
        current_version,
        latest_version,
        update_available,
        asset_name: asset.name.clone(),
        release_url: release.html_url.unwrap_or_default(),
    })
}

#[derive(Debug, Clone)]
pub enum ApplyDecision {
    Apply { check: UpgradeCheck },
    Skip { check: UpgradeCheck },
}

#[derive(Debug, Clone)]
pub enum ApplyRunOutcome {
    Applied {
        check: UpgradeCheck,
        outcome: ApplyOutcome,
    },
    Skipped {
        check: UpgradeCheck,
    },
}

pub async fn should_apply(config: &UpgradeConfig) -> Result<ApplyDecision> {
    let check = check(config).await?;
    if config.force || check.update_available {
        Ok(ApplyDecision::Apply { check })
    } else {
        Ok(ApplyDecision::Skip { check })
    }
}

async fn download<F>(config: &UpgradeConfig, progress: F) -> Result<UpgradeDownload>
where
    F: FnMut(DownloadProgress),
{
    let release = fetch_release(config).await?;
    let asset = select_asset(config, &release)?;
    let expected = sha256_from_asset_digest(asset)?;
    let client = build_asset_http_client(config)?;
    fs::create_dir_all(&config.cache_dir).map_err(|err| {
        DnsError::runtime(format!(
            "failed to create upgrade cache directory '{}': {}",
            config.cache_dir.display(),
            err
        ))
    })?;

    let archive_path = config.cache_dir.join(&asset.name);
    timeout(
        config.timeout,
        client.download_with_progress(
            HttpRequestOptions::from_url(asset.browser_download_url.as_str()).with_headers(vec![(
                USER_AGENT,
                HeaderValue::from_static(GITHUB_USER_AGENT),
            )]),
            &archive_path,
            progress,
        ),
    )
    .await
    .map_err(|_| DnsError::runtime("upgrade archive download timed out"))??;

    verify_sha256(&archive_path, &expected)?;
    Ok(UpgradeDownload {
        version: release.version_string(),
        asset_name: asset.name.clone(),
        archive_path,
        sha256: expected,
    })
}

pub async fn apply(
    config: &UpgradeConfig,
    restart_context: UpgradeContext,
) -> Result<ApplyRunOutcome> {
    let decision = should_apply(config).await?;
    apply_decision(config, restart_context, decision).await
}

pub async fn apply_decision(
    config: &UpgradeConfig,
    restart_context: UpgradeContext,
    decision: ApplyDecision,
) -> Result<ApplyRunOutcome> {
    match decision {
        ApplyDecision::Apply { check } => {
            let outcome = apply_unchecked(config, restart_context).await?;
            Ok(ApplyRunOutcome::Applied { check, outcome })
        }
        ApplyDecision::Skip { check } => Ok(ApplyRunOutcome::Skipped { check }),
    }
}

async fn apply_unchecked(
    config: &UpgradeConfig,
    restart_context: UpgradeContext,
) -> Result<ApplyOutcome> {
    #[cfg(windows)]
    {
        let _ = config;
        return Err(DnsError::runtime(
            "upgrade apply is not supported on Windows; use check or download",
        ));
    }

    #[cfg(not(windows))]
    {
        print_cli_apply_step(restart_context, "Acquiring upgrade lock...");
        let lock_path = config.cache_dir.join(".upgrade.lock");
        fs::create_dir_all(&config.cache_dir)?;
        let lock_file = File::create(&lock_path).map_err(|err| {
            DnsError::runtime(format!(
                "failed to create upgrade lock '{}': {}",
                lock_path.display(),
                err
            ))
        })?;
        lock_file.try_lock_exclusive().map_err(|err| {
            DnsError::runtime(format!("another upgrade appears to be running: {err}"))
        })?;

        print_cli_apply_step(
            restart_context,
            "Downloading archive and verifying GitHub asset digest...",
        );
        let progress_reporter = UpgradeDownloadProgressReporter::new(restart_context);
        let downloaded = download(config, move |progress| {
            progress_reporter.report(progress);
        })
        .await?;
        print_cli_apply_step(
            restart_context,
            format!(
                "Archive ready: {} (sha256 {})",
                downloaded.archive_path.display(),
                downloaded.sha256
            ),
        );
        if !downloaded.asset_name.ends_with(".tar.gz") {
            return Err(DnsError::runtime(format!(
                "upgrade apply requires a .tar.gz asset, got '{}'",
                downloaded.asset_name
            )));
        }

        let unpack_dir = config.cache_dir.join(format!(
            ".unpack-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));
        if unpack_dir.exists() {
            fs::remove_dir_all(&unpack_dir)?;
        }
        fs::create_dir_all(&unpack_dir)?;
        print_cli_apply_step(
            restart_context,
            format!("Unpacking archive into {}...", unpack_dir.display()),
        );
        unpack_tar_gz(&downloaded.archive_path, &unpack_dir)?;

        let extracted = find_extracted_binary(&unpack_dir)?;
        let current_exe = std::env::current_exe()
            .map_err(|err| DnsError::runtime(format!("failed to resolve current exe: {err}")))?;
        fs::create_dir_all(&config.backup_dir)?;
        let backup_path = config.backup_dir.join(format!(
            "forgedns-{}-{}",
            VERSION,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));

        print_cli_apply_step(
            restart_context,
            format!("Creating backup at {}...", backup_path.display()),
        );
        fs::copy(&current_exe, &backup_path).map_err(|err| {
            DnsError::runtime(format!(
                "failed to create binary backup '{}': {}",
                backup_path.display(),
                err
            ))
        })?;

        print_cli_apply_step(
            restart_context,
            format!("Replacing binary at {}...", current_exe.display()),
        );
        if let Err(err) = replace_binary(&extracted, &current_exe) {
            let _ = fs::copy(&backup_path, &current_exe);
            return Err(err);
        }
        print_cli_apply_step(restart_context, "Binary replacement completed.");

        if config.cleanup_after_apply {
            let _ = cleanup_upgrade_artifacts(config);
        }

        if config.restart == RestartMode::Service {
            print_cli_apply_step(restart_context, "Restarting installed service...");
            restart_after_apply(restart_context)?;
        }

        Ok(ApplyOutcome {
            installed_version: downloaded.version,
            asset_name: downloaded.asset_name,
            backup_path,
            binary_path: current_exe,
        })
    }
}

#[derive(Clone)]
struct UpgradeDownloadProgressReporter {
    restart_context: UpgradeContext,
    state: std::sync::Arc<std::sync::Mutex<UpgradeDownloadProgressState>>,
}

#[derive(Debug, Default)]
struct UpgradeDownloadProgressState {
    last_percent_bucket: Option<u64>,
    last_unknown_bucket: u64,
}

impl UpgradeDownloadProgressReporter {
    fn new(restart_context: UpgradeContext) -> Self {
        Self {
            restart_context,
            state: Default::default(),
        }
    }

    fn report(&self, progress: DownloadProgress) {
        match self.restart_context {
            UpgradeContext::Cli => self.report_cli(progress),
            UpgradeContext::Plugin => self.report_plugin(progress),
        }
    }

    fn report_cli(&self, progress: DownloadProgress) {
        match progress.total {
            Some(total) if total > 0 => {
                let percent = progress.downloaded.saturating_mul(100) / total;
                print!(
                    "\rDownload progress: {}% ({}/{})",
                    percent,
                    format_bytes(progress.downloaded),
                    format_bytes(total)
                );
                let _ = std::io::stdout().flush();
                if progress.downloaded >= total {
                    println!();
                }
            }
            _ => {
                print!("\rDownload progress: {}", format_bytes(progress.downloaded));
                let _ = std::io::stdout().flush();
            }
        }
    }

    fn report_plugin(&self, progress: DownloadProgress) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };

        match progress.total {
            Some(total) if total > 0 => {
                let percent = progress.downloaded.saturating_mul(100) / total;
                let bucket = (percent / 10) * 10;
                let should_log = state.last_percent_bucket != Some(bucket)
                    || progress.downloaded >= total && state.last_percent_bucket != Some(100);
                if should_log {
                    state.last_percent_bucket = Some(bucket);
                    info!(
                        downloaded = progress.downloaded,
                        total, percent, "upgrade archive download progress"
                    );
                }
            }
            _ => {
                let bucket = progress.downloaded / (1024 * 1024);
                if bucket > state.last_unknown_bucket {
                    state.last_unknown_bucket = bucket;
                    info!(
                        downloaded = progress.downloaded,
                        "upgrade archive download progress"
                    );
                }
            }
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        format!("{:.1} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.1} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.1} KiB", bytes_f / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn prompt_cleanup_after_apply() -> Result<bool> {
    loop {
        print!("Clean backup and cache directories? (Y/n): ");
        std::io::stdout()
            .flush()
            .map_err(|err| DnsError::runtime(format!("failed to flush stdout: {err}")))?;

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|err| DnsError::runtime(format!("failed to read cleanup choice: {err}")))?;

        match input.trim().to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer Y or n."),
        }
    }
}

fn cleanup_upgrade_artifacts(config: &UpgradeConfig) -> Result<Vec<PathBuf>> {
    let mut cleaned = Vec::new();
    cleanup_dir_if_exists(&config.cache_dir, &mut cleaned)?;
    if config.backup_dir != config.cache_dir {
        cleanup_dir_if_exists(&config.backup_dir, &mut cleaned)?;
    }
    Ok(cleaned)
}

fn cleanup_dir_if_exists(path: &Path, cleaned: &mut Vec<PathBuf>) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_dir_all(path).map_err(|err| {
        DnsError::runtime(format!(
            "failed to remove upgrade directory '{}': {}",
            path.display(),
            err
        ))
    })?;
    cleaned.push(path.to_path_buf());
    Ok(())
}

fn print_cli_apply_step(restart_context: UpgradeContext, message: impl AsRef<str>) {
    match restart_context {
        UpgradeContext::Cli => println!("{}", message.as_ref()),
        UpgradeContext::Plugin => info!(message = message.as_ref(), "upgrade apply step"),
    }
}

#[cfg(not(windows))]
fn restart_after_apply(restart_context: UpgradeContext) -> Result<()> {
    match restart_context {
        UpgradeContext::Cli => service::restart_installed_service(),
        UpgradeContext::Plugin => std::process::exit(EXIT_RESTART_REQUIRED),
    }
}

async fn fetch_release(config: &UpgradeConfig) -> Result<GitHubRelease> {
    let url = if config.target.trim() == "latest" {
        format!(
            "https://api.github.com/repos/{}/releases/latest",
            config.repository
        )
    } else {
        format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            config.repository,
            config.target.trim()
        )
    };
    let client = build_asset_http_client(config)?;
    let response = timeout(
        config.timeout,
        client.get_request(
            HttpRequestOptions::from_url(url.as_str()).with_headers(vec![(
                USER_AGENT,
                HeaderValue::from_static(GITHUB_USER_AGENT),
            )]),
        ),
    )
    .await
    .map_err(|_| DnsError::runtime("GitHub release request timed out"))??;
    let release = serde_json::from_slice::<GitHubRelease>(&response.body).map_err(|err| {
        DnsError::runtime(format!("failed to parse GitHub release response: {err}"))
    })?;
    if release.prerelease && !config.allow_prerelease {
        return Err(DnsError::runtime(format!(
            "release '{}' is a prerelease; pass allow_prerelease to use it",
            release.tag_name
        )));
    }
    Ok(release)
}

fn build_asset_http_client(config: &UpgradeConfig) -> Result<HttpClient> {
    let socks5 =
        match config
            .socks5
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            Some(raw) => Some(parse_socks5_opt(raw).ok_or_else(|| {
                DnsError::runtime(format!("invalid upgrade socks5 proxy '{raw}'"))
            })?),
            None => None,
        };
    Ok(HttpClient::new(HttpClientOptions {
        insecure_skip_verify: config.insecure_skip_verify,
        socks5,
    }))
}

fn select_asset<'a>(
    config: &UpgradeConfig,
    release: &'a GitHubRelease,
) -> Result<&'a ReleaseAsset> {
    if config.asset.trim() != "auto" {
        return find_asset(release, config.asset.trim());
    }
    let expected = current_archive_name()?;
    find_asset(release, &expected)
}

fn find_asset<'a>(release: &'a GitHubRelease, name: &str) -> Result<&'a ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or_else(|| {
            DnsError::runtime(format!(
                "release '{}' does not contain asset '{}'",
                release.tag_name, name
            ))
        })
}

fn current_archive_name() -> Result<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "x86" => "i686",
        "arm" => "arm",
        other => {
            return Err(DnsError::runtime(format!(
                "unsupported upgrade architecture '{other}'"
            )));
        }
    };
    let target = match std::env::consts::OS {
        "linux" => {
            if arch == "arm" {
                "arm-unknown-linux-musleabihf".to_string()
            } else {
                format!("{arch}-unknown-linux-musl")
            }
        }
        "macos" => format!("{arch}-apple-darwin"),
        "freebsd" => format!("{arch}-unknown-freebsd"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        other => {
            return Err(DnsError::runtime(format!(
                "unsupported upgrade OS '{other}'"
            )));
        }
    };
    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    Ok(format!("forgedns-{target}.{ext}"))
}

fn sha256_from_asset_digest(asset: &ReleaseAsset) -> Result<String> {
    let raw = asset.digest.as_deref().ok_or_else(|| {
        DnsError::runtime(format!(
            "release asset '{}' does not include a digest",
            asset.name
        ))
    })?;
    let Some(hash) = raw.strip_prefix("sha256:") else {
        return Err(DnsError::runtime(format!(
            "release asset '{}' uses unsupported digest '{}'",
            asset.name, raw
        )));
    };
    if hash.len() != 64 || hex::decode(hash).is_err() {
        return Err(DnsError::runtime(format!(
            "release asset '{}' has invalid SHA256 digest '{}'",
            asset.name, raw
        )));
    }
    Ok(hash.to_ascii_lowercase())
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if actual != expected.to_ascii_lowercase() {
        return Err(DnsError::runtime(format!(
            "SHA256 mismatch for '{}': expected {}, got {}",
            path.display(),
            expected,
            actual
        )));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|err| {
        DnsError::runtime(format!("failed to open '{}': {}", path.display(), err))
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            DnsError::runtime(format!("failed to read '{}': {}", path.display(), err))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(not(windows))]
fn unpack_tar_gz(archive: &Path, out_dir: &Path) -> Result<()> {
    let file = File::open(archive).map_err(|err| {
        DnsError::runtime(format!(
            "failed to open archive '{}': {}",
            archive.display(),
            err
        ))
    })?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(out_dir).map_err(|err| {
        DnsError::runtime(format!(
            "failed to unpack archive into '{}': {}",
            out_dir.display(),
            err
        ))
    })
}

#[cfg(not(windows))]
fn find_extracted_binary(unpack_dir: &Path) -> Result<PathBuf> {
    let candidate = unpack_dir.join("forgedns");
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(DnsError::runtime(format!(
        "archive did not contain forgedns binary at '{}'",
        candidate.display()
    )))
}

#[cfg(not(windows))]
fn replace_binary(source: &Path, target: &Path) -> Result<()> {
    let tmp = target.with_extension("forgedns-upgrade-new");
    fs::copy(source, &tmp).map_err(|err| {
        DnsError::runtime(format!(
            "failed to stage upgraded binary '{}': {}",
            tmp.display(),
            err
        ))
    })?;
    let permissions = fs::metadata(source)?.permissions();
    fs::set_permissions(&tmp, permissions)?;
    fs::rename(&tmp, target).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        DnsError::runtime(format!(
            "failed to replace binary '{}': {}",
            target.display(),
            err
        ))
    })
}

fn is_newer_version(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Ok(candidate), Ok(current)) => candidate > current,
        _ => candidate != current,
    }
}

fn parse_version(raw: &str) -> std::result::Result<Version, semver::Error> {
    Version::parse(raw.trim_start_matches('v'))
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    prerelease: bool,
    html_url: Option<String>,
    assets: Vec<ReleaseAsset>,
}

impl GitHubRelease {
    fn version_string(&self) -> String {
        self.tag_name.trim_start_matches('v').to_string()
    }
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asset_sha256_digest() {
        let asset = ReleaseAsset {
            name: "forgedns.tar.gz".to_string(),
            browser_download_url: "https://example.com/forgedns.tar.gz".to_string(),
            digest: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            ),
        };
        let parsed = sha256_from_asset_digest(&asset).unwrap();
        assert_eq!(
            parsed,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn version_compare_handles_v_prefix() {
        assert!(is_newer_version("v0.4.2", "0.4.1"));
        assert!(!is_newer_version("v0.4.1", "0.4.1"));
    }
}
