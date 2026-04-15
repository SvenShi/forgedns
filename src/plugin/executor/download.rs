/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `download` executor plugin.
//!
//! Downloads one or more remote `http/https` files into local directories and
//! overwrites the target files after the new content is fully written.
//!
//! Execution semantics:
//! - each configured download runs sequentially in declaration order;
//! - a failed item logs a warning and does not stop later items;
//! - the executor always returns [`ExecStep::Next`]; and
//! - the DNS request/response itself is never mutated.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::parse_simple_duration;
use crate::network::tls_config::{insecure_client_config, secure_client_config};
use crate::network::upstream::{Socks5Opt, connect_tcp_stream, parse_socks5_opt};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use http::Uri;
use http::header::LOCATION;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tower_service::Service;
use tracing::{info, warn};
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

type DownloadClient = Client<hyper_rustls::HttpsConnector<DownloadHttpConnector>, Empty<Bytes>>;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DownloadConfig {
    timeout: Option<String>,
    insecure_skip_verify: Option<bool>,
    socks5: Option<String>,
    startup_if_missing: Option<bool>,
    downloads: Vec<DownloadItemConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadItemConfig {
    url: String,
    dir: String,
    filename: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DownloadTarget {
    url: String,
    dir: PathBuf,
    filename: String,
    path: PathBuf,
}

#[derive(Debug)]
struct DownloadExecutor {
    tag: String,
    client: DownloadClient,
    timeout: Duration,
    downloads: Vec<DownloadTarget>,
    insecure_skip_verify: bool,
    socks5: Option<String>,
}

#[async_trait]
impl Plugin for DownloadExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for DownloadExecutor {
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        let mut success_count = 0usize;
        let mut failure_count = 0usize;

        for item in &self.downloads {
            match timeout(self.timeout, self.download_one(item)).await {
                Ok(Ok(())) => {
                    success_count += 1;
                    info!(
                        plugin = %self.tag,
                        url = %item.url,
                        target = %item.path.display(),
                        timeout_ms = self.timeout.as_millis(),
                        insecure_skip_verify = self.insecure_skip_verify,
                        socks5 = self.socks5.as_deref().unwrap_or(""),
                        "download completed"
                    );
                }
                Ok(Err(err)) => {
                    failure_count += 1;
                    warn!(
                        plugin = %self.tag,
                        url = %item.url,
                        target = %item.path.display(),
                        error = %err,
                        "download failed; continuing with remaining items"
                    );
                }
                Err(_) => {
                    failure_count += 1;
                    warn!(
                        plugin = %self.tag,
                        url = %item.url,
                        target = %item.path.display(),
                        timeout_ms = self.timeout.as_millis(),
                        "download timed out; continuing with remaining items"
                    );
                }
            }
        }

        info!(
            plugin = %self.tag,
            successes = success_count,
            failures = failure_count,
            total = self.downloads.len(),
            "download batch finished"
        );

        Ok(ExecStep::Next)
    }
}

impl DownloadExecutor {
    async fn download_one(&self, item: &DownloadTarget) -> Result<()> {
        let mut current_url = item.url.clone();

        for redirect_count in 0..=MAX_REDIRECTS {
            let uri = current_url.parse::<Uri>().map_err(|e| {
                DnsError::plugin(format!("invalid download url '{}': {}", current_url, e))
            })?;

            let request = Request::get(uri)
                .body(Empty::<Bytes>::new())
                .map_err(|e| DnsError::plugin(format!("failed to build request: {}", e)))?;

            let response = self.client.request(request).await.map_err(|e| {
                DnsError::plugin(format!("request failed for '{}': {}", current_url, e))
            })?;
            let status = response.status();
            if status.is_success() {
                return write_target_file(item.path.as_path(), response.into_body()).await;
            }

            if status.is_redirection() {
                if redirect_count == MAX_REDIRECTS {
                    return Err(DnsError::plugin(format!(
                        "request failed for '{}': too many redirects",
                        item.url
                    )));
                }

                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| {
                        DnsError::plugin(format!(
                            "request failed for '{}': redirect {} missing Location header",
                            current_url,
                            format_status(status)
                        ))
                    })?
                    .to_str()
                    .map_err(|e| {
                        DnsError::plugin(format!(
                            "request failed for '{}': invalid redirect Location header: {}",
                            current_url, e
                        ))
                    })?;

                current_url = resolve_redirect_url(current_url.as_str(), location)?;
                continue;
            }

            return Err(DnsError::plugin(format!(
                "request failed for '{}': unexpected status {}",
                current_url,
                format_status(status)
            )));
        }

        Err(DnsError::plugin(format!(
            "request failed for '{}': too many redirects",
            item.url
        )))
    }
}

#[derive(Debug, Clone)]
pub struct DownloadFactory;

#[derive(Clone, Debug)]
struct DownloadHttpConnector {
    socks5: Option<Socks5Opt>,
}

impl Service<Uri> for DownloadHttpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = DnsError;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let socks5 = self.socks5.clone();
        Box::pin(async move {
            let host = dst.host().ok_or_else(|| {
                DnsError::plugin(format!("download request uri '{}' is missing host", dst))
            })?;
            let port = dst
                .port_u16()
                .or_else(|| match dst.scheme_str() {
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                })
                .ok_or_else(|| {
                    DnsError::plugin(format!(
                        "download request uri '{}' uses unsupported or missing scheme",
                        dst
                    ))
                })?;
            let remote_ip = host.parse::<IpAddr>().ok();
            let stream = connect_tcp_stream(remote_ip, host.to_string(), port, socks5).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

register_plugin_factory!("download", DownloadFactory {});

impl PluginFactory for DownloadFactory {
    fn prepare_startup<'a>(
        &'a self,
        plugin_config: &'a PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> BoxFuture<'a, Result<()>> {
        let plugin_tag = plugin_config.tag.clone();
        Box::pin(async move {
            let runtime = build_download_runtime_config(plugin_config)?;
            if !runtime.startup_if_missing {
                return Ok(());
            }

            let missing_targets = runtime
                .downloads
                .iter()
                .filter(|item| !item.path.exists())
                .collect::<Vec<_>>();

            if missing_targets.is_empty() {
                info!(
                    plugin = %plugin_tag,
                    total = runtime.downloads.len(),
                    "startup download skipped; all target files already exist"
                );
                return Ok(());
            }

            let executor = DownloadExecutor {
                tag: plugin_tag.clone(),
                client: build_client(runtime.insecure_skip_verify, runtime.parsed_socks5),
                timeout: runtime.timeout,
                downloads: runtime.downloads.clone(),
                insecure_skip_verify: runtime.insecure_skip_verify,
                socks5: runtime.raw_socks5,
            };

            info!(
                plugin = %plugin_tag,
                missing = missing_targets.len(),
                total = runtime.downloads.len(),
                timeout_ms = runtime.timeout.as_millis(),
                "startup download began for missing target files"
            );

            for item in missing_targets {
                match timeout(executor.timeout, executor.download_one(item)).await {
                    Ok(Ok(())) => {
                        info!(
                            plugin = %executor.tag,
                            url = %item.url,
                            target = %item.path.display(),
                            "startup download completed for missing target"
                        );
                    }
                    Ok(Err(err)) => {
                        return Err(DnsError::plugin(format!(
                            "startup download failed for '{}' -> '{}': {}",
                            item.url,
                            item.path.display(),
                            err
                        )));
                    }
                    Err(_) => {
                        return Err(DnsError::plugin(format!(
                            "startup download timed out for '{}' -> '{}'",
                            item.url,
                            item.path.display()
                        )));
                    }
                }
            }

            Ok(())
        })
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let runtime = build_download_runtime_config(plugin_config)?;

        Ok(UninitializedPlugin::Executor(Box::new(DownloadExecutor {
            tag: plugin_config.tag.clone(),
            client: build_client(runtime.insecure_skip_verify, runtime.parsed_socks5),
            timeout: runtime.timeout,
            downloads: runtime.downloads,
            insecure_skip_verify: runtime.insecure_skip_verify,
            socks5: runtime.raw_socks5,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let raw = param.ok_or_else(|| {
            DnsError::plugin("download quick setup requires '<url> <dir>' arguments")
        })?;
        let (url, dir) = parse_quick_setup(raw.as_str())?;
        let downloads = resolve_download_targets(
            tag,
            vec![DownloadItemConfig {
                url,
                dir,
                filename: None,
            }],
        )?;

        Ok(UninitializedPlugin::Executor(Box::new(DownloadExecutor {
            tag: tag.to_string(),
            client: build_client(false, None),
            timeout: DEFAULT_TIMEOUT,
            downloads,
            insecure_skip_verify: false,
            socks5: None,
        })))
    }
}

struct DownloadRuntimeConfig {
    timeout: Duration,
    downloads: Vec<DownloadTarget>,
    insecure_skip_verify: bool,
    startup_if_missing: bool,
    raw_socks5: Option<String>,
    parsed_socks5: Option<Socks5Opt>,
}

fn build_download_runtime_config(plugin_config: &PluginConfig) -> Result<DownloadRuntimeConfig> {
    let cfg = plugin_config
        .args
        .clone()
        .ok_or_else(|| DnsError::plugin("download requires configuration arguments"))
        .and_then(parse_download_config)?;

    Ok(DownloadRuntimeConfig {
        timeout: parse_timeout(cfg.timeout.as_deref())?,
        parsed_socks5: parse_socks5(cfg.socks5.as_deref())?,
        downloads: resolve_download_targets(&plugin_config.tag, cfg.downloads)?,
        insecure_skip_verify: cfg.insecure_skip_verify.unwrap_or(false),
        startup_if_missing: cfg.startup_if_missing.unwrap_or(true),
        raw_socks5: cfg.socks5,
    })
}

fn parse_download_config(args: Value) -> Result<DownloadConfig> {
    serde_yaml_ng::from_value::<DownloadConfig>(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse download config: {}", e)))
}

fn parse_timeout(raw: Option<&str>) -> Result<Duration> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(DEFAULT_TIMEOUT);
    };
    parse_simple_duration(raw)
        .map_err(|e| DnsError::plugin(format!("invalid download timeout '{}': {}", raw, e)))
}

fn parse_quick_setup(raw: &str) -> Result<(String, String)> {
    let mut parts = raw.trim().splitn(2, char::is_whitespace);
    let url = parts
        .next()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .ok_or_else(|| DnsError::plugin("download quick setup requires a non-empty URL"))?;
    let dir = parts
        .next()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .ok_or_else(|| DnsError::plugin("download quick setup requires a non-empty directory"))?;
    Ok((url.to_string(), dir.to_string()))
}

fn resolve_download_targets(
    plugin_tag: &str,
    downloads: Vec<DownloadItemConfig>,
) -> Result<Vec<DownloadTarget>> {
    if downloads.is_empty() {
        return Err(DnsError::plugin(format!(
            "plugin '{}' download args.downloads must not be empty",
            plugin_tag
        )));
    }

    let mut targets = Vec::with_capacity(downloads.len());
    let mut seen_paths = HashSet::new();

    for (idx, item) in downloads.into_iter().enumerate() {
        let url = parse_download_url(plugin_tag, idx, item.url.as_str())?;
        let dir = item.dir.trim();
        if dir.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field 'args.downloads[{}].dir' must not be empty",
                plugin_tag, idx
            )));
        }

        let filename = item
            .filename
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| filename_from_url(&url).unwrap_or_default());
        if filename.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field 'args.downloads[{}]' could not derive filename from url '{}'",
                plugin_tag, idx, item.url
            )));
        }

        let dir_path = PathBuf::from(dir);
        let path = dir_path.join(&filename);
        let path_key = path.to_string_lossy().to_string();
        if !seen_paths.insert(path_key.clone()) {
            return Err(DnsError::plugin(format!(
                "plugin '{}' has duplicate download target path '{}'",
                plugin_tag, path_key
            )));
        }

        targets.push(DownloadTarget {
            url: url.to_string(),
            dir: dir_path,
            filename,
            path,
        });
    }

    Ok(targets)
}

fn parse_download_url(plugin_tag: &str, idx: usize, raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|e| {
        DnsError::plugin(format!(
            "plugin '{}' field 'args.downloads[{}].url' is invalid: {}",
            plugin_tag, idx, e
        ))
    })?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        scheme => Err(DnsError::plugin(format!(
            "plugin '{}' field 'args.downloads[{}].url' uses unsupported scheme '{}'",
            plugin_tag, idx, scheme
        ))),
    }
}

fn filename_from_url(url: &Url) -> Option<String> {
    url.path_segments()
        .and_then(Iterator::last)
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
}

fn build_client(insecure_skip_verify: bool, socks5: Option<Socks5Opt>) -> DownloadClient {
    let tls_config = if insecure_skip_verify {
        insecure_client_config()
    } else {
        secure_client_config()
    };

    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(DownloadHttpConnector { socks5 });

    Client::builder(TokioExecutor::new()).build(connector)
}

fn resolve_redirect_url(current_url: &str, location: &str) -> Result<String> {
    let base = Url::parse(current_url).map_err(|e| {
        DnsError::plugin(format!(
            "failed to parse redirect base url '{}': {}",
            current_url, e
        ))
    })?;
    base.join(location).map(|url| url.to_string()).map_err(|e| {
        DnsError::plugin(format!(
            "failed to resolve redirect location '{}' against '{}': {}",
            location, current_url, e
        ))
    })
}

fn parse_socks5(raw: Option<&str>) -> Result<Option<Socks5Opt>> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };
    parse_socks5_opt(raw)
        .map(Some)
        .ok_or_else(|| DnsError::plugin(format!("invalid download socks5 proxy '{}'", raw)))
}

async fn write_target_file(path: &Path, mut body: Incoming) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        DnsError::plugin(format!(
            "target path '{}' has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(dir).await.map_err(|e| {
        DnsError::plugin(format!(
            "failed to create target directory '{}': {}",
            dir.display(),
            e
        ))
    })?;

    let tmp_path = temp_path_for(path);
    let mut file = File::create(&tmp_path).await.map_err(|e| {
        DnsError::plugin(format!(
            "failed to create temp file '{}': {}",
            tmp_path.display(),
            e
        ))
    })?;
    while let Some(frame_result) = body.frame().await {
        let frame = match frame_result {
            Ok(frame) => frame,
            Err(e) => {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(DnsError::plugin(format!(
                    "failed to read response body: {}",
                    e
                )));
            }
        };
        if let Ok(data) = frame.into_data()
            && let Err(e) = file.write_all(&data).await
        {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(DnsError::plugin(format!(
                "failed to write temp file '{}': {}",
                tmp_path.display(),
                e
            )));
        }
    }
    file.sync_all().await.map_err(|e| {
        DnsError::plugin(format!(
            "failed to sync temp file '{}': {}",
            tmp_path.display(),
            e
        ))
    })?;
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, path).await {
        let rename_fallback = matches!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
        );
        if !rename_fallback {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(DnsError::plugin(format!(
                "failed to replace target file '{}': {}",
                path.display(),
                err
            )));
        }

        if fs::try_exists(path).await.unwrap_or(false)
            && let Err(e) = fs::remove_file(path).await
        {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(DnsError::plugin(format!(
                "failed to remove existing target file '{}': {}",
                path.display(),
                e
            )));
        }
        fs::rename(&tmp_path, path).await.map_err(|e| {
            DnsError::plugin(format!(
                "failed to replace target file '{}' after fallback: {}",
                path.display(),
                e
            ))
        })?;
    }

    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    tmp.set_file_name(format!(".{file_name}.{}.tmp", nanos));
    tmp
}

fn format_status(status: StatusCode) -> String {
    status
        .canonical_reason()
        .map(|reason| format!("{} {}", status.as_u16(), reason))
        .unwrap_or_else(|| status.as_u16().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::{plugin_config, test_context, test_registry};
    use serde_yaml_ng::Value;

    #[test]
    fn test_parse_quick_setup_requires_url_and_dir() {
        assert!(parse_quick_setup("").is_err());
        assert!(parse_quick_setup("https://example.com/file.txt").is_err());
        let (url, dir) = parse_quick_setup("https://example.com/file.txt /tmp/downloads").unwrap();
        assert_eq!(url, "https://example.com/file.txt");
        assert_eq!(dir, "/tmp/downloads");
    }

    #[test]
    fn test_resolve_targets_rejects_invalid_values() {
        let err = resolve_download_targets("dl", Vec::new()).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));

        let err = resolve_download_targets(
            "dl",
            vec![DownloadItemConfig {
                url: "ftp://example.com/file.txt".to_string(),
                dir: "/tmp".to_string(),
                filename: None,
            }],
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));

        let err = resolve_download_targets(
            "dl",
            vec![DownloadItemConfig {
                url: "https://example.com/".to_string(),
                dir: "/tmp".to_string(),
                filename: None,
            }],
        )
        .unwrap_err();
        assert!(err.to_string().contains("could not derive filename"));
    }

    #[test]
    fn test_resolve_targets_rejects_duplicate_paths() {
        let err = resolve_download_targets(
            "dl",
            vec![
                DownloadItemConfig {
                    url: "https://example.com/a.txt".to_string(),
                    dir: "/tmp".to_string(),
                    filename: Some("same.txt".to_string()),
                },
                DownloadItemConfig {
                    url: "https://example.com/b.txt".to_string(),
                    dir: "/tmp".to_string(),
                    filename: Some("same.txt".to_string()),
                },
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate download target path"));
    }

    #[test]
    fn test_download_factory_create_rejects_invalid_config() {
        let factory = DownloadFactory;
        let cfg = plugin_config("download", "download", Some(Value::String("bad".into())));
        assert!(
            factory
                .create(&cfg, test_registry(), &Default::default())
                .is_err()
        );
    }

    #[test]
    fn test_parse_socks5_accepts_and_rejects_values() {
        let parsed = parse_socks5(Some("127.0.0.1:1080")).expect("valid socks5 should parse");
        assert!(parsed.is_some());

        let err = parse_socks5(Some("bad")).expect_err("invalid socks5 should fail");
        assert!(err.to_string().contains("invalid download socks5 proxy"));
    }

    #[test]
    fn test_resolve_redirect_url_supports_relative_location() {
        let resolved = resolve_redirect_url(
            "https://example.com/releases/latest/download/file.dat",
            "/assets/file.dat",
        )
        .expect("relative redirect should resolve");
        assert_eq!(resolved, "https://example.com/assets/file.dat");
    }

    #[tokio::test]
    async fn test_download_executor_returns_next_for_empty_runtime_errors() {
        let plugin = DownloadExecutor {
            tag: "download".to_string(),
            client: build_client(false, None),
            timeout: Duration::from_millis(10),
            downloads: vec![DownloadTarget {
                url: "http://127.0.0.1:9/missing.txt".to_string(),
                dir: PathBuf::from("/tmp"),
                filename: "missing.txt".to_string(),
                path: PathBuf::from("/tmp/missing.txt"),
            }],
            insecure_skip_verify: false,
            socks5: None,
        };
        let mut ctx = test_context();
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should not fail");
        assert!(matches!(step, ExecStep::Next));
    }
}
