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
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use bytes::Bytes;
use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tracing::{info, warn};
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

type DownloadClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DownloadConfig {
    timeout: Option<String>,
    insecure_skip_verify: Option<bool>,
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
        let uri = item
            .url
            .parse::<Uri>()
            .map_err(|e| DnsError::plugin(format!("invalid download url '{}': {}", item.url, e)))?;

        let request = Request::get(uri)
            .body(Empty::<Bytes>::new())
            .map_err(|e| DnsError::plugin(format!("failed to build request: {}", e)))?;

        let response =
            self.client.request(request).await.map_err(|e| {
                DnsError::plugin(format!("request failed for '{}': {}", item.url, e))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(DnsError::plugin(format!(
                "request failed for '{}': unexpected status {}",
                item.url,
                format_status(status)
            )));
        }

        write_target_file(item.path.as_path(), response.into_body()).await
    }
}

#[derive(Debug, Clone)]
pub struct DownloadFactory;

register_plugin_factory!("download", DownloadFactory {});

impl PluginFactory for DownloadFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg = plugin_config
            .args
            .clone()
            .ok_or_else(|| DnsError::plugin("download requires configuration arguments"))
            .and_then(parse_download_config)?;

        let timeout = parse_timeout(cfg.timeout.as_deref())?;
        let downloads = resolve_download_targets(&plugin_config.tag, cfg.downloads)?;

        Ok(UninitializedPlugin::Executor(Box::new(DownloadExecutor {
            tag: plugin_config.tag.clone(),
            client: build_client(cfg.insecure_skip_verify.unwrap_or(false)),
            timeout,
            downloads,
            insecure_skip_verify: cfg.insecure_skip_verify.unwrap_or(false),
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
            client: build_client(false),
            timeout: DEFAULT_TIMEOUT,
            downloads,
            insecure_skip_verify: false,
        })))
    }
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

fn build_client(insecure_skip_verify: bool) -> DownloadClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

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
        .wrap_connector(http);

    Client::builder(TokioExecutor::new()).build(connector)
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
        assert!(factory.create(&cfg, test_registry()).is_err());
    }

    #[tokio::test]
    async fn test_download_executor_returns_next_for_empty_runtime_errors() {
        let plugin = DownloadExecutor {
            tag: "download".to_string(),
            client: build_client(false),
            timeout: Duration::from_millis(10),
            downloads: vec![DownloadTarget {
                url: "http://127.0.0.1:9/missing.txt".to_string(),
                dir: PathBuf::from("/tmp"),
                filename: "missing.txt".to_string(),
                path: PathBuf::from("/tmp/missing.txt"),
            }],
            insecure_skip_verify: false,
        };
        let mut ctx = test_context();
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should not fail");
        assert!(matches!(step, ExecStep::Next));
    }
}
