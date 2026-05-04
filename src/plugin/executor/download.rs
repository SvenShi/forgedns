// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::future::BoxFuture;
use serde::Deserialize;
use serde_yaml_ng::Value;
use tokio::time::timeout;
use tracing::{info, warn};
use url::Url;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::deserialize_duration_option;
use crate::network::http_client::{HttpClient, HttpClientOptions, HttpRequestOptions};
use crate::network::upstream::{Socks5Opt, parse_socks5_opt};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DownloadConfig {
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    timeout: Option<Duration>,
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
    client: HttpClient,
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
    #[hotpath::measure]
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
        self.client
            .download(
                HttpRequestOptions::from_url(item.url.as_str()),
                item.path.as_path(),
            )
            .await
    }
}

#[derive(Debug, Clone)]
pub struct DownloadFactory;

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
                client: build_http_client(runtime.insecure_skip_verify, runtime.parsed_socks5),
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
            client: build_http_client(runtime.insecure_skip_verify, runtime.parsed_socks5),
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
            client: build_http_client(false, None),
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
        timeout: cfg.timeout.unwrap_or(DEFAULT_TIMEOUT),
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

fn build_http_client(insecure_skip_verify: bool, socks5: Option<Socks5Opt>) -> HttpClient {
    HttpClient::new(HttpClientOptions {
        insecure_skip_verify,
        socks5,
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

#[cfg(test)]
mod tests {
    use serde_yaml_ng::Value;

    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::{plugin_config, test_context, test_registry};

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

    #[tokio::test]
    async fn test_download_executor_returns_next_for_empty_runtime_errors() {
        let plugin = DownloadExecutor {
            tag: "download".to_string(),
            client: build_http_client(false, None),
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
