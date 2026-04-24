/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `upgrade` executor plugin.
//!
//! Runs the shared upgrade subsystem from the plugin pipeline. This executor is
//! intended for cron or explicit sequence orchestration, but it does not require
//! a cron context.

use crate::app::cli::RestartMode;
use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::parse_simple_duration;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use crate::upgrade::{self, UpgradeConfig};
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Debug)]
struct UpgradeExecutor {
    tag: String,
    config: UpgradeConfig,
}

#[async_trait]
impl Plugin for UpgradeExecutor {
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
impl Executor for UpgradeExecutor {
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        info!(
            plugin = %self.tag,
            repository = %self.config.repository,
            asset = %self.config.asset,
            cache_dir = %self.config.cache_dir.display(),
            backup_dir = %self.config.backup_dir.display(),
            restart = ?self.config.restart,
            force = self.config.force,
            cleanup = self.config.cleanup_after_apply,
            "upgrade apply started"
        );

        let decision = upgrade::should_apply(&self.config).await?;
        match &decision {
            upgrade::ApplyDecision::Apply { check } => {
                info!(
                    plugin = %self.tag,
                    current = %check.current_version,
                    release = %check.latest_version,
                    asset = %check.asset_name,
                    update_available = check.update_available,
                    force = self.config.force,
                    "upgrade apply decision accepted"
                );
            }
            upgrade::ApplyDecision::Skip { check } => {
                info!(
                    plugin = %self.tag,
                    current = %check.current_version,
                    release = %check.latest_version,
                    asset = %check.asset_name,
                    update_available = check.update_available,
                    "upgrade apply skipped before download"
                );
            }
        }

        match upgrade::apply_decision(&self.config, upgrade::UpgradeContext::Plugin, decision)
            .await?
        {
            upgrade::ApplyRunOutcome::Applied { check, outcome } => {
                info!(
                    plugin = %self.tag,
                    current = %check.current_version,
                    release = %check.latest_version,
                    asset = %check.asset_name,
                    update_available = check.update_available,
                    force = self.config.force,
                    version = %outcome.installed_version,
                    backup = %outcome.backup_path.display(),
                    "upgrade apply completed"
                );
            }
            upgrade::ApplyRunOutcome::Skipped { check } => {
                info!(
                    plugin = %self.tag,
                    current = %check.current_version,
                    release = %check.latest_version,
                    asset = %check.asset_name,
                    update_available = check.update_available,
                    "no update available"
                );
            }
        }
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct UpgradeFactory;

register_plugin_factory!("upgrade", UpgradeFactory {});

impl PluginFactory for UpgradeFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let parsed = parse_upgrade_config(plugin_config.args.clone())?;
        let config = parsed.into_upgrade_config()?;
        Ok(UninitializedPlugin::Executor(Box::new(UpgradeExecutor {
            tag: plugin_config.tag.clone(),
            config,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(UpgradeExecutor {
            tag: tag.to_string(),
            config: parse_quick_setup(param)?,
        })))
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UpgradePluginConfig {
    repository: Option<String>,
    asset: Option<String>,
    cache_dir: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    restart: Option<RestartMode>,
    allow_prerelease: Option<bool>,
    force: Option<bool>,
    cleanup: Option<bool>,
    timeout: Option<String>,
    socks5: Option<String>,
    insecure_skip_verify: Option<bool>,
}

impl UpgradePluginConfig {
    fn into_upgrade_config(self) -> Result<UpgradeConfig> {
        let mut config = UpgradeConfig::default();
        if let Some(value) = self.repository {
            config.repository = value;
        }
        if let Some(value) = self.asset {
            config.asset = value;
        }
        if let Some(value) = self.cache_dir {
            config.cache_dir = value;
        }
        if let Some(value) = self.backup_dir {
            config.backup_dir = value;
        }
        if let Some(value) = self.restart {
            config.restart = value;
        }
        if let Some(value) = self.allow_prerelease {
            config.allow_prerelease = value;
        }
        if let Some(value) = self.force {
            config.force = value;
        }
        config.cleanup_after_apply = self.cleanup.unwrap_or(true);
        if let Some(value) = self
            .timeout
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            config.timeout = parse_simple_duration(value).map_err(|err| {
                DnsError::plugin(format!("invalid upgrade timeout '{}': {}", value, err))
            })?;
        }
        config.socks5 = self.socks5;
        if let Some(value) = self.insecure_skip_verify {
            config.insecure_skip_verify = value;
        }
        Ok(config)
    }
}

fn parse_upgrade_config(args: Option<Value>) -> Result<UpgradePluginConfig> {
    match args {
        Some(value) => serde_yaml_ng::from_value::<UpgradePluginConfig>(value)
            .map_err(|err| DnsError::plugin(format!("failed to parse upgrade config: {err}"))),
        None => Ok(UpgradePluginConfig::default()),
    }
}

fn parse_quick_setup(param: Option<String>) -> Result<UpgradeConfig> {
    let mut config = default_plugin_upgrade_config();
    let Some(raw) = param.map(|value| value.trim().to_string()) else {
        return Ok(config);
    };
    if raw.is_empty() {
        return Ok(config);
    }

    for token in raw.split_whitespace() {
        if token == "force" {
            config.force = true;
            continue;
        }

        let Some((key, value)) = token.split_once('=') else {
            return Err(DnsError::plugin(format!(
                "unsupported upgrade quick setup token '{}'",
                token
            )));
        };

        match key {
            "force" => {
                config.force = parse_bool_quick_setup(key, value)?;
            }
            _ => {
                return Err(DnsError::plugin(format!(
                    "unsupported upgrade quick setup token '{}'",
                    token
                )));
            }
        }
    }

    Ok(config)
}

fn default_plugin_upgrade_config() -> UpgradeConfig {
    UpgradeConfig {
        cleanup_after_apply: true,
        ..UpgradeConfig::default()
    }
}

fn parse_bool_quick_setup(key: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(DnsError::plugin(format!(
            "invalid upgrade quick setup '{}' value '{}', expected true or false",
            key, value
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::{plugin_config, test_registry};

    #[test]
    fn upgrade_factory_accepts_default_apply_config() {
        let factory = UpgradeFactory;
        let cfg = plugin_config("upgrade", "upgrade", None);
        let plugin = factory
            .create(&cfg, test_registry(), &Default::default())
            .expect("default upgrade config should parse");
        assert!(matches!(plugin, UninitializedPlugin::Executor(_)));
    }

    #[test]
    fn parse_upgrade_config_defaults_force_to_false() {
        let parsed = parse_upgrade_config(None).unwrap();
        let config = parsed.into_upgrade_config().unwrap();
        assert!(!config.force);
        assert!(config.cleanup_after_apply);
    }

    #[test]
    fn parse_upgrade_config_accepts_force_flag() {
        let value = serde_yaml_ng::from_str::<Value>("force: true").unwrap();
        let parsed = parse_upgrade_config(Some(value)).unwrap();
        let config = parsed.into_upgrade_config().unwrap();
        assert!(config.force);
    }

    #[test]
    fn parse_upgrade_config_accepts_cleanup_flag() {
        let value = serde_yaml_ng::from_str::<Value>("cleanup: false").unwrap();
        let parsed = parse_upgrade_config(Some(value)).unwrap();
        let config = parsed.into_upgrade_config().unwrap();
        assert!(!config.cleanup_after_apply);
    }

    #[test]
    fn parse_upgrade_config_rejects_mode() {
        let value = serde_yaml_ng::from_str::<Value>("mode: download").unwrap();
        let err = parse_upgrade_config(Some(value)).unwrap_err();
        assert!(err.to_string().contains("unknown field `mode`"));
    }

    #[test]
    fn parse_upgrade_config_rejects_target() {
        let value = serde_yaml_ng::from_str::<Value>("target: v0.4.1").unwrap();
        let err = parse_upgrade_config(Some(value)).unwrap_err();
        assert!(err.to_string().contains("unknown field `target`"));
    }

    #[test]
    fn quick_setup_accepts_empty_default_apply() {
        let config = parse_quick_setup(None).unwrap();
        assert!(!config.force);
        assert!(config.cleanup_after_apply);
        assert_eq!(config.repository, "SvenShi/forgedns");
    }

    #[test]
    fn quick_setup_accepts_apply_options() {
        let config = parse_quick_setup(Some("force=true".to_string())).unwrap();
        assert!(config.force);
        assert_eq!(config.repository, "SvenShi/forgedns");
    }

    #[test]
    fn upgrade_factory_quick_setup_returns_executor() {
        let factory = UpgradeFactory;
        let plugin = factory
            .quick_setup("upgrade", Some("force".to_string()), test_registry())
            .expect("quick setup should parse");
        assert!(matches!(plugin, UninitializedPlugin::Executor(_)));
    }

    #[test]
    fn quick_setup_rejects_non_force_options() {
        let err = parse_quick_setup(Some("restart=service".to_string())).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported upgrade quick setup token")
        );
    }

    #[test]
    fn quick_setup_rejects_mode() {
        let err = parse_quick_setup(Some("mode=download".to_string())).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported upgrade quick setup token")
        );
    }

    #[test]
    fn parse_upgrade_config_rejects_bad_timeout() {
        let value = serde_yaml_ng::from_str::<Value>("timeout: soon").unwrap();
        let parsed = parse_upgrade_config(Some(value)).unwrap();
        let err = parsed.into_upgrade_config().unwrap_err();
        assert!(err.to_string().contains("invalid upgrade timeout"));
    }
}
