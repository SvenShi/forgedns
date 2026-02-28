/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `env` matcher plugin.
//!
//! Matches startup/runtime environment variables.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{parse_quick_setup_rules, parse_rules_from_value};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EnvFactory {}

register_plugin_factory!("env", EnvFactory {});

impl PluginFactory for EnvFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let args = parse_rules_from_value(plugin_config.args.clone())?;
        let _ = parse_env_args(args)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let args = parse_rules_from_value(plugin_config.args.clone())?;
        let (key, value) = parse_env_args(args)?;
        Ok(UninitializedPlugin::Matcher(Box::new(EnvMatcher {
            tag: plugin_config.tag.clone(),
            key,
            value,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let args = parse_quick_setup_rules(param)?;
        let (key, value) = parse_env_args(args)?;
        Ok(UninitializedPlugin::Matcher(Box::new(EnvMatcher {
            tag: tag.to_string(),
            key,
            value,
        })))
    }
}

fn parse_env_args(args: Vec<String>) -> DnsResult<(String, Option<String>)> {
    if args.is_empty() {
        return Err(DnsError::plugin("env matcher requires env key"));
    }
    if args.len() > 2 {
        return Err(DnsError::plugin(
            "env matcher accepts only env key and optional value",
        ));
    }

    let key = args[0].trim().to_string();
    if key.is_empty() {
        return Err(DnsError::plugin("env key cannot be empty"));
    }
    let value = args.get(1).map(|v| v.trim().to_string());
    Ok((key, value))
}

#[derive(Debug)]
struct EnvMatcher {
    tag: String,
    key: String,
    value: Option<String>,
}

#[async_trait]
impl Plugin for EnvMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for EnvMatcher {
    async fn is_match(&self, _context: &mut DnsContext) -> bool {
        let Some(raw) = std::env::var_os(&self.key) else {
            return false;
        };

        if let Some(expect) = &self.value {
            raw.to_string_lossy() == expect.as_str()
        } else {
            true
        }
    }
}
