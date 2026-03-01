/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ttl` executor plugin.
//!
//! Supports fixed TTL (`ttl 300`) and range clamp (`ttl 300-600`).

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::rr::RecordType;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct TtlPolicy {
    fix: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
}

impl TtlPolicy {
    fn apply(&self, ttl: u32) -> u32 {
        if let Some(fix) = self.fix {
            return fix;
        }

        let mut out = ttl;
        if let Some(min) = self.min {
            out = out.max(min);
        }
        if let Some(max) = self.max {
            out = out.min(max);
        }
        out
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TtlConfig {
    fix: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
}

#[derive(Debug)]
struct TtlExecutor {
    tag: String,
    policy: TtlPolicy,
}

#[async_trait]
impl Plugin for TtlExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for TtlExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if let Some(response) = context.response.as_mut() {
            for record in response.answers_mut() {
                let ttl = self.policy.apply(record.ttl());
                record.set_ttl(ttl);
            }
            for record in response.name_servers_mut() {
                let ttl = self.policy.apply(record.ttl());
                record.set_ttl(ttl);
            }
            for record in response.additionals_mut() {
                if record.record_type() == RecordType::OPT {
                    continue;
                }
                let ttl = self.policy.apply(record.ttl());
                record.set_ttl(ttl);
            }
        }
        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct TtlFactory;

register_plugin_factory!("ttl", TtlFactory {});

impl PluginFactory for TtlFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let _ = parse_policy_from_config(plugin_config.args.clone())?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let policy = parse_policy_from_config(plugin_config.args.clone())?;

        Ok(UninitializedPlugin::Executor(Box::new(TtlExecutor {
            tag: plugin_config.tag.clone(),
            policy,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let raw = param.ok_or_else(|| DnsError::plugin("ttl quick setup requires parameter"))?;
        let policy = parse_policy_from_expr(raw.trim())?;

        Ok(UninitializedPlugin::Executor(Box::new(TtlExecutor {
            tag: tag.to_string(),
            policy,
        })))
    }
}

fn parse_policy_from_config(args: Option<serde_yml::Value>) -> Result<TtlPolicy> {
    let Some(args) = args else {
        return Err(DnsError::plugin("ttl plugin requires args"));
    };

    if let Some(raw) = args.as_str() {
        return parse_policy_from_expr(raw.trim());
    }

    let cfg: TtlConfig = serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse ttl config: {}", e)))?;
    if cfg.fix.is_some() {
        return Ok(TtlPolicy {
            fix: cfg.fix,
            min: None,
            max: None,
        });
    }

    if cfg.min.is_none() && cfg.max.is_none() {
        return Err(DnsError::plugin(
            "ttl config requires either 'fix' or at least one of 'min'/'max'",
        ));
    }

    Ok(TtlPolicy {
        fix: None,
        min: cfg.min,
        max: cfg.max,
    })
}

fn parse_policy_from_expr(raw: &str) -> Result<TtlPolicy> {
    if raw.is_empty() {
        return Err(DnsError::plugin("ttl parameter cannot be empty"));
    }

    if let Some((min, max)) = raw.split_once('-') {
        let min = min.trim().parse::<u32>().map_err(|e| {
            DnsError::plugin(format!("invalid ttl range lower bound '{}': {}", min, e))
        })?;
        let max = max.trim().parse::<u32>().map_err(|e| {
            DnsError::plugin(format!("invalid ttl range upper bound '{}': {}", max, e))
        })?;

        return Ok(TtlPolicy {
            fix: None,
            min: Some(min),
            max: if max == 0 { None } else { Some(max) },
        });
    }

    let fix = raw
        .parse::<u32>()
        .map_err(|e| DnsError::plugin(format!("invalid ttl value '{}': {}", raw, e)))?;

    Ok(TtlPolicy {
        fix: Some(fix),
        min: None,
        max: None,
    })
}
