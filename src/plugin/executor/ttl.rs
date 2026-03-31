/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ttl` executor plugin.
//!
//! Rewrites TTL values on generated response records.
//!
//! This executor follows the same request lifecycle contract as server modules:
//! it reads and mutates `DnsContext.response` in-place, then returns `Next`
//! to keep sequence execution moving.
//!
//! Supported policies:
//! - fixed TTL: `ttl 300` or `{ fix: 300 }`
//! - clamp range: `ttl 300-600` or `{ min: 300, max: 600 }`
//!
//! Coverage:
//! - answers and authority records are always rewritten.
//! - additional records are rewritten except EDNS OPT pseudo-records.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
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
    /// Force all response TTLs to a fixed value.
    fix: Option<u32>,
    /// Lower bound applied to response TTLs.
    min: Option<u32>,
    /// Upper bound applied to response TTLs.
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

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for TtlExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if let Some(response) = context.response_mut() {
            for record in response.answers_mut() {
                let ttl = self.policy.apply(record.ttl());
                record.set_ttl(ttl);
            }
            for record in response.authorities_mut() {
                let ttl = self.policy.apply(record.ttl());
                record.set_ttl(ttl);
            }
            for record in response.additionals_mut() {
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

fn parse_policy_from_config(args: Option<Value>) -> Result<TtlPolicy> {
    let Some(args) = args else {
        return Err(DnsError::plugin("ttl plugin requires args"));
    };

    if let Some(raw) = args.as_str() {
        return parse_policy_from_expr(raw.trim());
    }

    let cfg: TtlConfig = serde_yaml_ng::from_value(args)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::{plugin_config, test_context, test_registry};
    use crate::proto::rdata::{A, Edns};
    use crate::proto::{Name, RData, Record};

    #[test]
    fn test_parse_policy_from_expr_supports_fix_and_range() {
        let fixed = parse_policy_from_expr("300").expect("fixed ttl should parse");
        assert_eq!(fixed.apply(10), 300);

        let range = parse_policy_from_expr("100-200").expect("range ttl should parse");
        assert_eq!(range.apply(10), 100);
        assert_eq!(range.apply(150), 150);
        assert_eq!(range.apply(500), 200);
    }

    #[tokio::test]
    async fn test_execute_rewrites_ttl_but_keeps_opt_ttl() {
        let plugin = TtlExecutor {
            tag: "ttl_test".to_string(),
            policy: TtlPolicy {
                fix: Some(60),
                min: None,
                max: None,
            },
        };

        let mut response = crate::proto::Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(A::new(1, 1, 1, 1)),
        ));
        response.add_authority(Record::from_rdata(
            Name::from_ascii("ns.example.com.").unwrap(),
            30,
            RData::A(A::new(2, 2, 2, 2)),
        ));
        response.add_additional(Record::from_rdata(
            Name::from_ascii("extra.example.com.").unwrap(),
            45,
            RData::A(A::new(3, 3, 3, 3)),
        ));
        response.set_edns(Edns::new());

        let mut ctx = test_context();
        ctx.set_response(response);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("ttl execute should work");
        assert!(matches!(step, ExecStep::Next));

        let updated = ctx.response().expect("response should remain present");
        assert_eq!(updated.answers()[0].ttl(), 60);
        assert_eq!(updated.authorities()[0].ttl(), 60);
        assert_eq!(updated.additionals()[0].ttl(), 60);
        assert!(
            updated.edns().is_some(),
            "OPT should remain in the EDNS field"
        );
    }

    #[tokio::test]
    async fn test_execute_rewrites_response_ttls() {
        let plugin = TtlExecutor {
            tag: "ttl_test".to_string(),
            policy: TtlPolicy {
                fix: Some(60),
                min: None,
                max: None,
            },
        };

        let mut response = crate::proto::Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(A::new(1, 1, 1, 1)),
        ));

        let mut ctx = test_context();
        ctx.set_response(response);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("ttl execute should work");
        assert!(matches!(step, ExecStep::Next));

        let updated = ctx.response().expect("response should remain present");
        assert_eq!(updated.answers()[0].ttl(), 60);
    }

    #[test]
    fn test_factory_create_rejects_empty_args() {
        let factory = TtlFactory;
        let cfg = plugin_config("ttl", "ttl", None);
        let result = factory.create(&cfg, test_registry());
        assert!(result.is_err());
    }
}
