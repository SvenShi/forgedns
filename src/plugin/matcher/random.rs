/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `random` matcher plugin.
//!
//! Returns true with configured probability.
//!
//! This matcher is useful for probabilistic rollout / sampling policies in
//! sequence rules. Configuration takes exactly one probability in `[0.0, 1.0]`.
//! - `0.0`: always false
//! - `1.0`: always true

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
pub struct RandomFactory {}

register_plugin_factory!("random", RandomFactory {});

impl PluginFactory for RandomFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let args = parse_rules_from_value(plugin_config.args.clone())?;
        let probability = parse_probability(args)?;
        Ok(UninitializedPlugin::Matcher(Box::new(RandomMatcher {
            tag: plugin_config.tag.clone(),
            probability,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let args = parse_quick_setup_rules(param)?;
        let probability = parse_probability(args)?;
        Ok(UninitializedPlugin::Matcher(Box::new(RandomMatcher {
            tag: tag.to_string(),
            probability,
        })))
    }
}

fn parse_probability(args: Vec<String>) -> DnsResult<f64> {
    if args.len() != 1 {
        return Err(DnsError::plugin(
            "random matcher requires exactly one probability",
        ));
    }
    let p = args[0].trim().parse::<f64>().map_err(|e| {
        DnsError::plugin(format!("invalid random probability '{}': {}", args[0], e))
    })?;
    if !(0.0..=1.0).contains(&p) {
        return Err(DnsError::plugin("random probability must be in [0.0, 1.0]"));
    }
    Ok(p)
}

#[derive(Debug)]
struct RandomMatcher {
    tag: String,
    probability: f64,
}

#[async_trait]
impl Plugin for RandomMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for RandomMatcher {
    fn is_match(&self, _context: &mut DnsContext) -> bool {
        if self.probability <= 0.0 {
            return false;
        }
        if self.probability >= 1.0 {
            return true;
        }
        rand::random::<f64>() < self.probability
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_context;

    #[test]
    fn test_parse_probability_validation() {
        assert!(parse_probability(vec![]).is_err());
        assert!(parse_probability(vec!["0.5".to_string(), "0.2".to_string()]).is_err());
        assert!(parse_probability(vec!["-0.1".to_string()]).is_err());
        assert!(parse_probability(vec!["1.1".to_string()]).is_err());

        let parsed = parse_probability(vec!["0.25".to_string()]).expect("valid probability");
        assert_eq!(parsed, 0.25);
    }

    #[test]
    fn test_random_matcher_boundary_probability_is_deterministic() {
        let mut ctx = test_context();

        let always_false = RandomMatcher {
            tag: "random".to_string(),
            probability: 0.0,
        };
        assert!(!always_false.is_match(&mut ctx));

        let always_true = RandomMatcher {
            tag: "random".to_string(),
            probability: 1.0,
        };
        assert!(always_true.is_match(&mut ctx));
    }
}
