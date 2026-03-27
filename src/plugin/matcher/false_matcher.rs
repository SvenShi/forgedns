/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `_false` matcher plugin.
//!
//! Always returns false. This mirrors mosdns sequence built-in matcher behavior.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct FalseMatcherFactory {}

register_plugin_factory!("_false", FalseMatcherFactory {});

impl PluginFactory for FalseMatcherFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        Ok(UninitializedPlugin::Matcher(Box::new(FalseMatcher {
            tag: plugin_config.tag.clone(),
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        if let Some(param) = param
            && !param.trim().is_empty()
        {
            return Err(DnsError::plugin("_false does not accept parameters"));
        }
        Ok(UninitializedPlugin::Matcher(Box::new(FalseMatcher {
            tag: tag.to_string(),
        })))
    }
}

#[derive(Debug)]
struct FalseMatcher {
    tag: String,
}

#[async_trait]
impl Plugin for FalseMatcher {
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

impl Matcher for FalseMatcher {
    fn is_match(&self, _context: &mut DnsContext) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_registry;

    #[test]
    fn test_false_factory_rejects_non_empty_param() {
        let factory = FalseMatcherFactory {};
        let result = factory.quick_setup("tag", Some("unexpected".to_string()), test_registry());
        assert!(result.is_err());
    }
}
