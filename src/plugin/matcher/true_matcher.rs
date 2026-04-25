// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `_true` matcher plugin.
//!
//! Always returns true. This mirrors mosdns sequence built-in matcher behavior.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct TrueMatcherFactory {}

register_plugin_factory!("_true", TrueMatcherFactory {});

impl PluginFactory for TrueMatcherFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        Ok(UninitializedPlugin::Matcher(Box::new(TrueMatcher {
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
            return Err(DnsError::plugin("_true does not accept parameters"));
        }
        Ok(UninitializedPlugin::Matcher(Box::new(TrueMatcher {
            tag: tag.to_string(),
        })))
    }
}

#[derive(Debug)]
struct TrueMatcher {
    tag: String,
}

#[async_trait]
impl Plugin for TrueMatcher {
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

impl Matcher for TrueMatcher {
    #[hotpath::measure]
    fn is_match(&self, _context: &mut DnsContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_registry;

    #[test]
    fn test_true_factory_rejects_non_empty_param() {
        let factory = TrueMatcherFactory {};
        let result = factory.quick_setup("tag", Some("unexpected".to_string()), test_registry());
        assert!(result.is_err());
    }
}
