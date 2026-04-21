/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `has_resp` matcher plugin.
//!
//! Returns true when context already contains a DNS response.

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
pub struct HasRespFactory {}

register_plugin_factory!("has_resp", HasRespFactory {});

impl PluginFactory for HasRespFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        Ok(UninitializedPlugin::Matcher(Box::new(HasRespMatcher {
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
            return Err(DnsError::plugin("has_resp does not accept parameters"));
        }
        Ok(UninitializedPlugin::Matcher(Box::new(HasRespMatcher {
            tag: tag.to_string(),
        })))
    }
}

#[derive(Debug)]
struct HasRespMatcher {
    tag: String,
}

#[async_trait]
impl Plugin for HasRespMatcher {
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

impl Matcher for HasRespMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.response().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::{test_context, test_registry};

    #[test]
    fn test_has_resp_quick_setup_rejects_param() {
        let factory = HasRespFactory {};
        assert!(
            factory
                .quick_setup("has_resp", Some("unexpected".to_string()), test_registry(),)
                .is_err()
        );
    }

    #[test]
    fn test_has_resp_matcher_checks_response_presence() {
        let matcher = HasRespMatcher {
            tag: "has_resp".to_string(),
        };
        let mut ctx = test_context();
        assert!(!matcher.is_match(&mut ctx));
        ctx.set_response(crate::proto::Message::new());
        assert!(matcher.is_match(&mut ctx));
    }
}
