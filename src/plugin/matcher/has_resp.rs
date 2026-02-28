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
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        if plugin_config.args.is_some() {
            return Err(DnsError::plugin("has_resp does not accept args"));
        }
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
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
        if let Some(param) = param {
            if !param.trim().is_empty() {
                return Err(DnsError::plugin("has_resp does not accept parameters"));
            }
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

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

impl Matcher for HasRespMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.response.is_some()
    }
}
