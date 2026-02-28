/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `has_wanted_ans` matcher plugin.
//!
//! Returns true when answer section contains at least one RR whose type
//! matches any request question type.

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
pub struct HasWantedAnsFactory {}

register_plugin_factory!("has_wanted_ans", HasWantedAnsFactory {});

impl PluginFactory for HasWantedAnsFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        if plugin_config.args.is_some() {
            return Err(DnsError::plugin("has_wanted_ans does not accept args"));
        }
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        Ok(UninitializedPlugin::Matcher(Box::new(
            HasWantedAnsMatcher {
                tag: plugin_config.tag.clone(),
            },
        )))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        if let Some(param) = param {
            if !param.trim().is_empty() {
                return Err(DnsError::plugin(
                    "has_wanted_ans does not accept parameters",
                ));
            }
        }
        Ok(UninitializedPlugin::Matcher(Box::new(
            HasWantedAnsMatcher {
                tag: tag.to_string(),
            },
        )))
    }
}

#[derive(Debug)]
struct HasWantedAnsMatcher {
    tag: String,
}

#[async_trait]
impl Plugin for HasWantedAnsMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for HasWantedAnsMatcher {
    async fn is_match(&self, context: &mut DnsContext) -> bool {
        let Some(response) = context.response.as_ref() else {
            return false;
        };

        context.request.queries().iter().any(|query| {
            response
                .answers()
                .iter()
                .any(|rr| rr.record_type() == query.query_type())
        })
    }
}
