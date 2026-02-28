/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `qclass` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches DNS question classes in request queries.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_dns_class, parse_quick_setup_rules, parse_rules_from_value, parse_u16_rules,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QclassFactory {}

register_plugin_factory!("qclass", QclassFactory {});

impl PluginFactory for QclassFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        validate_non_empty_rules("qclass", &rules)?;
        let _ = parse_u16_rules("qclass", &rules, parse_dns_class)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_qclass_matcher(plugin_config.tag.clone(), rules)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_qclass_matcher(tag.to_string(), rules)
    }
}

fn build_qclass_matcher(tag: String, rules: Vec<String>) -> DnsResult<UninitializedPlugin> {
    validate_non_empty_rules("qclass", &rules)?;
    let qclasses = parse_u16_rules("qclass", &rules, parse_dns_class)?;
    Ok(UninitializedPlugin::Matcher(Box::new(QclassMatcher {
        tag,
        qclasses,
    })))
}

#[derive(Debug)]
struct QclassMatcher {
    tag: String,
    qclasses: AHashSet<u16>,
}

#[async_trait]
impl Plugin for QclassMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

impl Matcher for QclassMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context
            .request
            .queries()
            .iter()
            .any(|q| self.qclasses.contains(&u16::from(q.query_class())))
    }
}
