/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `mark` matcher plugin.
//!
//! Matches if current DNS context contains any specified set value.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{parse_quick_setup_rules, parse_rules_from_value};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct MarkFactory {}

register_plugin_factory!("mark", MarkFactory {});

impl PluginFactory for MarkFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let marks = parse_rules_from_value(plugin_config.args.clone())?;
        let _ = parse_mark_values(&marks)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let marks = parse_rules_from_value(plugin_config.args.clone())?;
        build_mark_matcher(plugin_config.tag.clone(), marks)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let marks = parse_quick_setup_rules(param)?;
        build_mark_matcher(tag.to_string(), marks)
    }
}

fn build_mark_matcher(tag: String, marks: Vec<String>) -> DnsResult<UninitializedPlugin> {
    let marks = parse_mark_values(&marks)?;
    Ok(UninitializedPlugin::Matcher(Box::new(MarkMatcher {
        tag,
        marks,
    })))
}

fn parse_mark_values(raw_marks: &[String]) -> DnsResult<AHashSet<String>> {
    if raw_marks.is_empty() {
        return Err(DnsError::plugin("mark matcher requires at least one mark"));
    }

    let mut marks = AHashSet::with_capacity(raw_marks.len());
    for raw in raw_marks {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        let mark = v
            .parse::<u32>()
            .map_err(|e| DnsError::plugin(format!("invalid mark value '{}': {}", v, e)))?;
        marks.insert(mark.to_string());
    }

    if marks.is_empty() {
        return Err(DnsError::plugin("mark matcher requires at least one mark"));
    }

    Ok(marks)
}

#[derive(Debug)]
struct MarkMatcher {
    tag: String,
    marks: AHashSet<String>,
}

#[async_trait]
impl Plugin for MarkMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for MarkMatcher {
    async fn is_match(&self, context: &mut DnsContext) -> bool {
        !context.marks.is_disjoint(&self.marks)
    }
}
