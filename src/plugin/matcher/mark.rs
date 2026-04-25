// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `mark` matcher plugin.
//!
//! Matches if current DNS context contains any specified set value.

use std::fmt::Debug;
use std::sync::Arc;

use ahash::AHashSet;
use async_trait::async_trait;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{parse_quick_setup_rules, parse_rules_from_value};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct MarkFactory {}

register_plugin_factory!("mark", MarkFactory {});

impl PluginFactory for MarkFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
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

fn parse_mark_values(raw_marks: &[String]) -> DnsResult<AHashSet<u32>> {
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
        marks.insert(mark);
    }

    if marks.is_empty() {
        return Err(DnsError::plugin("mark matcher requires at least one mark"));
    }

    Ok(marks)
}

#[derive(Debug)]
struct MarkMatcher {
    tag: String,
    marks: AHashSet<u32>,
}

#[async_trait]
impl Plugin for MarkMatcher {
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

impl Matcher for MarkMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        !context.marks().is_disjoint(&self.marks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_context;

    #[test]
    fn test_parse_mark_values_validation() {
        assert!(parse_mark_values(&[]).is_err());
        assert!(parse_mark_values(&["abc".to_string()]).is_err());

        let parsed = parse_mark_values(&["1".to_string(), " 2 ".to_string()])
            .expect("numeric marks should parse");
        assert!(parsed.contains(&1));
        assert!(parsed.contains(&2));
    }

    #[test]
    fn test_mark_matcher_checks_mark_intersection() {
        let matcher = MarkMatcher {
            tag: "mark".to_string(),
            marks: [1, 2].into_iter().collect(),
        };

        let mut ctx = test_context();
        ctx.marks_mut().insert(3);
        assert!(!matcher.is_match(&mut ctx));

        ctx.marks_mut().insert(1);
        assert!(matcher.is_match(&mut ctx));
    }
}
