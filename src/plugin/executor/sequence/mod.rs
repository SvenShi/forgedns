// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Deserializer};
use tokio::sync::OnceCell;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::executor::sequence::chain::{ChainBuilder, ChainProgram};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{
    Plugin, PluginFactory, PluginRegistry, UninitializedPlugin, expand_quick_setup_dependency_specs,
};
use crate::register_plugin_factory;

pub mod chain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SequenceRef {
    PluginTag(String),
    QuickSetup {
        plugin_type: String,
        param: Option<String>,
    },
}

pub(super) fn parse_sequence_ref(raw: &str) -> DnsResult<SequenceRef> {
    let raw = raw.trim_start();
    if raw.is_empty() {
        return Err(DnsError::plugin(format!(
            "invalid plugin reference: '{}'",
            raw
        )));
    }
    if let Some(tag) = raw.strip_prefix('$') {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(DnsError::plugin(format!(
                "invalid plugin reference: '{}'",
                raw
            )));
        }
        return Ok(SequenceRef::PluginTag(tag.to_string()));
    }

    let mut split = raw.splitn(2, char::is_whitespace);
    let plugin_type = split
        .next()
        .ok_or_else(|| DnsError::plugin(format!("invalid quick setup syntax: '{}'", raw)))?;
    let param = split.next().map(String::from);
    Ok(SequenceRef::QuickSetup {
        plugin_type: plugin_type.to_string(),
        param,
    })
}

/// Parse matcher expression and optional reverse prefix (`!`).
///
/// Examples:
/// - `$qname` -> `(false, "$qname")`
/// - `!$qname` -> `(true, "$qname")`
/// - `!qname domain:example.com` -> `(true, "qname domain:example.com")`
pub(super) fn parse_matcher_expr(raw: &str) -> DnsResult<(bool, &str)> {
    let matcher_expr = raw.trim_start();
    if let Some(matcher_expr) = matcher_expr.strip_prefix('!') {
        let matcher_expr = matcher_expr.trim_start();
        if matcher_expr.is_empty() {
            return Err(DnsError::plugin(format!(
                "invalid matcher reference: '{}'",
                raw
            )));
        }
        Ok((true, matcher_expr))
    } else {
        Ok((false, matcher_expr))
    }
}

pub(super) fn parse_control_flow_sequence_tag(op: &str, raw: &str) -> DnsResult<String> {
    let tag = raw.trim();
    if tag.is_empty() {
        return Err(DnsError::plugin(format!(
            "{} requires sequence tag argument",
            op
        )));
    }
    if tag.starts_with('$') {
        return Err(DnsError::plugin(format!(
            "{} target must be sequence tag without '$' prefix",
            op
        )));
    }
    Ok(tag.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawRuleMatchers {
    Single(String),
    Many(Vec<String>),
}

impl RawRuleMatchers {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::Single(expr) => vec![expr],
            Self::Many(exprs) => exprs,
        }
    }
}

fn deserialize_rule_matches<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<RawRuleMatchers>::deserialize(deserializer)?.map(RawRuleMatchers::into_vec))
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    #[serde(default, deserialize_with = "deserialize_rule_matches")]
    pub(super) matches: Option<Vec<String>>,
    exec: Option<String>,
}

#[derive(Debug)]
#[allow(unused)]
pub struct Sequence {
    tag: String,
    program: OnceCell<Arc<ChainProgram>>,
    rules: Vec<Rule>,
    registry: Arc<PluginRegistry>,
    quick_setup_executors: Vec<Arc<dyn Executor>>,
    quick_setup_matchers: Vec<Arc<dyn crate::plugin::matcher::Matcher>>,
}

#[async_trait]
impl Plugin for Sequence {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        let mut builder = ChainBuilder::new(self.registry.clone(), self.tag.clone());
        for rule in &self.rules {
            builder.append_node(rule).await?;
        }

        let (program, quick_setup_executors, quick_setup_matchers) = builder.build();
        self.program
            .set(program)
            .map_err(|_| DnsError::plugin("sequence program is already initialized"))?;
        self.quick_setup_executors = quick_setup_executors;
        self.quick_setup_matchers = quick_setup_matchers;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        let mut first_err: Option<DnsError> = None;
        for executor in &self.quick_setup_executors {
            if let Err(e) = executor.destroy().await
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        for matcher in &self.quick_setup_matchers {
            if let Err(e) = matcher.destroy().await
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Executor for Sequence {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> DnsResult<ExecStep> {
        self.program.get().unwrap().run(context).await
    }
}

fn parse_control_flow_dependency(exec: &str) -> Option<String> {
    let mut split = exec.trim().splitn(2, char::is_whitespace);
    let op = split.next()?;
    let arg = split.next()?.trim();
    if arg.is_empty() {
        return None;
    }
    if (op == "jump" || op == "goto")
        && let Ok(tag) = parse_control_flow_sequence_tag(op, arg)
    {
        return Some(tag);
    }
    None
}

#[derive(Debug, Clone)]
pub struct SequenceFactory {}

register_plugin_factory!("sequence", SequenceFactory {});

impl PluginFactory for SequenceFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let mut result = Vec::new();

        let Some(args) = plugin_config.args.clone() else {
            return result;
        };
        let Ok(rules) = serde_yaml_ng::from_value::<Vec<Rule>>(args) else {
            return result;
        };

        for (rule_idx, rule) in rules.into_iter().enumerate() {
            if let Some(matches) = rule.matches {
                for (match_idx, matcher) in matches.into_iter().enumerate() {
                    let field = format!("args[{}].matches[{}]", rule_idx, match_idx);
                    let Ok((_, matcher)) = parse_matcher_expr(&matcher) else {
                        continue;
                    };
                    match parse_sequence_ref(matcher) {
                        Ok(SequenceRef::PluginTag(tag)) => {
                            result.push(DependencySpec::matcher(field, tag));
                        }
                        Ok(SequenceRef::QuickSetup { plugin_type, param }) => {
                            result.extend(expand_quick_setup_dependency_specs(
                                &field,
                                &plugin_type,
                                param.as_deref(),
                            ));
                        }
                        Err(_) => {}
                    }
                }
            }
            if let Some(exec) = rule.exec {
                let field = format!("args[{}].exec", rule_idx);
                if let Some(tag) = parse_control_flow_dependency(&exec) {
                    result.push(DependencySpec::executor_type(field, tag, "sequence"));
                } else {
                    match parse_sequence_ref(&exec) {
                        Ok(SequenceRef::PluginTag(tag)) => {
                            result.push(DependencySpec::executor(field, tag));
                        }
                        Ok(SequenceRef::QuickSetup { plugin_type, param }) => {
                            result.extend(expand_quick_setup_dependency_specs(
                                &field,
                                &plugin_type,
                                param.as_deref(),
                            ));
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        result
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = serde_yaml_ng::from_value::<Vec<Rule>>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("sequence requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse sequence config: {}", e)))?;

        if rules.is_empty() {
            return Err(DnsError::plugin("sequence requires at least one rule"));
        }

        for rule in &rules {
            if rule.exec.is_none() && rule.matches.is_none() {
                return Err(DnsError::plugin("sequence rule cannot be empty"));
            }
            if let Some(exec) = &rule.exec {
                validate_control_flow_syntax(exec)?;
            }
        }

        Ok(UninitializedPlugin::Executor(Box::new(Sequence {
            tag: plugin_config.tag.clone(),
            program: OnceCell::new(),
            rules,
            registry,
            quick_setup_executors: Vec::new(),
            quick_setup_matchers: Vec::new(),
        })))
    }
}

fn validate_control_flow_syntax(exec: &str) -> DnsResult<()> {
    let mut split = exec.trim().splitn(2, char::is_whitespace);
    let Some(op) = split.next() else {
        return Ok(());
    };

    if op != "jump" && op != "goto" {
        return Ok(());
    }

    let arg = split.next().unwrap_or_default();
    parse_control_flow_sequence_tag(op, arg)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sequence_ref_and_control_flow_dependency() {
        assert!(parse_sequence_ref("$abc").is_ok());
        assert!(parse_sequence_ref("abc").is_ok());

        assert_eq!(parse_control_flow_dependency("accept"), None);
        assert_eq!(
            parse_control_flow_dependency("jump next"),
            Some("next".to_string())
        );
        assert_eq!(parse_control_flow_dependency("jump $next"), None);
        assert_eq!(
            parse_control_flow_sequence_tag("jump", "next").unwrap(),
            "next"
        );
        assert!(
            parse_control_flow_sequence_tag("jump", "$next")
                .unwrap_err()
                .to_string()
                .contains("without '$' prefix")
        );
    }

    #[test]
    fn test_rule_deserialize_supports_match_string_and_matches_sequence() {
        let single = serde_yaml_ng::from_str::<Rule>(
            r#"
matches: "$allow_all"
exec: accept
"#,
        )
        .expect("single matches string should deserialize");
        assert_eq!(
            single.matches.expect("matches field should exist"),
            vec!["$allow_all".to_string()]
        );

        let multi = serde_yaml_ng::from_str::<Rule>(
            r#"
matches:
  - "_true"
  - "qtype A"
exec: reject 2
"#,
        )
        .expect("matches sequence should deserialize");
        assert_eq!(
            multi.matches.expect("matches field should exist"),
            vec!["_true".to_string(), "qtype A".to_string()]
        );
    }
}
