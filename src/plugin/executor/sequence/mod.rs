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
use crate::plugin::dependency::{
    DependencySpec, SequenceFlowExpression, SequenceFlowExpressionKind, SequenceFlowReport,
    SequenceFlowRule,
};
use crate::plugin::executor::sequence::chain::{ChainBuilder, ChainProgram};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::matcher::parse_matcher_expr;
use crate::plugin::{
    Plugin, PluginFactory, PluginInitContext, PluginRef, UninitializedPlugin,
    expand_quick_setup_dependency_specs,
};
use crate::plugin_factory;

pub mod chain;

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
    quick_setup_executors: Vec<Arc<dyn Executor>>,
    quick_setup_matchers: Vec<Arc<dyn crate::plugin::matcher::Matcher>>,
}

#[async_trait]
impl Plugin for Sequence {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self, context: &PluginInitContext<'_>) -> DnsResult<()> {
        let mut builder = ChainBuilder::new(context, self.tag.clone());
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

pub(crate) fn analyze_sequence_flow(plugin_config: &PluginConfig) -> Option<SequenceFlowReport> {
    if plugin_config.plugin_type != "sequence" {
        return None;
    }

    let args = plugin_config.args.clone()?;
    let rules = serde_yaml_ng::from_value::<Vec<Rule>>(args).ok()?;
    let rules = rules
        .into_iter()
        .enumerate()
        .map(|(rule_idx, rule)| {
            let matches = rule
                .matches
                .unwrap_or_default()
                .into_iter()
                .enumerate()
                .map(|(match_idx, raw)| {
                    analyze_match_expression(format!("args[{rule_idx}].matches[{match_idx}]"), raw)
                })
                .collect();
            let exec = rule
                .exec
                .map(|raw| analyze_exec_expression(format!("args[{rule_idx}].exec"), raw));
            SequenceFlowRule {
                index: rule_idx,
                matches,
                exec,
            }
        })
        .collect();

    Some(SequenceFlowReport {
        tag: plugin_config.tag.clone(),
        rules,
    })
}

fn analyze_match_expression(field: String, raw: String) -> SequenceFlowExpression {
    let parsed = parse_matcher_expr(&raw).and_then(|(inverted, matcher)| {
        PluginRef::from_str(matcher).map(|plugin_ref| (inverted, plugin_ref))
    });

    match parsed {
        Ok((inverted, PluginRef::PluginTag(tag))) => SequenceFlowExpression {
            field,
            raw,
            kind: SequenceFlowExpressionKind::Plugin,
            target_tag: Some(tag),
            plugin_type: None,
            param: None,
            inverted,
            builtin: None,
        },
        Ok((inverted, PluginRef::QuickSetup { plugin_type, param })) => SequenceFlowExpression {
            field,
            raw,
            kind: SequenceFlowExpressionKind::QuickSetup,
            target_tag: None,
            plugin_type: Some(plugin_type),
            param,
            inverted,
            builtin: None,
        },
        Err(_) => SequenceFlowExpression {
            field,
            raw,
            kind: SequenceFlowExpressionKind::Invalid,
            target_tag: None,
            plugin_type: None,
            param: None,
            inverted: false,
            builtin: None,
        },
    }
}

fn analyze_exec_expression(field: String, raw: String) -> SequenceFlowExpression {
    if let Some(expression) = analyze_builtin_exec_expression(&field, &raw) {
        return expression;
    }

    match PluginRef::from_str(&raw) {
        Ok(PluginRef::PluginTag(tag)) => SequenceFlowExpression {
            field,
            raw,
            kind: SequenceFlowExpressionKind::Plugin,
            target_tag: Some(tag),
            plugin_type: None,
            param: None,
            inverted: false,
            builtin: None,
        },
        Ok(PluginRef::QuickSetup { plugin_type, param }) => SequenceFlowExpression {
            field,
            raw,
            kind: SequenceFlowExpressionKind::QuickSetup,
            target_tag: None,
            plugin_type: Some(plugin_type),
            param,
            inverted: false,
            builtin: None,
        },
        Err(_) => SequenceFlowExpression {
            field,
            raw,
            kind: SequenceFlowExpressionKind::Invalid,
            target_tag: None,
            plugin_type: None,
            param: None,
            inverted: false,
            builtin: None,
        },
    }
}

fn analyze_builtin_exec_expression(field: &str, raw: &str) -> Option<SequenceFlowExpression> {
    let trimmed = raw.trim();
    let mut split = trimmed.splitn(2, char::is_whitespace);
    let op = split.next()?;
    let param = split
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let is_builtin = matches!(
        op,
        "accept" | "return" | "reject" | "jump" | "goto" | "mark"
    );
    if !is_builtin {
        return None;
    }

    let target_tag = if matches!(op, "jump" | "goto") {
        param.and_then(|tag| parse_control_flow_sequence_tag(op, tag).ok())
    } else {
        None
    };
    let plugin_type = if matches!(op, "jump" | "goto") {
        Some("sequence".to_string())
    } else {
        None
    };

    Some(SequenceFlowExpression {
        field: field.to_string(),
        raw: raw.to_string(),
        kind: SequenceFlowExpressionKind::Builtin,
        target_tag,
        plugin_type,
        param: param.map(str::to_string),
        inverted: false,
        builtin: Some(op.to_string()),
    })
}

#[derive(Debug, Clone)]
#[plugin_factory("sequence")]
pub struct SequenceFactory {}

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
                    match PluginRef::from_str(matcher) {
                        Ok(PluginRef::PluginTag(tag)) => {
                            result.push(DependencySpec::matcher(field, tag));
                        }
                        Ok(PluginRef::QuickSetup { plugin_type, param }) => {
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
                    match PluginRef::from_str(&exec) {
                        Ok(PluginRef::PluginTag(tag)) => {
                            result.push(DependencySpec::executor(field, tag));
                        }
                        Ok(PluginRef::QuickSetup { plugin_type, param }) => {
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
        _init_context: &crate::plugin::PluginInitContext<'_>,
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
        assert!(PluginRef::from_str("$abc").is_ok());
        assert!(PluginRef::from_str("abc").is_ok());

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

    #[test]
    fn test_analyze_sequence_flow_reports_match_exec_and_quick_setup() {
        let config = PluginConfig {
            tag: "seq".to_string(),
            plugin_type: "sequence".to_string(),
            args: Some(
                serde_yaml_ng::from_str(
                    r#"
- matches:
    - "!$blocked"
    - "qname domain:example.com"
  exec: "forward 1.1.1.1"
- exec: "jump child_seq"
- exec: accept
"#,
                )
                .expect("sequence args should parse"),
            ),
        };

        let flow = analyze_sequence_flow(&config).expect("sequence flow should parse");
        assert_eq!(flow.tag, "seq");
        assert_eq!(flow.rules.len(), 3);
        assert_eq!(
            flow.rules[0].matches[0].target_tag.as_deref(),
            Some("blocked")
        );
        assert!(flow.rules[0].matches[0].inverted);
        assert_eq!(
            flow.rules[0].matches[1].plugin_type.as_deref(),
            Some("qname")
        );
        assert_eq!(
            flow.rules[0].matches[1].param.as_deref(),
            Some("domain:example.com")
        );
        assert_eq!(
            flow.rules[0]
                .exec
                .as_ref()
                .and_then(|expr| expr.plugin_type.as_deref()),
            Some("forward")
        );
        assert_eq!(
            flow.rules[1]
                .exec
                .as_ref()
                .and_then(|expr| expr.builtin.as_deref()),
            Some("jump")
        );
        assert_eq!(
            flow.rules[1]
                .exec
                .as_ref()
                .and_then(|expr| expr.target_tag.as_deref()),
            Some("child_seq")
        );
        assert_eq!(
            flow.rules[2]
                .exec
                .as_ref()
                .and_then(|expr| expr.builtin.as_deref()),
            Some("accept")
        );
    }
}
