// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `any_match` matcher plugin.
//!
//! This matcher composes multiple matcher expressions and returns `true` when
//! any child matcher evaluates to `true`.
//!
//! It supports:
//! - referenced matcher tags, e.g. `$match_qname`;
//! - quick-setup matcher expressions, e.g. `qtype 1`; and
//! - negated matcher expressions via `!`, e.g. `!$has_resp`.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use serde_yaml_ng::Value;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::matcher_utils::validate_non_empty_rules;
use crate::plugin::matcher::{Matcher, MatcherRef, parse_matcher_expr};
use crate::plugin::{
    Plugin, PluginFactory, PluginHolder, PluginRef, PluginRegistry, UninitializedPlugin,
    expand_quick_setup_dependency_specs,
};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct AnyMatchFactory {}

register_plugin_factory!("any_match", AnyMatchFactory {});

impl PluginFactory for AnyMatchFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(matchers) = parse_matcher_exprs_from_value(plugin_config.args.clone()) else {
            return vec![];
        };

        let mut result = Vec::new();
        for (idx, matcher_ref) in matchers.iter().enumerate() {
            let field = format!("args.matchers[{idx}]");
            let Ok((_, matcher_expr)) = parse_matcher_expr(matcher_ref) else {
                continue;
            };
            match PluginRef::from_str(matcher_expr) {
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
        result
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let matchers = parse_matcher_exprs_from_value(plugin_config.args.clone())?;
        build_any_match(plugin_config.tag.clone(), matchers, registry)
    }
}

fn parse_matcher_exprs_from_value(args: Option<Value>) -> DnsResult<Vec<String>> {
    let args = args.ok_or_else(|| DnsError::plugin("any_match requires args"))?;
    let expressions = match args {
        Value::String(s) => s
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for item in seq {
                match item {
                    Value::String(s) => {
                        let expression = s.trim();
                        if !expression.is_empty() {
                            out.push(expression.to_string());
                        }
                    }
                    other => {
                        return Err(DnsError::plugin(format!(
                            "any_match args must be string list, got {:?}",
                            other
                        )));
                    }
                }
            }
            out
        }
        other => {
            return Err(DnsError::plugin(format!(
                "any_match args must be string or string array, got {:?}",
                other
            )));
        }
    };
    validate_non_empty_rules("any_match", &expressions)?;
    Ok(expressions)
}

fn build_any_match(
    tag: String,
    matchers: Vec<String>,
    registry: Arc<PluginRegistry>,
) -> DnsResult<UninitializedPlugin> {
    validate_non_empty_rules("any_match", &matchers)?;
    Ok(UninitializedPlugin::Matcher(Box::new(AnyMatchMatcher {
        tag,
        matcher_refs: matchers,
        matchers: None,
        registry,
    })))
}

#[derive(Debug)]
struct AnyMatchMatcher {
    tag: String,
    /// Raw matcher expressions from config `args`.
    matcher_refs: Vec<String>,
    /// Resolved matcher instances, initialized once in plugin `init`.
    matchers: Option<Vec<MatcherRef>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for AnyMatchMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        let mut result = Vec::with_capacity(self.matcher_refs.len());

        for (idx, matcher_ref) in self.matcher_refs.iter().enumerate() {
            // `parse_matcher_expr` handles optional `!` prefix and returns the
            // normalized matcher expression body.
            let (reverse, matcher_expr) = parse_matcher_expr(matcher_ref)?;
            let plugin_ref = PluginRef::from_str(matcher_expr)?;

            let matchers = match plugin_ref {
                PluginRef::PluginTag(matcher_tag) => self.registry.get_matcher_dependency(
                    &self.tag,
                    &format!("args.matchers[{idx}]"),
                    &matcher_tag,
                )?,

                PluginRef::QuickSetup { plugin_type, param } => {
                    let quick_tag = format!("@qs:match:{}:{}:{}", self.tag, idx, plugin_type);

                    let uninitialized: UninitializedPlugin =
                        self.registry
                            .clone()
                            .quick_setup(&plugin_type, &quick_tag, param)?;

                    match uninitialized.init_and_wrap().await? {
                        PluginHolder::Matcher(matcher) => matcher,
                        _ => {
                            return Err(DnsError::plugin(format!(
                                "quick setup plugin '{}' is not a matcher",
                                plugin_type
                            )));
                        }
                    }
                }
            };
            result.push(MatcherRef::new(matchers, reverse));
        }
        self.matchers.replace(result);
        Ok(())
    }
}

impl Matcher for AnyMatchMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        // Short-circuit on first positive child matcher to keep the hot path
        // cheap.
        self.matchers
            .as_ref()
            .unwrap()
            .iter()
            .any(|matcher| matcher.is_match(context))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_yaml_ng::Value;

    use super::*;
    use crate::config::types::PluginConfig;
    use crate::plugin::dependency::{DependencyKind, DependencySpec};
    use crate::plugin::matcher::false_matcher::FalseMatcherFactory;
    use crate::plugin::matcher::qtype::QtypeFactory;
    use crate::plugin::matcher::true_matcher::TrueMatcherFactory;
    use crate::plugin::test_utils::test_context;
    use crate::proto::{DNSClass, Name, Question, RecordType};

    #[test]
    fn test_dependency_specs_extract_tag_and_quick_setup_references() {
        let config = PluginConfig {
            tag: "any".to_string(),
            plugin_type: "any_match".to_string(),
            args: Some(
                serde_yaml_ng::from_str::<Value>(
                    r#"
- "$a"
- "!$b"
- "_false"
- "qtype 1"
- "qname $domains"
"#,
                )
                .expect("args should parse"),
            ),
        };

        let specs = AnyMatchFactory {}.get_dependency_specs(&config);
        assert_eq!(
            specs,
            vec![
                DependencySpec::matcher("args.matchers[0]", "a"),
                DependencySpec::matcher("args.matchers[1]", "b"),
                DependencySpec::provider(
                    "args.matchers[4] -> quick_setup(qname).domain_set_tags[0]",
                    "domains"
                ),
            ]
        );
    }

    #[test]
    fn test_build_any_match_rejects_empty_rules() {
        assert!(
            build_any_match(
                "any".to_string(),
                Vec::new(),
                Arc::new(PluginRegistry::new())
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn test_any_match_supports_negation_and_quick_setup_matchers() {
        let mut registry = PluginRegistry::new();
        registry.register_factory(
            "_true",
            DependencyKind::Matcher,
            Box::new(TrueMatcherFactory {}),
        );
        registry.register_factory(
            "_false",
            DependencyKind::Matcher,
            Box::new(FalseMatcherFactory {}),
        );
        registry.register_factory(
            "any_match",
            DependencyKind::Matcher,
            Box::new(AnyMatchFactory {}),
        );
        registry.register_factory("qtype", DependencyKind::Matcher, Box::new(QtypeFactory {}));
        let registry = Arc::new(registry);

        let configs = vec![
            PluginConfig {
                tag: "always_false".to_string(),
                plugin_type: "_false".to_string(),
                args: None,
            },
            PluginConfig {
                tag: "any".to_string(),
                plugin_type: "any_match".to_string(),
                args: Some(
                    serde_yaml_ng::from_str::<Value>(
                        r#"
- "$always_false"
- "!$always_false"
- "_false"
"#,
                    )
                    .expect("args should parse"),
                ),
            },
            PluginConfig {
                tag: "any_qtype".to_string(),
                plugin_type: "any_match".to_string(),
                args: Some(
                    serde_yaml_ng::from_str::<Value>(
                        r#"
- "qtype 1"
"#,
                    )
                    .expect("args should parse"),
                ),
            },
        ];

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugins should initialize");

        let plugin = registry
            .get_plugin("any")
            .expect("any matcher should be registered");
        let mut ctx = test_context();
        assert!(plugin.matcher().is_match(&mut ctx));
        let plugin = registry
            .get_plugin("any_qtype")
            .expect("any qtype matcher should be registered");
        ctx.request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        assert!(plugin.matcher().is_match(&mut ctx));

        registry.destory().await;
    }
}
