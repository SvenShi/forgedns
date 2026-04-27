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

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::matcher_utils::{parse_rules_from_value, validate_non_empty_rules};
use crate::plugin::matcher::{Matcher, MatcherRef, parse_matcher_expr};
use crate::plugin::{
    Plugin, PluginFactory, PluginHolder, PluginRef, PluginRegistry, UninitializedPlugin,
};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct AnyMatchFactory {}

register_plugin_factory!("any_match", AnyMatchFactory {});

impl PluginFactory for AnyMatchFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(matchers) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };

        matchers
            .iter()
            .enumerate()
            .filter_map(|(idx, matcher_ref)| {
                parse_matcher_expr(matcher_ref)
                    .ok()
                    .and_then(|(_, matcher_expr)| PluginRef::from_str(matcher_expr).ok())
                    .and_then(|plugin| match plugin {
                        PluginRef::PluginTag(tag) => Some(DependencySpec::matcher(
                            format!("args.matchers[{idx}]"),
                            tag,
                        )),
                        _ => None,
                    })
            })
            .collect()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let matchers = parse_rules_from_value(plugin_config.args.clone())?;
        build_any_match(plugin_config.tag.clone(), matchers, registry)
    }
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
                    let quick_tag = format!("@qs:match:{}:{}:{}", &self.tag, idx, plugin_type);

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
    use crate::plugin::matcher::true_matcher::TrueMatcherFactory;
    use crate::plugin::test_utils::test_context;

    #[test]
    fn test_dependency_specs_extract_only_tag_references() {
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

        registry.destory().await;
    }
}
