// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! High-performance domain expression set provider.
//!
//! Responsibilities:
//! - load domain expressions from inline config and files.
//! - resolve referenced domain-capable providers declared in `sets`.
//! - provide hot-path membership checks for matcher plugins.
//!
//! Performance model:
//! - local expressions are compiled once per init/reload.
//! - runtime lookup uses pre-normalized input and optional pre-split labels.
//! - runtime lookup checks the local matcher first, then referenced providers
//!   through stable handles so child reloads become visible immediately.

use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, info};

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::DomainRuleMatcher;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{Name, Question};
use crate::register_plugin_factory;

#[derive(Debug, Clone, Deserialize, Default)]
struct DomainSetArgs {
    /// Inline domain expressions.
    #[serde(default)]
    exps: Vec<String>,
    /// Referenced domain_set plugin tags.
    #[serde(default)]
    sets: Vec<String>,
    /// Text files containing one expression per line.
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Default)]
struct DomainSetSnapshot {
    matcher: DomainRuleMatcher,
}

#[derive(Debug)]
pub struct DomainSet {
    tag: String,
    args: DomainSetArgs,
    registry: Arc<PluginRegistry>,
    referenced_sets: Vec<Arc<dyn Provider>>,
    snapshot: ArcSwap<DomainSetSnapshot>,
}

impl DomainSet {
    #[hotpath::measure]
    fn build_local_snapshot(&self) -> DnsResult<DomainSetSnapshot> {
        let start_ms = AppClock::elapsed_millis();
        let mut rules = self.args.exps.clone();
        for file in &self.args.files {
            append_rules_from_file(&mut rules, file)?;
        }

        let mut matcher = DomainRuleMatcher::default();
        load_domain_rules(&mut matcher, &rules)?;
        matcher.finalize().map_err(DnsError::plugin)?;

        let has_domain_rules = matcher.has_rules();
        let total_full_rules = matcher.full_rule_count();
        let total_domain_rules = matcher.trie_rule_count();
        let total_keyword_rules = matcher.keyword_rule_count();
        let total_regex_rules = matcher.regexp_rule_count();
        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(start_ms);
        info!(
            tag = %self.tag,
            local_rules = rules.len(),
            referenced_sets = self.args.sets.len(),
            full_rules = total_full_rules,
            domain_rules = total_domain_rules,
            keyword_rules = total_keyword_rules,
            regex_rules = total_regex_rules,
            has_domain_rules,
            elapsed_ms,
            "domain_set snapshot built"
        );

        Ok(DomainSetSnapshot { matcher })
    }
}

#[async_trait]
impl Plugin for DomainSet {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        let mut providers = Vec::with_capacity(self.args.sets.len());
        for (set_idx, set_tag) in self.args.sets.iter().enumerate() {
            let field = format!("args.sets[{}]", set_idx);
            debug!(
                tag = %self.tag,
                referenced_set = %set_tag,
                "resolving referenced domain provider"
            );
            let provider =
                self.registry
                    .get_provider_dependency(&self.tag, &field, set_tag.as_str())?;
            if !provider.supports_domain_matching() {
                return Err(DnsError::plugin(format!(
                    "plugin '{}' field '{}' expects provider '{}' to support domain matching",
                    self.tag, field, set_tag
                )));
            }
            providers.push(provider);
        }
        self.referenced_sets = providers;
        self.reload().await
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

#[async_trait]
impl Provider for DomainSet {
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    #[hotpath::measure]
    fn contains_name(&self, name: &Name) -> bool {
        let snapshot = self.snapshot.load();
        snapshot.matcher.is_match_name(name)
            || self
                .referenced_sets
                .iter()
                .any(|set| set.contains_name(name))
    }

    #[inline]
    #[hotpath::measure]
    fn contains_question(&self, question: &Question) -> bool {
        let snapshot = self.snapshot.load();
        snapshot.matcher.is_match_name(question.name())
            || self
                .referenced_sets
                .iter()
                .any(|set| set.contains_question(question) || set.contains_name(question.name()))
    }

    #[hotpath::measure]
    async fn reload(&self) -> DnsResult<()> {
        let snapshot = self.build_local_snapshot()?;
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    fn supports_domain_matching(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct DomainSetFactory {}

register_plugin_factory!("domain_set", DomainSetFactory {});

impl PluginFactory for DomainSetFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        plugin_config
            .args
            .clone()
            .and_then(|args| serde_yaml_ng::from_value::<DomainSetArgs>(args).ok())
            .map(|args| {
                args.sets
                    .into_iter()
                    .enumerate()
                    .map(|(idx, tag)| DependencySpec::provider(format!("args.sets[{}]", idx), tag))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let args = plugin_config
            .args
            .clone()
            .map(serde_yaml_ng::from_value::<DomainSetArgs>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse domain_set config: {}", e)))?
            .unwrap_or_default();
        info!(
            tag = %plugin_config.tag,
            exps = args.exps.len(),
            files = args.files.len(),
            sets = args.sets.len(),
            "domain_set configured"
        );

        Ok(UninitializedPlugin::Provider(Box::new(DomainSet {
            tag: plugin_config.tag.clone(),
            args,
            registry,
            referenced_sets: Vec::new(),
            snapshot: ArcSwap::from_pointee(DomainSetSnapshot::default()),
        })))
    }
}

fn append_rules_from_file(rules: &mut Vec<String>, path: &str) -> DnsResult<()> {
    crate::plugin::provider::provider_utils::for_each_nonempty_rule_line(
        path,
        "domain rules",
        |raw, _| {
            rules.push(raw.to_string());
            Ok(())
        },
    )
}

fn load_domain_rules(matcher: &mut DomainRuleMatcher, rules: &[String]) -> DnsResult<()> {
    for (idx, rule) in rules.iter().enumerate() {
        add_domain_rule(matcher, rule, &format!("rules[{}]", idx))?;
    }
    Ok(())
}

fn add_domain_rule(matcher: &mut DomainRuleMatcher, exp: &str, source: &str) -> DnsResult<()> {
    matcher
        .add_expression(exp, source)
        .map_err(DnsError::plugin)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::plugin::provider::provider_utils::for_each_nonempty_rule_text;
    use crate::proto::Name;

    fn load_rules_text(
        matcher: &mut DomainRuleMatcher,
        source_name: &str,
        content: &str,
    ) -> DnsResult<()> {
        for_each_nonempty_rule_text(content, |raw, line_no| {
            let source = format!("file '{}', line {}", source_name, line_no);
            add_domain_rule(matcher, raw, &source)
        })
    }

    #[test]
    fn test_domain_match_priority() {
        let mut m = DomainRuleMatcher::default();
        add_domain_rule(&mut m, "full:exact.com", "test").unwrap();
        add_domain_rule(&mut m, "domain:example.com", "test").unwrap();
        add_domain_rule(&mut m, "keyword:abc", "test").unwrap();
        add_domain_rule(&mut m, "regexp:^re.+\\.com$", "test").unwrap();
        m.finalize().unwrap();

        assert!(m.is_match_name(&Name::from_ascii("exact.com.").unwrap()));
        assert!(m.is_match_name(&Name::from_ascii("www.example.com").unwrap()));
        assert!(m.is_match_name(&Name::from_ascii("re123.com").unwrap()));
        assert!(m.is_match_name(&Name::from_ascii("xabcx.org").unwrap()));
        assert!(!m.is_match_name(&Name::from_ascii("none.org").unwrap()));
    }

    #[test]
    fn test_default_rule_is_domain() {
        let mut m = DomainRuleMatcher::default();
        add_domain_rule(&mut m, "google.com", "test").unwrap();
        m.finalize().unwrap();

        assert!(m.is_match_name(&Name::from_ascii("google.com").unwrap()));
        assert!(m.is_match_name(&Name::from_ascii("www.google.com").unwrap()));
        assert!(!m.is_match_name(&Name::from_ascii("google").unwrap()));
        assert!(!m.is_match_name(&Name::from_ascii("google.cn").unwrap()));
    }

    #[test]
    fn test_file_line_error_has_line_number() {
        let mut m = DomainRuleMatcher::default();
        let err =
            load_rules_text(&mut m, "inline-domain-test", "google.com\nregexp:[bad\n").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("line 2"),
            "error should include line number: {msg}"
        );
    }

    #[test]
    fn test_case_insensitive_and_trailing_dot() {
        let mut m = DomainRuleMatcher::default();
        add_domain_rule(&mut m, "full:Google.Com", "test").unwrap();
        m.finalize().unwrap();
        assert!(m.is_match_name(&Name::from_ascii("google.com.").unwrap()));
        assert!(m.is_match_name(&Name::from_ascii("GOOGLE.COM").unwrap()));
    }

    #[derive(Debug)]
    struct StaticDomainProvider {
        domain: String,
    }

    #[async_trait]
    impl Plugin for StaticDomainProvider {
        fn tag(&self) -> &str {
            "static-provider"
        }

        async fn init(&mut self) -> crate::core::error::Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> crate::core::error::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for StaticDomainProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn contains_name(&self, name: &Name) -> bool {
            name.as_str().eq_ignore_ascii_case(&self.domain)
        }

        fn contains_ip(&self, _ip: IpAddr) -> bool {
            false
        }
    }

    #[test]
    fn test_contains_with_shared_set() {
        let mut local = DomainRuleMatcher::default();
        add_domain_rule(&mut local, "local.example", "test").unwrap();
        local.finalize().unwrap();

        let shared = Arc::new(StaticDomainProvider {
            domain: "shared.example".to_string(),
        }) as Arc<dyn Provider>;

        let ds = DomainSet {
            tag: "test".to_string(),
            args: DomainSetArgs::default(),
            registry: Arc::new(PluginRegistry::new()),
            referenced_sets: vec![shared.clone()],
            snapshot: ArcSwap::from_pointee(DomainSetSnapshot { matcher: local }),
        };
        assert!(ds.contains_name(&Name::from_ascii("local.example").unwrap()));
        assert!(!ds.contains_name(&Name::from_ascii("none.example").unwrap()));
        assert!(shared.contains_name(&Name::from_ascii("shared.example").unwrap()));
        assert!(ds.contains_name(&Name::from_ascii("shared.example").unwrap()));
    }
}
