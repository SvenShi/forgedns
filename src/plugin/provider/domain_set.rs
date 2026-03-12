/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! High-performance domain expression set provider.
//!
//! Responsibilities:
//! - load domain expressions from inline config and files.
//! - resolve referenced `domain_set` providers and flatten them.
//! - provide hot-path membership checks for matcher plugins.
//!
//! Performance model:
//! - expressions are compiled once at init time.
//! - runtime lookup uses pre-normalized input and optional pre-split labels.
//! - flattened matcher graph avoids recursive provider traversal.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::QueryView;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::{DomainRuleMatcher, normalize_domain_cow, split_labels_rev};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::provider::Provider;
use crate::plugin::provider::provider_utils::{for_each_nonempty_rule_line, push_unique_matcher};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use smallvec::SmallVec;
use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{debug, info};

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
struct DomainMatcher {
    rules: DomainRuleMatcher,
}

impl DomainMatcher {
    #[inline]
    fn has_domain_rules(&self) -> bool {
        self.rules.has_trie_rules()
    }

    #[inline]
    fn full_rule_count(&self) -> usize {
        self.rules.full_rule_count()
    }

    #[inline]
    fn domain_rule_count(&self) -> usize {
        self.rules.trie_rule_count()
    }

    #[inline]
    fn keyword_rule_count(&self) -> usize {
        self.rules.keyword_rule_count()
    }

    #[inline]
    fn regex_rule_count(&self) -> usize {
        self.rules.regexp_rule_count()
    }

    /// Parse and load one expression.
    fn add_exp(&mut self, exp: &str, source: &str) -> DnsResult<()> {
        self.rules
            .add_expression(exp, source)
            .map_err(DnsError::plugin)
    }

    fn load_exps(&mut self, exps: &[String]) -> DnsResult<()> {
        for (idx, exp) in exps.iter().enumerate() {
            let source = format!("exps[{}]", idx);
            self.add_exp(exp, &source)?;
        }
        Ok(())
    }

    /// Load expressions from file and attach precise line info to parsing errors.
    fn load_file(&mut self, path: &str) -> DnsResult<()> {
        for_each_nonempty_rule_line(path, "domain rules", |raw, line_no| {
            let source = format!("file '{}', line {}", path, line_no);
            self.add_exp(raw, &source)
        })
    }

    fn load_files(&mut self, files: &[String]) -> DnsResult<()> {
        for file in files {
            self.load_file(file)?;
        }
        Ok(())
    }

    fn finalize(&mut self) -> DnsResult<()> {
        self.rules.finalize().map_err(DnsError::plugin)
    }

    #[inline]
    fn contains_normalized(&self, domain: &str, labels_rev: &[&str]) -> bool {
        self.rules.is_match_normalized(domain, labels_rev)
    }

    #[inline]
    fn contains_query_view(&self, query_view: &QueryView) -> bool {
        self.rules.is_match_query_view(query_view)
    }

    #[cfg(test)]
    #[inline]
    fn contains(&self, domain: &str) -> bool {
        let normalized = normalize_domain_cow(domain);
        let domain = normalized.as_ref();
        if domain.is_empty() {
            return false;
        }
        let mut labels = SmallVec::<[&str; 8]>::new();
        split_labels_rev(domain, &mut labels);
        self.contains_normalized(domain, &labels)
    }
}

#[derive(Debug)]
pub struct DomainSet {
    tag: String,
    /// Flattened matcher list from self + referenced sets.
    /// This avoids recursive provider calls on the hot path.
    matchers: Vec<Arc<DomainMatcher>>,
    has_domain_rules: bool,
}

#[async_trait]
impl Plugin for DomainSet {
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

#[async_trait]
impl Provider for DomainSet {
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn contains_domain(&self, domain: &str) -> bool {
        let normalized = normalize_domain_cow(domain);
        let domain = normalized.as_ref();
        if domain.is_empty() {
            return false;
        }

        let mut labels = SmallVec::<[&str; 8]>::new();
        if self.has_domain_rules {
            split_labels_rev(domain, &mut labels);
        }

        self.contains_domain_prepared(domain, &labels)
    }

    #[inline]
    fn contains_domain_prepared(&self, domain: &str, labels_rev: &[&str]) -> bool {
        if domain.is_empty() || self.matchers.is_empty() {
            return false;
        }

        let mut labels_buf = SmallVec::<[&str; 8]>::new();
        let labels = if self.has_domain_rules && labels_rev.is_empty() {
            // Build labels locally when caller does not provide pre-split labels.
            split_labels_rev(domain, &mut labels_buf);
            labels_buf.as_slice()
        } else {
            labels_rev
        };

        // Fast path for the common one-set case.
        if self.matchers.len() == 1 {
            return self.matchers[0].contains_normalized(domain, labels);
        }

        for matcher in &self.matchers {
            if matcher.contains_normalized(domain, labels) {
                return true;
            }
        }
        false
    }

    #[inline]
    fn contains_query_view(&self, query_view: &QueryView) -> bool {
        if self.matchers.is_empty() {
            return false;
        }

        if self.matchers.len() == 1 {
            return self.matchers[0].contains_query_view(query_view);
        }

        self.matchers
            .iter()
            .any(|matcher| matcher.contains_query_view(query_view))
    }

    #[inline]
    fn has_trie_domain_rules(&self) -> bool {
        self.has_domain_rules
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
            .and_then(|args| serde_yml::from_value::<DomainSetArgs>(args).ok())
            .map(|args| {
                args.sets
                    .into_iter()
                    .enumerate()
                    .map(|(idx, tag)| {
                        DependencySpec::provider_type(
                            format!("args.sets[{}]", idx),
                            tag,
                            "domain_set",
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        // Provider init latency logging does not require high-precision syscall timing.
        let start_ms = AppClock::elapsed_millis();
        let args = plugin_config
            .args
            .clone()
            .map(serde_yml::from_value::<DomainSetArgs>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse domain_set config: {}", e)))?
            .unwrap_or_default();
        let referenced_set_count = args.sets.len();
        debug!(
            tag = %plugin_config.tag,
            exps = args.exps.len(),
            files = args.files.len(),
            sets = referenced_set_count,
            "initializing domain_set"
        );

        let mut local_matcher = DomainMatcher::default();
        local_matcher.load_exps(&args.exps)?;
        local_matcher.load_files(&args.files)?;
        local_matcher.finalize()?;

        let mut matchers = Vec::with_capacity(1 + args.sets.len());
        let mut seen = AHashSet::with_capacity(1 + args.sets.len());
        push_unique_matcher(&mut matchers, &mut seen, Arc::new(local_matcher));

        for (set_idx, set_tag) in args.sets.into_iter().enumerate() {
            let field = format!("args.sets[{}]", set_idx);
            debug!(
                tag = %plugin_config.tag,
                referenced_set = %set_tag,
                "resolving referenced domain_set"
            );
            let provider = registry.get_provider_dependency_of_type(
                &plugin_config.tag,
                &field,
                set_tag.as_str(),
                "domain_set",
            )?;
            let domain_set = provider
                .as_any()
                .downcast_ref::<DomainSet>()
                .ok_or_else(|| {
                    DnsError::plugin(format!(
                        "plugin '{}' field '{}' expects provider instance 'domain_set', but '{}' is not DomainSet",
                        plugin_config.tag, field, set_tag
                    ))
                })?;

            for matcher in &domain_set.matchers {
                push_unique_matcher(&mut matchers, &mut seen, matcher.clone());
            }
        }

        let has_domain_rules = matchers.iter().any(|matcher| matcher.has_domain_rules());
        let total_full_rules: usize = matchers.iter().map(|m| m.full_rule_count()).sum();
        let total_domain_rules: usize = matchers.iter().map(|m| m.domain_rule_count()).sum();
        let total_keyword_rules: usize = matchers.iter().map(|m| m.keyword_rule_count()).sum();
        let total_regex_rules: usize = matchers.iter().map(|m| m.regex_rule_count()).sum();
        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(start_ms);
        info!(
            tag = %plugin_config.tag,
            flat_matchers = matchers.len(),
            referenced_sets = referenced_set_count,
            full_rules = total_full_rules,
            domain_rules = total_domain_rules,
            keyword_rules = total_keyword_rules,
            regex_rules = total_regex_rules,
            has_domain_rules,
            elapsed_ms,
            "domain_set initialized"
        );

        Ok(UninitializedPlugin::Provider(Box::new(DomainSet {
            tag: plugin_config.tag.clone(),
            matchers,
            has_domain_rules,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::provider::provider_utils::for_each_nonempty_rule_text;
    use std::net::IpAddr;

    fn load_rules_text(
        matcher: &mut DomainMatcher,
        source_name: &str,
        content: &str,
    ) -> DnsResult<()> {
        for_each_nonempty_rule_text(content, |raw, line_no| {
            let source = format!("file '{}', line {}", source_name, line_no);
            matcher.add_exp(raw, &source)
        })
    }

    #[test]
    fn test_domain_match_priority() {
        let mut m = DomainMatcher::default();
        m.add_exp("full:exact.com", "test").unwrap();
        m.add_exp("domain:example.com", "test").unwrap();
        m.add_exp("keyword:abc", "test").unwrap();
        m.add_exp("regexp:^re.+\\.com$", "test").unwrap();
        m.finalize().unwrap();

        assert!(m.contains("exact.com."));
        assert!(m.contains("www.example.com"));
        assert!(m.contains("re123.com"));
        assert!(m.contains("xabcx.org"));
        assert!(!m.contains("none.org"));
    }

    #[test]
    fn test_default_rule_is_domain() {
        let mut m = DomainMatcher::default();
        m.add_exp("google.com", "test").unwrap();
        m.finalize().unwrap();

        assert!(m.contains("google.com"));
        assert!(m.contains("www.google.com"));
        assert!(!m.contains("google"));
        assert!(!m.contains("google.cn"));
    }

    #[test]
    fn test_file_line_error_has_line_number() {
        let mut m = DomainMatcher::default();
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
        let mut m = DomainMatcher::default();
        m.add_exp("full:Google.Com", "test").unwrap();
        m.finalize().unwrap();
        assert!(m.contains("google.com."));
        assert!(m.contains("GOOGLE.COM"));
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

        fn contains_domain(&self, domain: &str) -> bool {
            normalize_domain_cow(domain).as_ref() == self.domain
        }

        fn contains_ip(&self, _ip: IpAddr) -> bool {
            false
        }
    }

    #[test]
    fn test_contains_with_shared_set() {
        let mut local = DomainMatcher::default();
        local.add_exp("local.example", "test").unwrap();
        local.finalize().unwrap();

        let shared = Arc::new(StaticDomainProvider {
            domain: "shared.example".to_string(),
        }) as Arc<dyn Provider>;

        let ds = DomainSet {
            tag: "test".to_string(),
            matchers: vec![Arc::new(local)],
            has_domain_rules: true,
        };
        assert!(ds.contains_domain("local.example"));
        assert!(!ds.contains_domain("none.example"));
        assert!(shared.contains_domain("shared.example"));
    }
}
