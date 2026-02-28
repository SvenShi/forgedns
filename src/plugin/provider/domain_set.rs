/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::{DomainRuleMatcher, normalize_domain_cow, split_labels_rev};
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, PluginType, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use smallvec::SmallVec;
use std::any::Any;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Instant;
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
        if path.trim().is_empty() {
            return Ok(());
        }

        let file = File::open(path).map_err(|e| {
            DnsError::plugin(format!(
                "failed to open domain rules file '{}': {}",
                path, e
            ))
        })?;
        let mut reader = BufReader::with_capacity(256 * 1024, file);

        // Reuse one line buffer to avoid per-line allocations while loading huge files.
        let mut line = String::with_capacity(256);
        let mut line_no = 0usize;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read domain rules file '{}' at line {}: {}",
                    path,
                    line_no + 1,
                    e
                ))
            })?;
            if n == 0 {
                break;
            }
            line_no += 1;

            let raw = line.trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let source = format!("file '{}', line {}", path, line_no);
            self.add_exp(raw, &source)?;
        }

        Ok(())
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

    async fn init(&mut self) {}

    async fn destroy(&self) {}
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
        if domain.is_empty() || self.matchers.is_empty() {
            return false;
        }

        let mut labels = SmallVec::<[&str; 8]>::new();
        if self.has_domain_rules {
            split_labels_rev(domain, &mut labels);
        }

        // Fast path for the common one-set case.
        if self.matchers.len() == 1 {
            return self.matchers[0].contains_normalized(domain, &labels);
        }

        for matcher in &self.matchers {
            if matcher.contains_normalized(domain, &labels) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct DomainSetFactory {}

register_plugin_factory!("domain_set", DomainSetFactory {});

impl PluginFactory for DomainSetFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        if let Some(args) = plugin_config.args.clone() {
            serde_yml::from_value::<DomainSetArgs>(args).map_err(|e| {
                DnsError::plugin(format!("domain_set config parsing failed: {}", e))
            })?;
        }
        Ok(())
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        plugin_config
            .args
            .clone()
            .and_then(|args| serde_yml::from_value::<DomainSetArgs>(args).ok())
            .map(|args| args.sets)
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let start = Instant::now();
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

        for set_tag in args.sets {
            debug!(
                tag = %plugin_config.tag,
                referenced_set = %set_tag,
                "resolving referenced domain_set"
            );
            let plugin = registry.get_plugin(set_tag.as_str()).ok_or_else(|| {
                DnsError::plugin(format!("domain_set '{}' does not exist", set_tag))
            })?;

            if !matches!(plugin.plugin_type, PluginType::Provider) {
                return Err(DnsError::plugin(format!(
                    "'{}' is not a provider plugin",
                    set_tag
                )));
            }

            let provider = plugin.to_provider();
            let domain_set = provider
                .as_any()
                .downcast_ref::<DomainSet>()
                .ok_or_else(|| {
                    DnsError::plugin(format!(
                        "'{}' is not a domain_set plugin and cannot be used in sets",
                        set_tag
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
        let elapsed = start.elapsed();
        info!(
            tag = %plugin_config.tag,
            flat_matchers = matchers.len(),
            referenced_sets = referenced_set_count,
            full_rules = total_full_rules,
            domain_rules = total_domain_rules,
            keyword_rules = total_keyword_rules,
            regex_rules = total_regex_rules,
            has_domain_rules,
            elapsed_ms = elapsed.as_millis(),
            "domain_set initialized"
        );

        Ok(UninitializedPlugin::Provider(Box::new(DomainSet {
            tag: plugin_config.tag.clone(),
            matchers,
            has_domain_rules,
        })))
    }
}

#[inline]
fn push_unique_matcher(
    matchers: &mut Vec<Arc<DomainMatcher>>,
    seen: &mut AHashSet<usize>,
    matcher: Arc<DomainMatcher>,
) {
    let ptr = Arc::as_ptr(&matcher) as usize;
    if seen.insert(ptr) {
        matchers.push(matcher);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("forgedns-domain-set-{}.txt", ts));
        std::fs::write(&path, "google.com\nregexp:[bad\n").unwrap();

        let mut m = DomainMatcher::default();
        let err = m.load_file(path.to_str().unwrap()).unwrap_err();
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

        async fn init(&mut self) {}

        async fn destroy(&self) {}
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

    #[test]
    #[ignore]
    fn benchmark_domain_set_million_rules() {
        let rule_count = std::env::var("FORGEDNS_BENCH_RULES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1_000_000);
        let query_count = std::env::var("FORGEDNS_BENCH_QUERIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(500_000);

        let build_start = Instant::now();
        let mut matcher = DomainMatcher::default();
        for i in 0..rule_count {
            let exp = format!("domain:d{}.bench.test", i);
            matcher.add_exp(&exp, "bench").unwrap();
        }
        matcher.add_exp("full:exact.bench.test", "bench").unwrap();
        matcher.add_exp("keyword:adtrack", "bench").unwrap();
        matcher
            .add_exp("regexp:^edge[0-9]+\\.bench\\.test$", "bench")
            .unwrap();
        matcher.finalize().unwrap();
        let build_elapsed = build_start.elapsed();

        let mut queries = Vec::with_capacity(query_count);
        for i in 0..query_count {
            if i % 4 == 0 {
                queries.push(format!("www.d{}.bench.test", i % rule_count));
            } else if i % 4 == 1 {
                queries.push("exact.bench.test.".to_string());
            } else if i % 4 == 2 {
                queries.push(format!("edge{}.bench.test", i));
            } else {
                queries.push(format!("miss{}.example.org", i));
            }
        }

        let warmup_start = Instant::now();
        let mut warmup_hits = 0usize;
        for q in &queries {
            if matcher.contains(q) {
                warmup_hits += 1;
            }
        }
        let warmup_elapsed = warmup_start.elapsed();

        let start = Instant::now();
        let mut hits = 0usize;
        for q in &queries {
            if matcher.contains(q) {
                hits += 1;
            }
        }
        let elapsed = start.elapsed();

        let qps = (query_count as f64) / elapsed.as_secs_f64();
        println!(
            "domain_set bench: rules={}, queries={}, hits={}, warmup_hits={}, build={:.3}s, warmup={:.3}s, elapsed={:.3}s, qps={:.2}",
            rule_count,
            query_count,
            hits,
            warmup_hits,
            build_elapsed.as_secs_f64(),
            warmup_elapsed.as_secs_f64(),
            elapsed.as_secs_f64(),
            qps
        );
    }
}
