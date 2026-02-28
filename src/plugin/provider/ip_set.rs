/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! High-performance IP/CIDR set provider.
//!
//! Design goals:
//! - Constant-time-ish membership checks on hot path.
//! - Unified IPv4/IPv6 semantics.
//! - Zero recursion in runtime matching when sets are composed.
//! - Precise parse errors for file-based rules.

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::IpPrefixMatcher;
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, PluginType, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use std::any::Any;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

#[derive(Debug, Clone, Deserialize, Default)]
struct IpSetArgs {
    /// Inline ip/cidr rules.
    #[serde(default)]
    ips: Vec<String>,
    /// Referenced ip_set plugin tags.
    #[serde(default)]
    sets: Vec<String>,
    /// Text files containing one ip/cidr rule per line.
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Default)]
struct IpMatcher {
    matcher: IpPrefixMatcher,
}

impl IpMatcher {
    #[inline]
    fn has_v4_rules(&self) -> bool {
        self.matcher.has_v4_rules()
    }

    #[inline]
    fn has_v6_rules(&self) -> bool {
        self.matcher.has_v6_rules()
    }

    #[inline]
    fn v4_rule_count(&self) -> usize {
        self.matcher.v4_rule_count()
    }

    #[inline]
    fn v6_rule_count(&self) -> usize {
        self.matcher.v6_rule_count()
    }

    fn add_ip_rule(&mut self, rule: &str, source: &str) -> DnsResult<()> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(());
        }

        self.matcher.add_rule(rule).map_err(|e| {
            DnsError::plugin(format!("invalid ip/cidr '{}' in {}: {}", rule, source, e))
        })?;
        Ok(())
    }

    fn load_ips(&mut self, ips: &[String]) -> DnsResult<()> {
        for (idx, ip) in ips.iter().enumerate() {
            let source = format!("ips[{}]", idx);
            self.add_ip_rule(ip, &source)?;
        }
        Ok(())
    }

    fn load_file(&mut self, path: &str) -> DnsResult<()> {
        if path.trim().is_empty() {
            return Ok(());
        }

        let file = File::open(path).map_err(|e| {
            DnsError::plugin(format!("failed to open ip rules file '{}': {}", path, e))
        })?;
        let mut reader = BufReader::with_capacity(256 * 1024, file);

        // Reuse line buffer to reduce allocations for huge rule files.
        let mut line = String::with_capacity(256);
        let mut line_no = 0usize;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read ip rules file '{}' at line {}: {}",
                    path,
                    line_no + 1,
                    e
                ))
            })?;
            if n == 0 {
                break;
            }
            line_no += 1;

            let rule = normalize_rule_line(&line);
            if rule.is_empty() {
                continue;
            }

            let source = format!("file '{}', line {}", path, line_no);
            self.add_ip_rule(rule, &source)?;
        }

        Ok(())
    }

    fn load_files(&mut self, files: &[String]) -> DnsResult<()> {
        for file in files {
            self.load_file(file)?;
        }
        Ok(())
    }

    #[inline]
    fn contains_ip(&self, ip: IpAddr) -> bool {
        self.matcher.contains_ip(ip)
    }
}

#[derive(Debug)]
pub struct IpSet {
    tag: String,
    /// Flattened matcher list from self + referenced sets.
    /// Runtime lookup does not recurse through provider references.
    matchers: Vec<Arc<IpMatcher>>,
    /// Family-level fast guards to avoid useless scans.
    has_v4_rules: bool,
    has_v6_rules: bool,
}

#[async_trait]
impl Plugin for IpSet {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Provider for IpSet {
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn contains_ip(&self, ip: IpAddr) -> bool {
        if self.matchers.is_empty() {
            return false;
        }

        let has_family_rules = match ip {
            IpAddr::V4(_) => self.has_v4_rules,
            IpAddr::V6(_) => self.has_v6_rules,
        };
        if !has_family_rules {
            return false;
        }

        if self.matchers.len() == 1 {
            return self.matchers[0].contains_ip(ip);
        }

        self.matchers.iter().any(|matcher| matcher.contains_ip(ip))
    }
}

#[derive(Debug, Clone)]
pub struct IpSetFactory {}

register_plugin_factory!("ip_set", IpSetFactory {});

impl PluginFactory for IpSetFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        if let Some(args) = plugin_config.args.clone() {
            serde_yml::from_value::<IpSetArgs>(args)
                .map_err(|e| DnsError::plugin(format!("ip_set config parsing failed: {}", e)))?;
        }
        Ok(())
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        plugin_config
            .args
            .clone()
            .and_then(|args| serde_yml::from_value::<IpSetArgs>(args).ok())
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
            .map(serde_yml::from_value::<IpSetArgs>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse ip_set config: {}", e)))?
            .unwrap_or_default();
        let referenced_set_count = args.sets.len();
        debug!(
            tag = %plugin_config.tag,
            ips = args.ips.len(),
            files = args.files.len(),
            sets = referenced_set_count,
            "initializing ip_set"
        );

        let mut local_matcher = IpMatcher::default();
        local_matcher.load_ips(&args.ips)?;
        local_matcher.load_files(&args.files)?;

        // Build a flattened matcher list (local + referenced sets), with dedup.
        let mut matchers = Vec::with_capacity(1 + args.sets.len());
        let mut seen = AHashSet::with_capacity(1 + args.sets.len());
        push_unique_matcher(&mut matchers, &mut seen, Arc::new(local_matcher));

        for set_tag in args.sets {
            debug!(
                tag = %plugin_config.tag,
                referenced_set = %set_tag,
                "resolving referenced ip_set"
            );
            let plugin = registry
                .get_plugin(set_tag.as_str())
                .ok_or_else(|| DnsError::plugin(format!("ip_set '{}' does not exist", set_tag)))?;

            if !matches!(plugin.plugin_type, PluginType::Provider) {
                return Err(DnsError::plugin(format!(
                    "'{}' is not a provider plugin",
                    set_tag
                )));
            }

            let provider = plugin.to_provider();
            let ip_set = provider.as_any().downcast_ref::<IpSet>().ok_or_else(|| {
                DnsError::plugin(format!(
                    "'{}' is not an ip_set plugin and cannot be used in sets",
                    set_tag
                ))
            })?;

            for matcher in &ip_set.matchers {
                push_unique_matcher(&mut matchers, &mut seen, matcher.clone());
            }
        }

        let has_v4_rules = matchers.iter().any(|matcher| matcher.has_v4_rules());
        let has_v6_rules = matchers.iter().any(|matcher| matcher.has_v6_rules());
        let total_v4_rules: usize = matchers.iter().map(|m| m.v4_rule_count()).sum();
        let total_v6_rules: usize = matchers.iter().map(|m| m.v6_rule_count()).sum();
        let elapsed = start.elapsed();
        info!(
            tag = %plugin_config.tag,
            flat_matchers = matchers.len(),
            referenced_sets = referenced_set_count,
            v4_rules = total_v4_rules,
            v6_rules = total_v6_rules,
            has_v4_rules,
            has_v6_rules,
            elapsed_ms = elapsed.as_millis(),
            "ip_set initialized"
        );

        Ok(UninitializedPlugin::Provider(Box::new(IpSet {
            tag: plugin_config.tag.clone(),
            matchers,
            has_v4_rules,
            has_v6_rules,
        })))
    }
}

#[inline]
fn push_unique_matcher(
    matchers: &mut Vec<Arc<IpMatcher>>,
    seen: &mut AHashSet<usize>,
    matcher: Arc<IpMatcher>,
) {
    // Pointer-level dedup is enough because referenced sets share Arc instances.
    let ptr = Arc::as_ptr(&matcher) as usize;
    if seen.insert(ptr) {
        matchers.push(matcher);
    }
}

#[inline]
fn normalize_rule_line(line: &str) -> &str {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return "";
    }
    line.split_once('#')
        .map(|(rule, _)| rule)
        .unwrap_or(line)
        .trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipv4_and_ipv6_match() {
        let mut m = IpMatcher::default();
        m.add_ip_rule("192.168.1.0/24", "test").unwrap();
        m.add_ip_rule("2001:db8::/32", "test").unwrap();

        assert!(m.contains_ip("192.168.1.7".parse().unwrap()));
        assert!(!m.contains_ip("192.168.2.1".parse().unwrap()));
        assert!(m.contains_ip("2001:db8:1::1".parse().unwrap()));
        assert!(!m.contains_ip("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_single_ip_default_prefix() {
        let mut m = IpMatcher::default();
        m.add_ip_rule("1.1.1.1", "test").unwrap();
        m.add_ip_rule("2001:db8::1", "test").unwrap();

        assert!(m.contains_ip("1.1.1.1".parse().unwrap()));
        assert!(!m.contains_ip("1.1.1.2".parse().unwrap()));
        assert!(m.contains_ip("2001:db8::1".parse().unwrap()));
        assert!(!m.contains_ip("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_host_bits_are_masked() {
        let mut m = IpMatcher::default();
        m.add_ip_rule("10.10.10.7/24", "test").unwrap();
        assert!(m.contains_ip("10.10.10.200".parse().unwrap()));
        assert!(!m.contains_ip("10.10.11.1".parse().unwrap()));
    }

    #[test]
    fn test_file_line_error_has_line_number() {
        let path = std::env::temp_dir().join("forgedns-ip-set-test.txt");
        std::fs::write(&path, "1.1.1.1\n2001::1/200\n").unwrap();

        let mut m = IpMatcher::default();
        let err = m.load_file(path.to_str().unwrap()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("line 2"),
            "error should include line number: {msg}"
        );
    }

    #[test]
    fn test_parse_error_includes_input() {
        let mut m = IpMatcher::default();
        let err = m.add_ip_rule("1.1.1.1/abc", "test").unwrap_err();
        assert!(err.to_string().contains("1.1.1.1/abc"));
    }

    #[test]
    fn test_inline_comment_in_file() {
        let path = std::env::temp_dir().join("forgedns-ip-set-comment-test.txt");
        std::fs::write(&path, "1.1.1.1 # test\n# ignore\n\n").unwrap();

        let mut m = IpMatcher::default();
        m.load_file(path.to_str().unwrap()).unwrap();
        assert!(m.contains_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    #[ignore]
    fn benchmark_ip_set_million_rules() {
        let rule_count = std::env::var("FORGEDNS_IP_BENCH_RULES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1_000_000);
        let query_count = std::env::var("FORGEDNS_IP_BENCH_QUERIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(500_000);

        let build_start = Instant::now();
        let mut matcher = IpMatcher::default();
        for i in 0..rule_count {
            let ip = Ipv4Addr::from((i as u32) << 8);
            let rule = format!("{}/24", ip);
            matcher.add_ip_rule(&rule, "bench").unwrap();
        }
        matcher.add_ip_rule("2001:db8::/32", "bench").unwrap();
        let build_elapsed = build_start.elapsed();

        let mut queries = Vec::with_capacity(query_count);
        for i in 0..query_count {
            if i % 4 == 0 {
                let n = (i % rule_count) as u32;
                queries.push(IpAddr::V4(Ipv4Addr::from((n << 8) | 88)));
            } else if i % 4 == 1 {
                queries.push(IpAddr::V4(Ipv4Addr::from(
                    0xC000_0000u32.wrapping_add(i as u32),
                )));
            } else if i % 4 == 2 {
                queries.push(IpAddr::V6("2001:db8::1234".parse().unwrap()));
            } else {
                queries.push(IpAddr::V6("2001:db9::1".parse().unwrap()));
            }
        }

        let warmup_start = Instant::now();
        let mut warmup_hits = 0usize;
        for ip in &queries {
            if matcher.contains_ip(*ip) {
                warmup_hits += 1;
            }
        }
        let warmup_elapsed = warmup_start.elapsed();

        let start = Instant::now();
        let mut hits = 0usize;
        for ip in &queries {
            if matcher.contains_ip(*ip) {
                hits += 1;
            }
        }
        let elapsed = start.elapsed();
        let qps = (query_count as f64) / elapsed.as_secs_f64();
        println!(
            "ip_set bench: rules={}, queries={}, hits={}, warmup_hits={}, build={:.3}s, warmup={:.3}s, elapsed={:.3}s, qps={:.2}",
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
