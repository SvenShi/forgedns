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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

const NO_CHILD: u32 = u32::MAX;

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

#[derive(Debug, Clone, Copy)]
struct BitTrieNode {
    terminal: bool,
    zero: u32,
    one: u32,
}

impl Default for BitTrieNode {
    fn default() -> Self {
        Self {
            terminal: false,
            zero: NO_CHILD,
            one: NO_CHILD,
        }
    }
}

#[derive(Debug)]
struct BitTrie {
    /// Flat arena to keep branch traversal cache-friendly.
    nodes: Vec<BitTrieNode>,
    /// Number of effective prefixes inserted.
    rule_count: usize,
}

impl Default for BitTrie {
    fn default() -> Self {
        Self {
            nodes: vec![BitTrieNode::default()],
            rule_count: 0,
        }
    }
}

impl BitTrie {
    #[inline]
    fn has_rules(&self) -> bool {
        self.rule_count > 0
    }

    #[inline]
    fn insert_prefix(&mut self, bits: u128, prefix_len: u8) {
        // If root already terminal, /0 has covered everything.
        if self.nodes[0].terminal {
            return;
        }

        let mut cursor = 0u32;
        for depth in 0..prefix_len {
            // If a shorter prefix already exists on this path,
            // a longer prefix is redundant.
            if self.nodes[cursor as usize].terminal {
                return;
            }

            let bit = bit_at(bits, depth);
            let next = if bit == 0 {
                let zero = self.nodes[cursor as usize].zero;
                if zero == NO_CHILD {
                    let idx = self.nodes.len() as u32;
                    self.nodes.push(BitTrieNode::default());
                    self.nodes[cursor as usize].zero = idx;
                    idx
                } else {
                    zero
                }
            } else {
                let one = self.nodes[cursor as usize].one;
                if one == NO_CHILD {
                    let idx = self.nodes.len() as u32;
                    self.nodes.push(BitTrieNode::default());
                    self.nodes[cursor as usize].one = idx;
                    idx
                } else {
                    one
                }
            };

            cursor = next;
        }

        let node = &mut self.nodes[cursor as usize];
        if !node.terminal {
            // Mark terminal and prune deeper branches because they are
            // shadowed by this prefix.
            node.terminal = true;
            node.zero = NO_CHILD;
            node.one = NO_CHILD;
            self.rule_count += 1;
        }
    }

    #[inline]
    fn contains_bits(&self, bits: u128, total_bits: u8) -> bool {
        // Fast-path for /0.
        if self.nodes[0].terminal {
            return true;
        }

        let mut cursor = 0u32;
        for depth in 0..total_bits {
            let node = &self.nodes[cursor as usize];
            let next = if bit_at(bits, depth) == 0 {
                node.zero
            } else {
                node.one
            };
            if next == NO_CHILD {
                return false;
            }
            cursor = next;
            if self.nodes[cursor as usize].terminal {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Copy)]
enum ParsedPrefix {
    /// IPv4 bits are left-aligned in u128 (high 32 bits used).
    V4 {
        bits: u128,
        prefix_len: u8,
    },
    V6 {
        bits: u128,
        prefix_len: u8,
    },
}

#[derive(Debug, Default)]
struct IpMatcher {
    /// Separate tries keep IPv4 and IPv6 hot paths minimal.
    v4: BitTrie,
    v6: BitTrie,
}

impl IpMatcher {
    #[inline]
    fn has_v4_rules(&self) -> bool {
        self.v4.has_rules()
    }

    #[inline]
    fn has_v6_rules(&self) -> bool {
        self.v6.has_rules()
    }

    #[inline]
    fn v4_rule_count(&self) -> usize {
        self.v4.rule_count
    }

    #[inline]
    fn v6_rule_count(&self) -> usize {
        self.v6.rule_count
    }

    fn add_ip_rule(&mut self, rule: &str, source: &str) -> DnsResult<()> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(());
        }

        match parse_ip_prefix(rule).map_err(|e| {
            DnsError::plugin(format!("invalid ip/cidr '{}' in {}: {}", rule, source, e))
        })? {
            ParsedPrefix::V4 { bits, prefix_len } => self.v4.insert_prefix(bits, prefix_len),
            ParsedPrefix::V6 { bits, prefix_len } => self.v6.insert_prefix(bits, prefix_len),
        }
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
        match ip {
            IpAddr::V4(ip) => {
                if !self.v4.has_rules() {
                    return false;
                }
                self.v4.contains_bits(ipv4_to_u128(ip), 32)
            }
            IpAddr::V6(ip) => {
                if !self.v6.has_rules() {
                    return false;
                }
                self.v6.contains_bits(ipv6_to_u128(ip), 128)
            }
        }
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
fn bit_at(bits: u128, depth: u8) -> u8 {
    // Depth 0 means the highest bit.
    ((bits >> (127 - depth as u32)) & 1) as u8
}

#[inline]
fn ipv4_to_u128(ip: Ipv4Addr) -> u128 {
    // Keep IPv4 in high bits so bit_at() can be shared with IPv6 trie logic.
    (u32::from(ip) as u128) << 96
}

#[inline]
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
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

fn parse_ip_prefix(raw: &str) -> Result<ParsedPrefix, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty input".to_string());
    }

    let (ip_part, prefix_part) = if let Some((ip, prefix)) = raw.split_once('/') {
        if raw.as_bytes().iter().filter(|&&b| b == b'/').count() != 1 {
            return Err("invalid cidr format".to_string());
        }
        (ip.trim(), Some(prefix.trim()))
    } else {
        (raw, None)
    };

    let ip = ip_part
        .parse::<IpAddr>()
        .map_err(|e| format!("invalid ip address: {}", e))?;

    match ip {
        IpAddr::V4(ip) => {
            let prefix_len = match prefix_part {
                Some(s) => s
                    .parse::<u8>()
                    .map_err(|e| format!("invalid ipv4 prefix '{}': {}", s, e))?,
                None => 32,
            };
            if prefix_len > 32 {
                return Err(format!(
                    "ipv4 prefix out of range: {} (expected 0..=32)",
                    prefix_len
                ));
            }
            let masked = mask_v4_bits(u32::from(ip), prefix_len);
            Ok(ParsedPrefix::V4 {
                bits: (masked as u128) << 96,
                prefix_len,
            })
        }
        IpAddr::V6(ip) => {
            let prefix_len = match prefix_part {
                Some(s) => s
                    .parse::<u8>()
                    .map_err(|e| format!("invalid ipv6 prefix '{}': {}", s, e))?,
                None => 128,
            };
            if prefix_len > 128 {
                return Err(format!(
                    "ipv6 prefix out of range: {} (expected 0..=128)",
                    prefix_len
                ));
            }
            let masked = mask_v6_bits(ipv6_to_u128(ip), prefix_len);
            Ok(ParsedPrefix::V6 {
                bits: masked,
                prefix_len,
            })
        }
    }
}

#[inline]
fn mask_v4_bits(bits: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - prefix_len as u32))
    }
}

#[inline]
fn mask_v6_bits(bits: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix_len as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
