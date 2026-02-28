/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared high-performance rule matchers used by providers and matchers.

use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NO_CHILD: u32 = u32::MAX;

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
pub(crate) struct IpPrefixMatcher {
    /// Separate tries keep IPv4 and IPv6 hot paths minimal.
    v4: BitTrie,
    v6: BitTrie,
}

impl IpPrefixMatcher {
    #[inline]
    pub(crate) fn has_v4_rules(&self) -> bool {
        self.v4.has_rules()
    }

    #[inline]
    pub(crate) fn has_v6_rules(&self) -> bool {
        self.v6.has_rules()
    }

    #[inline]
    pub(crate) fn v4_rule_count(&self) -> usize {
        self.v4.rule_count
    }

    #[inline]
    pub(crate) fn v6_rule_count(&self) -> usize {
        self.v6.rule_count
    }

    pub(crate) fn add_rule(&mut self, raw_rule: &str) -> Result<(), String> {
        let rule = raw_rule.trim();
        if rule.is_empty() {
            return Ok(());
        }

        match parse_ip_prefix(rule)? {
            ParsedPrefix::V4 { bits, prefix_len } => self.v4.insert_prefix(bits, prefix_len),
            ParsedPrefix::V6 { bits, prefix_len } => self.v6.insert_prefix(bits, prefix_len),
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn contains_ip(&self, ip: IpAddr) -> bool {
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

#[derive(Debug, Default)]
pub(crate) struct DomainTrieNode {
    pub(crate) terminal: bool,
    pub(crate) children: AHashMap<Box<str>, u32>,
}

#[derive(Debug)]
pub(crate) struct DomainTrie {
    /// Flat arena to avoid pointer-heavy tree allocations.
    pub(crate) nodes: Vec<DomainTrieNode>,
    pub(crate) rule_count: usize,
}

impl Default for DomainTrie {
    fn default() -> Self {
        Self {
            nodes: vec![DomainTrieNode::default()],
            rule_count: 0,
        }
    }
}

impl DomainTrie {
    #[inline]
    pub(crate) fn has_rules(&self) -> bool {
        self.rule_count > 0
    }

    /// Insert a domain rule by reversed labels, e.g. `google.com` => `com -> google`.
    pub(crate) fn insert(&mut self, domain: &str) {
        let mut cursor = 0u32;
        for label in domain.rsplit('.') {
            if label.is_empty() {
                continue;
            }

            let next = if let Some(next) = self.nodes[cursor as usize].children.get(label) {
                *next
            } else {
                let idx = self.nodes.len() as u32;
                self.nodes.push(DomainTrieNode::default());
                self.nodes[cursor as usize]
                    .children
                    .insert(label.to_owned().into_boxed_str(), idx);
                idx
            };
            cursor = next;
        }

        let node = &mut self.nodes[cursor as usize];
        if !node.terminal {
            node.terminal = true;
            self.rule_count += 1;
        }
    }

    /// Match a parsed query label slice against domain suffix rules.
    #[inline]
    pub(crate) fn contains_labels(&self, labels_rev: &[&str]) -> bool {
        let mut cursor = 0u32;
        for label in labels_rev {
            let Some(next) = self.nodes[cursor as usize].children.get(*label) else {
                return false;
            };
            cursor = *next;
            if self.nodes[cursor as usize].terminal {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DomainRuleKind {
    Full,
    Domain,
    Keyword,
    Regexp,
}

#[inline]
pub(crate) fn split_domain_rule_expression(exp: &str) -> (DomainRuleKind, &str) {
    if let Some(v) = exp.strip_prefix("full:") {
        (DomainRuleKind::Full, v)
    } else if let Some(v) = exp.strip_prefix("domain:") {
        (DomainRuleKind::Domain, v)
    } else if let Some(v) = exp.strip_prefix("keyword:") {
        (DomainRuleKind::Keyword, v)
    } else if let Some(v) = exp.strip_prefix("regexp:") {
        (DomainRuleKind::Regexp, v)
    } else {
        (DomainRuleKind::Domain, exp)
    }
}

#[derive(Debug, Default)]
pub(crate) struct FullDomainMatcher {
    rules: AHashSet<Box<str>>,
}

impl FullDomainMatcher {
    #[inline]
    pub(crate) fn add_rule(&mut self, rule: &str) {
        self.rules.insert(rule.to_owned().into_boxed_str());
    }

    #[inline]
    pub(crate) fn is_match(&self, domain: &str) -> bool {
        self.rules.contains(domain)
    }

    #[inline]
    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[derive(Debug, Default)]
pub(crate) struct TrieDomainMatcher {
    trie: DomainTrie,
}

impl TrieDomainMatcher {
    #[inline]
    pub(crate) fn add_rule(&mut self, rule: &str) {
        self.trie.insert(rule);
    }

    #[inline]
    pub(crate) fn is_match(&self, labels_rev: &[&str]) -> bool {
        self.trie.contains_labels(labels_rev)
    }

    #[inline]
    pub(crate) fn has_rules(&self) -> bool {
        self.trie.has_rules()
    }

    #[inline]
    pub(crate) fn rule_count(&self) -> usize {
        self.trie.rule_count
    }
}

#[derive(Debug, Default)]
pub(crate) struct KeywordDomainMatcher {
    pending_patterns: Vec<String>,
    matcher: Option<AhoCorasick>,
    rule_count: usize,
}

impl KeywordDomainMatcher {
    #[inline]
    pub(crate) fn add_rule(&mut self, rule: &str) {
        self.pending_patterns.push(rule.to_owned());
        self.rule_count += 1;
    }

    pub(crate) fn finalize(&mut self) -> Result<(), String> {
        if self.pending_patterns.is_empty() {
            return Ok(());
        }

        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(false)
            .build(&self.pending_patterns)
            .map_err(|e| format!("failed to build keyword matcher: {}", e))?;
        self.matcher = Some(matcher);
        self.pending_patterns.clear();
        self.pending_patterns.shrink_to_fit();
        Ok(())
    }

    #[inline]
    pub(crate) fn is_match(&self, domain: &str) -> bool {
        self.matcher.as_ref().is_some_and(|m| m.is_match(domain))
    }

    #[inline]
    pub(crate) fn rule_count(&self) -> usize {
        self.rule_count
    }
}

#[derive(Debug, Default)]
pub(crate) struct RegexpDomainMatcher {
    pending_patterns: Vec<String>,
    matcher: Option<RegexSet>,
    rule_count: usize,
}

impl RegexpDomainMatcher {
    pub(crate) fn add_rule(&mut self, raw_rule: &str) -> Result<(), String> {
        RegexBuilder::new(raw_rule)
            .case_insensitive(true)
            .build()
            .map_err(|e| format!("invalid regexp '{}': {}", raw_rule, e))?;
        self.pending_patterns.push(raw_rule.to_owned());
        self.rule_count += 1;
        Ok(())
    }

    pub(crate) fn finalize(&mut self) -> Result<(), String> {
        if self.pending_patterns.is_empty() {
            return Ok(());
        }
        let matcher = RegexSetBuilder::new(&self.pending_patterns)
            .case_insensitive(true)
            .build()
            .map_err(|e| format!("failed to build regex set: {}", e))?;
        self.matcher = Some(matcher);
        self.pending_patterns.clear();
        self.pending_patterns.shrink_to_fit();
        Ok(())
    }

    #[inline]
    pub(crate) fn is_match(&self, domain: &str) -> bool {
        self.matcher.as_ref().is_some_and(|m| m.is_match(domain))
    }

    #[inline]
    pub(crate) fn rule_count(&self) -> usize {
        self.rule_count
    }
}

#[derive(Debug, Default)]
pub(crate) struct DomainRuleMatcher {
    full: Option<FullDomainMatcher>,
    trie: Option<TrieDomainMatcher>,
    keyword: Option<KeywordDomainMatcher>,
    regexp: Option<RegexpDomainMatcher>,
}

impl DomainRuleMatcher {
    #[inline]
    pub(crate) fn has_rules(&self) -> bool {
        self.full.as_ref().is_some_and(|m| m.rule_count() > 0)
            || self.trie.as_ref().is_some_and(|m| m.has_rules())
            || self.keyword.as_ref().is_some_and(|m| m.rule_count() > 0)
            || self.regexp.as_ref().is_some_and(|m| m.rule_count() > 0)
    }

    #[inline]
    pub(crate) fn has_trie_rules(&self) -> bool {
        self.trie.as_ref().is_some_and(|m| m.has_rules())
    }

    #[inline]
    pub(crate) fn full_rule_count(&self) -> usize {
        self.full.as_ref().map_or(0, FullDomainMatcher::rule_count)
    }

    #[inline]
    pub(crate) fn trie_rule_count(&self) -> usize {
        self.trie.as_ref().map_or(0, TrieDomainMatcher::rule_count)
    }

    #[inline]
    pub(crate) fn keyword_rule_count(&self) -> usize {
        self.keyword
            .as_ref()
            .map_or(0, KeywordDomainMatcher::rule_count)
    }

    #[inline]
    pub(crate) fn regexp_rule_count(&self) -> usize {
        self.regexp
            .as_ref()
            .map_or(0, RegexpDomainMatcher::rule_count)
    }

    pub(crate) fn add_expression(&mut self, exp: &str, source: &str) -> Result<(), String> {
        let exp = exp.trim();
        if exp.is_empty() {
            return Ok(());
        }

        let (kind, value) = split_domain_rule_expression(exp);
        match kind {
            DomainRuleKind::Regexp => {
                let value = value.trim();
                if value.is_empty() {
                    return Err(format!("invalid empty regexp expression in {}", source));
                }
                self.regexp
                    .get_or_insert_with(RegexpDomainMatcher::default)
                    .add_rule(value)
                    .map_err(|e| format!("{} in {}", e, source))?;
            }
            DomainRuleKind::Full | DomainRuleKind::Domain | DomainRuleKind::Keyword => {
                let normalized = normalize_domain_cow(value.trim());
                if normalized.is_empty() {
                    return Err(format!("invalid empty domain expression in {}", source));
                }
                match kind {
                    DomainRuleKind::Full => self
                        .full
                        .get_or_insert_with(FullDomainMatcher::default)
                        .add_rule(normalized.as_ref()),
                    DomainRuleKind::Domain => self
                        .trie
                        .get_or_insert_with(TrieDomainMatcher::default)
                        .add_rule(normalized.as_ref()),
                    DomainRuleKind::Keyword => self
                        .keyword
                        .get_or_insert_with(KeywordDomainMatcher::default)
                        .add_rule(normalized.as_ref()),
                    DomainRuleKind::Regexp => unreachable!(),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finalize(&mut self) -> Result<(), String> {
        if let Some(keyword) = &mut self.keyword {
            keyword.finalize()?;
        }
        if let Some(regexp) = &mut self.regexp {
            regexp.finalize()?;
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn is_match_normalized(&self, domain: &str, labels_rev: &[&str]) -> bool {
        if self.full.as_ref().is_some_and(|m| m.is_match(domain)) {
            return true;
        }
        if self.trie.as_ref().is_some_and(|m| m.is_match(labels_rev)) {
            return true;
        }
        if self.keyword.as_ref().is_some_and(|m| m.is_match(domain)) {
            return true;
        }
        self.regexp.as_ref().is_some_and(|m| m.is_match(domain))
    }
}

#[inline]
pub(crate) fn normalize_domain_cow(domain: &str) -> Cow<'_, str> {
    let bytes = domain.as_bytes();

    // Trim start
    let mut start = 0;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }

    // Trim end
    let mut end = bytes.len();
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    // Remove trailing dots
    while end > start && bytes[end - 1] == b'.' {
        end -= 1;
    }

    if start == end {
        return Cow::Borrowed("");
    }

    let slice = &domain[start..end];

    if slice.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(slice.to_ascii_lowercase())
    } else {
        Cow::Borrowed(slice)
    }
}

#[inline]
pub(crate) fn split_labels_rev<'a>(domain: &'a str, labels: &mut SmallVec<[&'a str; 8]>) {
    labels.clear();
    labels.extend(domain.rsplit('.').filter(|label| !label.is_empty()));
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
