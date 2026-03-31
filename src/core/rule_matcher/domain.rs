/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! High-performance domain rule matching primitives shared by providers and matchers.
//!
//! This module intentionally keeps domain matching independent from any concrete plugin so
//! large rule sets can be parsed once, compiled once, and then reused on the hot query path.
//! The matcher supports four rule families commonly seen in rule-list ecosystems:
//!
//! - `full:` exact FQDN matches.
//! - `domain:` suffix matches such as `example.com` matching `www.example.com`.
//! - `keyword:` substring matches compiled into a single Aho-Corasick automaton.
//! - `regexp:` regular expressions compiled into a single `RegexSet`.
//!
//! The public `DomainRuleMatcher` is an aggregator over these specialized engines. Parsing and
//! normalization happen when rules are loaded, while request-time matching stays branch-light.

use crate::proto::Name;
use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use std::borrow::Cow;

/// A single node in the reversed-label trie used by `domain:` suffix rules.
///
/// For a rule like `www.example.com`, labels are inserted as `com -> example -> www`.
/// This makes suffix matching on an already-normalized DNS name a straight walk from TLD
/// toward the leftmost label. `terminal` means the path up to this node already forms a
/// complete suffix rule, so matching can stop early without consuming all labels.
#[derive(Debug, Default)]
pub(crate) struct DomainTrieNode {
    pub(crate) terminal: bool,
    pub(crate) children: AHashMap<Box<str>, u32>,
}

/// A compact arena-backed trie for domain suffix rules.
///
/// The trie stores all nodes in a flat `Vec` and uses `u32` indices instead of pointers.
/// Compared with a pointer-heavy recursive structure, this keeps allocations predictable and
/// improves locality for repeated lookups on the query path.
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

    /// Insert a suffix rule by reversed labels, e.g. `google.com` => `com -> google`.
    ///
    /// Duplicate logical rules are collapsed by only incrementing `rule_count` the first time
    /// the final node becomes terminal.
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

    /// Match a normalized DNS name against the suffix trie.
    ///
    /// The walk proceeds from the rightmost label to the leftmost label. As soon as a terminal
    /// node is reached the rule matches, which naturally implements "match this suffix or any
    /// subdomain below it".
    #[inline]
    pub(crate) fn contains_name(&self, name: &Name) -> bool {
        let mut cursor = 0u32;
        for label in name.iter_labels_rev() {
            let Some(next) = self.nodes[cursor as usize].children.get(label) else {
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

/// Split a textual rule expression into its rule kind and payload.
///
/// Expressions without an explicit prefix default to `domain:` semantics because suffix rules
/// are the most common representation in traditional rule-list files.
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

/// Exact domain matcher for `full:` rules.
///
/// The caller is responsible for normalizing the domain text before insertion so lookups can
/// stay as a plain hash set membership test.
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

/// Trie-backed suffix matcher for `domain:` rules.
///
/// This is the preferred engine for common domain suffix lists because it avoids regex or
/// substring scans and allows early exits while walking DNS labels.
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
    pub(crate) fn is_match(&self, name: &Name) -> bool {
        self.trie.contains_name(name)
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

/// Substring matcher for `keyword:` rules.
///
/// Rules are buffered first and then compiled into one Aho-Corasick automaton during
/// `finalize()`. This keeps insertion simple while making repeated lookups cheap.
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

    /// Compile pending keyword rules into a single automaton.
    ///
    /// The builder is case-sensitive because rule text has already been normalized to lowercase
    /// before insertion, which avoids paying for case folding during every match.
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

/// Regular-expression matcher for `regexp:` rules.
///
/// Each rule is syntax-checked on insertion so configuration errors can be reported with the
/// original source location. Successful rules are later compiled into one `RegexSet`.
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

/// Aggregated domain matcher used by rule providers and request matchers.
///
/// The type keeps each rule family in its own specialized engine instead of forcing every rule
/// through a single generic matcher. This lets the hot path evaluate exact and suffix matches
/// first, then fall back to more expensive keyword and regex checks only when needed.
#[derive(Debug, Default)]
pub struct DomainRuleMatcher {
    full: Option<FullDomainMatcher>,
    trie: Option<TrieDomainMatcher>,
    keyword: Option<KeywordDomainMatcher>,
    regexp: Option<RegexpDomainMatcher>,
}

impl DomainRuleMatcher {
    #[inline]
    pub fn has_rules(&self) -> bool {
        self.full.as_ref().is_some_and(|m| m.rule_count() > 0)
            || self.trie.as_ref().is_some_and(|m| m.has_rules())
            || self.keyword.as_ref().is_some_and(|m| m.rule_count() > 0)
            || self.regexp.as_ref().is_some_and(|m| m.rule_count() > 0)
    }

    #[inline]
    pub fn has_trie_rules(&self) -> bool {
        self.trie.as_ref().is_some_and(|m| m.has_rules())
    }

    #[inline]
    pub fn full_rule_count(&self) -> usize {
        self.full.as_ref().map_or(0, FullDomainMatcher::rule_count)
    }

    #[inline]
    pub fn trie_rule_count(&self) -> usize {
        self.trie.as_ref().map_or(0, TrieDomainMatcher::rule_count)
    }

    #[inline]
    pub fn keyword_rule_count(&self) -> usize {
        self.keyword
            .as_ref()
            .map_or(0, KeywordDomainMatcher::rule_count)
    }

    #[inline]
    pub fn regexp_rule_count(&self) -> usize {
        self.regexp
            .as_ref()
            .map_or(0, RegexpDomainMatcher::rule_count)
    }

    /// Parse and insert one domain expression from a specific source.
    ///
    /// `source` is included in validation errors so callers can surface accurate diagnostics for
    /// files, providers, or config fragments. Domain-like rules are normalized here to ensure the
    /// compiled matchers only store lowercase names without trailing dots.
    pub fn add_expression(&mut self, exp: &str, source: &str) -> Result<(), String> {
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

    /// Compile deferred matcher state after all rules have been loaded.
    ///
    /// `full:` and `domain:` rules are ready immediately, but keyword and regex rules benefit
    /// from bulk compilation into shared automata. Callers should finalize once after loading
    /// and before the matcher is placed on the request path.
    pub fn finalize(&mut self) -> Result<(), String> {
        if let Some(keyword) = &mut self.keyword {
            keyword.finalize()?;
        }
        if let Some(regexp) = &mut self.regexp {
            regexp.finalize()?;
        }
        Ok(())
    }

    /// Match a normalized DNS `Name` against all configured rule families.
    ///
    /// The evaluation order is intentionally biased toward the cheapest checks:
    /// exact match, suffix trie, substring automaton, then regex set.
    #[inline]
    pub fn is_match_name(&self, name: &Name) -> bool {
        let domain = name.normalized();
        if self.full.as_ref().is_some_and(|m| m.is_match(domain)) {
            return true;
        }
        if self.trie.as_ref().is_some_and(|m| m.is_match(name)) {
            return true;
        }
        if self.keyword.as_ref().is_some_and(|m| m.is_match(domain)) {
            return true;
        }
        self.regexp.as_ref().is_some_and(|m| m.is_match(domain))
    }
}

/// Normalize user-provided domain text without forcing an allocation in the common case.
///
/// The function trims surrounding ASCII whitespace, removes trailing dots, and lowercases the
/// result only when uppercase bytes are present. `Cow` is used so already-normalized input can
/// be borrowed directly.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_domain_rule_expression_defaults_to_domain_kind() {
        let (kind, value) = split_domain_rule_expression("example.com");

        assert_eq!(kind, DomainRuleKind::Domain);
        assert_eq!(value, "example.com");
    }

    #[test]
    fn test_normalize_domain_cow_trims_lowercases_and_strips_dot() {
        let normalized = normalize_domain_cow("  WWW.Example.COM.  ");

        assert_eq!(normalized.as_ref(), "www.example.com");
    }

    #[test]
    fn test_domain_rule_matcher_matches_suffix_rule_after_finalize() {
        let mut matcher = DomainRuleMatcher::default();
        matcher
            .add_expression("domain:example.com", "test source")
            .expect("expression should be accepted");
        matcher.finalize().expect("finalize should succeed");
        let name = Name::from_ascii("www.example.com.").unwrap();
        let matched = matcher.is_match_name(&name);

        assert!(matched);
    }

    #[test]
    fn test_domain_rule_matcher_rejects_empty_regexp_expression() {
        let mut matcher = DomainRuleMatcher::default();

        let result = matcher.add_expression("regexp:   ", "rule.txt:8");

        assert_eq!(
            result,
            Err("invalid empty regexp expression in rule.txt:8".to_string())
        );
    }
}
