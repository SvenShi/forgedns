/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared high-performance rule matchers used by providers and matchers.

use crate::message::Name;
use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv6Addr};

const IPV4_PAGE_SHIFT: u32 = 16;
const IPV4_PAGE_MASK: u32 = (1 << IPV4_PAGE_SHIFT) - 1;
const IPV4_PAGE_COUNT: usize = 1 << IPV4_PAGE_SHIFT;
const IPV4_BITMAP_WORDS: usize = 1 << (IPV4_PAGE_SHIFT - 6);
const SMALL_IPV4_PAGE_RANGE_THRESHOLD: usize = 16;
const SMALL_IPV6_LINEAR_THRESHOLD: usize = 8;
const DENSE_IPV4_PAGE_THRESHOLD: usize = 4096;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Ipv4Range {
    start: u32,
    end: u32,
}

impl Ipv4Range {
    #[inline]
    fn from_network(network: u32, prefix_len: u8) -> Self {
        let host_mask = if prefix_len == 32 {
            0
        } else {
            u32::MAX >> prefix_len as u32
        };
        Self {
            start: network,
            end: network | host_mask,
        }
    }

    #[inline]
    fn contains(&self, value: u32) -> bool {
        value >= self.start && value <= self.end
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Ipv6Range {
    start: u128,
    end: u128,
}

impl Ipv6Range {
    #[inline]
    fn from_network(network: u128, prefix_len: u8) -> Self {
        let host_mask = if prefix_len == 128 {
            0
        } else {
            u128::MAX >> prefix_len as u32
        };
        Self {
            start: network,
            end: network | host_mask,
        }
    }

    #[inline]
    fn contains(&self, value: u128) -> bool {
        value >= self.start && value <= self.end
    }
}

#[derive(Debug)]
enum Ipv4Page {
    Empty,
    Full,
    Small(Box<[(u16, u16)]>),
    Bitmap(Box<[u64]>),
}

impl Default for Ipv4Page {
    fn default() -> Self {
        Self::Empty
    }
}

impl Ipv4Page {
    #[inline]
    fn contains(&self, low_bits: u16) -> bool {
        match self {
            Self::Empty => false,
            Self::Full => true,
            Self::Small(ranges) => ranges
                .iter()
                .take_while(|(start, _)| *start <= low_bits)
                .any(|(start, end)| low_bits >= *start && low_bits <= *end),
            Self::Bitmap(words) => {
                let word_idx = (low_bits as usize) >> 6;
                let bit_idx = low_bits as usize & 63;
                (words[word_idx] & (1u64 << bit_idx)) != 0
            }
        }
    }
}

#[derive(Debug)]
enum Ipv4MatcherBackend {
    MatchAll,
    Sparse(Box<[(u16, Ipv4Page)]>),
    Dense(Box<[Ipv4Page]>),
}

#[derive(Debug)]
struct Ipv4Matcher {
    backend: Ipv4MatcherBackend,
    rule_count: usize,
}

impl Ipv4Matcher {
    #[inline]
    fn has_rules(&self) -> bool {
        self.rule_count > 0
    }

    #[inline]
    fn contains(&self, value: u32) -> bool {
        match &self.backend {
            Ipv4MatcherBackend::MatchAll => true,
            Ipv4MatcherBackend::Sparse(pages) => {
                let high = (value >> IPV4_PAGE_SHIFT) as u16;
                let low = (value & IPV4_PAGE_MASK) as u16;
                match pages.binary_search_by_key(&high, |(page, _)| *page) {
                    Ok(idx) => {
                        let (_, page) = &pages[idx];
                        page.contains(low)
                    }
                    Err(_) => false,
                }
            }
            Ipv4MatcherBackend::Dense(pages) => {
                let high = (value >> IPV4_PAGE_SHIFT) as usize;
                let low = (value & IPV4_PAGE_MASK) as u16;
                pages[high].contains(low)
            }
        }
    }
}

#[derive(Debug, Default)]
struct Ipv6IntervalMatcher {
    ranges: Box<[Ipv6Range]>,
    rule_count: usize,
}

impl Ipv6IntervalMatcher {
    #[inline]
    fn has_rules(&self) -> bool {
        self.rule_count > 0
    }

    #[inline]
    fn contains(&self, value: u128) -> bool {
        if self.ranges.is_empty() {
            return false;
        }

        if self.ranges.len() <= SMALL_IPV6_LINEAR_THRESHOLD {
            return self.ranges.iter().any(|range| range.contains(value));
        }

        let idx = self.ranges.partition_point(|range| range.start <= value);
        idx > 0 && self.ranges[idx - 1].contains(value)
    }
}

#[derive(Debug, Clone, Copy)]
enum ParsedPrefix {
    V4 { network: u32, prefix_len: u8 },
    V6 { network: u128, prefix_len: u8 },
}

#[derive(Debug, Default)]
pub(crate) struct IpPrefixMatcher {
    v4_rules: Vec<Ipv4Range>,
    v6_rules: Vec<Ipv6Range>,
    v4: Option<Ipv4Matcher>,
    v6: Option<Ipv6IntervalMatcher>,
}

impl IpPrefixMatcher {
    #[inline]
    pub(crate) fn has_v4_rules(&self) -> bool {
        self.v4.as_ref().is_some_and(Ipv4Matcher::has_rules) || !self.v4_rules.is_empty()
    }

    #[inline]
    pub(crate) fn has_v6_rules(&self) -> bool {
        self.v6.as_ref().is_some_and(Ipv6IntervalMatcher::has_rules) || !self.v6_rules.is_empty()
    }

    #[inline]
    pub(crate) fn v4_rule_count(&self) -> usize {
        self.v4
            .as_ref()
            .map_or(self.v4_rules.len(), |matcher| matcher.rule_count)
    }

    #[inline]
    pub(crate) fn v6_rule_count(&self) -> usize {
        self.v6
            .as_ref()
            .map_or(self.v6_rules.len(), |matcher| matcher.rule_count)
    }

    pub(crate) fn add_rule(&mut self, raw_rule: &str) -> Result<(), String> {
        let rule = raw_rule.trim();
        if rule.is_empty() {
            return Ok(());
        }

        match parse_ip_prefix(rule)? {
            ParsedPrefix::V4 {
                network,
                prefix_len,
            } => {
                self.v4_rules
                    .push(Ipv4Range::from_network(network, prefix_len));
                self.v4 = None;
            }
            ParsedPrefix::V6 {
                network,
                prefix_len,
            } => {
                self.v6_rules
                    .push(Ipv6Range::from_network(network, prefix_len));
                self.v6 = None;
            }
        }
        Ok(())
    }

    pub(crate) fn finalize(&mut self) {
        self.v4 = compile_ipv4_matcher(&mut self.v4_rules);
        self.v6 = compile_ipv6_matcher(&mut self.v6_rules);
    }

    #[inline]
    pub(crate) fn contains_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let value = u32::from(ip);
                self.v4
                    .as_ref()
                    .is_some_and(|matcher| matcher.contains(value))
                    || self.v4.is_none() && contains_ipv4_uncompiled(&self.v4_rules, value)
            }
            IpAddr::V6(ip) => {
                let value = ipv6_to_u128(ip);
                self.v6
                    .as_ref()
                    .is_some_and(|matcher| matcher.contains(value))
                    || self.v6.is_none() && contains_ipv6_uncompiled(&self.v6_rules, value)
            }
        }
    }
}

fn compile_ipv4_matcher(ranges: &mut Vec<Ipv4Range>) -> Option<Ipv4Matcher> {
    if ranges.is_empty() {
        return None;
    }

    merge_ipv4_ranges(ranges);
    let rule_count = ranges.len();
    if rule_count == 1 && ranges[0].start == 0 && ranges[0].end == u32::MAX {
        return Some(Ipv4Matcher {
            backend: Ipv4MatcherBackend::MatchAll,
            rule_count,
        });
    }

    let mut active_pages = Vec::<(u16, SmallVec<[(u16, u16); 4]>)>::new();
    for range in ranges.iter().copied() {
        let start_page = (range.start >> IPV4_PAGE_SHIFT) as usize;
        let end_page = (range.end >> IPV4_PAGE_SHIFT) as usize;
        for page in start_page..=end_page {
            let local_start = if page == start_page {
                (range.start & IPV4_PAGE_MASK) as u16
            } else {
                0
            };
            let local_end = if page == end_page {
                (range.end & IPV4_PAGE_MASK) as u16
            } else {
                u16::MAX
            };
            push_ipv4_page_range(&mut active_pages, page as u16, local_start, local_end);
        }
    }

    let backend = if active_pages.len() >= DENSE_IPV4_PAGE_THRESHOLD {
        let mut dense = Vec::with_capacity(IPV4_PAGE_COUNT);
        dense.resize_with(IPV4_PAGE_COUNT, Ipv4Page::default);
        for (page_idx, page_ranges) in active_pages {
            dense[page_idx as usize] = build_ipv4_page(page_ranges);
        }
        Ipv4MatcherBackend::Dense(dense.into_boxed_slice())
    } else {
        let sparse = active_pages
            .into_iter()
            .map(|(page_idx, page_ranges)| (page_idx, build_ipv4_page(page_ranges)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ipv4MatcherBackend::Sparse(sparse)
    };

    Some(Ipv4Matcher {
        backend,
        rule_count,
    })
}

fn compile_ipv6_matcher(ranges: &mut Vec<Ipv6Range>) -> Option<Ipv6IntervalMatcher> {
    if ranges.is_empty() {
        return None;
    }

    merge_ipv6_ranges(ranges);
    Some(Ipv6IntervalMatcher {
        ranges: ranges.clone().into_boxed_slice(),
        rule_count: ranges.len(),
    })
}

#[inline]
fn contains_ipv4_uncompiled(ranges: &[Ipv4Range], value: u32) -> bool {
    ranges.iter().any(|range| range.contains(value))
}

#[inline]
fn contains_ipv6_uncompiled(ranges: &[Ipv6Range], value: u128) -> bool {
    ranges.iter().any(|range| range.contains(value))
}

#[inline]
fn push_ipv4_page_range(
    pages: &mut Vec<(u16, SmallVec<[(u16, u16); 4]>)>,
    page: u16,
    start: u16,
    end: u16,
) {
    if let Some((last_page, ranges)) = pages.last_mut()
        && *last_page == page
    {
        ranges.push((start, end));
        return;
    }

    let mut ranges = SmallVec::<[(u16, u16); 4]>::new();
    ranges.push((start, end));
    pages.push((page, ranges));
}

fn build_ipv4_page(ranges: SmallVec<[(u16, u16); 4]>) -> Ipv4Page {
    if ranges.is_empty() {
        return Ipv4Page::Empty;
    }
    if ranges.len() == 1 && ranges[0] == (0, u16::MAX) {
        return Ipv4Page::Full;
    }
    if ranges.len() <= SMALL_IPV4_PAGE_RANGE_THRESHOLD {
        return Ipv4Page::Small(ranges.into_vec().into_boxed_slice());
    }

    let mut bitmap = vec![0u64; IPV4_BITMAP_WORDS].into_boxed_slice();
    for (start, end) in ranges {
        set_ipv4_bitmap_range(bitmap.as_mut(), start, end);
    }
    Ipv4Page::Bitmap(bitmap)
}

fn set_ipv4_bitmap_range(words: &mut [u64], start: u16, end: u16) {
    let start_word = (start as usize) >> 6;
    let end_word = (end as usize) >> 6;
    let start_bit = start as u32 & 63;
    let end_bit = end as u32 & 63;

    if start_word == end_word {
        words[start_word] |= bit_mask_between(start_bit, end_bit);
        return;
    }

    words[start_word] |= u64::MAX << start_bit;
    for word in &mut words[start_word + 1..end_word] {
        *word = u64::MAX;
    }
    words[end_word] |= bit_mask_between(0, end_bit);
}

#[inline]
fn bit_mask_between(start_bit: u32, end_bit: u32) -> u64 {
    let end_mask = if end_bit == 63 {
        u64::MAX
    } else {
        (1u64 << (end_bit + 1)) - 1
    };
    end_mask & (u64::MAX << start_bit)
}

fn merge_ipv4_ranges(ranges: &mut Vec<Ipv4Range>) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_unstable_by_key(|range| range.start);
    let mut write = 0usize;
    for read in 1..ranges.len() {
        let next = ranges[read];
        let current = &mut ranges[write];
        if next.start <= current.end.saturating_add(1) {
            current.end = current.end.max(next.end);
        } else {
            write += 1;
            ranges[write] = next;
        }
    }
    ranges.truncate(write + 1);
}

fn merge_ipv6_ranges(ranges: &mut Vec<Ipv6Range>) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_unstable_by_key(|range| range.start);
    let mut write = 0usize;
    for read in 1..ranges.len() {
        let next = ranges[read];
        let current = &mut ranges[write];
        if next.start <= current.end.saturating_add(1) {
            current.end = current.end.max(next.end);
        } else {
            write += 1;
            ranges[write] = next;
        }
    }
    ranges.truncate(write + 1);
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
    pub(crate) fn is_match_name(&self, name: &Name) -> bool {
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
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

fn parse_ip_prefix(raw: &str) -> Result<ParsedPrefix, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty input".to_string());
    }

    // Accept both "ip" and "ip/prefix" forms. For "ip/prefix", reject multiple
    // slashes early so parse errors are deterministic and user-facing.
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
            // Bare IPv4 address means host prefix /32.
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
                network: masked,
                prefix_len,
            })
        }
        IpAddr::V6(ip) => {
            // Bare IPv6 address means host prefix /128.
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
                network: masked,
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
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_prefix_matcher_matches_masked_ipv4_prefix() {
        let mut matcher = IpPrefixMatcher::default();
        matcher
            .add_rule("192.0.2.99/24")
            .expect("rule should be accepted");
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
    }

    #[test]
    fn test_ip_prefix_matcher_ignores_redundant_more_specific_rule() {
        let mut matcher = IpPrefixMatcher::default();
        matcher
            .add_rule("2001:db8::/32")
            .expect("broad rule should be accepted");
        matcher
            .add_rule("2001:db8:1::/48")
            .expect("specific rule should be accepted");
        matcher.finalize();

        assert_eq!(matcher.v6_rule_count(), 1);
    }

    #[test]
    fn test_ip_prefix_matcher_matches_ipv4_prefix_across_pages() {
        let mut matcher = IpPrefixMatcher::default();
        matcher
            .add_rule("10.0.0.0/8")
            .expect("broad rule should be accepted");
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 255, 7, 9))));
        assert!(!matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

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
