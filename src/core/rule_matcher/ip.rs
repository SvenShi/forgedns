/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! High-performance IP prefix matcher shared by providers and DNS matchers.
//!
//! Rules are collected in a simple append-only form during loading and can later be compiled
//! into structures tuned for repeated membership checks:
//!
//! - IPv4 ranges are partitioned by the high 16 bits of the address, then each page is encoded
//!   as empty, fully covered, a few inline ranges, or a bitmap.
//! - IPv6 ranges are merged into a sorted non-overlapping array and queried either linearly for
//!   tiny rule sets or with a partition-based lookup for larger ones.
//!
//! This keeps startup logic straightforward while ensuring the query-time path stays allocation
//! free and branch-light.

use std::net::{IpAddr, Ipv6Addr};

/// Use the upper 16 bits as the first-level IPv4 page index.
const V4_PAGE_BITS: u32 = 16;
const V4_PAGE_COUNT: usize = 1 << V4_PAGE_BITS;
const V4_LOW_MASK: u32 = (1 << V4_PAGE_BITS) - 1;
const V4_BITMAP_WORDS: usize = 1 << (V4_PAGE_BITS - 6);

/// Encodings used by each compiled IPv4 page.
const V4_KIND_EMPTY: u8 = 0;
const V4_KIND_FULL: u8 = 1;
const V4_KIND_INLINE1: u8 = 2;
const V4_KIND_INLINE2: u8 = 3;
const V4_KIND_INLINE4: u8 = 4;
const V4_KIND_BITMAP: u8 = 5;

/// Small IPv6 rule sets are faster to scan linearly than to search indirectly.
const V6_SMALL_LINEAR_THRESHOLD: usize = 8;

/// Inclusive IPv4 range stored as raw bits after prefix normalization.
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

/// Inclusive IPv6 range stored as raw 128-bit integers.
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

#[derive(Debug, Clone, Copy)]
enum ParsedPrefix {
    V4 { network: u32, prefix_len: u8 },
    V6 { network: u128, prefix_len: u8 },
}

/// Metadata for one IPv4 page in the compiled matcher.
///
/// `aux` indexes one of the side arrays selected by `kind`.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, Default)]
struct V4PageMeta {
    kind: u8,
    len: u8,
    _pad: u16,
    aux: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct V4Inline1 {
    start: u16,
    end: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct V4Inline2 {
    a0: u16,
    b0: u16,
    a1: u16,
    b1: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct V4Inline4 {
    a0: u16,
    b0: u16,
    a1: u16,
    b1: u16,
    a2: u16,
    b2: u16,
    a3: u16,
    b3: u16,
}

type V4Bitmap = [u64; V4_BITMAP_WORDS];

/// Compiled IPv4 matcher tuned for repeated hot-path membership checks.
#[derive(Debug, Default)]
struct V4Matcher {
    pages: Box<[V4PageMeta]>,
    inline1: Box<[V4Inline1]>,
    inline2: Box<[V4Inline2]>,
    inline4: Box<[V4Inline4]>,
    bitmaps: Box<[V4Bitmap]>,
    rule_count: usize,
}

impl V4Matcher {
    #[inline]
    fn has_rules(&self) -> bool {
        self.rule_count > 0
    }

    /// Query the compiled IPv4 matcher using a raw `u32` address.
    #[inline(always)]
    fn contains(&self, ip: u32) -> bool {
        let high = (ip >> V4_PAGE_BITS) as usize;
        let low = ip as u16;

        let Some(meta) = self.pages.get(high).copied() else {
            return false;
        };

        match meta.kind {
            V4_KIND_EMPTY => false,
            V4_KIND_FULL => true,
            V4_KIND_INLINE1 => match self.inline1.get(meta.aux as usize) {
                Some(r) => low >= r.start && low <= r.end,
                None => false,
            },
            V4_KIND_INLINE2 => match self.inline2.get(meta.aux as usize) {
                Some(r) => {
                    ((low >= r.a0 && low <= r.b0) as u8 | (low >= r.a1 && low <= r.b1) as u8) != 0
                }
                None => false,
            },
            V4_KIND_INLINE4 => match self.inline4.get(meta.aux as usize) {
                Some(r) => match meta.len {
                    3 => {
                        ((low >= r.a0 && low <= r.b0) as u8
                            | (low >= r.a1 && low <= r.b1) as u8
                            | (low >= r.a2 && low <= r.b2) as u8)
                            != 0
                    }
                    4 => {
                        ((low >= r.a0 && low <= r.b0) as u8
                            | (low >= r.a1 && low <= r.b1) as u8
                            | (low >= r.a2 && low <= r.b2) as u8
                            | (low >= r.a3 && low <= r.b3) as u8)
                            != 0
                    }
                    _ => false,
                },
                None => false,
            },
            V4_KIND_BITMAP => match self.bitmaps.get(meta.aux as usize) {
                Some(bm) => {
                    let word_idx = (low as usize) >> 6;
                    let bit_idx = low as usize & 63;
                    match bm.get(word_idx) {
                        Some(word) => (word & (1u64 << bit_idx)) != 0,
                        None => false,
                    }
                }
                None => false,
            },
            _ => false,
        }
    }
}

/// Compiled IPv6 matcher backed by sorted merged ranges.
#[derive(Debug, Default)]
struct V6Matcher {
    ranges: Box<[Ipv6Range]>,
    rule_count: usize,
}

impl V6Matcher {
    #[inline]
    fn has_rules(&self) -> bool {
        self.rule_count > 0
    }

    /// Query the compiled IPv6 matcher.
    #[inline(always)]
    fn contains(&self, value: u128) -> bool {
        if self.ranges.is_empty() {
            return false;
        }

        if self.ranges.len() <= V6_SMALL_LINEAR_THRESHOLD {
            return self.ranges.iter().any(|range| range.contains(value));
        }

        let idx = self.ranges.partition_point(|range| range.start <= value);
        idx > 0 && self.ranges[idx - 1].contains(value)
    }
}

/// Public IP prefix matcher used by providers and IP-oriented rule plugins.
///
/// Callers typically append rules with `add_rule()`, call `finalize()` once after loading,
/// and then use one of the `contains_*` methods on the request path.
#[derive(Debug, Default)]
pub struct IpPrefixMatcher {
    v4_rules: Vec<Ipv4Range>,
    v6_rules: Vec<Ipv6Range>,
    v4: Option<V4Matcher>,
    v6: Option<V6Matcher>,
}

impl IpPrefixMatcher {
    #[inline]
    pub fn has_v4_rules(&self) -> bool {
        self.v4.as_ref().is_some_and(V4Matcher::has_rules) || !self.v4_rules.is_empty()
    }

    #[inline]
    pub fn has_v6_rules(&self) -> bool {
        self.v6.as_ref().is_some_and(V6Matcher::has_rules) || !self.v6_rules.is_empty()
    }

    #[inline]
    pub fn v4_rule_count(&self) -> usize {
        self.v4
            .as_ref()
            .map_or(self.v4_rules.len(), |matcher| matcher.rule_count)
    }

    #[inline]
    pub fn v6_rule_count(&self) -> usize {
        self.v6
            .as_ref()
            .map_or(self.v6_rules.len(), |matcher| matcher.rule_count)
    }

    /// Parse and append a host or CIDR rule.
    ///
    /// Empty lines are ignored so raw rule-list input can be streamed in directly.
    pub fn add_rule(&mut self, raw_rule: &str) -> Result<(), String> {
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

    /// Merge and compile all pending IPv4/IPv6 rules.
    pub fn finalize(&mut self) {
        self.v4 = compile_v4_matcher(&mut self.v4_rules);
        self.v6 = compile_v6_matcher(&mut self.v6_rules);
    }

    #[inline(always)]
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.contains_v4_u32(u32::from(ip)),
            IpAddr::V6(ip) => self.contains_v6_u128(ipv6_to_u128(ip)),
        }
    }

    #[inline(always)]
    pub fn contains_v4_u32(&self, ip: u32) -> bool {
        match &self.v4 {
            Some(matcher) => matcher.contains(ip),
            None => contains_v4_uncompiled(&self.v4_rules, ip),
        }
    }

    #[inline(always)]
    pub fn contains_v6_u128(&self, ip: u128) -> bool {
        match &self.v6 {
            Some(matcher) => matcher.contains(ip),
            None => contains_v6_uncompiled(&self.v6_rules, ip),
        }
    }
}

/// Compile merged IPv4 ranges into a two-level page matcher.
///
/// The high 16 bits select a page. Inside each page we choose the lightest representation that
/// can describe the covered low 16-bit intervals.
fn compile_v4_matcher(ranges: &mut Vec<Ipv4Range>) -> Option<V4Matcher> {
    if ranges.is_empty() {
        return None;
    }

    merge_v4_ranges(ranges);
    let rule_count = ranges.len();

    let mut page_ranges: Vec<Vec<(u16, u16)>> = (0..V4_PAGE_COUNT).map(|_| Vec::new()).collect();

    for range in ranges.iter().copied() {
        let start_page = (range.start >> V4_PAGE_BITS) as usize;
        let end_page = (range.end >> V4_PAGE_BITS) as usize;

        if start_page == end_page {
            page_ranges[start_page].push(((range.start & V4_LOW_MASK) as u16, range.end as u16));
            continue;
        }

        page_ranges[start_page].push(((range.start & V4_LOW_MASK) as u16, u16::MAX));

        for page in page_ranges.iter_mut().take(end_page).skip(start_page + 1) {
            page.clear();
            page.push((0, u16::MAX));
        }

        page_ranges[end_page].push((0, (range.end & V4_LOW_MASK) as u16));
    }

    let mut pages = vec![V4PageMeta::default(); V4_PAGE_COUNT].into_boxed_slice();
    let mut inline1 = Vec::<V4Inline1>::new();
    let mut inline2 = Vec::<V4Inline2>::new();
    let mut inline4 = Vec::<V4Inline4>::new();
    let mut bitmaps = Vec::<V4Bitmap>::new();

    for (page_idx, ranges) in page_ranges.iter_mut().enumerate() {
        if ranges.is_empty() {
            pages[page_idx].kind = V4_KIND_EMPTY;
            continue;
        }

        merge_local_u16_ranges(ranges);

        if ranges.len() == 1 && ranges[0] == (0, u16::MAX) {
            pages[page_idx].kind = V4_KIND_FULL;
            continue;
        }

        match ranges.len() {
            1 => {
                let idx = inline1.len() as u32;
                let (start, end) = ranges[0];
                inline1.push(V4Inline1 { start, end });
                pages[page_idx] = V4PageMeta {
                    kind: V4_KIND_INLINE1,
                    len: 1,
                    _pad: 0,
                    aux: idx,
                };
            }
            2 => {
                let idx = inline2.len() as u32;
                let [(a0, b0), (a1, b1)] = [ranges[0], ranges[1]];
                inline2.push(V4Inline2 { a0, b0, a1, b1 });
                pages[page_idx] = V4PageMeta {
                    kind: V4_KIND_INLINE2,
                    len: 2,
                    _pad: 0,
                    aux: idx,
                };
            }
            3 | 4 => {
                let idx = inline4.len() as u32;
                let mut packed = V4Inline4 {
                    a0: 0,
                    b0: 0,
                    a1: 0,
                    b1: 0,
                    a2: 0,
                    b2: 0,
                    a3: 0,
                    b3: 0,
                };

                let n = ranges.len();
                if n >= 1 {
                    let (a, b) = ranges[0];
                    packed.a0 = a;
                    packed.b0 = b;
                }
                if n >= 2 {
                    let (a, b) = ranges[1];
                    packed.a1 = a;
                    packed.b1 = b;
                }
                if n >= 3 {
                    let (a, b) = ranges[2];
                    packed.a2 = a;
                    packed.b2 = b;
                }
                if n >= 4 {
                    let (a, b) = ranges[3];
                    packed.a3 = a;
                    packed.b3 = b;
                }

                inline4.push(packed);
                pages[page_idx] = V4PageMeta {
                    kind: V4_KIND_INLINE4,
                    len: n as u8,
                    _pad: 0,
                    aux: idx,
                };
            }
            _ => {
                let idx = bitmaps.len() as u32;
                let mut bitmap = [0u64; V4_BITMAP_WORDS];
                for &(start, end) in ranges.iter() {
                    set_v4_bitmap_range(&mut bitmap, start, end);
                }
                bitmaps.push(bitmap);
                pages[page_idx] = V4PageMeta {
                    kind: V4_KIND_BITMAP,
                    len: 0,
                    _pad: 0,
                    aux: idx,
                };
            }
        }
    }

    Some(V4Matcher {
        pages,
        inline1: inline1.into_boxed_slice(),
        inline2: inline2.into_boxed_slice(),
        inline4: inline4.into_boxed_slice(),
        bitmaps: bitmaps.into_boxed_slice(),
        rule_count,
    })
}

/// Compile merged IPv6 ranges into a sorted boxed slice.
fn compile_v6_matcher(ranges: &mut Vec<Ipv6Range>) -> Option<V6Matcher> {
    if ranges.is_empty() {
        return None;
    }

    merge_v6_ranges(ranges);
    let rule_count = ranges.len();
    let ranges = ranges.clone().into_boxed_slice();

    Some(V6Matcher { ranges, rule_count })
}

#[inline]
fn contains_v4_uncompiled(ranges: &[Ipv4Range], value: u32) -> bool {
    ranges.iter().any(|range| range.contains(value))
}

#[inline]
fn contains_v6_uncompiled(ranges: &[Ipv6Range], value: u128) -> bool {
    ranges.iter().any(|range| range.contains(value))
}

/// Sort and merge overlapping or adjacent IPv4 ranges in place.
fn merge_v4_ranges(ranges: &mut Vec<Ipv4Range>) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_unstable_by_key(|r| r.start);

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

/// Sort and merge overlapping or adjacent IPv6 ranges in place.
fn merge_v6_ranges(ranges: &mut Vec<Ipv6Range>) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_unstable_by_key(|r| r.start);

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

/// Merge page-local low-16-bit intervals after IPv4 ranges have been split by page.
fn merge_local_u16_ranges(ranges: &mut Vec<(u16, u16)>) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_unstable_by_key(|r| r.0);

    let mut write = 0usize;
    for read in 1..ranges.len() {
        let next = ranges[read];
        let current = &mut ranges[write];

        if next.0 <= current.1.saturating_add(1) {
            current.1 = current.1.max(next.1);
        } else {
            write += 1;
            ranges[write] = next;
        }
    }

    ranges.truncate(write + 1);
}

/// Set every bit in the inclusive range `[start, end]` inside a page bitmap.
#[inline]
fn set_v4_bitmap_range(words: &mut [u64; V4_BITMAP_WORDS], start: u16, end: u16) {
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

/// Parse a host address or CIDR prefix and normalize it into network bits plus prefix length.
///
/// Bare addresses are treated as `/32` for IPv4 and `/128` for IPv6.
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

            let network = mask_v4_bits(u32::from(ip), prefix_len);
            Ok(ParsedPrefix::V4 {
                network,
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

            let network = mask_v6_bits(ipv6_to_u128(ip), prefix_len);
            Ok(ParsedPrefix::V6 {
                network,
                prefix_len,
            })
        }
    }
}

/// Keep only the leading `prefix_len` bits of an IPv4 address.
#[inline]
fn mask_v4_bits(bits: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - prefix_len as u32))
    }
}

/// Keep only the leading `prefix_len` bits of an IPv6 address.
#[inline]
fn mask_v6_bits(bits: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix_len as u32))
    }
}

/// Convert an IPv6 address into a big-endian integer for fast range comparisons.
#[inline]
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipv4_host_rule() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("192.0.2.1").unwrap();
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
    }

    #[test]
    fn test_ipv4_prefix_rule() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("10.0.0.0/8").unwrap();
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn test_ipv4_merge_rules() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("10.0.0.0/16").unwrap();
        matcher.add_rule("10.0.1.0/24").unwrap();
        matcher.finalize();

        assert_eq!(matcher.v4_rule_count(), 1);
        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 99))));
    }

    #[test]
    fn test_ipv4_cross_pages() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("10.0.0.0/15").unwrap();
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 255, 254))));
        assert!(!matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))));
    }

    #[test]
    fn test_ipv6_host_rule() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("2001:db8::1").unwrap();
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(!matcher.contains_ip(IpAddr::V6("2001:db8::2".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_prefix_rule() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("2001:db8::/32").unwrap();
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V6("2001:db8:1::1234".parse().unwrap())));
        assert!(matcher.contains_ip(IpAddr::V6("2001:db8:ffff::1".parse().unwrap())));
        assert!(!matcher.contains_ip(IpAddr::V6("2001:db9::1".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_more_specific_rule_removed() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("2001:db8::/32").unwrap();
        matcher.add_rule("2001:db8:1::/48").unwrap();
        matcher.add_rule("2001:db8:2::/48").unwrap();
        matcher.finalize();

        assert_eq!(matcher.v6_rule_count(), 1);
    }

    #[test]
    fn test_uncompiled_path_works() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("192.168.1.0/24").unwrap();
        matcher.add_rule("2001:db8::/32").unwrap();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8))));
        assert!(matcher.contains_ip(IpAddr::V6("2001:db8::1234".parse().unwrap())));
        assert!(!matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn test_invalid_input() {
        let mut matcher = IpPrefixMatcher::default();

        assert!(matcher.add_rule("1.2.3.4/33").is_err());
        assert!(matcher.add_rule("2001:db8::/129").is_err());
        assert!(matcher.add_rule("1.2.3.4/24/1").is_err());
    }

    #[test]
    fn test_contains_v4_u32_hotpath() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("203.0.113.0/24").unwrap();
        matcher.finalize();

        let ip = u32::from(Ipv4Addr::new(203, 0, 113, 10));
        assert!(matcher.contains_v4_u32(ip));
    }

    #[test]
    fn test_contains_v6_u128_hotpath() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("2001:db8:abcd::/48").unwrap();
        matcher.finalize();

        let ip = ipv6_to_u128("2001:db8:abcd::1".parse().unwrap());
        assert!(matcher.contains_v6_u128(ip));
    }

    #[test]
    fn test_ipv6_adjacent_ranges_merge() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("2001:db8::/127").unwrap();
        matcher.add_rule("2001:db8::2/127").unwrap();
        matcher.finalize();

        assert_eq!(matcher.v6_rule_count(), 1);
        assert!(matcher.contains_ip(IpAddr::V6("2001:db8::".parse().unwrap())));
        assert!(matcher.contains_ip(IpAddr::V6("2001:db8::3".parse().unwrap())));
        assert!(!matcher.contains_ip(IpAddr::V6("2001:db8::4".parse().unwrap())));
    }

    #[test]
    fn test_finalize_then_add_rule_still_works() {
        let mut matcher = IpPrefixMatcher::default();
        matcher.add_rule("10.0.0.0/8").unwrap();
        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));

        matcher.add_rule("192.168.0.0/16").unwrap();

        // uncompiled fallback after add_rule()
        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        matcher.finalize();

        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
        assert!(matcher.contains_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }
}
