/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS name model.

use crate::core::error::{DnsError, Result};
use smallvec::SmallVec;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::OnceLock;

const MAX_NAME_WIRE_OCTETS: usize = 255;
const MAX_COMPRESSION_POINTERS: usize = (MAX_NAME_WIRE_OCTETS + 1) / 2 - 2;

type WireBuf = SmallVec<[u8; 96]>;
type CanonicalFqdnBuf = SmallVec<[u8; 128]>;
type FqdnLabelOffsets = SmallVec<[u16; 8]>;
type WireLabelOffsets = SmallVec<[u8; 8]>;

const fn build_special_table() -> [bool; 256] {
    let mut table = [false; 256];
    table[b'.' as usize] = true;
    table[b' ' as usize] = true;
    table[b'\'' as usize] = true;
    table[b'@' as usize] = true;
    table[b';' as usize] = true;
    table[b'(' as usize] = true;
    table[b')' as usize] = true;
    table[b'"' as usize] = true;
    table[b'\\' as usize] = true;
    table
}

const fn build_decimal_escape_table() -> [[u8; 4]; 256] {
    let mut table = [[0u8; 4]; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = [
            b'\\',
            b'0' + (b / 100),
            b'0' + ((b / 10) % 10),
            b'0' + (b % 10),
        ];
        i += 1;
    }
    table
}

const fn build_ascii_lowercase_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        i += 1;
    }
    table
}

const SPECIAL_TABLE: [bool; 256] = build_special_table();
const DECIMAL_ESCAPE_TABLE: [[u8; 4]; 256] = build_decimal_escape_table();
const ASCII_LOWERCASE_TABLE: [u8; 256] = build_ascii_lowercase_table();

/// Owned DNS domain name.
///
/// Layout:
/// - `wire`: expanded wire name preserving original input/packet case
/// - `wire_label_offsets`: start offset of each label length octet in `wire`
/// - `presentation`: lazily built canonical lowercased escaped fqdn with offsets
#[derive(Debug)]
pub struct Name {
    wire: WireBuf,
    wire_label_offsets: WireLabelOffsets,
    presentation: OnceLock<PresentationData>,
}

#[derive(Debug, Clone)]
struct PresentationData {
    fqdn: CanonicalFqdnBuf,
    fqdn_label_offsets: FqdnLabelOffsets,
}

impl Clone for Name {
    fn clone(&self) -> Self {
        let cloned = Self {
            wire: self.wire.clone(),
            wire_label_offsets: self.wire_label_offsets.clone(),
            presentation: OnceLock::new(),
        };
        if let Some(data) = self.presentation.get() {
            let _ = cloned.presentation.set(data.clone());
        }
        cloned
    }
}

#[allow(dead_code)]
impl Name {
    /// Parse an ASCII domain name and normalize it into canonical form.
    #[inline]
    pub fn from_ascii(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "." {
            return Ok(Self::root());
        }
        if !trimmed.is_ascii() {
            return Err(DnsError::protocol(
                "non-ascii dns names are not supported in presentation form",
            ));
        }

        let bytes = trimmed.as_bytes();
        let len = bytes.len();

        let mut wire = WireBuf::new();
        let mut wire_label_offsets = WireLabelOffsets::new();

        let mut idx = 0usize;
        let mut label_len = 0usize;
        let mut saw_any_label = false;
        let mut saw_trailing_root = false;

        // 当前 label 的长度字节所在位置
        let mut label_len_pos = wire.len();
        wire_label_offsets.push(0);
        wire.push(0);

        while idx < len {
            let b = bytes[idx];

            match b {
                b'.' => {
                    if label_len == 0 {
                        return Err(DnsError::protocol("dns name contains empty label"));
                    }

                    wire[label_len_pos] = label_len as u8;
                    saw_any_label = true;

                    idx += 1;
                    label_len = 0;

                    if idx == len {
                        saw_trailing_root = true;
                        break;
                    }

                    if wire.len() > u8::MAX as usize {
                        return Err(DnsError::protocol("dns name exceeds 255 bytes"));
                    }

                    label_len_pos = wire.len();
                    wire_label_offsets.push(label_len_pos as u8);
                    wire.push(0);
                }

                b'\\' => {
                    idx += 1;
                    if idx >= len {
                        return Err(DnsError::protocol("dns name ends with incomplete escape"));
                    }

                    let b0 = bytes[idx];
                    let d0 = b0.wrapping_sub(b'0');

                    let octet = if d0 <= 9 && idx + 2 < len {
                        let b1 = bytes[idx + 1];
                        let b2 = bytes[idx + 2];
                        let d1 = b1.wrapping_sub(b'0');
                        let d2 = b2.wrapping_sub(b'0');

                        if d1 <= 9 && d2 <= 9 {
                            let value = d0 as u32 * 100 + d1 as u32 * 10 + d2 as u32;
                            if value > 255 {
                                return Err(DnsError::protocol(format!(
                                    "dns name decimal escape exceeds 255: \\{value:03}"
                                )));
                            }
                            idx += 3;
                            value as u8
                        } else {
                            idx += 1;
                            b0
                        }
                    } else {
                        idx += 1;
                        b0
                    };

                    if label_len >= 63 {
                        return Err(DnsError::protocol("dns label exceeds 63 bytes"));
                    }

                    wire.push(octet);
                    label_len += 1;
                }

                _ => {
                    if label_len >= 63 {
                        return Err(DnsError::protocol("dns label exceeds 63 bytes"));
                    }

                    wire.push(b);
                    label_len += 1;
                    idx += 1;
                }
            }
        }

        if label_len != 0 {
            wire[label_len_pos] = label_len as u8;
            saw_any_label = true;
        }

        if !saw_any_label {
            if saw_trailing_root {
                return Ok(Self::root());
            }
            return Err(DnsError::protocol("dns name contains no labels"));
        }

        wire.push(0);

        if wire.len() > MAX_NAME_WIRE_OCTETS {
            return Err(DnsError::protocol("dns name exceeds 255 bytes"));
        }

        Ok(Self {
            wire,
            wire_label_offsets,
            presentation: OnceLock::new(),
        })
    }

    /// Return the DNS root name.
    pub fn root() -> Self {
        let mut wire = WireBuf::new();
        wire.push(0);

        Self {
            wire,
            wire_label_offsets: WireLabelOffsets::new(),
            presentation: OnceLock::new(),
        }
    }

    /// Borrow the canonical fqdn presentation without a trailing dot.
    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.presentation().fqdn) }
    }

    /// Return the canonical fqdn presentation with a trailing dot.
    #[inline]
    pub fn to_fqdn(&self) -> String {
        if self.is_root() {
            ".".to_string()
        } else {
            let mut fqdn = String::with_capacity(self.as_str().len() + 1);
            fqdn.push_str(self.as_str());
            fqdn.push('.');
            fqdn
        }
    }

    /// Report whether the name is the DNS root.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.wire_label_offsets.is_empty()
    }

    /// Return the matcher-friendly normalized form without a trailing dot.
    #[inline]
    pub fn normalized(&self) -> &str {
        self.as_str()
    }

    /// Iterate labels in presentation order.
    pub fn labels(&self) -> NameLabels<'_> {
        NameLabels {
            name: self,
            index: 0,
            len: self.label_count(),
        }
    }

    /// Iterate labels from right to left without allocation.
    pub fn iter_labels_rev(&self) -> NameLabelsRev<'_> {
        NameLabelsRev {
            name: self,
            index: self.label_count(),
        }
    }

    /// Iterate wire label bytes in presentation order.
    pub(crate) fn iter_wire_labels(&self) -> WireLabels<'_> {
        WireLabels {
            name: self,
            index: 0,
            len: self.label_count(),
        }
    }

    #[inline]
    pub(crate) fn wire_label_meta_at(&self, index: usize) -> (u8, &[u8], &[u8]) {
        let len_pos = self.wire_label_offsets[index] as usize;
        let len = self.wire[len_pos];
        let start = len_pos + 1;
        let end = start + len as usize;
        (len, &self.wire[start..end], &self.wire[len_pos..])
    }

    #[inline]
    pub(crate) fn wire_label_len_and_suffix_at(&self, index: usize) -> (u8, &[u8]) {
        let len_pos = self.wire_label_offsets[index] as usize;
        let len = self.wire[len_pos];
        (len, &self.wire[len_pos..])
    }

    /// Number of labels in this name.
    #[inline]
    pub(crate) fn label_count(&self) -> usize {
        self.wire_label_offsets.len()
    }

    /// Borrow one label from the canonical fqdn representation.
    #[inline]
    pub(crate) fn fqdn_label_at(&self, index: usize) -> &[u8] {
        let presentation = self.presentation();
        let start = presentation.fqdn_label_offsets[index] as usize;
        let end = presentation
            .fqdn_label_offsets
            .get(index + 1)
            .copied()
            .map(|v| v as usize - 1)
            .unwrap_or(presentation.fqdn.len());
        &presentation.fqdn[start..end]
    }

    /// Borrow one label from the expanded wire representation.
    #[inline]
    pub(crate) fn wire_label_at(&self, index: usize) -> &[u8] {
        let len_pos = self.wire_label_offsets[index] as usize;
        let len = self.wire[len_pos] as usize;
        let start = len_pos + 1;
        let end = start + len;
        &self.wire[start..end]
    }

    /// Borrow the canonical suffix from label index `index` to the end, without a trailing dot.
    #[inline]
    pub(crate) fn suffix_from(&self, index: usize) -> &str {
        let start = self.presentation().fqdn_label_offsets[index] as usize;
        &self.as_str()[start..]
    }

    /// Borrow the original-case wire suffix from `wire`, including the terminating root label.
    #[inline]
    pub(crate) fn wire_suffix_from(&self, index: usize) -> &[u8] {
        if index == self.label_count() {
            &self.wire[self.wire.len() - 1..]
        } else {
            let start = self.wire_label_offsets[index] as usize;
            &self.wire[start..]
        }
    }

    /// Borrow the expanded wire name.
    #[inline]
    pub(crate) fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Return the DNS wire length without compression.
    #[inline]
    pub fn bytes_len(&self) -> usize {
        self.wire.len()
    }

    /// Return encoded byte length at offset `off` with optional compression.
    #[inline]
    pub(crate) fn bytes_len_at<'a>(
        &'a self,
        off: usize,
        compress: bool,
        compression: &mut crate::message::codec::LenCompressionMap<'a>,
    ) -> usize {
        crate::message::codec::domain_name_len(self, off, compression, compress)
    }

    /// Parse `in-addr.arpa` and `ip6.arpa` names into concrete IP addresses.
    pub fn parse_arpa_name(&self) -> Result<ParsedArpaName> {
        let raw = self.normalized();

        if let Some(prefix) = raw.strip_suffix(".in-addr.arpa") {
            let mut parts = prefix
                .split('.')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(DnsError::protocol("invalid in-addr.arpa name"));
            }
            parts.reverse();
            let mut octets = [0u8; 4];
            for (idx, part) in parts.into_iter().enumerate() {
                octets[idx] = part
                    .parse::<u8>()
                    .map_err(|_| DnsError::protocol("invalid in-addr.arpa octet"))?;
            }
            return Ok(ParsedArpaName {
                addr: IpAddr::V4(Ipv4Addr::from(octets)),
            });
        }

        if let Some(prefix) = raw.strip_suffix(".ip6.arpa") {
            let nibbles = prefix
                .split('.')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            if nibbles.len() != 32 {
                return Err(DnsError::protocol("invalid ip6.arpa name"));
            }

            let mut hex = String::with_capacity(32);
            for nibble in nibbles.iter().rev() {
                if nibble.len() != 1 || !nibble.as_bytes()[0].is_ascii_hexdigit() {
                    return Err(DnsError::protocol("invalid ip6.arpa nibble"));
                }
                hex.push_str(nibble);
            }

            let mut bytes = [0u8; 16];
            for idx in 0..16 {
                bytes[idx] = u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16)
                    .map_err(|_| DnsError::protocol("invalid ip6.arpa nibble"))?;
            }
            return Ok(ParsedArpaName {
                addr: IpAddr::V6(Ipv6Addr::from(bytes)),
            });
        }

        Err(DnsError::protocol("name is not a supported arpa name"))
    }

    #[hotpath::measure]
    pub(crate) fn parse(packet: &[u8], start: usize) -> Result<(Self, usize)> {
        if start >= packet.len() {
            return Err(DnsError::protocol("dns name offset exceeds packet length"));
        }

        let mut cursor = start;
        let mut next_offset = None;
        let mut wire = WireBuf::new();
        let mut wire_label_offsets = WireLabelOffsets::new();
        let mut visited = SmallVec::<[u16; 16]>::new();
        let mut pointer_count = 0usize;
        let mut wire_budget = MAX_NAME_WIRE_OCTETS;

        loop {
            if cursor >= packet.len() {
                return Err(DnsError::protocol("dns name exceeds packet length"));
            }
            let len = unsafe { *packet.get_unchecked(cursor) };

            match len & 0xC0 {
                0x00 => {
                    // root
                    if len == 0 {
                        let end = next_offset.unwrap_or(cursor + 1);

                        if wire_label_offsets.is_empty() {
                            return Ok((Self::root(), end));
                        }
                        wire.push(0);

                        if wire.len() > MAX_NAME_WIRE_OCTETS {
                            return Err(DnsError::protocol("dns name exceeds 255 bytes"));
                        }

                        return Ok((
                            Self {
                                wire,
                                wire_label_offsets,
                                presentation: OnceLock::new(),
                            },
                            end,
                        ));
                    }

                    if len > 63 {
                        return Err(DnsError::protocol("dns label length exceeds 63 bytes"));
                    }

                    // label
                    let label_start = cursor + 1;
                    let label_end = label_start + len as usize;
                    if label_end > packet.len() {
                        return Err(DnsError::protocol("dns label exceeds packet length"));
                    }

                    wire_budget = wire_budget
                        .checked_sub(len as usize + 1)
                        .ok_or_else(|| DnsError::protocol("dns name exceeds 255 bytes"))?;

                    wire_label_offsets.push(
                        u8::try_from(wire.len())
                            .map_err(|_| DnsError::protocol("dns name exceeds 255 bytes"))?,
                    );

                    wire.push(len);
                    if label_end > packet.len() {
                        return Err(DnsError::protocol("dns name label exceeds packet length"));
                    }
                    let label = unsafe { packet.get_unchecked(label_start..label_end) };
                    wire.extend_from_slice(label);

                    cursor = label_end;
                }
                // pointer
                0xC0 => {
                    let low = *packet
                        .get(cursor + 1)
                        .ok_or_else(|| DnsError::protocol("truncated dns compression pointer"))?;
                    let ptr = (((len as u16 & 0x3F) << 8) | low as u16) as usize;

                    if ptr >= packet.len() {
                        return Err(DnsError::protocol(
                            "dns compression pointer exceeds packet length",
                        ));
                    }
                    if visited.contains(&(ptr as u16)) {
                        return Err(DnsError::protocol(
                            "dns name compression pointer loop detected",
                        ));
                    }

                    pointer_count += 1;
                    if pointer_count > MAX_COMPRESSION_POINTERS {
                        return Err(DnsError::protocol("too many dns compression pointers"));
                    }

                    if next_offset.is_none() {
                        next_offset = Some(cursor + 2);
                    }
                    visited.push(ptr as u16);
                    cursor = ptr;
                }
                _ => return Err(DnsError::protocol("invalid dns label type")),
            }
        }
    }
}

impl Name {
    #[inline]
    fn presentation(&self) -> &PresentationData {
        self.presentation
            .get_or_init(|| build_presentation_from_wire(&self.wire, &self.wire_label_offsets))
    }
}

fn build_presentation_from_wire(
    wire: &[u8],
    wire_label_offsets: &WireLabelOffsets,
) -> PresentationData {
    if wire_label_offsets.is_empty() {
        let fqdn = CanonicalFqdnBuf::new();
        return PresentationData {
            fqdn,
            fqdn_label_offsets: FqdnLabelOffsets::new(),
        };
    }

    let mut fqdn = CanonicalFqdnBuf::new();
    let mut fqdn_label_offsets = FqdnLabelOffsets::with_capacity(wire_label_offsets.len());

    for (index, len_pos) in wire_label_offsets.iter().copied().enumerate() {
        if index > 0 {
            fqdn.push(b'.');
        }
        fqdn_label_offsets.push(fqdn.len() as u16);

        let len_pos = len_pos as usize;
        let len = wire[len_pos] as usize;
        let start = len_pos + 1;
        let end = start + len;
        let mut i = start;
        while i < end {
            let byte = unsafe { *wire.get_unchecked(i) };
            let lower = unsafe { *ASCII_LOWERCASE_TABLE.get_unchecked(byte as usize) };
            append_presentation_octet_unchecked(&mut fqdn, lower);
            i += 1;
        }
    }
    PresentationData {
        fqdn,
        fqdn_label_offsets,
    }
}

#[inline(always)]
fn append_presentation_octet_unchecked(out: &mut CanonicalFqdnBuf, byte: u8) {
    if byte >= b' ' && byte <= b'~' {
        let special = unsafe { *SPECIAL_TABLE.get_unchecked(byte as usize) };
        if special {
            out.push(b'\\');
            out.push(byte);
        } else {
            out.push(byte);
        }
    } else {
        let escaped = unsafe { DECIMAL_ESCAPE_TABLE.get_unchecked(byte as usize) };
        out.extend_from_slice(escaped);
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Name {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_ascii(s)
    }
}

/// Iterator over labels in presentation order.
pub struct NameLabels<'a> {
    name: &'a Name,
    index: usize,
    len: usize,
}

impl<'a> Iterator for NameLabels<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        if index >= self.len {
            return None;
        }
        self.index += 1;
        let label = self.name.fqdn_label_at(index);
        Some(unsafe { std::str::from_utf8_unchecked(label) })
    }
}

/// Iterator over wire label bytes from owned names.
pub(crate) struct WireLabels<'a> {
    name: &'a Name,
    index: usize,
    len: usize,
}

impl<'a> Iterator for WireLabels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        if index >= self.len {
            return None;
        }
        self.index += 1;
        Some(self.name.wire_label_at(index))
    }
}

/// Iterator over normalized labels from right to left.
pub struct NameLabelsRev<'a> {
    name: &'a Name,
    index: usize,
}

impl<'a> Iterator for NameLabelsRev<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == 0 {
            return None;
        }
        self.index -= 1;
        let label = self.name.fqdn_label_at(self.index);
        Some(unsafe { std::str::from_utf8_unchecked(label) })
    }
}

/// Parsed reverse-lookup name converted back into an IP address.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ParsedArpaName {
    addr: IpAddr,
}

impl ParsedArpaName {
    /// Return the parsed IP address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Basic byte-for-byte name roundtrips, including root and an escaped dot label.
    fn parse_wire_name_roundtrip_cases() {
        let cases: &[(&[u8], &str)] = &[
            (&[0], "."),
            (
                &[
                    7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
                ],
                "example.com.",
            ),
            (
                &[5, b'a', b'a', b'.', b'b', b'b', 2, b'n', b'l', 0],
                "aa\\.bb.nl.",
            ),
        ];

        for (packet, fqdn) in cases {
            let (name, next) = Name::parse(packet, 0).unwrap();
            assert_eq!(next, packet.len());
            assert_eq!(name.wire(), *packet);
            assert_eq!(name.to_fqdn(), *fqdn);
        }
    }

    #[test]
    // Reserved label type prefixes 01xxxxxx and 10xxxxxx are forbidden by RFC 1035.
    fn parse_wire_name_rejects_reserved_label_types() {
        for packet in [
            [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x80],
            [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x40],
        ] {
            let err = Name::parse(&packet, 0).expect_err("reserved label type must fail");
            assert!(err.to_string().contains("invalid dns label type"));
        }
    }

    #[test]
    // Reverse-lookup helpers are used by matchers and should stay stable for both IPv4
    // and IPv6 nibble-style names.
    fn parse_arpa_name_roundtrip_examples() {
        let v4 = Name::from_ascii("4.3.2.1.in-addr.arpa.").unwrap();
        assert_eq!(
            v4.parse_arpa_name().unwrap().addr(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );

        let v6 = Name::from_ascii(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        )
        .unwrap();
        assert_eq!(
            v6.parse_arpa_name().unwrap().addr(),
            IpAddr::V6("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    // Covers one valid compressed suffix case plus the most valuable malformed
    // pointer variants.
    fn parse_wire_name_pointer_matrix() {
        let cases: Vec<(&str, Vec<u8>, bool)> = vec![
            (
                "compressed suffix",
                vec![
                    7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 3, b'w',
                    b'w', b'w', 0xc0, 0x00,
                ],
                true,
            ),
            ("pointer loop", vec![0xc0, 0x00], false),
            ("truncated pointer", vec![0xc0], false),
            ("pointer past end", vec![0xc0, 0x10], false),
            ("label exceeds packet", vec![3, b'w'], false),
        ];

        for (name, packet, ok) in cases {
            let start = if ok { 13 } else { 0 };
            let result = Name::parse(&packet, start);
            assert_eq!(result.is_ok(), ok, "{name}");
            if let Ok((parsed, _)) = result {
                assert_eq!(parsed.to_fqdn(), "www.example.com.");
            }
        }
    }

    #[test]
    fn from_ascii_accepts_decimal_escape_upper_bound() {
        let name = Name::from_ascii("bad\\255char.example.").expect("255 escape should parse");

        assert_eq!(name.wire_label_at(0), b"bad\xffchar");
        assert_eq!(name.to_fqdn(), "bad\\255char.example.");
    }

    #[test]
    fn from_ascii_rejects_decimal_escape_above_u8_range() {
        for raw in ["bad\\256char.example.", "bad\\999char.example."] {
            let err = Name::from_ascii(raw).expect_err("overflowing decimal escape must fail");
            assert!(err.to_string().contains("decimal escape exceeds 255"));
        }
    }
}
