/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Borrowed DNS name views.
//!
//! `NameRef` preserves the original wire bytes and label boundaries from a
//! packet. Callers that need exact bytes should prefer `iter_label_bytes()`,
//! while string iterators are only suitable for labels that are valid UTF-8.

use smallvec::SmallVec;
use std::ops::Range;

/// Borrowed metadata for one label inside a packet-backed name.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LabelRef {
    /// Byte offset of the first label byte inside the packet.
    start: u16,
    /// Label length in bytes.
    len: u8,
}

impl LabelRef {
    /// Construct a borrowed label reference.
    #[inline]
    pub(crate) fn new(start: u16, len: u8) -> Self {
        Self { start, len }
    }

    #[inline]
    /// Return the byte offset of the first label byte.
    pub fn start(&self) -> u16 {
        self.start
    }

    #[inline]
    /// Return the label length in bytes.
    pub fn len(&self) -> u8 {
        self.len
    }
}

/// Borrowed DNS name view that keeps references into packet bytes.
#[derive(Debug, Clone)]
pub struct NameRef<'a> {
    /// Borrowed packet bytes backing the name.
    packet: &'a [u8],
    /// Full on-wire byte range of the encoded name.
    wire_range: Range<u16>,
    /// Parsed label boundaries inside `packet`.
    labels: SmallVec<[LabelRef; 8]>,
    /// Whether the encoded name terminated as a fully-qualified name.
    is_fqdn: bool,
}

impl<'a> NameRef<'a> {
    /// Construct a borrowed name view from parsed wire metadata.
    pub(crate) fn new(
        packet: &'a [u8],
        wire_range: Range<u16>,
        labels: SmallVec<[LabelRef; 8]>,
        is_fqdn: bool,
    ) -> Self {
        Self {
            packet,
            wire_range,
            labels,
            is_fqdn,
        }
    }

    #[inline]
    /// Return the on-wire byte range of the encoded name.
    pub fn wire_range(&self) -> Range<u16> {
        self.wire_range.clone()
    }

    #[inline]
    /// Return the exact encoded wire bytes of this name.
    pub fn wire_bytes(&self) -> &'a [u8] {
        &self.packet[self.wire_range.start as usize..self.wire_range.end as usize]
    }

    #[inline]
    /// Report whether the name is fully qualified.
    pub fn is_fqdn(&self) -> bool {
        self.is_fqdn
    }

    #[inline]
    /// Report whether the name is the DNS root.
    pub fn is_root(&self) -> bool {
        self.labels.is_empty() && self.is_fqdn
    }

    #[inline]
    /// Return the number of parsed labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    #[inline]
    /// Iterate UTF-8 labels from left to right.
    pub fn iter_labels(&self) -> LabelsIter<'_, 'a> {
        LabelsIter {
            packet: self.packet,
            labels: self.labels.iter(),
        }
    }

    #[inline]
    /// Iterate UTF-8 labels from right to left.
    pub fn iter_labels_rev(&self) -> LabelsRevIter<'_, 'a> {
        LabelsRevIter {
            packet: self.packet,
            labels: self.labels.iter().rev(),
        }
    }

    #[inline]
    /// Iterate raw label bytes from left to right.
    pub fn iter_label_bytes(&self) -> LabelBytesIter<'_, 'a> {
        LabelBytesIter {
            packet: self.packet,
            labels: self.labels.iter(),
        }
    }

    #[inline]
    /// Iterate raw label bytes from right to left.
    pub fn iter_label_bytes_rev(&self) -> LabelBytesRevIter<'_, 'a> {
        LabelBytesRevIter {
            packet: self.packet,
            labels: self.labels.iter().rev(),
        }
    }

    #[inline]
    /// Return the parsed label references backing this name.
    pub fn label_refs(&self) -> &[LabelRef] {
        &self.labels
    }

    /// Return the matcher-friendly canonical form of the name.
    ///
    /// Safe ASCII bytes are lowercased in place. Any other byte is rendered as
    /// a `\DDD` escape so non-UTF8 labels survive packet-backed and owned
    /// normalization with identical semantics.
    pub fn normalized(&self) -> String {
        normalize_label_bytes(self.iter_label_bytes())
    }
}

/// Normalize raw DNS label bytes into ForgeDNS's matcher-friendly form.
pub(crate) fn normalize_label_bytes<'a>(labels: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut iter = labels.into_iter().peekable();
    if iter.peek().is_none() {
        return String::new();
    }

    let mut out = String::new();
    for (idx, label) in iter.enumerate() {
        if idx > 0 {
            out.push('.');
        }
        for &byte in label {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                out.push(char::from(byte.to_ascii_lowercase()));
            } else {
                out.push('\\');
                let hundreds = byte / 100;
                let tens = (byte / 10) % 10;
                let ones = byte % 10;
                out.push(char::from(b'0' + hundreds));
                out.push(char::from(b'0' + tens));
                out.push(char::from(b'0' + ones));
            }
        }
    }
    out
}

/// Iterator over UTF-8 labels in wire order.
pub struct LabelsIter<'n, 'a> {
    /// Borrowed packet bytes.
    packet: &'a [u8],
    /// Remaining label references.
    labels: std::slice::Iter<'n, LabelRef>,
}

impl<'n, 'a> Iterator for LabelsIter<'n, 'a> {
    type Item = &'a str;

    #[inline]
    /// Return the next UTF-8 label, skipping labels that are not valid UTF-8.
    fn next(&mut self) -> Option<Self::Item> {
        let label = self.labels.next()?;
        std::str::from_utf8(
            &self.packet[label.start as usize..label.start as usize + label.len as usize],
        )
        .ok()
    }
}

/// Iterator over UTF-8 labels in reverse order.
pub struct LabelsRevIter<'n, 'a> {
    /// Borrowed packet bytes.
    packet: &'a [u8],
    /// Remaining label references in reverse order.
    labels: std::iter::Rev<std::slice::Iter<'n, LabelRef>>,
}

impl<'n, 'a> Iterator for LabelsRevIter<'n, 'a> {
    type Item = &'a str;

    #[inline]
    /// Return the next UTF-8 label from the end of the name.
    fn next(&mut self) -> Option<Self::Item> {
        let label = self.labels.next()?;
        std::str::from_utf8(
            &self.packet[label.start as usize..label.start as usize + label.len as usize],
        )
        .ok()
    }
}

/// Iterator over raw label bytes in wire order.
pub struct LabelBytesIter<'n, 'a> {
    /// Borrowed packet bytes.
    packet: &'a [u8],
    /// Remaining label references.
    labels: std::slice::Iter<'n, LabelRef>,
}

impl<'n, 'a> Iterator for LabelBytesIter<'n, 'a> {
    type Item = &'a [u8];

    #[inline]
    /// Return the next raw label byte slice.
    fn next(&mut self) -> Option<Self::Item> {
        let label = self.labels.next()?;
        Some(&self.packet[label.start as usize..label.start as usize + label.len as usize])
    }
}

/// Iterator over raw label bytes in reverse order.
pub struct LabelBytesRevIter<'n, 'a> {
    /// Borrowed packet bytes.
    packet: &'a [u8],
    /// Remaining label references in reverse order.
    labels: std::iter::Rev<std::slice::Iter<'n, LabelRef>>,
}

impl<'n, 'a> Iterator for LabelBytesRevIter<'n, 'a> {
    type Item = &'a [u8];

    #[inline]
    /// Return the next raw label byte slice from the end of the name.
    fn next(&mut self) -> Option<Self::Item> {
        let label = self.labels.next()?;
        Some(&self.packet[label.start as usize..label.start as usize + label.len as usize])
    }
}
