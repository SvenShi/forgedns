/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Borrowed DNS question view extracted from a packet.

use crate::message::NameRef;
use crate::message::model::data::{DNSClass, RecordType};
use std::ops::Range;

/// Borrowed view of one DNS question section entry.
#[derive(Debug, Clone)]
pub struct QuestionRef<'a> {
    /// Borrowed question name.
    name: NameRef<'a>,
    /// Raw query type value.
    qtype: u16,
    /// Raw query class value.
    qclass: u16,
    /// Byte range of the full question inside the packet.
    wire_range: Range<u16>,
}

impl<'a> QuestionRef<'a> {
    /// Construct a borrowed question view from already parsed parts.
    pub(crate) fn new(name: NameRef<'a>, qtype: u16, qclass: u16, wire_range: Range<u16>) -> Self {
        Self {
            name,
            qtype,
            qclass,
            wire_range,
        }
    }

    #[inline]
    /// Return the borrowed question name.
    pub fn name(&self) -> &NameRef<'a> {
        &self.name
    }

    #[inline]
    /// Return the raw query type value.
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    #[inline]
    /// Return the decoded question type.
    pub fn question_type(&self) -> RecordType {
        RecordType::from(self.qtype)
    }

    #[inline]
    /// Return the raw query class value.
    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    #[inline]
    /// Return the decoded question class.
    pub fn question_class(&self) -> DNSClass {
        DNSClass::from(self.qclass)
    }

    #[inline]
    /// Return the byte range of the full question in the original packet.
    pub fn wire_range(&self) -> Range<u16> {
        self.wire_range.clone()
    }
}
