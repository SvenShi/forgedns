/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Borrowed DNS question view extracted from a packet.

use crate::core::error::Result;
use crate::message::NameRef;
use crate::message::model::data::{DNSClass, RecordType};
use crate::message::wire::parser::parse_question_meta;
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

/// Iterator over borrowed question views in the DNS question section.
pub struct QuestionsIter<'a> {
    packet: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> QuestionsIter<'a> {
    #[inline]
    pub(crate) fn new(packet: &'a [u8], offset: usize, remaining: u16) -> Self {
        Self {
            packet,
            offset,
            remaining,
        }
    }
}

impl<'a> Iterator for QuestionsIter<'a> {
    type Item = Result<QuestionRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;
        match parse_question_meta(self.packet, self.offset) {
            Ok((question_meta, next_offset)) => {
                self.offset = next_offset;
                Some(Ok(question_meta.as_question_ref(self.packet)))
            }
            Err(err) => {
                self.remaining = 0;
                Some(Err(err))
            }
        }
    }
}
