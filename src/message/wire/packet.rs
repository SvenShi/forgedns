/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Thin packet wrappers returned by the zero-copy parser.

use crate::core::error::Result;
use crate::message::parse_message;
use crate::message::wire::edns::EdnsRef;
use crate::message::wire::flags::DNS_HEADER_LEN;
use crate::message::wire::header::Header;
use crate::message::wire::meta::{EdnsMeta, QuestionMeta};
use crate::message::wire::question::{QuestionRef, QuestionsIter};
use crate::message::wire::record::{RecordSection, RecordsIter};
use bytes::Bytes;
use std::sync::OnceLock;

/// Immutable DNS packet wrapper shared across transports and packet helpers.
#[derive(Debug)]
pub struct Packet {
    /// Reference-counted packet bytes.
    bytes: Bytes,
    /// Cached zero-copy parse metadata reused across repeated packet scans.
    parsed: OnceLock<ParsedPacketCache>,
}

#[derive(Debug, Clone)]
struct ParsedPacketCache {
    header: Header,
    question: Option<QuestionMeta>,
    edns: Option<EdnsMeta>,
    sections: SectionOffsets,
}

impl ParsedPacketCache {
    #[inline]
    fn parsed_message<'a>(&self, packet: &'a [u8]) -> ParsedMessage<'a> {
        ParsedMessage::new(
            packet,
            self.header,
            self.question.clone(),
            self.edns.clone(),
            self.sections,
        )
    }
}

impl Packet {
    /// Wrap a reference-counted byte buffer as a DNS packet.
    #[inline]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            bytes,
            parsed: OnceLock::new(),
        }
    }

    /// Wrap an owned byte vector as a DNS packet.
    #[inline]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::from(bytes),
            parsed: OnceLock::new(),
        }
    }

    /// Borrow the raw wire bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Parse this packet into a zero-copy view.
    #[inline]
    pub fn parse(&self) -> Result<ParsedMessage<'_>> {
        if let Some(parsed) = self.parsed.get() {
            return Ok(parsed.parsed_message(self.as_slice()));
        }

        let parsed = parse_message(self.as_slice())?;
        let cached = ParsedPacketCache {
            header: parsed.header,
            question: parsed.question.clone(),
            edns: parsed.edns.clone(),
            sections: parsed.sections,
        };
        let _ = self.parsed.set(cached);
        Ok(parsed)
    }
}

impl Clone for Packet {
    fn clone(&self) -> Self {
        let parsed = OnceLock::new();
        if let Some(cache) = self.parsed.get() {
            let _ = parsed.set(cache.clone());
        }
        Self {
            bytes: self.bytes.clone(),
            parsed,
        }
    }
}

/// Byte offsets for the major DNS sections inside a packet.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SectionOffsets {
    /// Offset immediately after the question section.
    pub question_end: u16,
    /// Offset of the first answer record.
    pub answer_start: u16,
    /// Offset of the first authority record.
    pub authority_start: u16,
    /// Offset of the first additional record.
    pub additional_start: u16,
    /// Offset immediately after the whole message.
    pub end: u16,
}

/// Parsed zero-copy message view built directly from a packet.
#[derive(Debug, Clone)]
pub struct ParsedMessage<'a> {
    /// Borrowed packet bytes backing all sub-views.
    packet: &'a [u8],
    /// Decoded DNS header.
    header: Header,
    /// First question, if present.
    question: Option<QuestionMeta>,
    /// First OPT record, if present.
    edns: Option<EdnsMeta>,
    /// Section boundaries computed while parsing.
    sections: SectionOffsets,
}

impl<'a> ParsedMessage<'a> {
    /// Construct a parsed message view from already decoded components.
    pub(crate) fn new(
        packet: &'a [u8],
        header: Header,
        question: Option<QuestionMeta>,
        edns: Option<EdnsMeta>,
        sections: SectionOffsets,
    ) -> Self {
        Self {
            packet,
            header,
            question,
            edns,
            sections,
        }
    }

    #[inline]
    /// Return the borrowed packet bytes.
    pub fn packet(&self) -> &'a [u8] {
        self.packet
    }

    #[inline]
    /// Return the raw header view parsed directly from the packet bytes.
    pub fn header(&self) -> Header {
        self.header
    }

    #[inline]
    /// Return the first question carried by the packet, if present.
    pub fn first_question(&self) -> Option<QuestionRef<'a>> {
        self.question
            .as_ref()
            .map(|question| question.as_question_ref(self.packet))
    }

    #[inline]
    /// Iterate question-section entries without materializing owned questions.
    pub fn question_records(&self) -> QuestionsIter<'a> {
        QuestionsIter::new(self.packet(), DNS_HEADER_LEN, self.header().qdcount())
    }

    #[inline]
    /// Return the first OPT record, if present.
    pub fn edns(&self) -> Option<EdnsRef<'a>> {
        self.edns.as_ref().map(|edns| edns.as_edns_ref(self.packet))
    }

    #[inline]
    /// Return the section boundaries used by packet-level helpers.
    pub fn sections(&self) -> SectionOffsets {
        self.sections
    }

    #[inline]
    /// Return the cached first-question metadata.
    pub(crate) fn first_question_meta(&self) -> Option<&QuestionMeta> {
        self.question.as_ref()
    }

    #[inline]
    /// Return the cached EDNS metadata.
    pub(crate) fn edns_meta(&self) -> Option<&EdnsMeta> {
        self.edns.as_ref()
    }

    #[inline]
    /// Iterate resource records from the requested DNS section.
    pub fn records(&self, section: RecordSection) -> RecordsIter<'a> {
        match section {
            RecordSection::Answer => self.answer_records(),
            RecordSection::Authority => self.authority_records(),
            RecordSection::Additional => self.additional_records(),
        }
    }

    #[inline]
    /// Iterate answer-section resource records.
    pub fn answer_records(&self) -> RecordsIter<'a> {
        RecordsIter::new(
            self.packet(),
            self.sections().answer_start as usize,
            self.header().ancount(),
        )
    }

    #[inline]
    /// Iterate authority-section resource records.
    pub fn authority_records(&self) -> RecordsIter<'a> {
        RecordsIter::new(
            self.packet(),
            self.sections().authority_start as usize,
            self.header().nscount(),
        )
    }

    #[inline]
    /// Iterate additional-section resource records.
    pub fn additional_records(&self) -> RecordsIter<'a> {
        RecordsIter::new(
            self.packet(),
            self.sections().additional_start as usize,
            self.header().arcount(),
        )
    }
}
