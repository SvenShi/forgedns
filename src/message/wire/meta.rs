/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared packet metadata used by packet-backed and zero-copy message views.

use crate::message::wire::edns::EdnsRef;
use crate::message::wire::name::{LabelRef, NameRef};
use crate::message::wire::question::QuestionRef;
use smallvec::SmallVec;
use std::ops::Range;

/// Packet-backed metadata for one DNS name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct NameMeta {
    /// Full on-wire byte range of the encoded name.
    pub(crate) wire_range: Range<u16>,
    /// Parsed label boundaries inside the packet.
    pub(crate) labels: SmallVec<[LabelRef; 8]>,
    /// Whether the encoded name terminated as a fully-qualified name.
    pub(crate) is_fqdn: bool,
}

impl NameMeta {
    /// Construct packet-backed name metadata.
    #[inline]
    pub(crate) fn new(
        wire_range: Range<u16>,
        labels: SmallVec<[LabelRef; 8]>,
        is_fqdn: bool,
    ) -> Self {
        Self {
            wire_range,
            labels,
            is_fqdn,
        }
    }

    /// Rebuild a borrowed name view on top of `packet`.
    #[inline]
    pub(crate) fn as_name_ref<'a>(&self, packet: &'a [u8]) -> NameRef<'a> {
        NameRef::new(
            packet,
            self.wire_range.clone(),
            self.labels.clone(),
            self.is_fqdn,
        )
    }
}

/// Packet-backed metadata for one DNS question.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct QuestionMeta {
    /// Full question byte range in the packet.
    pub(crate) wire_range: Range<u16>,
    /// Encoded name metadata.
    pub(crate) name: NameMeta,
    /// Raw query type.
    pub(crate) qtype: u16,
    /// Raw query class.
    pub(crate) qclass: u16,
}

impl QuestionMeta {
    /// Construct packet-backed question metadata.
    #[inline]
    pub(crate) fn new(wire_range: Range<u16>, name: NameMeta, qtype: u16, qclass: u16) -> Self {
        Self {
            wire_range,
            name,
            qtype,
            qclass,
        }
    }

    /// Rebuild a borrowed question view on top of `packet`.
    #[inline]
    pub(crate) fn as_question_ref<'a>(&self, packet: &'a [u8]) -> QuestionRef<'a> {
        QuestionRef::new(
            self.name.as_name_ref(packet),
            self.qtype,
            self.qclass,
            self.wire_range.clone(),
        )
    }
}

/// Packet-backed metadata for the first OPT record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct EdnsMeta {
    /// Advertised UDP payload size.
    pub(crate) udp_payload_size: u16,
    /// Extended response code high bits.
    pub(crate) ext_rcode: u8,
    /// EDNS version.
    pub(crate) version: u8,
    /// Raw EDNS flags.
    pub(crate) flags: u16,
    /// Option payload byte range inside the packet.
    pub(crate) options_range: Range<u16>,
}

impl EdnsMeta {
    /// Construct packet-backed EDNS metadata.
    #[inline]
    pub(crate) fn new(
        udp_payload_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: u16,
        options_range: Range<u16>,
    ) -> Self {
        Self {
            udp_payload_size,
            ext_rcode,
            version,
            flags,
            options_range,
        }
    }

    /// Rebuild a borrowed EDNS view on top of `packet`.
    #[inline]
    pub(crate) fn as_edns_ref<'a>(&self, packet: &'a [u8]) -> EdnsRef<'a> {
        EdnsRef::new(
            self.udp_payload_size,
            self.ext_rcode,
            self.version,
            self.flags,
            self.options_range.clone(),
            packet,
        )
    }
}

/// Packet-backed metadata for one DNS resource record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RecordMeta {
    /// Full wire range of the resource record.
    pub(crate) wire_range: Range<u16>,
    /// Owner name metadata.
    pub(crate) name: NameMeta,
    /// Raw RR type.
    pub(crate) rr_type: u16,
    /// Raw class field.
    pub(crate) class: u16,
    /// Raw TTL field value.
    pub(crate) ttl: u32,
    /// Offset of the 32-bit TTL field.
    pub(crate) ttl_offset: u16,
    /// Raw RDATA byte range.
    pub(crate) rdata_range: Range<u16>,
}

impl RecordMeta {
    /// Construct packet-backed RR metadata.
    #[inline]
    pub(crate) fn new(
        wire_range: Range<u16>,
        name: NameMeta,
        rr_type: u16,
        class: u16,
        ttl: u32,
        ttl_offset: u16,
        rdata_range: Range<u16>,
    ) -> Self {
        Self {
            wire_range,
            name,
            rr_type,
            class,
            ttl,
            ttl_offset,
            rdata_range,
        }
    }
}
