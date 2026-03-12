/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Zero-copy DNS packet parser used by packet-backed message mode.
//!
//! The parser keeps references into the original packet instead of allocating
//! owned names or records. It caches the first question directly in the parsed
//! view and still walks all questions and sections so later helpers can iterate
//! them without reparsing the header/section layout.

use crate::core::error::{DnsError, Result};
use crate::message::wire::flags::DNS_HEADER_LEN;
use crate::message::wire::meta::{EdnsMeta, NameMeta, QuestionMeta, RecordMeta};
use crate::message::{Header, LabelRef, ParsedMessage, SectionOffsets};
use smallvec::SmallVec;
/// RR type value for the EDNS OPT pseudo-record.
const OPT_RR_TYPE: u16 = 41;

/// Parse a DNS packet into a zero-copy [`ParsedMessage`] view.
pub fn parse_message(packet: &[u8]) -> Result<ParsedMessage<'_>> {
    let header = Header::parse(packet)?;

    let mut offset = DNS_HEADER_LEN;
    let mut first_question = None;
    for index in 0..header.qdcount() {
        let (question, next_offset) = parse_question_meta(packet, offset)?;
        offset = next_offset;
        // Keep the first question inline for the common fast path, but still
        // walk the whole section so later question iterators can reuse the
        // validated section layout.
        if index == 0 {
            first_question = Some(question);
        }
    }

    let answer_start = offset as u16;
    for _ in 0..header.ancount() {
        offset = skip_rr_meta(packet, offset)?.0;
    }

    let authority_start = offset as u16;
    for _ in 0..header.nscount() {
        offset = skip_rr_meta(packet, offset)?.0;
    }

    let additional_start = offset as u16;
    let mut edns = None;
    for _ in 0..header.arcount() {
        let (next_offset, parsed_edns) = skip_rr_meta(packet, offset)?;
        if let Some(opt) = parsed_edns {
            if edns.is_some() {
                return Err(DnsError::protocol("multiple OPT records in dns message"));
            }
            edns = Some(opt);
        }
        offset = next_offset;
    }

    if offset != packet.len() {
        return Err(DnsError::protocol("dns packet has trailing bytes"));
    }

    Ok(ParsedMessage::new(
        packet,
        header,
        first_question,
        edns,
        SectionOffsets {
            question_end: answer_start,
            answer_start,
            authority_start,
            additional_start,
            end: offset as u16,
        },
    ))
}

/// Skip one resource record and optionally project it as a borrowed EDNS view.
fn skip_rr_meta(packet: &[u8], offset: usize) -> Result<(usize, Option<EdnsMeta>)> {
    let (record, next_offset) = parse_record_meta(packet, offset)?;
    let edns = (record.rr_type == OPT_RR_TYPE).then(|| {
        EdnsMeta::new(
            record.class,
            (record.ttl >> 24) as u8,
            (record.ttl >> 16) as u8,
            record.ttl as u16,
            record.rdata_range.clone(),
        )
    });
    Ok((next_offset, edns))
}

/// Parse one DNS name into packet-backed metadata.
pub(crate) fn parse_name_meta(packet: &[u8], start: usize) -> Result<(NameMeta, usize)> {
    if start >= packet.len() {
        return Err(DnsError::protocol("dns name offset exceeds packet length"));
    }

    let wire_start = start;
    let mut cursor = start;
    let mut next_offset = None;
    let mut labels = SmallVec::<[LabelRef; 8]>::new();
    let mut visited = SmallVec::<[u16; 16]>::new();
    let mut jump_count = 0usize;

    loop {
        if jump_count > packet.len() {
            return Err(DnsError::protocol(
                "dns name compression pointer loop detected",
            ));
        }

        let len = *packet
            .get(cursor)
            .ok_or_else(|| DnsError::protocol("dns name exceeds packet length"))?;

        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    let end = next_offset.unwrap_or(cursor + 1);
                    return Ok((
                        NameMeta::new(wire_start as u16..end as u16, labels, true),
                        end,
                    ));
                }

                if len > 63 {
                    return Err(DnsError::protocol("dns label length exceeds 63 bytes"));
                }

                let label_start = cursor + 1;
                let label_end = label_start + len as usize;
                if label_end > packet.len() {
                    return Err(DnsError::protocol("dns label exceeds packet length"));
                }

                labels.push(LabelRef::new(label_start as u16, len));
                cursor = label_end;
            }
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

                if next_offset.is_none() {
                    // Compression pointers terminate the on-wire encoding of the
                    // current name. `next_offset` keeps the caller's original
                    // stream position while `cursor` jumps to the suffix target.
                    next_offset = Some(cursor + 2);
                }
                visited.push(ptr as u16);
                cursor = ptr;
                jump_count += 1;
            }
            _ => {
                return Err(DnsError::protocol("invalid dns label type"));
            }
        }
    }
}

/// Parse one DNS question into packet-backed metadata.
pub(crate) fn parse_question_meta(packet: &[u8], offset: usize) -> Result<(QuestionMeta, usize)> {
    let question_start = offset;
    let (name, next_offset) = parse_name_meta(packet, offset)?;
    if next_offset + 4 > packet.len() {
        return Err(DnsError::protocol("dns question exceeds packet length"));
    }

    let qtype = u16::from_be_bytes([packet[next_offset], packet[next_offset + 1]]);
    let qclass = u16::from_be_bytes([packet[next_offset + 2], packet[next_offset + 3]]);
    let end = next_offset + 4;
    Ok((
        QuestionMeta::new(question_start as u16..end as u16, name, qtype, qclass),
        end,
    ))
}

/// Parse one resource-record header into packet-backed metadata.
pub(crate) fn parse_record_meta(packet: &[u8], offset: usize) -> Result<(RecordMeta, usize)> {
    let (name, next_offset) = parse_name_meta(packet, offset)?;
    if next_offset + 10 > packet.len() {
        return Err(DnsError::protocol(
            "dns resource record header exceeds packet length",
        ));
    }

    let rr_type = u16::from_be_bytes([packet[next_offset], packet[next_offset + 1]]);
    let class = u16::from_be_bytes([packet[next_offset + 2], packet[next_offset + 3]]);
    let ttl_offset = next_offset + 4;
    let ttl = u32::from_be_bytes([
        packet[ttl_offset],
        packet[ttl_offset + 1],
        packet[ttl_offset + 2],
        packet[ttl_offset + 3],
    ]);
    let rdlen = u16::from_be_bytes([packet[next_offset + 8], packet[next_offset + 9]]) as usize;
    let rdata_start = next_offset + 10;
    let rdata_end = rdata_start + rdlen;
    if rdata_end > packet.len() {
        return Err(DnsError::protocol(
            "dns resource record data exceeds packet length",
        ));
    }

    Ok((
        RecordMeta::new(
            offset as u16..rdata_end as u16,
            name,
            rr_type,
            class,
            ttl,
            ttl_offset as u16,
            rdata_start as u16..rdata_end as u16,
        ),
        rdata_end,
    ))
}

/// Parse one name-only RDATA payload into borrowed name metadata.
pub(crate) fn parse_name_rdata_meta(
    packet: &[u8],
    start: usize,
    end: usize,
    kind: &str,
) -> Result<NameMeta> {
    let (name, next) = parse_name_meta(packet, start)?;
    if next != end {
        return Err(DnsError::protocol(format!("invalid {} rdata length", kind)));
    }
    Ok(name)
}

/// Parse one MX RDATA payload into preference and exchange-name metadata.
pub(crate) fn parse_mx_rdata_meta(
    packet: &[u8],
    start: usize,
    end: usize,
) -> Result<(u16, NameMeta)> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid MX rdata length"));
    }

    let preference = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let (exchange, next) = parse_name_meta(packet, start + 2)?;
    if next != end {
        return Err(DnsError::protocol("invalid MX rdata length"));
    }
    Ok((preference, exchange))
}

/// Parsed SOA RDATA components reused by borrowed and owned decoders.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SoaFields {
    pub(crate) mname: NameMeta,
    pub(crate) rname: NameMeta,
    pub(crate) serial: u32,
    pub(crate) refresh: i32,
    pub(crate) retry: i32,
    pub(crate) expire: i32,
    pub(crate) minimum: u32,
}

/// Parse one SOA RDATA payload into shared field metadata.
pub(crate) fn parse_soa_rdata_fields(packet: &[u8], start: usize, end: usize) -> Result<SoaFields> {
    let (mname, next) = parse_name_meta(packet, start)?;
    let (rname, cursor) = parse_name_meta(packet, next)?;
    if cursor + 20 != end {
        return Err(DnsError::protocol("invalid SOA rdata length"));
    }

    Ok(SoaFields {
        mname,
        rname,
        serial: u32::from_be_bytes([
            packet[cursor],
            packet[cursor + 1],
            packet[cursor + 2],
            packet[cursor + 3],
        ]),
        refresh: u32::from_be_bytes([
            packet[cursor + 4],
            packet[cursor + 5],
            packet[cursor + 6],
            packet[cursor + 7],
        ]) as i32,
        retry: u32::from_be_bytes([
            packet[cursor + 8],
            packet[cursor + 9],
            packet[cursor + 10],
            packet[cursor + 11],
        ]) as i32,
        expire: u32::from_be_bytes([
            packet[cursor + 12],
            packet[cursor + 13],
            packet[cursor + 14],
            packet[cursor + 15],
        ]) as i32,
        minimum: u32::from_be_bytes([
            packet[cursor + 16],
            packet[cursor + 17],
            packet[cursor + 18],
            packet[cursor + 19],
        ]),
    })
}

/// Validate TXT character-string framing and decode UTF-8 chunks into owned strings.
pub(crate) fn parse_txt_strings(packet: &[u8], start: usize, end: usize) -> Result<Vec<String>> {
    let mut cursor = start;
    let mut parts = Vec::new();
    while cursor < end {
        let len = packet[cursor] as usize;
        cursor += 1;
        if cursor + len > end {
            return Err(DnsError::protocol("invalid TXT rdata length"));
        }
        let part = std::str::from_utf8(&packet[cursor..cursor + len])
            .map_err(|_| DnsError::protocol("invalid TXT rdata utf8"))?;
        parts.push(part.to_string());
        cursor += len;
    }
    Ok(parts)
}

/// Validate TXT character-string framing without allocating.
pub(crate) fn validate_txt_rdata(packet: &[u8], start: usize, end: usize) -> Result<()> {
    let mut cursor = start;
    while cursor < end {
        let len = packet[cursor] as usize;
        cursor += 1;
        if cursor + len > end {
            return Err(DnsError::protocol("invalid TXT rdata length"));
        }
        cursor += len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a standard query header with one question and a custom additional count.
    fn base_query_header(id: u16, arcount: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&arcount.to_be_bytes());
        bytes
    }

    /// Build a raw DNS header for parser tests with caller-controlled counters.
    fn base_header(id: u16, qdcount: u16, ancount: u16, arcount: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        bytes.extend_from_slice(&qdcount.to_be_bytes());
        bytes.extend_from_slice(&ancount.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&arcount.to_be_bytes());
        bytes
    }

    /// Append one uncompressed QNAME in presentation-label form.
    fn append_qname(bytes: &mut Vec<u8>, labels: &[&[u8]]) {
        for label in labels {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label);
        }
        bytes.push(0);
    }

    #[test]
    /// Verify the parser extracts header fields, question metadata, and section boundaries.
    fn parse_simple_query_extracts_header_question_and_sections() {
        let mut packet = base_query_header(0x1234, 0);
        append_qname(&mut packet, &[b"WWW", b"Example", b"COM"]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let view = parse_message(&packet).expect("packet should parse");
        let question = view.first_question().expect("question should exist");

        assert_eq!(view.header().id(), 0x1234);
        assert!(view.header().recursion_desired());
        assert_eq!(question.qtype(), 1);
        assert_eq!(question.qclass(), 1);
        assert_eq!(question.name().normalized(), "www.example.com");
        assert_eq!(
            question.name().iter_labels_rev().collect::<Vec<_>>(),
            vec!["COM", "Example", "WWW"]
        );
        assert_eq!(view.sections().question_end as usize, packet.len());
    }

    #[test]
    /// Verify OPT parsing exposes DO-bit and ECS metadata without full decode.
    fn parse_edns_do_and_ecs() {
        let mut packet = base_query_header(0x55aa, 1);
        append_qname(&mut packet, &[b"example", b"com"]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        packet.push(0);
        packet.extend_from_slice(&OPT_RR_TYPE.to_be_bytes());
        packet.extend_from_slice(&1232u16.to_be_bytes());
        packet.extend_from_slice(&0x00008000u32.to_be_bytes());

        let ecs = [
            0x00, 0x08, // option code
            0x00, 0x07, // length
            0x00, 0x01, // family ipv4
            24,   // source prefix
            0,    // scope prefix
            192, 0, 2, // address bytes
        ];
        packet.extend_from_slice(&(ecs.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ecs);

        let view = parse_message(&packet).expect("packet should parse");
        let edns = view.edns().expect("edns should exist");
        let ecs = edns.client_subnet().expect("ecs should exist");

        assert_eq!(edns.udp_payload_size(), 1232);
        assert!(edns.dnssec_ok());
        assert_eq!(ecs.family(), 1);
        assert_eq!(ecs.source_prefix(), 24);
        assert_eq!(ecs.scope_prefix(), 0);
        assert_eq!(ecs.address(), &[192, 0, 2]);
    }

    #[test]
    /// Reject malformed packets whose compressed names loop back on themselves.
    fn parse_rejects_compression_pointer_loop() {
        let mut packet = base_query_header(1, 0);
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let err = parse_message(&packet).expect_err("loop should be rejected");
        assert!(
            err.to_string().contains("compression pointer loop"),
            "unexpected error: {err}"
        );
    }

    #[test]
    /// Reject packets that contain trailing bytes after the declared sections.
    fn parse_rejects_trailing_bytes() {
        let mut packet = base_query_header(2, 0);
        append_qname(&mut packet, &[b"example", b"org"]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);

        let err = parse_message(&packet).expect_err("trailing bytes should be rejected");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    /// Preserve non-UTF8 labels in the normalized escaped-name representation.
    fn parse_preserves_non_utf8_label_in_normalized_form() {
        let mut packet = base_query_header(3, 0);
        packet.push(1);
        packet.push(0xff);
        append_qname(&mut packet, &[b"example"]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let view = parse_message(&packet).expect("packet should parse");
        let question = view.first_question().expect("question should exist");

        assert_eq!(question.name().normalized(), "\\255.example");
    }

    #[test]
    /// Track the full question section even when only the first question view is cached.
    fn parse_keeps_first_question_but_tracks_all_question_bytes() {
        let mut packet = base_header(4, 2, 1, 0);
        append_qname(&mut packet, &[b"first", b"example", b"com"]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        append_qname(&mut packet, &[b"second", b"example", b"com"]);
        packet.extend_from_slice(&28u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let answer_start = packet.len();
        packet.extend_from_slice(&0xC00Cu16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[1, 1, 1, 1]);

        let view = parse_message(&packet).expect("packet should parse");
        let question = view.first_question().expect("first question should exist");

        assert_eq!(question.name().normalized(), "first.example.com");
        assert_eq!(question.qtype(), 1);
        assert_eq!(view.sections().answer_start as usize, answer_start);
    }
}
