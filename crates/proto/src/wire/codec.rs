// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared message encoder and decoder.

use crate::core::error::{DnsError, Result};
use crate::proto::wire::{CompressionState, encode_edns_record, encode_rdata, parse_rdata};
use crate::proto::{
    DNSClass, Header, Message, MessageType, Name, Question, RData, Rcode, Record, RecordType,
};

pub(crate) const DNS_HEADER_LEN: usize = 12;
const MIN_QUESTION_WIRE_LEN: usize = 5;
const MIN_RECORD_WIRE_LEN: usize = 11;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_AD: u16 = 0x0020;
const FLAG_CD: u16 = 0x0010;

#[inline(always)]
pub(crate) fn read_u16_be(packet: &[u8], offset: usize) -> u16 {
    debug_assert!(offset + 1 < packet.len());
    unsafe {
        ((*packet.get_unchecked(offset) as u16) << 8) | (*packet.get_unchecked(offset + 1) as u16)
    }
}

#[inline(always)]
pub(crate) fn read_u32_be(packet: &[u8], offset: usize) -> u32 {
    debug_assert!(offset + 3 < packet.len());
    unsafe {
        ((*packet.get_unchecked(offset) as u32) << 24)
            | ((*packet.get_unchecked(offset + 1) as u32) << 16)
            | ((*packet.get_unchecked(offset + 2) as u32) << 8)
            | (*packet.get_unchecked(offset + 3) as u32)
    }
}

#[inline(always)]
#[allow(clippy::uninit_vec)]
pub(crate) fn push_u16(out: &mut Vec<u8>, value: u16) {
    let len = out.len();
    out.reserve(2);
    unsafe {
        out.set_len(len + 2);
        *out.get_unchecked_mut(len) = (value >> 8) as u8;
        *out.get_unchecked_mut(len + 1) = value as u8;
    }
}

#[inline(always)]
#[allow(clippy::uninit_vec)]
pub(crate) fn push_u32(out: &mut Vec<u8>, value: u32) {
    let len = out.len();
    out.reserve(4);
    unsafe {
        out.set_len(len + 4);
        *out.get_unchecked_mut(len) = (value >> 24) as u8;
        *out.get_unchecked_mut(len + 1) = (value >> 16) as u8;
        *out.get_unchecked_mut(len + 2) = (value >> 8) as u8;
        *out.get_unchecked_mut(len + 3) = value as u8;
    }
}

#[inline(always)]
pub(crate) fn set_u16(buf: &mut [u8], offset: usize, value: u16) {
    unsafe {
        *buf.get_unchecked_mut(offset) = (value >> 8) as u8;
        *buf.get_unchecked_mut(offset + 1) = value as u8;
    }
}
#[inline(always)]
#[allow(clippy::uninit_vec)]
fn prepare_output_buffer_append(out: &mut Vec<u8>) -> usize {
    let start = out.len();
    out.reserve(DNS_HEADER_LEN);
    unsafe {
        out.set_len(start + DNS_HEADER_LEN);
        std::ptr::write_bytes(out.as_mut_ptr().add(start), 0, DNS_HEADER_LEN);
    }
    start
}

#[inline]
/// Encode the DNS header per RFC 1035 section 4.1.1.
///
/// Extended response codes follow RFC 6891 section 6.1.3 and therefore require
/// EDNS.
fn set_header(
    out: &mut [u8],
    message: &Message,
    id: u16,
    truncated: bool,
    ancount: u16,
    nscount: u16,
    arcount: u16,
) -> Result<()> {
    let rcode = message.rcode();
    if rcode.has_extended_bits() && message.edns().is_none() {
        return Err(DnsError::protocol("extended dns rcode requires edns"));
    }
    let mut flags = u16::from(rcode.low());

    if matches!(message.message_type(), MessageType::Response) {
        flags |= FLAG_QR;
    }
    flags |= u16::from(u8::from(message.opcode()) & 0x0F) << 11;
    if message.authoritative() {
        flags |= FLAG_AA;
    }
    if truncated {
        flags |= FLAG_TC;
    }
    if message.recursion_desired() {
        flags |= FLAG_RD;
    }
    if message.recursion_available() {
        flags |= FLAG_RA;
    }
    if message.authentic_data() {
        flags |= FLAG_AD;
    }
    if message.checking_disabled() {
        flags |= FLAG_CD;
    }

    let qdcount = u16::try_from(message.questions().len())
        .map_err(|_| DnsError::protocol("too many dns questions"))?;

    set_u16(out, 0, id);
    set_u16(out, 2, flags);
    set_u16(out, 4, qdcount);
    set_u16(out, 6, ancount);
    set_u16(out, 8, nscount);
    set_u16(out, 10, arcount);
    Ok(())
}

/// Decode a full DNS message from wire format.
///
/// Section layout follows RFC 1035 section 4.1. Message-level EDNS handling
/// follows RFC 6891, while SIG0/TSIG placement checks follow RFC 2931 / RFC
/// 8945.
pub(crate) fn decode_message(packet: &[u8]) -> Result<Message> {
    let (
        mut header,
        mut offset,
        low_rcode,
        question_count,
        answer_count,
        authority_count,
        additional_count,
    ) = parse_header(packet)?;

    let mut questions = Vec::with_capacity(bounded_section_capacity(
        packet.len().saturating_sub(offset),
        question_count,
        MIN_QUESTION_WIRE_LEN,
    ));

    parse_questions_into(packet, &mut offset, question_count, &mut questions)?;

    let mut answers = Vec::with_capacity(bounded_section_capacity(
        packet.len().saturating_sub(offset),
        answer_count,
        MIN_RECORD_WIRE_LEN,
    ));
    parse_records_into(packet, &mut offset, answer_count, &mut answers)?;

    let mut authorities = Vec::with_capacity(bounded_section_capacity(
        packet.len().saturating_sub(offset),
        authority_count,
        MIN_RECORD_WIRE_LEN,
    ));
    parse_records_into(packet, &mut offset, authority_count, &mut authorities)?;

    let mut additionals = Vec::with_capacity(bounded_section_capacity(
        packet.len().saturating_sub(offset),
        additional_count,
        MIN_RECORD_WIRE_LEN,
    ));

    let mut signature = Vec::with_capacity(1);
    let mut edns = None;
    let mut saw_sig0 = false;
    let mut saw_tsig = false;

    for _ in 0..additional_count {
        if saw_tsig {
            return Err(DnsError::protocol("tsig must be final resource record"));
        }

        let prev_offset = offset;
        let (record, next_offset) = parse_record(packet, offset)?;
        if next_offset <= prev_offset {
            return Err(DnsError::protocol("parser did not advance"));
        }

        match record.data() {
            RData::OPT(opt) => {
                if saw_sig0 {
                    return Err(DnsError::protocol("sig0 must be final resource record"));
                }
                if edns.is_some() {
                    return Err(DnsError::protocol("more than one edns record present"));
                }
                edns = Some(opt.0.clone());
            }
            RData::SIG(_) => {
                if saw_sig0 {
                    return Err(DnsError::protocol("more than one sig0 record present"));
                }
                saw_sig0 = true;
                signature.push(record);
            }
            RData::TSIG(_) => {
                saw_tsig = true;
                signature.push(record);
            }
            _ => {
                if saw_sig0 {
                    return Err(DnsError::protocol("sig0 must be final resource record"));
                }
                additionals.push(record);
            }
        }

        offset = next_offset;
    }

    header.set_rcode(Rcode::from_parts(
        edns.as_ref().map(|e| e.ext_rcode()).unwrap_or(0),
        low_rcode as u8,
    ));

    if offset != packet.len() {
        return Err(DnsError::protocol("dns packet has trailing bytes"));
    }

    Ok(Message {
        header,
        compress: false,
        questions,
        answers,
        authorities,
        additionals,
        signature,
        edns,
    })
}

#[inline]
fn bounded_section_capacity(
    remaining_len: usize,
    declared_count: u16,
    min_entry_len: usize,
) -> usize {
    if min_entry_len == 0 {
        return declared_count as usize;
    }

    declared_count.min((remaining_len / min_entry_len).min(u16::MAX as usize) as u16) as usize
}

/// Decode the fixed 12-byte DNS header defined by RFC 1035 section 4.1.1.
fn parse_header(packet: &[u8]) -> Result<(Header, usize, u16, u16, u16, u16, u16)> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsError::protocol("dns packet shorter than header"));
    }

    let id = read_u16_be(packet, 0);
    let flags = read_u16_be(packet, 2);
    let question_count = read_u16_be(packet, 4);
    let answer_count = read_u16_be(packet, 6);
    let authority_count = read_u16_be(packet, 8);
    let additional_count = read_u16_be(packet, 10);

    Ok((
        Header::from_wire(id, flags),
        DNS_HEADER_LEN,
        flags & 0x000F,
        question_count,
        answer_count,
        authority_count,
        additional_count,
    ))
}

#[inline]
fn parse_questions_into(
    packet: &[u8],
    offset: &mut usize,
    count: u16,
    out: &mut Vec<Question>,
) -> Result<()> {
    let mut off = *offset;
    for _ in 0..count {
        let prev = off;
        let (question, next) = parse_question(packet, off)?;
        if next <= prev {
            return Err(DnsError::protocol("parser did not advance"));
        }
        out.push(question);
        off = next;
    }
    *offset = off;
    Ok(())
}

#[inline]
fn parse_records_into(
    packet: &[u8],
    offset: &mut usize,
    count: u16,
    out: &mut Vec<Record>,
) -> Result<()> {
    let mut off = *offset;
    for _ in 0..count {
        let prev = off;
        let (record, next) = parse_record(packet, off)?;
        if next <= prev {
            return Err(DnsError::protocol("parser did not advance"));
        }
        out.push(record);
        off = next;
    }
    *offset = off;
    Ok(())
}

/// Decode a DNS question entry as defined by RFC 1035 section 4.1.2.
fn parse_question(packet: &[u8], offset: usize) -> Result<(Question, usize)> {
    let (name, next_offset) = Name::parse(packet, offset)?;
    if next_offset + 4 > packet.len() {
        return Err(DnsError::protocol("dns question exceeds packet length"));
    }

    let qtype = RecordType::from(read_u16_be(packet, next_offset));
    let qclass = DNSClass::from(read_u16_be(packet, next_offset + 2));

    Ok((Question::new(name, qtype, qclass), next_offset + 4))
}

/// Decode a DNS resource record header and its RDATA payload per RFC 1035
/// section 4.1.3.
fn parse_record(packet: &[u8], offset: usize) -> Result<(Record, usize)> {
    let (name, next_offset) = Name::parse(packet, offset)?;
    if next_offset + 10 > packet.len() {
        return Err(DnsError::protocol(
            "dns resource record header exceeds packet length",
        ));
    }

    let rr_type = RecordType::from(read_u16_be(packet, next_offset));
    let class = read_u16_be(packet, next_offset + 2);
    let ttl = read_u32_be(packet, next_offset + 4);
    let rdlen = read_u16_be(packet, next_offset + 8) as usize;

    let rdata_start = next_offset + 10;
    let rdata_end = rdata_start + rdlen;
    if rdata_end > packet.len() {
        return Err(DnsError::protocol(
            "dns resource record data exceeds packet length",
        ));
    }

    let data = parse_rdata(packet, &name, rr_type, class, ttl, rdata_start, rdata_end)?;
    Ok((
        Record::from_rdata_with_class(name, ttl, DNSClass::from(class), data),
        rdata_end,
    ))
}

/// Encode a complete DNS message using the standard RFC 1035 section ordering.
pub(crate) fn encode_message_into(message: &Message, id: u16, out: &mut Vec<u8>) -> Result<()> {
    encode_message_into_mode(message, id, out, is_compressible(message))?;
    Ok(())
}

/// Encode a complete DNS message using the standard RFC 1035 section ordering.
pub(crate) fn encode_message_into_mode(
    message: &Message,
    id: u16,
    out: &mut Vec<u8>,
    compress: bool,
) -> Result<()> {
    let header_offset = prepare_output_buffer_append(out);
    let mut compression = CompressionState::new(compress);

    for question in message.questions() {
        encode_name(out, question.name(), &mut compression)?;
        push_u16(out, u16::from(question.qtype()));
        push_u16(out, u16::from(question.qclass()));
    }

    let mut ancount = 0u16;
    let mut nscount = 0u16;
    let mut arcount = 0u16;

    encode_section(out, message.answers(), &mut ancount, &mut compression)?;
    encode_section(out, message.authorities(), &mut nscount, &mut compression)?;

    for record in message.additionals() {
        encode_record(out, record, &mut compression)?;
        arcount += 1;
    }
    if let Some(edns) = message.edns() {
        encode_edns_record(out, edns, message.rcode().high())?;
        arcount += 1;
    }

    for record in message.signature() {
        encode_record(out, record, &mut compression)?;
        arcount += 1;
    }

    set_header(
        &mut out[header_offset..header_offset + DNS_HEADER_LEN],
        message,
        id,
        message.truncated(),
        ancount,
        nscount,
        arcount,
    )?;
    Ok(())
}

/// Encode a complete DNS message while respecting a size budget.
///
/// When the full message does not fit, this path reserves budget for the
/// detached trailer (OPT plus signature records), emits prefix records from
/// Answer, Authority, and Additional, then writes the trailer with name
/// compression disabled.
pub(crate) fn encode_message_with_limit(
    message: &Message,
    max_size: Option<usize>,
    id: u16,
    out: &mut Vec<u8>,
) -> Result<()> {
    if let Some(limit) = max_size {
        // Fast path 1: the full uncompressed message already fits the requested budget.
        if message.bytes_len_with_compression(false) <= limit {
            encode_message_into(message, id, out)?;
            return Ok(());
        }

        // Fast path 2: the compressed full message still fits, so no truncation is
        // required.
        let lens = message.compute_truncation_lens(true);
        if lens.total_len <= limit {
            encode_message_into_mode(message, id, out, true)?;
            return Ok(());
        }

        let header_offset = prepare_output_buffer_append(out);
        let mut compression = CompressionState::new(true);

        for question in message.questions() {
            encode_name(out, question.name(), &mut compression)?;
            push_u16(out, u16::from(question.qtype()));
            push_u16(out, u16::from(question.qclass()));
        }

        // The main sections may consume only the remaining space after reserving the
        // fixed trailer block calculated by `compute_truncation_lens`.
        if lens.trailer_len > limit {
            return Err(DnsError::protocol(
                "dns message cannot fit within UDP payload while preserving EDNS/signature trailer",
            ));
        }
        let with_trailer_limit = limit - lens.trailer_len;

        let mut ancount = 0u16;
        let mut nscount = 0u16;
        let mut arcount = 0u16;
        let mut truncated = false;

        if encode_section_with_limit(
            out,
            message.answers(),
            with_trailer_limit,
            &mut ancount,
            &mut compression,
        )? {
            if encode_section_with_limit(
                out,
                message.authorities(),
                with_trailer_limit,
                &mut nscount,
                &mut compression,
            )? {
                if !encode_section_with_limit(
                    out,
                    message.additionals(),
                    with_trailer_limit,
                    &mut arcount,
                    &mut compression,
                )? {
                    truncated = true;
                }
            } else {
                truncated = true;
            }
        } else {
            truncated = true;
        }
        // The trailer is intentionally emitted without compression so it cannot
        // reference names introduced by RR data that may have been omitted
        // during truncation.
        compression.disable();

        if let Some(edns) = message.edns() {
            arcount += 1;
            encode_edns_record(out, edns, message.rcode().high())?;
        }

        for record in message.signature() {
            arcount += 1;
            encode_record(out, record, &mut compression)?;
        }

        set_header(
            &mut out[header_offset..header_offset + DNS_HEADER_LEN],
            message,
            id,
            truncated || message.truncated(),
            ancount,
            nscount,
            arcount,
        )?;

        Ok(())
    } else {
        encode_message_into(message, id, out)
    }
}

pub(crate) fn is_compressible(message: &Message) -> bool {
    message.compress()
        && (message.questions().len() > 1
            || !message.answers().is_empty()
            || !message.authorities().is_empty()
            || !message.additionals().is_empty()
            || !message.signature().is_empty()
            || message.edns().is_some())
}

/// Encode every record in one section and increment the caller-owned section
/// count.
fn encode_section<'a>(
    out: &mut Vec<u8>,
    records: &'a [Record],
    count: &mut u16,
    compression: &mut CompressionState<'a>,
) -> Result<()> {
    for record in records {
        encode_record(out, record, compression)?;
        *count += 1;
    }
    Ok(())
}

/// Encode a section until the packet would exceed `limit`, truncating at record
/// boundaries.
///
/// The caller passes a budget that already excludes the fixed trailer size.
/// When a record would overflow that budget, its partially written wire bytes
/// are discarded and the section terminates immediately.
fn encode_section_with_limit<'a>(
    out: &mut Vec<u8>,
    records: &'a [Record],
    limit: usize,
    count: &mut u16,
    compression: &mut CompressionState<'a>,
) -> Result<bool> {
    for record in records {
        let start = out.len();
        encode_record(out, record, compression)?;
        if out.len() > limit {
            out.truncate(start);
            return Ok(false);
        }
        *count += 1;
    }
    Ok(true)
}

/// Encode a possibly-compressed DNS name using RFC 1035 section 4.1.4
/// compression pointers.
fn encode_name<'a>(
    out: &mut Vec<u8>,
    name: &'a Name,
    compression: &mut CompressionState<'a>,
) -> Result<()> {
    encode_name_mode(out, name, compression, true)
}

/// Encode a DNS name while forbidding a compression pointer to the current
/// owner name.
fn encode_name_no_compress<'a>(
    out: &mut Vec<u8>,
    name: &'a Name,
    compression: &mut CompressionState<'a>,
) -> Result<()> {
    encode_name_mode(out, name, compression, false)
}
/// Shared DNS name encoder used by owner names and embedded RDATA names.
///
/// This method enforces the RFC 1035 label length and total-name length limits,
/// optionally searches the compression table for the longest reusable suffix,
/// and emits either raw labels plus a terminal zero or raw labels plus a
/// compression pointer.
fn encode_name_mode<'a>(
    out: &mut Vec<u8>,
    name: &'a Name,
    compression: &mut CompressionState<'a>,
    compress_current: bool,
) -> Result<()> {
    if name.is_root() {
        out.push(0);
        return Ok(());
    }

    debug_assert!(name.bytes_len() <= 255);

    let match_suffix = if compress_current {
        compression.pointer_for(name)
    } else {
        None
    };
    let raw_label_count = match_suffix
        .map(|(index, _)| index)
        .unwrap_or_else(|| name.label_count());

    for index in 0..raw_label_count {
        let (label_len, label, suffix) = name.wire_label_meta_at(index);

        let out_len = out.len();
        if out_len < 0x4000 {
            compression.insert_suffix(suffix, out_len as u16);
        }
        out.push(label_len);
        out.extend_from_slice(label);
    }

    if let Some((_, ptr)) = match_suffix {
        push_u16(out, 0xC000 | ptr);
    } else {
        out.push(0);
    }

    Ok(())
}

/// Encode a resource record with owner name, header fields, and typed RDATA.
fn encode_record<'a>(
    out: &mut Vec<u8>,
    record: &'a Record,
    compression: &mut CompressionState<'a>,
) -> Result<()> {
    encode_name(out, record.name(), compression)?;
    push_u16(out, u16::from(record.rr_type()));
    push_u16(out, u16::from(record.class()));
    push_u32(out, record.ttl());

    let rdlen_pos = out.len();
    out.push(0);
    out.push(0);
    let rdata_start = out.len();
    {
        let mut write_name = |out: &mut Vec<u8>, name: &'a Name, compress_current: bool| {
            if compress_current {
                encode_name(out, name, compression)
            } else {
                encode_name_no_compress(out, name, compression)
            }
        };
        encode_rdata(record.data(), out, &mut write_name)?;
    }

    let rdlen = out.len() - rdata_start;
    let rdlen =
        u16::try_from(rdlen).map_err(|_| DnsError::protocol("dns rdata exceeds u16 length"))?;
    set_u16(out, rdlen_pos, rdlen);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::proto::*;

    fn roundtrip_with_answer(data: RData, answer_name: &str) -> Record {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii(answer_name).expect("valid fixture name"),
            RecordType::A,
            DNSClass::IN,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii(answer_name).expect("valid fixture name"),
            300,
            data,
        ));

        let encoded = message.to_bytes().expect("message should encode");
        let decoded = Message::from_bytes(&encoded).expect("message should decode");
        decoded.answers()[0].clone()
    }

    fn roundtrip_rdata(data: RData) -> RData {
        let owner = if matches!(data, RData::OPT(_)) {
            Name::root()
        } else {
            Name::from_ascii("owner.example.com.").unwrap()
        };
        let rr_type = data.rr_type();
        let class = match &data {
            RData::OPT(opt) => opt.0.udp_payload_size(),
            _ => u16::from(DNSClass::IN),
        };
        let ttl = match &data {
            RData::OPT(opt) => opt.0.raw_ttl(),
            _ => 300,
        };

        let mut wire = Vec::new();
        let mut write_name = |out: &mut Vec<u8>, name: &Name, _compress_current: bool| {
            out.extend_from_slice(name.wire());
            Ok(())
        };
        encode_rdata(&data, &mut wire, &mut write_name).expect("rdata should encode");
        parse_rdata(&wire, &owner, rr_type, class, ttl, 0, wire.len()).expect("rdata should decode")
    }

    #[test]
    fn question_record_and_message_roundtrip_bytes() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_opcode(Opcode::Notify);
        message.set_authoritative(true);
        message.set_recursion_desired(true);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A::new(1, 2, 3, 4)),
        ));

        let encoded = message.to_bytes().unwrap();
        let decoded = Message::from_bytes(&encoded).unwrap();
        let reencoded = decoded.to_bytes().unwrap();

        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn header_helpers_roundtrip_flags_and_counts() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_opcode(Opcode::Notify);
        message.set_authoritative(true);
        message.set_truncated(true);
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_authentic_data(true);
        message.set_checking_disabled(true);
        message.set_rcode(Rcode::NXDomain);

        let mut buf = vec![0u8; DNS_HEADER_LEN];
        set_header(&mut buf, &message, 0x1234, true, 2, 3, 4).unwrap();
        let (header, offset, low_rcode, qd, an, ns, ar) = parse_header(&buf).unwrap();

        assert_eq!(offset, DNS_HEADER_LEN);
        assert_eq!(header.id(), 0x1234);
        assert_eq!(header.message_type(), MessageType::Response);
        assert_eq!(header.opcode(), Opcode::Notify);
        assert!(header.authoritative());
        assert!(header.truncated());
        assert!(header.recursion_desired());
        assert!(header.recursion_available());
        assert!(header.authentic_data());
        assert!(header.checking_disabled());
        assert_eq!(low_rcode, u16::from(Rcode::NXDomain));
        assert_eq!((qd, an, ns, ar), (0, 2, 3, 4));
    }

    #[test]
    fn prepare_output_buffer_append_reserves_header_slot() {
        let mut out = vec![1, 2, 3];
        let start = prepare_output_buffer_append(&mut out);
        assert_eq!(start, 3);
        assert_eq!(out.len(), 3 + DNS_HEADER_LEN);
        assert_eq!(&out[..3], &[1, 2, 3]);
        assert_eq!(&out[3..], &[0; DNS_HEADER_LEN]);
    }

    #[test]
    fn message_roundtrip_matrix_covers_common_layouts() {
        let mut query = Message::new();
        query.set_id(0x1001);
        query.set_recursion_desired(true);
        query.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        let mut response = query.response(Rcode::NoError);
        response.set_authoritative(true);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A::new(1, 2, 3, 4)),
        ));

        let mut response_with_edns = response.clone();
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1400);
        edns.set_dnssec_ok(true);
        edns.insert(EdnsOption::Local(EdnsLocal::new(65001, vec![1, 2, 3])));
        response_with_edns.set_edns(edns);

        let mut compressed = response_with_edns.clone();
        compressed.set_compress(true);
        compressed.add_additional(Record::from_rdata(
            Name::from_ascii("ns1.example.com.").unwrap(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));

        let mut signed = response.clone();
        signed.signature_mut().push(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            0,
            RData::SIG(SIG(RRSIG {
                type_covered: u16::from(RecordType::A),
                algorithm: 8,
                labels: 2,
                orig_ttl: 300,
                expiration: 400,
                inception: 200,
                key_tag: 1234,
                signer_name: Name::from_ascii("sig.example.com.").unwrap(),
                signature: vec![1, 2, 3].into_boxed_slice(),
            })),
        ));

        let cases = vec![query, response, response_with_edns, compressed, signed];
        for message in cases {
            let encoded = message.to_bytes().unwrap();
            let decoded = Message::from_bytes(&encoded).unwrap();
            let reencoded = decoded.to_bytes().unwrap();
            if message.compress() {
                let decoded_reencoded = Message::from_bytes(&reencoded).unwrap();
                assert_eq!(
                    decoded_reencoded, decoded,
                    "compressed message semantic mismatch"
                );
            } else {
                assert_eq!(reencoded, encoded, "message roundtrip mismatch");
            }
        }
    }

    #[test]
    fn decode_message_rejects_invalid_wire_matrix() {
        let cases: &[(&str, &[u8])] = &[
            ("short header", &[0u8; 11]),
            (
                "trailing garbage",
                &[
                    0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7,
                    b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
                    0xFF,
                ],
            ),
            (
                "duplicate opt",
                &[
                    0x12, 0x34, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0, 0,
                    0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0x29, 0x04, 0xD0,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            (
                "opt owner not root",
                &[
                    0x12, 0x34, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 7,
                    b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 0x29,
                    0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
        ];

        for (name, packet) in cases {
            assert!(Message::from_bytes(packet).is_err(), "{name} should fail");
        }
    }

    #[test]
    fn decode_message_rejects_invalid_additional_order_matrix() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "sig0 not final",
                vec![
                    0x12, 0x34, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0, 0,
                    0x18, 0x00, 0x01, 0, 0, 0, 0, 0, 4, 0, 1, 8, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
                    1, b'a', 0, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            (
                "tsig not final",
                vec![
                    0x12, 0x34, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 1,
                    b'a', 0, 0x00, 0xFA, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 1, b'a',
                    0, 0, 0, 0, 0, 0, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            (
                "duplicate opt",
                vec![
                    0x12, 0x34, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0, 0,
                    0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0x29, 0x04, 0xD0,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
        ];

        for (name, packet) in cases {
            assert!(Message::from_bytes(&packet).is_err(), "{name} should fail");
        }
    }

    #[test]
    fn bounded_section_capacity_is_limited_by_remaining_packet_len() {
        assert_eq!(
            bounded_section_capacity(0, u16::MAX, MIN_QUESTION_WIRE_LEN),
            0
        );
        assert_eq!(
            bounded_section_capacity(12, u16::MAX, MIN_RECORD_WIRE_LEN),
            1
        );
        assert_eq!(
            bounded_section_capacity(4, u16::MAX, MIN_QUESTION_WIRE_LEN),
            0
        );
    }

    #[test]
    fn srv_rdata_roundtrip() {
        let answer = roundtrip_with_answer(
            RData::SRV(SRV::new(
                1,
                2,
                853,
                Name::from_ascii("resolver.example.com.").unwrap(),
            )),
            "_dns._tcp.example.com.",
        );

        match answer.data() {
            RData::SRV(value) => {
                assert_eq!(value.priority(), 1);
                assert_eq!(value.weight(), 2);
                assert_eq!(value.port(), 853);
                assert_eq!(value.target().to_fqdn(), "resolver.example.com.");
            }
            other => panic!("expected SRV answer, got: {other:?}"),
        }
    }

    #[test]
    fn naptr_rdata_roundtrip() {
        let answer = roundtrip_with_answer(
            RData::NAPTR(NAPTR::new(
                10,
                20,
                b"U".to_vec().into_boxed_slice(),
                b"E2U+sip".to_vec().into_boxed_slice(),
                b"!^.*$!sip:info@example.com!".to_vec().into_boxed_slice(),
                Name::from_ascii("replacement.example.com.").unwrap(),
            )),
            "example.com.",
        );

        match answer.data() {
            RData::NAPTR(value) => {
                assert_eq!(value.order(), 10);
                assert_eq!(value.preference(), 20);
                assert_eq!(value.flags(), b"U");
                assert_eq!(value.services(), b"E2U+sip");
                assert_eq!(value.regexp(), b"!^.*$!sip:info@example.com!");
                assert_eq!(value.replacement().to_fqdn(), "replacement.example.com.");
            }
            other => panic!("expected NAPTR answer, got: {other:?}"),
        }
    }

    #[test]
    fn caa_rdata_roundtrip() {
        let answer = roundtrip_with_answer(
            RData::CAA(CAA::new(
                128,
                b"issue".to_vec().into_boxed_slice(),
                b"letsencrypt.org".to_vec().into_boxed_slice(),
            )),
            "example.com.",
        );

        match answer.data() {
            RData::CAA(value) => {
                assert_eq!(value.flag(), 128);
                assert_eq!(value.tag(), b"issue");
                assert_eq!(value.value(), b"letsencrypt.org");
            }
            other => panic!("expected CAA answer, got: {other:?}"),
        }
    }

    #[test]
    fn tlsa_rdata_roundtrip() {
        let answer = roundtrip_with_answer(
            RData::TLSA(TLSA::new(
                3,
                1,
                1,
                vec![0xDE, 0xAD, 0xBE, 0xEF].into_boxed_slice(),
            )),
            "_853._tcp.example.com.",
        );

        match answer.data() {
            RData::TLSA(value) => {
                assert_eq!(value.usage(), 3);
                assert_eq!(value.selector(), 1);
                assert_eq!(value.matching_type(), 1);
                assert_eq!(value.certificate(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("expected TLSA answer, got: {other:?}"),
        }
    }

    #[test]
    fn svcb_rdata_roundtrip() {
        let answer = roundtrip_with_answer(
            RData::SVCB(SVCB::new(
                1,
                Name::from_ascii("svc.example.com.").unwrap(),
                vec![
                    SvcParam::new(3, 8443u16.to_be_bytes().to_vec().into_boxed_slice()),
                    SvcParam::new(1, b"/dns-query".to_vec().into_boxed_slice()),
                ],
            )),
            "_dns.example.com.",
        );

        match answer.data() {
            RData::SVCB(value) => {
                assert_eq!(value.priority(), 1);
                assert_eq!(value.target().to_fqdn(), "svc.example.com.");
                assert_eq!(value.params().len(), 2);
                assert_eq!(value.params()[0].key(), 1);
                assert_eq!(value.params()[0].value(), b"/dns-query");
                assert_eq!(value.params()[1].key(), 3);
                assert_eq!(value.params()[1].value(), &8443u16.to_be_bytes());
            }
            other => panic!("expected SVCB answer, got: {other:?}"),
        }
    }

    #[test]
    fn loc_rdata_roundtrip() {
        let answer = roundtrip_with_answer(
            RData::LOC(LOC::new(
                0,
                0x12,
                0x13,
                0x14,
                0x8123_4567,
                0x8456_7890,
                10_000_123,
            )),
            "example.com.",
        );

        match answer.data() {
            RData::LOC(value) => {
                assert_eq!(value.version(), 0);
                assert_eq!(value.size(), 0x12);
                assert_eq!(value.horiz_pre(), 0x13);
                assert_eq!(value.vert_pre(), 0x14);
                assert_eq!(value.latitude(), 0x8123_4567);
                assert_eq!(value.longitude(), 0x8456_7890);
                assert_eq!(value.altitude(), 10_000_123);
            }
            other => panic!("expected LOC answer, got: {other:?}"),
        }
    }

    #[test]
    fn rdata_roundtrip_matrix_covers_supported_variants() {
        let name = |value: &str| Name::from_ascii(value).unwrap();
        let txt_wire = |value: &[u8]| {
            let mut out = Vec::with_capacity(value.len() + 1);
            out.push(value.len() as u8);
            out.extend_from_slice(value);
            out.into_boxed_slice()
        };

        let mut opt = Edns::new();
        opt.set_udp_payload_size(1400);
        opt.set_ext_rcode(1);
        opt.set_dnssec_ok(true);
        opt.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)),
            24,
            0,
        )));
        opt.insert(EdnsOption::Local(EdnsLocal::new(65001, vec![1, 2, 3])));

        let cases = vec![
            RData::A(A::new(1, 2, 3, 4)),
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            RData::CNAME(CNAME(name("alias.example.com."))),
            RData::NS(NS(name("ns1.example.com."))),
            RData::PTR(PTR(name("ptr.example.com."))),
            RData::MD(MD(name("md.example.com."))),
            RData::MF(MF(name("mf.example.com."))),
            RData::MB(MB(name("mb.example.com."))),
            RData::MG(MG(name("mg.example.com."))),
            RData::MR(MR(name("mr.example.com."))),
            RData::MX(MX::new(10, name("mx.example.com."))),
            RData::SRV(SRV::new(1, 2, 443, name("srv.example.com."))),
            RData::NAPTR(NAPTR::new(
                10,
                20,
                b"U".to_vec().into_boxed_slice(),
                b"E2U+sip".to_vec().into_boxed_slice(),
                b"!^.*$!sip:info@example.com!".to_vec().into_boxed_slice(),
                name("replace.example.com."),
            )),
            RData::CAA(CAA::new(
                0,
                b"issue".to_vec().into_boxed_slice(),
                b"letsencrypt.org".to_vec().into_boxed_slice(),
            )),
            RData::TXT(TXT::new(txt_wire(b"hello"))),
            RData::SPF(SPF(TXT::new(txt_wire(b"v=spf1 -all")))),
            RData::AVC(AVC(TXT::new(txt_wire(b"avc")))),
            RData::RESINFO(RESINFO(TXT::new(txt_wire(b"resinfo")))),
            RData::DOA(DOA(vec![0xDE, 0xAD].into_boxed_slice())),
            RData::SOA(SOA::new(
                name("ns.example.com."),
                name("hostmaster.example.com."),
                1,
                2,
                3,
                4,
                5,
            )),
            RData::OPT(OPT(opt)),
            RData::SIG(SIG(RRSIG {
                type_covered: u16::from(RecordType::A),
                algorithm: 8,
                labels: 2,
                orig_ttl: 300,
                expiration: 400,
                inception: 200,
                key_tag: 1234,
                signer_name: name("sig.example.com."),
                signature: vec![1, 2, 3].into_boxed_slice(),
            })),
            RData::KEY(KEY(DNSKEY::new(
                256,
                3,
                8,
                vec![1, 2, 3].into_boxed_slice(),
            ))),
            RData::DS(DS::new(1234, 8, 2, vec![1, 2, 3, 4].into_boxed_slice())),
            RData::SSHFP(SSHFP::new(1, 1, vec![1, 2, 3].into_boxed_slice())),
            RData::CERT(CERT::new(1, 1234, 8, vec![1, 2, 3].into_boxed_slice())),
            RData::SIG(SIG(RRSIG {
                type_covered: u16::from(RecordType::AAAA),
                algorithm: 8,
                labels: 2,
                orig_ttl: 600,
                expiration: 700,
                inception: 500,
                key_tag: 4321,
                signer_name: name("rrsig.example.com."),
                signature: vec![9, 8, 7].into_boxed_slice(),
            })),
            RData::NSEC(NSEC::new(
                name("next.example.com."),
                TypeBitMaps::from_types(vec![RecordType::A, RecordType::AAAA]),
            )),
            RData::DNSKEY(DNSKEY::new(257, 3, 8, vec![4, 5, 6].into_boxed_slice())),
            RData::DHCID(DHCID(vec![1, 2, 3].into_boxed_slice())),
            RData::NSEC3(NSEC3::new(
                1,
                0,
                10,
                vec![0xAA, 0xBB].into_boxed_slice(),
                vec![0x01, 0x02].into_boxed_slice(),
                TypeBitMaps::from_types(vec![RecordType::MX]),
            )),
            RData::NSEC3PARAM(NSEC3PARAM::new(1, 0, 10, vec![0xAA].into_boxed_slice())),
            RData::TLSA(TLSA::new(3, 1, 1, vec![1, 2, 3].into_boxed_slice())),
            RData::SMIMEA(SMIMEA(TLSA::new(3, 1, 1, vec![4, 5, 6].into_boxed_slice()))),
            RData::HIP(HIP::new(
                vec![1, 2, 3, 4].into_boxed_slice(),
                1,
                vec![5, 6, 7].into_boxed_slice(),
                vec![name("rv.example.com.")],
            )),
            RData::NINFO(NINFO(vec![1, 2].into_boxed_slice())),
            RData::RKEY(RKEY(vec![3, 4].into_boxed_slice())),
            RData::TALINK(TALINK::new(
                name("prev.example.com."),
                name("next.example.com."),
            )),
            RData::CDS(CDS(DS::new(22, 8, 2, vec![1, 2].into_boxed_slice()))),
            RData::CDNSKEY(CDNSKEY(DNSKEY::new(
                257,
                3,
                8,
                vec![8, 9].into_boxed_slice(),
            ))),
            RData::OPENPGPKEY(OPENPGPKEY(vec![0xAA, 0xBB].into_boxed_slice())),
            RData::CSYNC(CSYNC::new(
                9,
                1,
                TypeBitMaps::from_types(vec![RecordType::NS]),
            )),
            RData::ZONEMD(ZONEMD::new(1, 1, 1, vec![1, 2, 3].into_boxed_slice())),
            RData::TKEY(TKEY::new(
                name("gss-tsig."),
                1,
                2,
                3,
                4,
                vec![5, 6].into_boxed_slice(),
                vec![7, 8].into_boxed_slice(),
            )),
            RData::TSIG(TSIG::new(
                name("hmac-sha256."),
                0x010203040506,
                300,
                vec![1, 2, 3].into_boxed_slice(),
                1234,
                0,
                vec![4, 5].into_boxed_slice(),
            )),
            RData::TA(TA(DS::new(11, 8, 2, vec![6, 7].into_boxed_slice()))),
            RData::DLV(DLV(DS::new(12, 8, 2, vec![8, 9].into_boxed_slice()))),
            RData::KX(KX::new(10, name("kx.example.com."))),
            RData::IPSECKEY(IPSECKEY::new(
                10,
                1,
                2,
                Ipv4Addr::new(1, 1, 1, 1)
                    .octets()
                    .to_vec()
                    .into_boxed_slice(),
                vec![9, 9].into_boxed_slice(),
            )),
            RData::SVCB(SVCB::new(
                1,
                name("svc.example.com."),
                vec![
                    SvcParam::new(1, b"h2".to_vec().into_boxed_slice()),
                    SvcParam::new(3, 443u16.to_be_bytes().to_vec().into_boxed_slice()),
                ],
            )),
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                name("https.example.com."),
                vec![SvcParam::new(
                    3,
                    8443u16.to_be_bytes().to_vec().into_boxed_slice(),
                )],
            ))),
            RData::AMTRELAY(AMTRELAY::new(
                1,
                1,
                Ipv4Addr::new(10, 0, 0, 1)
                    .octets()
                    .to_vec()
                    .into_boxed_slice(),
            )),
            RData::URI(URI::new(
                1,
                2,
                b"https://example.com".to_vec().into_boxed_slice(),
            )),
            RData::NID(NID::new(1, 0x0102_0304_0506_0708)),
            RData::L32(L32::new(1, Ipv4Addr::new(9, 9, 9, 9))),
            RData::L64(L64::new(1, 0x1112_1314_1516_1718)),
            RData::LP(LP::new(1, name("lp.example.com."))),
            RData::EUI48(EUI48(0x0011_2233_4455)),
            RData::EUI64(EUI64(0x0011_2233_4455_6677)),
            RData::NULL(NULL::new(vec![1, 2, 3].into_boxed_slice())),
            RData::HINFO(HINFO::new(
                b"x86_64".to_vec().into_boxed_slice(),
                b"linux".to_vec().into_boxed_slice(),
            )),
            RData::MINFO(MINFO::new(
                name("rmail.example.com."),
                name("email.example.com."),
            )),
            RData::RP(RP::new(name("mbox.example.com."), name("txt.example.com."))),
            RData::AFSDB(AFSDB::new(1, name("afsdb.example.com."))),
            RData::X25(X25::new(b"311061700956".to_vec().into_boxed_slice())),
            RData::WKS(WKS::new(
                Ipv4Addr::new(1, 2, 3, 4),
                6,
                vec![0b0001_0000].into_boxed_slice(),
            )),
            RData::NSAP(NSAP(vec![0x47, 0x00].into_boxed_slice())),
            RData::ISDN(ISDN::new(
                b"150862028003217".to_vec().into_boxed_slice(),
                Some(b"004".to_vec().into_boxed_slice()),
            )),
            RData::RT(RT::new(1, name("rt.example.com."))),
            RData::EID(EID(vec![1, 2].into_boxed_slice())),
            RData::NIMLOC(NIMLOC(vec![3, 4].into_boxed_slice())),
            RData::NSAPPTR(NSAPPTR(name("nsaptr.example.com."))),
            RData::PX(PX::new(
                1,
                name("map822.example.com."),
                name("mapx400.example.com."),
            )),
            RData::GPOS(GPOS::new(
                b"-0.001".to_vec().into_boxed_slice(),
                b"51.4778".to_vec().into_boxed_slice(),
                b"45.0".to_vec().into_boxed_slice(),
            )),
            RData::NXT(NXT(NSEC::new(
                name("nxt.example.com."),
                TypeBitMaps::from_types(vec![RecordType::A]),
            ))),
            RData::ATMA(ATMA(vec![0x47, 0x00, 0x10].into_boxed_slice())),
            RData::A6(A6::new(
                64,
                vec![0, 1, 2, 3, 4, 5, 6, 7].into_boxed_slice(),
                Some(name("prefix.example.com.")),
            )),
            RData::SINK(SINK::new(1, 2, vec![3, 4, 5].into_boxed_slice())),
            RData::DNAME(DNAME(name("target.example.com."))),
            RData::APL(APL::new(vec![AplPrefix::new(
                1,
                24,
                false,
                vec![192, 0, 2].into_boxed_slice(),
            )])),
            RData::UINFO(UINFO(b"user info".to_vec().into_boxed_slice())),
            RData::UID(UID(1000)),
            RData::GID(GID(1000)),
            RData::UNSPEC(UNSPEC(vec![0xAA, 0xBB].into_boxed_slice())),
            RData::ANAME(ANAME(name("aname.example.com."))),
            RData::IXFR(IXFR),
            RData::AXFR(AXFR),
            RData::MAILB(MAILB),
            RData::MAILA(MAILA),
            RData::ANY(ANY),
            RData::Unknown {
                rr_type: 65400,
                data: vec![9, 8, 7],
            },
        ];

        for case in cases {
            let decoded = roundtrip_rdata(case.clone());
            assert_eq!(decoded, case, "roundtrip mismatch for {:?}", case.rr_type());
        }
    }

    #[test]
    fn extended_rcode_requires_edns() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_rcode(Rcode::BADVERS);

        let err = message
            .to_bytes()
            .expect_err("rcode without edns must fail");
        assert!(err.to_string().contains("extended dns rcode requires edns"));
    }

    #[test]
    fn extended_rcode_is_encoded_via_edns() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_rcode(Rcode::BADVERS);
        message.set_edns(Edns::new());

        let encoded = message.to_bytes().expect("message should encode");
        let decoded = Message::from_bytes(&encoded).expect("message should decode");
        assert_eq!(decoded.rcode(), Rcode::BADVERS);
    }

    #[test]
    fn extended_rcode_survives_udp_truncation_with_opt_retained() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_rcode(Rcode::BADCOOKIE);
        message.add_question(Question::new(
            Name::from_ascii("large.example.com.").unwrap(),
            RecordType::TXT,
            DNSClass::IN,
        ));
        for index in 0..48 {
            message.add_answer(Record::from_rdata(
                Name::from_ascii("large.example.com.").unwrap(),
                60,
                RData::TXT(TXT::new(
                    std::iter::once(120u8)
                        .chain(std::iter::repeat_n(b'a' + (index as u8 % 26), 120))
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )),
            ));
        }

        let mut edns = Edns::new();
        edns.set_udp_payload_size(512);
        message.set_edns(edns);

        let encoded = message
            .to_bytes_with_limit(512)
            .expect("message should truncate and encode");
        let decoded = Message::from_bytes(&encoded).expect("message should decode");

        assert!(encoded.len() <= 512);
        assert!(decoded.truncated());
        assert!(decoded.edns().is_some());
        assert_eq!(decoded.rcode(), Rcode::BADCOOKIE);
    }

    #[test]
    fn limited_encode_trailer_disables_name_compression() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_compress(true);
        message.add_question(Question::new(
            Name::from_ascii("shared.example.com.").unwrap(),
            RecordType::TXT,
            DNSClass::IN,
        ));
        for index in 0..32 {
            message.add_answer(Record::from_rdata(
                Name::from_ascii("shared.example.com.").unwrap(),
                60,
                RData::TXT(TXT::new(
                    std::iter::once(80u8)
                        .chain(std::iter::repeat_n(b'a' + (index as u8 % 26), 80))
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )),
            ));
        }
        message.signature_mut().push(Record::from_rdata(
            Name::from_ascii("tail.shared.example.com.").unwrap(),
            0,
            RData::SIG(SIG(RRSIG {
                type_covered: u16::from(RecordType::TXT),
                algorithm: 8,
                labels: 2,
                orig_ttl: 300,
                expiration: 400,
                inception: 200,
                key_tag: 1234,
                signer_name: Name::from_ascii("sig.shared.example.com.").unwrap(),
                signature: vec![1, 2, 3, 4].into_boxed_slice(),
            })),
        ));

        let encoded = message
            .to_bytes_with_limit(512)
            .expect("message should encode within udp limit");

        let (_, mut offset, _, qdcount, ancount, nscount, arcount) =
            parse_header(&encoded).unwrap();
        assert_eq!(qdcount, 1);
        assert_eq!(arcount, 1);

        let (_, next) = Name::parse(&encoded, offset).unwrap();
        offset = next + 4;

        for _ in 0..ancount {
            let (_, rr_name_end) = Name::parse(&encoded, offset).unwrap();
            let rdlen = usize::from(read_u16_be(&encoded, rr_name_end + 2 + 2 + 4));
            offset = rr_name_end + 2 + 2 + 4 + 2 + rdlen;
        }
        for _ in 0..nscount {
            let (_, rr_name_end) = Name::parse(&encoded, offset).unwrap();
            let rdlen = usize::from(read_u16_be(&encoded, rr_name_end + 2 + 2 + 4));
            offset = rr_name_end + 2 + 2 + 4 + 2 + rdlen;
        }

        let owner_start = offset;
        let (_, owner_end) = Name::parse(&encoded, owner_start).unwrap();
        assert!(
            !encoded[owner_start..owner_end].contains(&0xC0),
            "signature owner name should not use compression pointers"
        );

        offset = owner_end;
        offset += 2; // type
        offset += 2; // class
        offset += 4; // ttl
        let rdlen = usize::from(read_u16_be(&encoded, offset));
        offset += 2;

        let signer_name_offset = offset + 2 + 1 + 1 + 4 + 4 + 4 + 2;
        let (_, signer_name_end) = Name::parse(&encoded, signer_name_offset).unwrap();
        assert!(
            signer_name_end <= offset + rdlen,
            "signer name must stay within the SIG RDATA"
        );
        assert!(
            !encoded[signer_name_offset..signer_name_end].contains(&0xC0),
            "signature signer name should not use compression pointers"
        );
    }

    #[test]
    fn limited_encode_rejects_trailer_larger_than_limit() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        message.set_edns(Edns::new());

        let err = message
            .to_bytes_with_limit(10)
            .expect_err("trailer larger than limit should fail");
        let text = err.to_string();
        assert!(
            text.contains("cannot fit within UDP payload while preserving EDNS/signature trailer"),
            "unexpected error: {text}"
        );
    }

    #[test]
    fn svcb_rejects_duplicate_keys() {
        let answer = Record::from_rdata(
            Name::from_ascii("_dns.example.com.").unwrap(),
            300,
            RData::SVCB(SVCB::new(
                1,
                Name::from_ascii("svc.example.com.").unwrap(),
                vec![
                    SvcParam::new(3, 8443u16.to_be_bytes().to_vec().into_boxed_slice()),
                    SvcParam::new(3, 443u16.to_be_bytes().to_vec().into_boxed_slice()),
                ],
            )),
        );
        let mut message = Message::new();
        message.add_answer(answer);

        let err = message
            .to_bytes()
            .expect_err("duplicate SVCB key must fail");
        assert!(err.to_string().contains("strictly increasing"));
    }

    #[test]
    fn svcb_rejects_unsorted_wire_keys() {
        let packet = [
            0x00, 0x01, // priority
            0x03, b's', b'v', b'c', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, // target
            0x00, 0x03, 0x00, 0x02, 0x20, 0xFB, // key 3
            0x00, 0x01, 0x00, 0x01, b'h', // key 1 after key 3 => invalid
        ];
        let err = parse_rdata(
            &packet,
            &Name::from_ascii("_dns.example.com.").unwrap(),
            RecordType::SVCB,
            u16::from(DNSClass::IN),
            300,
            0,
            packet.len(),
        )
        .expect_err("out-of-order SVCB keys must fail");
        assert!(err.to_string().contains("strictly increasing"));
    }

    #[test]
    fn nsec_rejects_invalid_type_bitmap() {
        let packet = [
            4, b'n', b'e', b'x', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0, // next domain
            0, 0, // window 0, invalid zero block length
        ];
        let err = parse_rdata(
            &packet,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::NSEC,
            u16::from(DNSClass::IN),
            300,
            0,
            packet.len(),
        )
        .expect_err("invalid bitmap must fail");
        assert!(err.to_string().contains("empty NSEC(3) block"));
    }

    #[test]
    fn csync_rejects_invalid_type_bitmap() {
        let packet = [
            0, 0, 0, 1, // serial
            0, 0, // flags
            0, 33, // window 0, invalid block length 33
        ];
        let err = parse_rdata(
            &packet,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::CSYNC,
            u16::from(DNSClass::IN),
            300,
            0,
            packet.len(),
        )
        .expect_err("invalid bitmap must fail");
        assert!(err.to_string().contains("block too long"));
    }
}
