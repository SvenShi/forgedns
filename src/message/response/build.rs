/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Packet-level and owned-message response builders.

use crate::core::error::{DnsError, Result};
use crate::message::rdata::Edns;
use crate::message::wire::constants::{CLASS_IN, RCODE_NOERROR, TYPE_A, TYPE_AAAA, TYPE_OPT};
use crate::message::wire::flags::{DNS_HEADER_LEN, EDNS_FLAG_DO, FLAG_CD, FLAG_QR, FLAG_RD};
use crate::message::{Message, MessageType, Packet, ResponseCode};
use smallvec::SmallVec;
use std::net::IpAddr;

/// Build a minimal owned DNS response from a request, preserving id/opcode/query.
pub fn build_response_message_from_request(request: &Message, rcode: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_op_code(request.op_code());
    response.set_message_type(MessageType::Response);
    response.set_recursion_desired(request.recursion_desired());
    response.set_checking_disabled(request.checking_disabled());
    response.set_response_code(rcode);
    *response.questions_mut() = request.questions().to_vec();
    if let Some(request_edns) = request.edns_access() {
        let mut edns = Edns::new();
        edns.set_udp_payload_size(request_edns.udp_payload_size().max(512));
        edns.set_version(request_edns.version());
        edns.flags_mut().dnssec_ok = request_edns.dnssec_ok();
        edns.set_ext_rcode((u16::from(rcode) >> 4) as u8);
        response.set_edns(edns);
    } else if u16::from(rcode) > 0x0f {
        let mut edns = Edns::new();
        edns.set_ext_rcode((u16::from(rcode) >> 4) as u8);
        response.set_edns(edns);
    }
    response
}

/// Build a minimal DNS response packet by reusing the request question section.
///
/// The response preserves opcode, RD/CD bits, and EDNS parameters from the
/// request. When an extended RCODE is needed, an OPT record is emitted even if
/// the request did not carry one so the extra RCODE bits have a place on the
/// wire.
pub fn build_response_packet(request: &Packet, rcode: u16) -> Result<Packet> {
    let parsed = request.parse()?;
    let packet = request.as_slice();
    let question_end = parsed.sections().question_end as usize;
    let request_flags = parsed.header().flags();
    let request_edns = parsed.edns();
    let emit_opt = request_edns.is_some() || rcode > 0x0f;
    let response_flags =
        FLAG_QR | (request_flags & 0x7800) | (request_flags & (FLAG_RD | FLAG_CD)) | (rcode & 0x0f);

    let mut out = Vec::with_capacity(question_end + if emit_opt { 11 } else { 0 });
    out.extend_from_slice(&parsed.header().id().to_be_bytes());
    out.extend_from_slice(&response_flags.to_be_bytes());
    out.extend_from_slice(&parsed.header().qdcount().to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(emit_opt as u16).to_be_bytes());
    out.extend_from_slice(&packet[DNS_HEADER_LEN..question_end]);
    if let Some(edns) = request_edns {
        append_opt_record(
            &mut out,
            edns.udp_payload_size().max(512),
            (rcode >> 4) as u8,
            edns.version(),
            edns.flags() & EDNS_FLAG_DO,
        );
    } else if emit_opt {
        append_opt_record(&mut out, 1232, (rcode >> 4) as u8, 0, 0);
    }
    Ok(Packet::from_vec(out))
}

/// Build a synthetic `A`/`AAAA` response packet from one request packet.
///
/// Only addresses matching the first question type are emitted. If no address
/// matches, the helper falls back to an empty `NOERROR` response.
pub fn build_address_response_packet(
    request: &Packet,
    ttl: u32,
    addresses: &[IpAddr],
) -> Result<Packet> {
    let parsed = request.parse()?;
    if parsed.header().qdcount() != 1 {
        return Err(DnsError::protocol(
            "synthetic address response requires exactly one question",
        ));
    }

    let question = parsed
        .first_question()
        .ok_or_else(|| DnsError::protocol("dns question missing from request packet"))?;
    if question.qclass() != CLASS_IN {
        return Err(DnsError::protocol(
            "synthetic address response requires IN class question",
        ));
    }

    let mut filtered = SmallVec::<[IpAddr; 8]>::new();
    for &addr in addresses {
        match (question.qtype(), addr) {
            (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_)) => filtered.push(addr),
            _ => {}
        }
    }

    if filtered.is_empty() {
        return build_response_packet(request, u16::from(RCODE_NOERROR));
    }

    let packet = request.as_slice();
    let question_end = parsed.sections().question_end as usize;
    let response_flags = FLAG_QR
        | (parsed.header().flags() & 0x7800)
        | (parsed.header().flags() & (FLAG_RD | FLAG_CD));
    let answer_count = u16::try_from(filtered.len())
        .map_err(|_| DnsError::protocol("too many synthetic address answers"))?;
    let emit_opt = parsed.edns().is_some();

    let estimated_answer_len = match question.qtype() {
        TYPE_A => 16usize,
        TYPE_AAAA => 28usize,
        _ => {
            return Err(DnsError::protocol(
                "synthetic address response only supports A/AAAA questions",
            ));
        }
    };

    let mut out = Vec::with_capacity(question_end + filtered.len() * estimated_answer_len);
    out.extend_from_slice(&parsed.header().id().to_be_bytes());
    out.extend_from_slice(&response_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&answer_count.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(emit_opt as u16).to_be_bytes());
    out.extend_from_slice(&packet[DNS_HEADER_LEN..question_end]);

    for addr in filtered {
        // The first question name always starts at offset 12.
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&question.qtype().to_be_bytes());
        out.extend_from_slice(&question.qclass().to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        match addr {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }

    if let Some(edns) = parsed.edns() {
        append_opt_record(
            &mut out,
            edns.udp_payload_size().max(512),
            0,
            edns.version(),
            edns.flags() & EDNS_FLAG_DO,
        );
    }

    Ok(Packet::from_vec(out))
}

/// Append a minimal OPT pseudo-record to `out`.
fn append_opt_record(
    out: &mut Vec<u8>,
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    flags: u16,
) {
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&udp_payload_size.to_be_bytes());
    let ttl = (u32::from(ext_rcode) << 24) | (u32::from(version) << 16) | u32::from(flags);
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
}
