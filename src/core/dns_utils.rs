/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared DNS-level helpers used across plugins and executors.
//!
//! These helpers sit just above the `message` package and intentionally prefer
//! packet-aware fast paths before falling back to owned-message traversal. They
//! are shared by matchers, executors, cache logic, and server glue.

use crate::core::context::DnsContext;
use crate::message::Edns;
use crate::message::{Message, MessageType, ResponseCode};
use crate::message::{RData, Record, RecordType};
use crate::message::{
    RejectResponsePlan, ResponsePlan, build_response_packet, response_answer_any_ip,
    response_answer_ip_ttls, response_answer_ips, response_cnames, response_has_answer_type,
    response_rcode,
};
use smallvec::SmallVec;
use std::net::IpAddr;

/// Parse symbolic DNS response code name.
///
/// # Examples
/// ```
/// use forgedns::core::dns_utils::parse_named_response_code;
/// use forgedns::message::ResponseCode;
///
/// assert_eq!(parse_named_response_code("SERVFAIL"), Some(ResponseCode::ServFail));
/// assert_eq!(parse_named_response_code("3"), Some(ResponseCode::NXDomain));
/// assert_eq!(parse_named_response_code("UNKNOWN"), None);
/// ```
pub fn parse_named_response_code(raw: &str) -> Option<ResponseCode> {
    if let Ok(code) = raw.parse::<u16>() {
        return Some(code.into());
    }

    match raw.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(ResponseCode::NoError),
        "FORMERR" => Some(ResponseCode::FormErr),
        "SERVFAIL" => Some(ResponseCode::ServFail),
        "NXDOMAIN" => Some(ResponseCode::NXDomain),
        "NOTIMP" => Some(ResponseCode::NotImp),
        "REFUSED" => Some(ResponseCode::Refused),
        "YXDOMAIN" => Some(ResponseCode::YXDomain),
        "YXRRSET" => Some(ResponseCode::YXRRSet),
        "NXRRSET" => Some(ResponseCode::NXRRSet),
        "NOTAUTH" => Some(ResponseCode::NotAuth),
        "NOTZONE" => Some(ResponseCode::NotZone),
        "BADVERS" => Some(ResponseCode::BADVERS),
        "BADSIG" => Some(ResponseCode::BADSIG),
        "BADKEY" => Some(ResponseCode::BADKEY),
        "BADTIME" => Some(ResponseCode::BADTIME),
        "BADMODE" => Some(ResponseCode::BADMODE),
        "BADNAME" => Some(ResponseCode::BADNAME),
        "BADALG" => Some(ResponseCode::BADALG),
        "BADTRUNC" => Some(ResponseCode::BADTRUNC),
        "BADCOOKIE" => Some(ResponseCode::BADCOOKIE),
        _ => None,
    }
}

/// Build a minimal DNS response from request, preserving id/opcode/query.
///
/// # Examples
/// ```
/// use forgedns::core::dns_utils::build_response_from_request;
/// use forgedns::message::{Message, MessageType, Question, ResponseCode};
/// use forgedns::message::{Name, RecordType};
///
/// let mut request = Message::new();
/// request.set_id(7);
/// request.add_question(Question::new(Name::from_ascii("example.com.").unwrap(), RecordType::A));
///
/// let response = build_response_from_request(&request, ResponseCode::Refused);
///
/// assert_eq!(response.id(), 7);
/// assert_eq!(response.message_type(), MessageType::Response);
/// assert_eq!(response.response_code(), ResponseCode::Refused);
/// assert_eq!(response.questions().len(), 1);
/// ```
pub fn build_response_from_request(request: &Message, rcode: ResponseCode) -> Message {
    if let Some(packet) = request.packet() {
        if let Ok(response) = build_response_packet(packet, u16::from(rcode)) {
            if let Ok(message) = Message::from_packet(response) {
                return message;
            }
        }
    }

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

#[inline]
/// Build a lazy response plan that can reuse packet bytes when possible.
pub fn build_response_plan_from_request(request: &Message, rcode: ResponseCode) -> ResponsePlan {
    RejectResponsePlan::new(request.clone(), rcode).into()
}

/// Iterate all records in answer/authority/additional sections.
pub fn response_records(message: &Message) -> impl Iterator<Item = &Record> {
    message
        .answers()
        .iter()
        .chain(message.name_servers().iter())
        .chain(message.additionals().iter())
}

/// Extract A/AAAA IP from a resource record.
pub fn rr_to_ip(record: &Record) -> Option<IpAddr> {
    match record.record_type() {
        RecordType::A => match record.data() {
            RData::A(v) => Some(IpAddr::V4(v.0)),
            _ => None,
        },
        RecordType::AAAA => match record.data() {
            RData::AAAA(v) => Some(IpAddr::V6(v.0)),
            _ => None,
        },
        _ => None,
    }
}

/// Extract normalized CNAME target from a resource record.
pub fn rr_to_cname(record: &Record) -> Option<String> {
    match record.data() {
        RData::CNAME(v) => Some(v.0.to_utf8().trim_end_matches('.').to_ascii_lowercase()),
        _ => None,
    }
}

#[inline]
/// Report whether the context already carries any response plan.
pub fn context_has_response(context: &DnsContext) -> bool {
    context.response.is_some()
}

/// Return the numeric response code carried by the context response, if any.
pub fn context_response_code(context: &DnsContext) -> Option<u16> {
    let response = context.response.as_ref()?;
    if let Some(rcode) = response.response_code_hint() {
        return Some(u16::from(rcode));
    }
    if let Some(packet) = response.packet() {
        return response_rcode(packet).ok();
    }
    response
        .message()
        .map(|message| u16::from(message.response_code()))
}

/// Collect all answer-section IPs from the current context response.
pub fn context_response_ips(context: &DnsContext) -> SmallVec<[IpAddr; 8]> {
    let Some(response) = context.response.as_ref() else {
        return SmallVec::new();
    };
    if let Some(packet) = response.packet() {
        return response_answer_ips(packet).unwrap_or_default();
    }
    response
        .message()
        .into_iter()
        .flat_map(|message| message.answers().iter())
        .filter_map(rr_to_ip)
        .collect()
}

/// Report whether any answer-section IP in the current response matches `pred`.
pub fn context_response_has_ip(context: &DnsContext, mut pred: impl FnMut(IpAddr) -> bool) -> bool {
    let Some(response) = context.response.as_ref() else {
        return false;
    };
    if let Some(packet) = response.packet() {
        return response_answer_any_ip(packet, pred).unwrap_or(false);
    }
    response
        .message()
        .into_iter()
        .flat_map(|message| message.answers().iter())
        .filter_map(rr_to_ip)
        .any(&mut pred)
}

/// Collect answer-section IPs together with their TTLs from the current response.
pub fn context_answer_ip_ttls(context: &DnsContext) -> SmallVec<[(IpAddr, u32); 8]> {
    let Some(response) = context.response.as_ref() else {
        return SmallVec::new();
    };
    if let Some(packet) = response.packet() {
        return response_answer_ip_ttls(packet).unwrap_or_default();
    }
    let mut out = SmallVec::<[(IpAddr, u32); 8]>::new();
    for record in response
        .message()
        .into_iter()
        .flat_map(|message| message.answers().iter())
    {
        if let Some(ip) = rr_to_ip(record) {
            out.push((ip, record.ttl()));
        }
    }
    out
}

/// Collect all CNAME targets from the current response.
pub fn context_response_cnames(context: &DnsContext) -> SmallVec<[String; 4]> {
    let Some(response) = context.response.as_ref() else {
        return SmallVec::new();
    };
    if let Some(packet) = response.packet() {
        return response_cnames(packet).unwrap_or_default();
    }
    response
        .message()
        .into_iter()
        .flat_map(response_records)
        .filter_map(rr_to_cname)
        .collect()
}

/// Report whether the current response contains any answer RR of a wanted type.
pub fn context_has_answer_type(context: &DnsContext, wanted: &[u16]) -> bool {
    let Some(response) = context.response.as_ref() else {
        return false;
    };
    if let Some(packet) = response.packet() {
        return response_has_answer_type(packet, wanted).unwrap_or(false);
    }
    response
        .message()
        .into_iter()
        .flat_map(|message| message.answers().iter())
        .any(|rr| wanted.contains(&u16::from(rr.record_type())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Question;
    use crate::message::rdata::{A, CNAME};
    use crate::message::{Name, RData};

    #[test]
    /// Verify named and numeric response-code parsing share the same lookup table.
    fn test_parse_named_response_code_supports_name_and_numeric() {
        assert_eq!(
            parse_named_response_code("NOERROR"),
            Some(ResponseCode::NoError)
        );
        assert_eq!(parse_named_response_code("2"), Some(ResponseCode::ServFail));
        assert_eq!(parse_named_response_code("UNKNOWN_CODE"), None);
    }

    #[test]
    /// Verify synthetic response builders preserve request identity and question section.
    fn test_build_response_from_request_preserves_id_opcode_and_queries() {
        let mut request = Message::new();
        request.set_id(1234);
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        let response = build_response_from_request(&request, ResponseCode::Refused);
        assert_eq!(response.id(), 1234);
        assert_eq!(response.questions().len(), 1);
        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert_eq!(response.message_type(), MessageType::Response);
    }

    #[test]
    /// Verify helper extractors normalize IP and CNAME payloads consistently.
    fn test_rr_extract_helpers() {
        let a_record = Record::from_rdata(
            Name::from_ascii("a.example.").unwrap(),
            60,
            RData::A(A::new(1, 1, 1, 1)),
        );
        assert_eq!(
            rr_to_ip(&a_record),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)))
        );

        let cname_record = Record::from_rdata(
            Name::from_ascii("www.example.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("TARGET.EXAMPLE.").unwrap())),
        );
        assert_eq!(
            rr_to_cname(&cname_record).as_deref(),
            Some("target.example")
        );
    }
}
