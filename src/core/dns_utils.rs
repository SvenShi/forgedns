/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared DNS-level helpers used across plugins and executors.

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::IpAddr;

/// Parse symbolic DNS response code name.
///
/// # Examples
/// ```
/// use forgedns::core::dns_utils::parse_named_response_code;
/// use hickory_proto::op::ResponseCode;
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
/// use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
/// use hickory_proto::rr::{Name, RecordType};
///
/// let mut request = Message::new();
/// request.set_id(7);
/// request.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
///
/// let response = build_response_from_request(&request, ResponseCode::Refused);
///
/// assert_eq!(response.id(), 7);
/// assert_eq!(response.message_type(), MessageType::Response);
/// assert_eq!(response.response_code(), ResponseCode::Refused);
/// assert_eq!(response.queries().len(), 1);
/// ```
pub fn build_response_from_request(request: &Message, rcode: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_op_code(request.op_code());
    response.set_message_type(MessageType::Response);
    response.set_response_code(rcode);
    *response.queries_mut() = request.queries().to_vec();
    response
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
            RData::A(v) => Some(IpAddr::V4(**v)),
            _ => None,
        },
        RecordType::AAAA => match record.data() {
            RData::AAAA(v) => Some(IpAddr::V6(**v)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData};

    #[test]
    fn test_parse_named_response_code_supports_name_and_numeric() {
        assert_eq!(
            parse_named_response_code("NOERROR"),
            Some(ResponseCode::NoError)
        );
        assert_eq!(parse_named_response_code("2"), Some(ResponseCode::ServFail));
        assert_eq!(parse_named_response_code("UNKNOWN_CODE"), None);
    }

    #[test]
    fn test_build_response_from_request_preserves_id_opcode_and_queries() {
        let mut request = Message::new();
        request.set_id(1234);
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        let response = build_response_from_request(&request, ResponseCode::Refused);
        assert_eq!(response.id(), 1234);
        assert_eq!(response.queries().len(), 1);
        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert_eq!(response.message_type(), MessageType::Response);
    }

    #[test]
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
