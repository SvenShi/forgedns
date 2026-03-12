/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use super::{
    Response, build_address_response_packet, build_response_message_from_request,
    build_response_packet, response_answer_any_ip, response_answer_ip_ttls, response_answer_ips,
    response_cnames, response_has_answer_type, response_ips, response_rcode, rewrite_response_ttls,
};
use crate::message::Packet;
use crate::message::model::data::rdata::{A, CNAME, Edns};
use crate::message::model::message::Message;
use crate::message::model::{Name, OpCode, Question, RData, Record, RecordType, ResponseCode};
use crate::message::wire::constants::TYPE_A;
use std::net::{IpAddr, Ipv4Addr};

#[test]
/// Verify synthetic response packets preserve the request ID, opcode, and question section.
fn build_response_packet_preserves_id_opcode_and_question() {
    let mut request = Message::new();
    request.set_id(7);
    request.set_op_code(OpCode::Update);
    request.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));

    let packet = Packet::from_vec(request.to_bytes().unwrap());
    let response = build_response_packet(&packet, u16::from(ResponseCode::Refused)).unwrap();
    let decoded = Message::from_bytes(response.as_slice()).unwrap();

    assert_eq!(decoded.id(), 7);
    assert_eq!(decoded.op_code(), OpCode::Update);
    assert_eq!(decoded.response_code(), ResponseCode::Refused);
    assert_eq!(decoded.questions().len(), 1);
}

#[test]
/// Verify synthetic responses preserve request EDNS state and extended RCODE bits.
fn build_response_packet_preserves_request_edns_and_extended_rcode() {
    let mut request = Message::new();
    request.set_id(21);
    request.set_recursion_desired(true);
    request.set_checking_disabled(true);
    request.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.set_udp_payload_size(1400);
    edns.flags_mut().dnssec_ok = true;
    request.set_edns(edns);

    let packet = Packet::from_vec(request.to_bytes().unwrap());
    let response = build_response_packet(&packet, u16::from(ResponseCode::BADVERS)).unwrap();
    let decoded = Message::from_packet(response).unwrap();

    assert_eq!(decoded.response_code(), ResponseCode::BADVERS);
    assert!(decoded.recursion_desired());
    assert!(decoded.checking_disabled());
    let edns = decoded.edns().expect("edns should exist");
    assert_eq!(edns.udp_payload_size(), 1400);
    assert!(edns.flags().dnssec_ok);
}

#[test]
/// Verify owned response builders preserve request identity and header semantics.
fn build_response_message_from_request_preserves_id_opcode_and_queries() {
    let mut request = Message::new();
    request.set_id(1234);
    request.set_op_code(OpCode::Update);
    request.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));

    let response = build_response_message_from_request(&request, ResponseCode::Refused);
    assert_eq!(response.id(), 1234);
    assert_eq!(response.questions().len(), 1);
    assert_eq!(response.response_code(), ResponseCode::Refused);
    assert_eq!(
        response.message_type(),
        crate::message::model::MessageType::Response
    );
}

#[test]
/// Verify synthetic address responses emit one answer per matching IP address.
fn build_address_response_packet_emits_a_answers() {
    let mut request = Message::new();
    request.set_id(7);
    request.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));

    let packet = Packet::from_vec(request.to_bytes().unwrap());
    let response = build_address_response_packet(
        &packet,
        300,
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ],
    )
    .unwrap();
    let decoded = Message::from_bytes(response.as_slice()).unwrap();

    assert_eq!(decoded.answers().len(), 2);
    assert_eq!(decoded.answers()[0].ttl(), 300);
}

#[test]
/// Exercise packet-level helpers that scan IPs, CNAMEs, and TTLs without full decode.
fn response_helpers_parse_ips_cnames_and_ttls() {
    let mut response = Message::new();
    response.set_id(7);
    response.set_response_code(ResponseCode::NoError);
    response.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    response.add_answer(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        RData::A(A::new(1, 1, 1, 1)),
    ));
    response.add_name_server(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        30,
        RData::CNAME(CNAME(Name::from_ascii("alias.example.com.").unwrap())),
    ));

    let packet = Packet::from_vec(response.to_bytes().unwrap());
    assert_eq!(
        response_rcode(&packet).unwrap(),
        u16::from(ResponseCode::NoError)
    );
    assert!(response_has_answer_type(&packet, &[TYPE_A]).unwrap());
    assert!(
        response_answer_any_ip(&packet, |ip| ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).unwrap()
    );
    assert_eq!(response_answer_ips(&packet).unwrap().len(), 1);
    assert_eq!(response_ips(&packet).unwrap().len(), 1);
    assert_eq!(response_answer_ip_ttls(&packet).unwrap()[0].1, 60);
    assert_eq!(response_cnames(&packet).unwrap()[0], "alias.example.com");

    let rewritten = rewrite_response_ttls(&packet, |_| 120).unwrap();
    let decoded = Message::from_bytes(rewritten.as_slice()).unwrap();
    assert_eq!(decoded.answers()[0].ttl(), 120);
    assert_eq!(decoded.name_servers()[0].ttl(), 120);
}

#[test]
/// Verify owned record helper methods expose IP and CNAME payloads.
fn owned_record_helpers_extract_ip_and_cname() {
    let a_record = Record::from_rdata(
        Name::from_ascii("a.example.").unwrap(),
        60,
        RData::A(A::new(1, 1, 1, 1)),
    );
    assert_eq!(
        a_record.ip_addr(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );

    let cname_record = Record::from_rdata(
        Name::from_ascii("www.example.").unwrap(),
        60,
        RData::CNAME(CNAME(Name::from_ascii("TARGET.EXAMPLE.").unwrap())),
    );
    assert_eq!(
        cname_record.cname_target().map(Name::normalized).as_deref(),
        Some("target.example")
    );
}

#[test]
/// Answer-only helpers must ignore matching records that appear only in additional data.
fn response_answer_helpers_ignore_additional_ip_records() {
    let mut response = Message::new();
    response.set_id(7);
    response.set_response_code(ResponseCode::NoError);
    response.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    response.add_additional(Record::from_rdata(
        Name::from_ascii("ns.example.com.").unwrap(),
        60,
        RData::A(A::new(8, 8, 8, 8)),
    ));

    let packet = Packet::from_vec(response.to_bytes().unwrap());

    assert_eq!(response_answer_ips(&packet).unwrap().len(), 0);
    assert!(
        !response_answer_any_ip(&packet, |ip| ip == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).unwrap()
    );
    assert_eq!(response_ips(&packet).unwrap().len(), 1);
}

#[test]
/// Early-exit answer matchers should stop scanning as soon as the first hit is found.
fn answer_ip_matcher_stops_after_first_match() {
    let mut response = Message::new();
    response.set_id(7);
    response.set_response_code(ResponseCode::NoError);
    response.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    response.add_answer(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        RData::A(A::new(1, 1, 1, 1)),
    ));
    response.add_answer(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        RData::A(A::new(8, 8, 8, 8)),
    ));

    let packet = Packet::from_vec(response.to_bytes().unwrap());
    let mut visits = 0usize;

    assert!(response_has_answer_type(&packet, &[TYPE_A]).unwrap());
    assert!(
        response_answer_any_ip(&packet, |ip| {
            visits += 1;
            ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        })
        .unwrap()
    );
    assert_eq!(visits, 1);
}

#[test]
/// Verify response object helpers reuse packet fast paths and owned fallbacks consistently.
fn response_value_helpers_match_packet_and_owned_views() {
    let mut message = Message::new();
    message.set_id(9);
    message.set_response_code(ResponseCode::NoError);
    message.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    message.add_answer(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        45,
        RData::A(A::new(1, 1, 1, 1)),
    ));
    message.add_name_server(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        30,
        RData::CNAME(CNAME(Name::from_ascii("alias.example.com.").unwrap())),
    ));

    let packet_response = Response::from_packet(Packet::from_vec(message.to_bytes().unwrap()));
    let owned_response = Response::from_message(message);

    assert_eq!(packet_response.response_code(), Some(ResponseCode::NoError));
    assert_eq!(owned_response.response_code(), Some(ResponseCode::NoError));
    assert_eq!(packet_response.answer_ips(), owned_response.answer_ips());
    assert_eq!(
        packet_response.answer_ip_ttls(),
        owned_response.answer_ip_ttls()
    );
    assert_eq!(packet_response.cnames(), owned_response.cnames());
    assert!(packet_response.has_answer_type(&[TYPE_A]));
    assert!(owned_response.has_answer_ip(|ip| ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
}
