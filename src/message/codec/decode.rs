/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Decode wire-format packets into the owned message model.

use crate::core::error::{DnsError, Result};
use crate::message::model::data::rdata::name::{CNAME, NS, PTR};
use crate::message::model::data::rdata::{A, AAAA, Edns, MX, OPT, SOA, TXT};
use crate::message::model::data::{DNSClass, Name, RData, Record, RecordType};
use crate::message::model::message::{MessageData, MessageHeaderData};
use crate::message::model::question::Question;
use crate::message::wire::edns::EdnsRef;
use crate::message::wire::flags::DNS_HEADER_LEN;
use crate::message::wire::header::Header;
use crate::message::wire::parser::{
    parse_mx_rdata_meta, parse_name_rdata_meta, parse_question_meta, parse_record_meta,
    parse_soa_rdata_fields, parse_txt_strings,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Fully decode a DNS packet into the owned message representation.
pub(crate) fn decode_owned(packet: &[u8]) -> Result<MessageData> {
    let header = Header::parse(packet)?;
    let mut message = MessageData::new();
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.qdcount() {
        let (question, next_offset) = parse_question_meta(packet, offset)?;
        message.questions.push(Question {
            name: Name::from_wire_ref(&question.name.as_name_ref(packet)),
            question_type: RecordType::from(question.qtype),
            question_class: DNSClass::from(question.qclass),
        });
        offset = next_offset;
    }

    let mut ext_rcode = 0u8;
    for _ in 0..header.ancount() {
        let (record, next_offset) = parse_record(packet, offset)?;
        message.answers.push(record);
        offset = next_offset;
    }
    for _ in 0..header.nscount() {
        let (record, next_offset) = parse_record(packet, offset)?;
        message.name_servers.push(record);
        offset = next_offset;
    }
    for _ in 0..header.arcount() {
        let (record, next_offset) = parse_record(packet, offset)?;
        if let RData::OPT(opt) = record.data() {
            ext_rcode = opt.ext_rcode();
        }
        message.additionals.push(record);
        offset = next_offset;
    }

    if offset != packet.len() {
        return Err(DnsError::protocol("dns packet has trailing bytes"));
    }

    message.header = MessageHeaderData::from_header(header, ext_rcode);
    Ok(message)
}

/// Parse one full resource record from `packet` starting at `offset`.
fn parse_record(packet: &[u8], offset: usize) -> Result<(Record, usize)> {
    let (record_meta, next_offset) = parse_record_meta(packet, offset)?;
    let record_type_enum = RecordType::from(record_meta.rr_type);
    let data = parse_rdata(
        packet,
        record_type_enum,
        record_meta.class,
        record_meta.ttl,
        record_meta.rdata_range.start as usize,
        record_meta.rdata_range.end as usize,
    )?;
    Ok((
        Record::from_rdata(
            Name::from_wire_ref(&record_meta.name.as_name_ref(packet)),
            record_meta.ttl,
            data,
        ),
        next_offset,
    ))
}

/// Parse type-specific RDATA bytes into the owned representation.
fn parse_rdata(
    packet: &[u8],
    record_type: RecordType,
    class: u16,
    ttl: u32,
    start: usize,
    end: usize,
) -> Result<RData> {
    match record_type {
        RecordType::A => {
            if end - start != 4 {
                return Err(DnsError::protocol("invalid A rdata length"));
            }
            Ok(RData::A(A(Ipv4Addr::new(
                packet[start],
                packet[start + 1],
                packet[start + 2],
                packet[start + 3],
            ))))
        }
        RecordType::AAAA => {
            if end - start != 16 {
                return Err(DnsError::protocol("invalid AAAA rdata length"));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&packet[start..end]);
            Ok(RData::AAAA(AAAA(Ipv6Addr::from(bytes))))
        }
        RecordType::CNAME => {
            let name = parse_name_rdata_meta(packet, start, end, "CNAME")?;
            Ok(RData::CNAME(CNAME(Name::from_wire_ref(
                &name.as_name_ref(packet),
            ))))
        }
        RecordType::NS => {
            let name = parse_name_rdata_meta(packet, start, end, "NS")?;
            Ok(RData::NS(NS(Name::from_wire_ref(
                &name.as_name_ref(packet),
            ))))
        }
        RecordType::PTR => {
            let name = parse_name_rdata_meta(packet, start, end, "PTR")?;
            Ok(RData::PTR(PTR(Name::from_wire_ref(
                &name.as_name_ref(packet),
            ))))
        }
        RecordType::MX => {
            let (preference, exchange) = parse_mx_rdata_meta(packet, start, end)?;
            Ok(RData::MX(MX::new(
                preference,
                Name::from_wire_ref(&exchange.as_name_ref(packet)),
            )))
        }
        RecordType::TXT => Ok(RData::TXT(TXT::new(parse_txt_strings(packet, start, end)?))),
        RecordType::SOA => {
            let soa = parse_soa_rdata_fields(packet, start, end)?;
            Ok(RData::SOA(SOA::new(
                Name::from_wire_ref(&soa.mname.as_name_ref(packet)),
                Name::from_wire_ref(&soa.rname.as_name_ref(packet)),
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum,
            )))
        }
        RecordType::OPT => Ok(RData::OPT(OPT(Edns::from_ref(&EdnsRef::new(
            class,
            (ttl >> 24) as u8,
            (ttl >> 16) as u8,
            ttl as u16,
            start as u16..end as u16,
            packet,
        ))))),
        RecordType::ANY | RecordType::Unknown(_) => Ok(RData::Unknown {
            record_type: u16::from(record_type),
            data: packet[start..end].to_vec(),
        }),
    }
}
