/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Borrowed resource-record views parsed directly from packet bytes.
//!
//! These views let hot-path code inspect RR owner names, types, TTLs, and
//! selected RDATA structures without materializing owned [`Record`] values.

use crate::core::error::{DnsError, Result};
use crate::message::model::data::{DNSClass, RecordType};
use crate::message::wire::constants::{
    TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_OPT, TYPE_PTR, TYPE_SOA, TYPE_TXT,
};
use crate::message::wire::edns::EdnsRef;
use crate::message::wire::name::NameRef;
use crate::message::wire::parser::{
    parse_mx_rdata_meta, parse_name_rdata_meta, parse_record_meta, parse_soa_rdata_fields,
    validate_txt_rdata,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

/// DNS RR sections exposed by [`ParsedMessage`] iterators.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecordSection {
    Answer,
    Authority,
    Additional,
}

/// Borrowed resource-record view backed by the original packet bytes.
#[derive(Debug, Clone)]
pub struct RecordView<'a> {
    packet: &'a [u8],
    wire_range: Range<u16>,
    name: NameRef<'a>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    ttl_offset: u16,
    rdata_range: Range<u16>,
    rdata: RDataView<'a>,
}

impl<'a> RecordView<'a> {
    #[inline]
    fn new(
        packet: &'a [u8],
        wire_range: Range<u16>,
        name: NameRef<'a>,
        rr_type: u16,
        class: u16,
        ttl: u32,
        ttl_offset: u16,
        rdata_range: Range<u16>,
        rdata: RDataView<'a>,
    ) -> Self {
        Self {
            packet,
            wire_range,
            name,
            rr_type,
            class,
            ttl,
            ttl_offset,
            rdata_range,
            rdata,
        }
    }

    #[inline]
    pub fn wire_range(&self) -> Range<u16> {
        self.wire_range.clone()
    }

    #[inline]
    pub fn wire_bytes(&self) -> &'a [u8] {
        &self.packet[self.wire_range.start as usize..self.wire_range.end as usize]
    }

    #[inline]
    pub fn name(&self) -> &NameRef<'a> {
        &self.name
    }

    #[inline]
    pub fn rr_type(&self) -> u16 {
        self.rr_type
    }

    #[inline]
    pub fn record_type(&self) -> RecordType {
        RecordType::from(self.rr_type)
    }

    #[inline]
    pub fn class(&self) -> u16 {
        self.class
    }

    #[inline]
    pub fn dns_class(&self) -> DNSClass {
        DNSClass::from(self.class)
    }

    #[inline]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    #[inline]
    pub fn ttl_offset(&self) -> usize {
        self.ttl_offset as usize
    }

    #[inline]
    pub fn rdata_range(&self) -> Range<u16> {
        self.rdata_range.clone()
    }

    #[inline]
    pub fn raw_rdata(&self) -> &'a [u8] {
        &self.packet[self.rdata_range.start as usize..self.rdata_range.end as usize]
    }

    #[inline]
    pub fn rdata(&self) -> &RDataView<'a> {
        &self.rdata
    }

    #[inline]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.rdata.ip_addr()
    }

    #[inline]
    pub fn cname_target(&self) -> Option<&NameRef<'a>> {
        match &self.rdata {
            RDataView::Cname(target) => Some(target),
            _ => None,
        }
    }

    #[inline]
    pub fn negative_ttl_from_soa(&self) -> Option<u32> {
        match &self.rdata {
            RDataView::Soa(soa) => Some(self.ttl.min(soa.minimum())),
            _ => None,
        }
    }
}

/// Borrowed RDATA view.
#[derive(Debug, Clone)]
pub enum RDataView<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(NameRef<'a>),
    Ns(NameRef<'a>),
    Ptr(NameRef<'a>),
    Mx(MxView<'a>),
    Txt(TxtView<'a>),
    Soa(SoaView<'a>),
    Opt(EdnsRef<'a>),
    Unknown { record_type: u16, data: &'a [u8] },
}

impl<'a> RDataView<'a> {
    #[inline]
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
            Self::Cname(_) => RecordType::CNAME,
            Self::Ns(_) => RecordType::NS,
            Self::Ptr(_) => RecordType::PTR,
            Self::Mx(_) => RecordType::MX,
            Self::Txt(_) => RecordType::TXT,
            Self::Soa(_) => RecordType::SOA,
            Self::Opt(_) => RecordType::OPT,
            Self::Unknown { record_type, .. } => RecordType::Unknown(*record_type),
        }
    }

    #[inline]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self {
            Self::A(addr) => Some(IpAddr::V4(*addr)),
            Self::Aaaa(addr) => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }
}

/// Borrowed MX RDATA.
#[derive(Debug, Clone)]
pub struct MxView<'a> {
    preference: u16,
    exchange: NameRef<'a>,
}

impl<'a> MxView<'a> {
    #[inline]
    pub fn preference(&self) -> u16 {
        self.preference
    }

    #[inline]
    pub fn exchange(&self) -> &NameRef<'a> {
        &self.exchange
    }
}

/// Borrowed TXT RDATA.
#[derive(Debug, Clone, Copy)]
pub struct TxtView<'a> {
    data: &'a [u8],
}

impl<'a> TxtView<'a> {
    #[inline]
    pub fn raw(&self) -> &'a [u8] {
        self.data
    }

    #[inline]
    pub fn chunks(&self) -> TxtChunksIter<'a> {
        TxtChunksIter {
            data: self.data,
            cursor: 0,
        }
    }
}

/// Borrowed SOA RDATA.
#[derive(Debug, Clone)]
pub struct SoaView<'a> {
    mname: NameRef<'a>,
    rname: NameRef<'a>,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl<'a> SoaView<'a> {
    #[inline]
    pub fn mname(&self) -> &NameRef<'a> {
        &self.mname
    }

    #[inline]
    pub fn rname(&self) -> &NameRef<'a> {
        &self.rname
    }

    #[inline]
    pub fn serial(&self) -> u32 {
        self.serial
    }

    #[inline]
    pub fn refresh(&self) -> i32 {
        self.refresh
    }

    #[inline]
    pub fn retry(&self) -> i32 {
        self.retry
    }

    #[inline]
    pub fn expire(&self) -> i32 {
        self.expire
    }

    #[inline]
    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}

/// Iterator over TXT character-string chunks.
pub struct TxtChunksIter<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> Iterator for TxtChunksIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.data.len() {
            return None;
        }

        let len = self.data[self.cursor] as usize;
        let start = self.cursor + 1;
        let end = start + len;
        if end > self.data.len() {
            self.cursor = self.data.len();
            return None;
        }

        self.cursor = end;
        Some(&self.data[start..end])
    }
}

/// Iterator over borrowed RR views in one DNS section.
pub struct RecordsIter<'a> {
    packet: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> RecordsIter<'a> {
    #[inline]
    pub(crate) fn new(packet: &'a [u8], offset: usize, remaining: u16) -> Self {
        Self {
            packet,
            offset,
            remaining,
        }
    }
}

impl<'a> Iterator for RecordsIter<'a> {
    type Item = Result<RecordView<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;
        match parse_record(self.packet, self.offset) {
            Ok((record, next_offset)) => {
                self.offset = next_offset;
                Some(Ok(record))
            }
            Err(err) => {
                self.remaining = 0;
                Some(Err(err))
            }
        }
    }
}

pub(crate) fn parse_record(packet: &[u8], offset: usize) -> Result<(RecordView<'_>, usize)> {
    let (record_meta, next_offset) = parse_record_meta(packet, offset)?;
    let rdata = parse_rdata(
        packet,
        record_meta.rr_type,
        record_meta.class,
        record_meta.ttl,
        record_meta.rdata_range.start as usize,
        record_meta.rdata_range.end as usize,
    )?;
    Ok((
        RecordView::new(
            packet,
            record_meta.wire_range.clone(),
            record_meta.name.as_name_ref(packet),
            record_meta.rr_type,
            record_meta.class,
            record_meta.ttl,
            record_meta.ttl_offset,
            record_meta.rdata_range.clone(),
            rdata,
        ),
        next_offset,
    ))
}

fn parse_rdata<'a>(
    packet: &'a [u8],
    rr_type: u16,
    class: u16,
    ttl: u32,
    start: usize,
    end: usize,
) -> Result<RDataView<'a>> {
    match rr_type {
        TYPE_A => {
            if end - start != 4 {
                return Err(DnsError::protocol("invalid A rdata length"));
            }
            Ok(RDataView::A(Ipv4Addr::new(
                packet[start],
                packet[start + 1],
                packet[start + 2],
                packet[start + 3],
            )))
        }
        TYPE_AAAA => {
            if end - start != 16 {
                return Err(DnsError::protocol("invalid AAAA rdata length"));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&packet[start..end]);
            Ok(RDataView::Aaaa(Ipv6Addr::from(bytes)))
        }
        TYPE_CNAME => Ok(RDataView::Cname(
            parse_name_rdata_meta(packet, start, end, "CNAME")?.as_name_ref(packet),
        )),
        TYPE_NS => Ok(RDataView::Ns(
            parse_name_rdata_meta(packet, start, end, "NS")?.as_name_ref(packet),
        )),
        TYPE_PTR => Ok(RDataView::Ptr(
            parse_name_rdata_meta(packet, start, end, "PTR")?.as_name_ref(packet),
        )),
        TYPE_MX => {
            let (preference, exchange) = parse_mx_rdata_meta(packet, start, end)?;
            Ok(RDataView::Mx(MxView {
                preference,
                exchange: exchange.as_name_ref(packet),
            }))
        }
        TYPE_TXT => {
            validate_txt_rdata(packet, start, end)?;
            Ok(RDataView::Txt(TxtView {
                data: &packet[start..end],
            }))
        }
        TYPE_SOA => {
            let soa = parse_soa_rdata_fields(packet, start, end)?;
            Ok(RDataView::Soa(SoaView {
                mname: soa.mname.as_name_ref(packet),
                rname: soa.rname.as_name_ref(packet),
                serial: soa.serial,
                refresh: soa.refresh,
                retry: soa.retry,
                expire: soa.expire,
                minimum: soa.minimum,
            }))
        }
        TYPE_OPT => Ok(RDataView::Opt(EdnsRef::new(
            class,
            (ttl >> 24) as u8,
            (ttl >> 16) as u8,
            ttl as u16,
            start as u16..end as u16,
            packet,
        ))),
        other => Ok(RDataView::Unknown {
            record_type: other,
            data: &packet[start..end],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::model::data::rdata::name::{CNAME, PTR};
    use crate::message::model::data::rdata::opt::{ClientSubnet, EdnsOption};
    use crate::message::model::data::rdata::{A, AAAA, Edns as OwnedEdns, MX, SOA, TXT};
    use crate::message::model::message::Message;
    use crate::message::model::{Name, Question, RData, Record};
    use crate::message::{Packet, RecordType};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_packet() -> Packet {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::new(1, 1, 1, 1)),
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("alias.example.com.").unwrap(),
            120,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("mx.example.com.").unwrap(),
            180,
            RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap())),
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("txt.example.com.").unwrap(),
            240,
            RData::TXT(TXT::new(vec!["hello".into(), "world".into()])),
        ));
        message.add_name_server(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                120,
                60,
                3600,
                45,
            )),
        ));
        message.add_additional(Record::from_rdata(
            Name::from_ascii("ns.example.com.").unwrap(),
            90,
            RData::AAAA(AAAA::new(Ipv6Addr::LOCALHOST)),
        ));
        message.add_additional(Record::from_rdata(
            Name::from_ascii("ptr.example.com.").unwrap(),
            90,
            RData::PTR(PTR(Name::from_ascii("target.example.com.").unwrap())),
        ));

        let mut edns = OwnedEdns::new();
        edns.set_udp_payload_size(1400);
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([192, 0, 2, 0]),
            24,
            0,
        )));
        message.set_edns(edns);

        Packet::from_vec(message.to_bytes().unwrap())
    }

    #[test]
    fn parsed_message_iterates_borrowed_record_views() {
        let packet = test_packet();
        let parsed = packet.parse().unwrap();

        let answers = parsed
            .answer_records()
            .collect::<Result<Vec<_>>>()
            .expect("answers should parse");
        assert_eq!(answers.len(), 4);
        assert_eq!(
            answers[0].ip_addr(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        assert_eq!(
            answers[1]
                .cname_target()
                .map(NameRef::normalized)
                .as_deref(),
            Some("target.example.com")
        );

        let RDataView::Mx(mx) = answers[2].rdata() else {
            panic!("expected MX record view");
        };
        assert_eq!(mx.preference(), 10);
        assert_eq!(mx.exchange().normalized(), "mail.example.com");

        let RDataView::Txt(txt) = answers[3].rdata() else {
            panic!("expected TXT record view");
        };
        assert_eq!(
            txt.chunks().collect::<Vec<_>>(),
            vec![b"hello".as_slice(), b"world".as_slice()]
        );
    }

    #[test]
    fn parsed_message_iterates_soa_ptr_and_opt_views() {
        let packet = test_packet();
        let parsed = packet.parse().unwrap();

        let authority = parsed
            .authority_records()
            .collect::<Result<Vec<_>>>()
            .expect("authority should parse");
        assert_eq!(authority.len(), 1);
        assert_eq!(authority[0].negative_ttl_from_soa(), Some(45));
        let RDataView::Soa(soa) = authority[0].rdata() else {
            panic!("expected SOA record view");
        };
        assert_eq!(soa.mname().normalized(), "ns1.example.com");
        assert_eq!(soa.rname().normalized(), "hostmaster.example.com");

        let additional = parsed
            .additional_records()
            .collect::<Result<Vec<_>>>()
            .expect("additional should parse");
        assert_eq!(additional.len(), 3);
        assert_eq!(
            additional[0].ip_addr(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        let RDataView::Ptr(target) = additional[1].rdata() else {
            panic!("expected PTR record view");
        };
        assert_eq!(target.normalized(), "target.example.com");
        let RDataView::Opt(edns) = additional[2].rdata() else {
            panic!("expected OPT record view");
        };
        assert_eq!(edns.udp_payload_size(), 1400);
        assert!(edns.client_subnet().is_some());
    }
}
