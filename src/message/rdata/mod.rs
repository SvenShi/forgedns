/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned RDATA payloads and EDNS helpers.

use crate::message::RecordType;
use std::net::IpAddr;

mod basic;
mod dnssec;
mod legacy;
mod service;

pub use basic::*;
pub use dnssec::*;
pub use legacy::*;
pub use service::*;

/// Supported owned RDATA payloads.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RData {
    /// IPv4 address payload.
    A(A),
    /// IPv6 address payload.
    AAAA(AAAA),
    /// Canonical name target payload.
    CNAME(CNAME),
    /// Authoritative name server target payload.
    NS(NS),
    /// Mail destination payload.
    MD(MD),
    /// Mail forwarder payload.
    MF(MF),
    /// Reverse lookup target payload.
    PTR(PTR),
    /// Mailbox domain name payload.
    MB(MB),
    /// Mail group member payload.
    MG(MG),
    /// Mail rename payload.
    MR(MR),
    /// Null payload.
    NULL(NULL),
    /// Host information payload.
    HINFO(HINFO),
    /// Mailbox or mail list information payload.
    MINFO(MINFO),
    /// Mail exchanger payload.
    MX(MX),
    /// Responsible person payload.
    RP(RP),
    /// AFS database payload.
    AFSDB(AFSDB),
    /// X.25 address payload.
    X25(X25),
    /// Well-known services payload.
    WKS(WKS),
    /// NSAP payload.
    NSAP(NSAP),
    /// ISDN payload.
    ISDN(ISDN),
    /// Route through payload.
    RT(RT),
    /// Endpoint identifier payload.
    EID(EID),
    /// Nimrod locator payload.
    NIMLOC(NIMLOC),
    /// NSAP-PTR payload.
    NSAPPTR(NSAPPTR),
    /// SIG payload.
    SIG(SIG),
    /// KEY payload.
    KEY(KEY),
    /// PX payload.
    PX(PX),
    /// GPOS payload.
    GPOS(GPOS),
    /// LOC payload.
    LOC(LOC),
    /// NXT payload.
    NXT(NXT),
    /// Service locator payload.
    SRV(SRV),
    /// Naming authority pointer payload.
    NAPTR(NAPTR),
    /// KX payload.
    KX(KX),
    /// CERT payload.
    CERT(CERT),
    /// ATM address payload.
    ATMA(ATMA),
    /// A6 payload.
    A6(A6),
    /// Kitchen sink payload.
    SINK(SINK),
    /// DNAME payload.
    DNAME(DNAME),
    /// APL payload.
    APL(APL),
    /// DS payload.
    DS(DS),
    /// SSHFP payload.
    SSHFP(SSHFP),
    /// IPSECKEY payload.
    IPSECKEY(IPSECKEY),
    /// RRSIG payload.
    RRSIG(RRSIG),
    /// NSEC payload.
    NSEC(NSEC),
    /// DNSKEY payload.
    DNSKEY(DNSKEY),
    /// DHCID payload.
    DHCID(DHCID),
    /// NSEC3 payload.
    NSEC3(NSEC3),
    /// NSEC3PARAM payload.
    NSEC3PARAM(NSEC3PARAM),
    /// TLSA payload.
    TLSA(TLSA),
    /// SMIMEA payload.
    SMIMEA(SMIMEA),
    /// HIP payload.
    HIP(HIP),
    /// NINFO payload.
    NINFO(NINFO),
    /// RKEY payload.
    RKEY(RKEY),
    /// TALINK payload.
    TALINK(TALINK),
    /// CDS payload.
    CDS(CDS),
    /// CDNSKEY payload.
    CDNSKEY(CDNSKEY),
    /// OPENPGPKEY payload.
    OPENPGPKEY(OPENPGPKEY),
    /// CSYNC payload.
    CSYNC(CSYNC),
    /// ZONEMD payload.
    ZONEMD(ZONEMD),
    /// SVCB payload.
    SVCB(SVCB),
    /// HTTPS payload.
    HTTPS(HTTPS),
    /// SPF payload.
    SPF(SPF),
    /// UINFO payload.
    UINFO(UINFO),
    /// UID payload.
    UID(UID),
    /// GID payload.
    GID(GID),
    /// UNSPEC payload.
    UNSPEC(UNSPEC),
    /// NID payload.
    NID(NID),
    /// L32 payload.
    L32(L32),
    /// L64 payload.
    L64(L64),
    /// LP payload.
    LP(LP),
    /// EUI48 payload.
    EUI48(EUI48),
    /// EUI64 payload.
    EUI64(EUI64),
    /// ANAME payload.
    ANAME(ANAME),
    /// URI payload.
    URI(URI),
    /// Certification authority authorization payload.
    CAA(CAA),
    /// AVC payload.
    AVC(AVC),
    /// DOA payload.
    DOA(DOA),
    /// AMTRELAY payload.
    AMTRELAY(AMTRELAY),
    /// RESINFO payload.
    RESINFO(RESINFO),
    /// TKEY payload.
    TKEY(TKEY),
    /// TSIG payload.
    TSIG(TSIG),
    /// IXFR payload.
    IXFR(IXFR),
    /// AXFR payload.
    AXFR(AXFR),
    /// MAILB payload.
    MAILB(MAILB),
    /// MAILA payload.
    MAILA(MAILA),
    /// ANY payload.
    ANY(ANY),
    /// TA payload.
    TA(TA),
    /// DLV payload.
    DLV(DLV),
    /// Text record payload.
    TXT(TXT),
    /// Start of authority payload.
    SOA(SOA),
    /// EDNS OPT pseudo-record payload.
    OPT(OPT),
    /// Opaque payload for unsupported record types.
    Unknown { rr_type: u16, data: Vec<u8> },
}

impl RData {
    /// Return the RR type for this payload.
    pub fn rr_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::AAAA(_) => RecordType::AAAA,
            RData::CNAME(_) => RecordType::CNAME,
            RData::NS(_) => RecordType::NS,
            RData::MD(_) => RecordType::MD,
            RData::MF(_) => RecordType::MF,
            RData::PTR(_) => RecordType::PTR,
            RData::MB(_) => RecordType::MB,
            RData::MG(_) => RecordType::MG,
            RData::MR(_) => RecordType::MR,
            RData::NULL(_) => RecordType::NULL,
            RData::HINFO(_) => RecordType::HINFO,
            RData::MINFO(_) => RecordType::MINFO,
            RData::MX(_) => RecordType::MX,
            RData::RP(_) => RecordType::RP,
            RData::AFSDB(_) => RecordType::AFSDB,
            RData::X25(_) => RecordType::X25,
            RData::WKS(_) => RecordType::WKS,
            RData::NSAP(_) => RecordType::NSAP,
            RData::ISDN(_) => RecordType::ISDN,
            RData::RT(_) => RecordType::RT,
            RData::EID(_) => RecordType::EID,
            RData::NIMLOC(_) => RecordType::NIMLOC,
            RData::NSAPPTR(_) => RecordType::NSAPPTR,
            RData::SIG(_) => RecordType::SIG,
            RData::KEY(_) => RecordType::KEY,
            RData::PX(_) => RecordType::PX,
            RData::GPOS(_) => RecordType::GPOS,
            RData::LOC(_) => RecordType::LOC,
            RData::NXT(_) => RecordType::NXT,
            RData::SRV(_) => RecordType::SRV,
            RData::NAPTR(_) => RecordType::NAPTR,
            RData::KX(_) => RecordType::KX,
            RData::CERT(_) => RecordType::CERT,
            RData::ATMA(_) => RecordType::ATMA,
            RData::A6(_) => RecordType::A6,
            RData::SINK(_) => RecordType::SINK,
            RData::DNAME(_) => RecordType::DNAME,
            RData::APL(_) => RecordType::APL,
            RData::DS(_) => RecordType::DS,
            RData::SSHFP(_) => RecordType::SSHFP,
            RData::IPSECKEY(_) => RecordType::IPSECKEY,
            RData::RRSIG(_) => RecordType::RRSIG,
            RData::NSEC(_) => RecordType::NSEC,
            RData::DNSKEY(_) => RecordType::DNSKEY,
            RData::DHCID(_) => RecordType::DHCID,
            RData::NSEC3(_) => RecordType::NSEC3,
            RData::NSEC3PARAM(_) => RecordType::NSEC3PARAM,
            RData::TLSA(_) => RecordType::TLSA,
            RData::SMIMEA(_) => RecordType::SMIMEA,
            RData::HIP(_) => RecordType::HIP,
            RData::NINFO(_) => RecordType::NINFO,
            RData::RKEY(_) => RecordType::RKEY,
            RData::TALINK(_) => RecordType::TALINK,
            RData::CDS(_) => RecordType::CDS,
            RData::CDNSKEY(_) => RecordType::CDNSKEY,
            RData::OPENPGPKEY(_) => RecordType::OPENPGPKEY,
            RData::CSYNC(_) => RecordType::CSYNC,
            RData::ZONEMD(_) => RecordType::ZONEMD,
            RData::SVCB(_) => RecordType::SVCB,
            RData::HTTPS(_) => RecordType::HTTPS,
            RData::SPF(_) => RecordType::SPF,
            RData::UINFO(_) => RecordType::UINFO,
            RData::UID(_) => RecordType::UID,
            RData::GID(_) => RecordType::GID,
            RData::UNSPEC(_) => RecordType::UNSPEC,
            RData::NID(_) => RecordType::NID,
            RData::L32(_) => RecordType::L32,
            RData::L64(_) => RecordType::L64,
            RData::LP(_) => RecordType::LP,
            RData::EUI48(_) => RecordType::EUI48,
            RData::EUI64(_) => RecordType::EUI64,
            RData::ANAME(_) => RecordType::ANAME,
            RData::URI(_) => RecordType::URI,
            RData::CAA(_) => RecordType::CAA,
            RData::AVC(_) => RecordType::AVC,
            RData::DOA(_) => RecordType::DOA,
            RData::AMTRELAY(_) => RecordType::AMTRELAY,
            RData::RESINFO(_) => RecordType::RESINFO,
            RData::TKEY(_) => RecordType::TKEY,
            RData::TSIG(_) => RecordType::TSIG,
            RData::IXFR(_) => RecordType::IXFR,
            RData::AXFR(_) => RecordType::AXFR,
            RData::MAILB(_) => RecordType::MAILB,
            RData::MAILA(_) => RecordType::MAILA,
            RData::ANY(_) => RecordType::ANY,
            RData::TA(_) => RecordType::TA,
            RData::DLV(_) => RecordType::DLV,
            RData::TXT(_) => RecordType::TXT,
            RData::SOA(_) => RecordType::SOA,
            RData::OPT(_) => RecordType::OPT,
            RData::Unknown { rr_type, .. } => RecordType::Unknown(*rr_type),
        }
    }

    /// Extract an IP address from `A` and `AAAA` payloads.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self {
            RData::A(value) => Some(IpAddr::V4(value.0)),
            RData::AAAA(value) => Some(IpAddr::V6(value.0)),
            _ => None,
        }
    }

    /// Return encoded RDATA byte length at offset `off`.
    pub(crate) fn bytes_len<'a>(
        &'a self,
        compression: &mut crate::message::codec::LenCompressionMap<'a>,
    ) -> usize {
        match self {
            RData::A(_) => 4,
            RData::AAAA(_) => 16,
            RData::CNAME(value) => value.0.bytes_len_at(true, compression),
            RData::NS(value) => value.0.bytes_len_at(true, compression),
            RData::MD(value) => value.0.bytes_len_at(true, compression),
            RData::MF(value) => value.0.bytes_len_at(true, compression),
            RData::PTR(value) => value.0.bytes_len_at(true, compression),
            RData::MB(value) => value.0.bytes_len_at(true, compression),
            RData::MG(value) => value.0.bytes_len_at(true, compression),
            RData::MR(value) => value.0.bytes_len_at(true, compression),
            RData::NULL(value) => value.data().len(),
            RData::HINFO(value) => 1 + value.cpu().len() + 1 + value.os().len(),
            RData::MINFO(value) => {
                let rmail_len = value.rmail().bytes_len_at(true, compression);
                rmail_len + value.email().bytes_len_at(true, compression)
            }
            RData::MX(value) => 2 + value.exchange().bytes_len_at(true, compression),
            RData::RP(value) => {
                let mbox_len = value.mbox().bytes_len_at(false, compression);
                mbox_len + value.txt().bytes_len_at(false, compression)
            }
            RData::AFSDB(value) => 2 + value.hostname().bytes_len_at(false, compression),
            RData::X25(value) => 1 + value.psdn_address().len(),
            RData::WKS(value) => 5 + value.bitmap().len(),
            RData::NSAP(value) => value.0.len(),
            RData::ISDN(value) => {
                1 + value.address().len() + value.sub_address().map(|v| 1 + v.len()).unwrap_or(0)
            }
            RData::RT(value) => 2 + value.host().bytes_len_at(false, compression),
            RData::EID(value) => value.0.len(),
            RData::NIMLOC(value) => value.0.len(),
            RData::NSAPPTR(value) => value.0.bytes_len_at(false, compression),
            RData::SIG(value) => {
                18 + value.0.signer_name().bytes_len_at(false, compression)
                    + value.0.signature().len()
            }
            RData::KEY(value) => 4 + value.0.public_key().len(),
            RData::PX(value) => {
                let map822_len = value.map822().bytes_len_at(false, compression);
                2 + map822_len + value.mapx400().bytes_len_at(false, compression)
            }
            RData::GPOS(value) => {
                1 + value.longitude().len()
                    + 1
                    + value.latitude().len()
                    + 1
                    + value.altitude().len()
            }
            RData::LOC(_) => 16,
            RData::NXT(value) => {
                value.0.next_domain().bytes_len_at(false, compression) + value.0.type_bitmap().len()
            }
            RData::SRV(value) => 6 + value.target().bytes_len_at(false, compression),
            RData::NAPTR(value) => {
                let fixed_len = 2
                    + 2
                    + 1
                    + value.flags().len()
                    + 1
                    + value.services().len()
                    + 1
                    + value.regexp().len();
                fixed_len + value.replacement().bytes_len_at(false, compression)
            }
            RData::KX(value) => 2 + value.exchanger().bytes_len_at(false, compression),
            RData::CERT(value) => 5 + value.certificate().len(),
            RData::ATMA(value) => value.0.len(),
            RData::A6(value) => {
                let suffix_len = value.suffix().len();
                let prefix_len = value
                    .prefix_name()
                    .map(|name| name.bytes_len_at(true, compression))
                    .unwrap_or(0);
                1 + suffix_len + prefix_len
            }
            RData::SINK(value) => 2 + value.data().len(),
            RData::DNAME(value) => value.0.bytes_len_at(true, compression),
            RData::OPT(value) => value
                .options()
                .iter()
                .map(|opt| 4 + opt.payload_len())
                .sum(),
            RData::APL(value) => value
                .prefixes()
                .iter()
                .map(|p| 4 + p.afd_part().len())
                .sum(),
            RData::DS(value) => 4 + value.digest().len(),
            RData::SSHFP(value) => 2 + value.fingerprint().len(),
            RData::IPSECKEY(value) => 3 + value.gateway().len() + value.public_key().len(),
            RData::RRSIG(value) => {
                18 + value.signer_name().bytes_len_at(false, compression) + value.signature().len()
            }
            RData::NSEC(value) => {
                value.next_domain().bytes_len_at(false, compression) + value.type_bitmap().len()
            }
            RData::DNSKEY(value) => 4 + value.public_key().len(),
            RData::DHCID(value) => value.0.len(),
            RData::NSEC3(value) => {
                5 + value.salt().len() + 1 + value.next_domain().len() + value.type_bitmap().len()
            }
            RData::NSEC3PARAM(value) => 5 + value.salt().len(),
            RData::TLSA(value) => 3 + value.certificate().len(),
            RData::SMIMEA(value) => 3 + value.0.certificate().len(),
            RData::HIP(value) => {
                let mut len = 4 + value.hit().len() + value.public_key().len();
                for rendezvous in value.rendezvous_servers() {
                    let name_wire_len = rendezvous.bytes_len_at(false, compression);
                    len += name_wire_len;
                }
                len
            }
            RData::NINFO(value) => value.0.len(),
            RData::RKEY(value) => value.0.len(),
            RData::TALINK(value) => {
                let prev_len = value.previous_name().bytes_len_at(true, compression);
                prev_len + value.next_name().bytes_len_at(true, compression)
            }
            RData::CDS(value) => 4 + value.0.digest().len(),
            RData::CDNSKEY(value) => 4 + value.0.public_key().len(),
            RData::OPENPGPKEY(value) => value.0.len(),
            RData::CSYNC(value) => 6 + value.type_bitmap().len(),
            RData::ZONEMD(value) => 6 + value.digest().len(),
            RData::SVCB(value) => {
                2 + value.target().bytes_len_at(false, compression)
                    + value
                        .params()
                        .iter()
                        .map(|p| 4 + p.value().len())
                        .sum::<usize>()
            }
            RData::HTTPS(value) => {
                2 + value.0.target().bytes_len_at(false, compression)
                    + value
                        .0
                        .params()
                        .iter()
                        .map(|p| 4 + p.value().len())
                        .sum::<usize>()
            }
            RData::SPF(value) => value.0.wire_data().len(),
            RData::UINFO(value) => value.0.len(),
            RData::UID(_) => 4,
            RData::GID(_) => 4,
            RData::UNSPEC(value) => value.0.len(),
            RData::NID(_) => 10,
            RData::L32(_) => 6,
            RData::L64(_) => 10,
            RData::LP(value) => 2 + value.fqdn().bytes_len_at(false, compression),
            RData::EUI48(_) => 6,
            RData::EUI64(_) => 8,
            RData::ANAME(value) => value.0.bytes_len_at(true, compression),
            RData::URI(value) => 4 + value.target().len(),
            RData::CAA(value) => 2 + value.tag().len() + value.value().len(),
            RData::AVC(value) => value.0.wire_data().len(),
            RData::DOA(value) => value.0.len(),
            RData::AMTRELAY(value) => 2 + value.gateway().len(),
            RData::RESINFO(value) => value.0.wire_data().len(),
            RData::TKEY(value) => {
                value.algorithm().bytes_len_at(false, compression)
                    + 4
                    + 4
                    + 2
                    + 2
                    + 2
                    + value.key().len()
                    + 2
                    + value.other_data().len()
            }
            RData::TSIG(value) => {
                value.algorithm().bytes_len_at(false, compression)
                    + 6
                    + 2
                    + 2
                    + value.mac().len()
                    + 2
                    + 2
                    + 2
                    + value.other_data().len()
            }
            RData::IXFR(_) | RData::AXFR(_) | RData::MAILB(_) | RData::MAILA(_) | RData::ANY(_) => {
                0
            }
            RData::TA(value) => 4 + value.0.digest().len(),
            RData::DLV(value) => 4 + value.0.digest().len(),
            RData::TXT(value) => value.wire_data().len(),
            RData::SOA(value) => {
                let mname_len = value.mname().bytes_len_at(true, compression);
                mname_len + value.rname().bytes_len_at(true, compression) + 20
            }
            RData::Unknown { data, .. } => data.len(),
        }
    }
}
