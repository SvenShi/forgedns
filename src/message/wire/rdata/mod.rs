/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! RDATA wire encoding and decoding helpers.

mod basic;
mod dnssec;
mod legacy;
mod service;

use crate::core::error::{DnsError, Result};
use crate::message::rdata::*;
use crate::message::{Name, RData, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[inline]
fn copy_boxed(packet: &[u8], start: usize, end: usize) -> Box<[u8]> {
    Box::<[u8]>::from(&packet[start..end])
}

#[inline]
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.push((value >> 8) as u8);
    out.push(value as u8);
}

#[inline]
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.push((value >> 24) as u8);
    out.push((value >> 16) as u8);
    out.push((value >> 8) as u8);
    out.push(value as u8);
}

/// Decode typed RDATA according to the RR-specific wire format defined by the corresponding RFC.
pub(crate) fn parse_rdata(
    packet: &[u8],
    owner_name: &Name,
    rr_type: RecordType,
    class: u16,
    ttl: u32,
    start: usize,
    end: usize,
) -> Result<RData> {
    match rr_type {
        RecordType::A => basic::parse_a(packet, start, end),
        RecordType::AAAA => basic::parse_aaaa(packet, start, end),
        RecordType::CNAME => basic::parse_cname(packet, start, end),
        RecordType::NS => basic::parse_ns(packet, start, end),
        RecordType::PTR => basic::parse_ptr(packet, start, end),
        RecordType::MX => basic::parse_mx(packet, start, end),
        RecordType::SRV => basic::parse_srv(packet, start, end),
        RecordType::NAPTR => basic::parse_naptr(packet, start, end),
        RecordType::CAA => basic::parse_caa(packet, start, end),
        RecordType::TXT => basic::parse_txt(packet, start, end),
        RecordType::SPF => basic::parse_spf(packet, start, end),
        RecordType::AVC => basic::parse_avc(packet, start, end),
        RecordType::RESINFO => basic::parse_resinfo(packet, start, end),
        RecordType::DOA => basic::parse_doa(packet, start, end),
        RecordType::SOA => basic::parse_soa(packet, start, end),
        RecordType::OPT => basic::parse_opt(packet, owner_name, class, ttl, start, end),
        RecordType::SIG => dnssec::parse_sig(packet, start, end),
        RecordType::KEY => dnssec::parse_key(packet, start, end),
        RecordType::DS => dnssec::parse_ds(packet, start, end),
        RecordType::SSHFP => dnssec::parse_sshfp(packet, start, end),
        RecordType::CERT => dnssec::parse_cert(packet, start, end),
        RecordType::RRSIG => dnssec::parse_rrsig(packet, start, end),
        RecordType::NSEC => dnssec::parse_nsec(packet, start, end),
        RecordType::DNSKEY => dnssec::parse_dnskey(packet, start, end),
        RecordType::DHCID => dnssec::parse_dhcid(packet, start, end),
        RecordType::NSEC3 => dnssec::parse_nsec3(packet, start, end),
        RecordType::NSEC3PARAM => dnssec::parse_nsec3param(packet, start, end),
        RecordType::TLSA => dnssec::parse_tlsa(packet, start, end),
        RecordType::SMIMEA => dnssec::parse_smimea(packet, start, end),
        RecordType::HIP => dnssec::parse_hip(packet, start, end),
        RecordType::NINFO => dnssec::parse_ninfo(packet, start, end),
        RecordType::RKEY => dnssec::parse_rkey(packet, start, end),
        RecordType::TALINK => dnssec::parse_talink(packet, start, end),
        RecordType::CDS => dnssec::parse_cds(packet, start, end),
        RecordType::CDNSKEY => dnssec::parse_cdnskey(packet, start, end),
        RecordType::OPENPGPKEY => dnssec::parse_openpgpkey(packet, start, end),
        RecordType::CSYNC => dnssec::parse_csync(packet, start, end),
        RecordType::ZONEMD => dnssec::parse_zonemd(packet, start, end),
        RecordType::TKEY => dnssec::parse_tkey(packet, start, end),
        RecordType::TSIG => dnssec::parse_tsig(packet, start, end),
        RecordType::TA => dnssec::parse_ta(packet, start, end),
        RecordType::DLV => dnssec::parse_dlv(packet, start, end),
        RecordType::KX => service::parse_kx(packet, start, end),
        RecordType::IPSECKEY => service::parse_ipseckey(packet, start, end),
        RecordType::SVCB => service::parse_svcb(packet, start, end),
        RecordType::HTTPS => service::parse_https(packet, start, end),
        RecordType::AMTRELAY => service::parse_amtrelay(packet, start, end),
        RecordType::URI => service::parse_uri(packet, start, end),
        RecordType::NID => service::parse_nid(packet, start, end),
        RecordType::L32 => service::parse_l32(packet, start, end),
        RecordType::L64 => service::parse_l64(packet, start, end),
        RecordType::LP => service::parse_lp(packet, start, end),
        RecordType::EUI48 => service::parse_eui48(packet, start, end),
        RecordType::EUI64 => service::parse_eui64(packet, start, end),
        RecordType::MD => legacy::parse_md(packet, start, end),
        RecordType::MF => legacy::parse_mf(packet, start, end),
        RecordType::MB => legacy::parse_mb(packet, start, end),
        RecordType::MG => legacy::parse_mg(packet, start, end),
        RecordType::MR => legacy::parse_mr(packet, start, end),
        RecordType::NULL => legacy::parse_null(packet, start, end),
        RecordType::WKS => legacy::parse_wks(packet, start, end),
        RecordType::HINFO => legacy::parse_hinfo(packet, start, end),
        RecordType::MINFO => legacy::parse_minfo(packet, start, end),
        RecordType::RP => legacy::parse_rp(packet, start, end),
        RecordType::AFSDB => legacy::parse_afsdb(packet, start, end),
        RecordType::X25 => legacy::parse_x25(packet, start, end),
        RecordType::NSAP => legacy::parse_nsap(packet, start, end),
        RecordType::ISDN => legacy::parse_isdn(packet, start, end),
        RecordType::RT => legacy::parse_rt(packet, start, end),
        RecordType::EID => legacy::parse_eid(packet, start, end),
        RecordType::NIMLOC => legacy::parse_nimloc(packet, start, end),
        RecordType::NSAPPTR => legacy::parse_nsapptr(packet, start, end),
        RecordType::PX => legacy::parse_px(packet, start, end),
        RecordType::GPOS => legacy::parse_gpos(packet, start, end),
        RecordType::LOC => legacy::parse_loc(packet, start, end),
        RecordType::NXT => legacy::parse_nxt(packet, start, end),
        RecordType::ATMA => legacy::parse_atma(packet, start, end),
        RecordType::A6 => legacy::parse_a6(packet, start, end),
        RecordType::SINK => legacy::parse_sink(packet, start, end),
        RecordType::DNAME => legacy::parse_dname(packet, start, end),
        RecordType::APL => legacy::parse_apl(packet, start, end),
        RecordType::UINFO => legacy::parse_uinfo(packet, start, end),
        RecordType::UID => legacy::parse_uid(packet, start, end),
        RecordType::GID => legacy::parse_gid(packet, start, end),
        RecordType::UNSPEC => legacy::parse_unspec(packet, start, end),
        RecordType::ANAME => legacy::parse_aname(packet, start, end),
        RecordType::IXFR => legacy::parse_ixfr(start, end),
        RecordType::AXFR => legacy::parse_axfr(start, end),
        RecordType::MAILB => legacy::parse_mailb(start, end),
        RecordType::MAILA => legacy::parse_maila(start, end),
        RecordType::ANY => legacy::parse_any(start, end),
        RecordType::Unknown(code) => Ok(RData::Unknown {
            rr_type: code,
            data: packet[start..end].to_vec(),
        }),
        RecordType::ZERO => Ok(RData::Unknown {
            rr_type: 0,
            data: packet[start..end].to_vec(),
        }),
    }
}

/// Encode typed RDATA according to the RR-specific wire format defined by the corresponding RFC.
pub(crate) fn encode_rdata<'a>(
    rdata: &'a RData,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    match rdata {
        RData::A(value) => {
            basic::encode_a(value, out);
            Ok(())
        }
        RData::AAAA(value) => {
            basic::encode_aaaa(value, out);
            Ok(())
        }
        RData::CNAME(value) => basic::encode_name_rdata(out, &value.0, write_name, true),
        RData::NS(value) => basic::encode_name_rdata(out, &value.0, write_name, true),
        RData::PTR(value) => basic::encode_name_rdata(out, &value.0, write_name, true),
        RData::MX(value) => basic::encode_mx(value, out, write_name),
        RData::SRV(value) => basic::encode_srv(value, out, write_name),
        RData::NAPTR(value) => basic::encode_naptr(value, out, write_name),
        RData::CAA(value) => basic::encode_caa(value, out),
        RData::TXT(value) => {
            basic::encode_txt(value, out);
            Ok(())
        }
        RData::SPF(value) => {
            basic::encode_spf(value, out);
            Ok(())
        }
        RData::AVC(value) => {
            basic::encode_avc(value, out);
            Ok(())
        }
        RData::RESINFO(value) => {
            basic::encode_resinfo(value, out);
            Ok(())
        }
        RData::DOA(value) => {
            basic::encode_doa(value, out);
            Ok(())
        }
        RData::SOA(value) => basic::encode_soa(value, out, write_name),
        RData::OPT(value) => basic::encode_opt(value, out),
        RData::SIG(value) => dnssec::encode_sig(value, out, write_name),
        RData::KEY(value) => {
            dnssec::encode_key(value, out);
            Ok(())
        }
        RData::DS(value) => {
            dnssec::encode_ds(value, out);
            Ok(())
        }
        RData::SSHFP(value) => {
            dnssec::encode_sshfp(value, out);
            Ok(())
        }
        RData::CERT(value) => {
            dnssec::encode_cert(value, out);
            Ok(())
        }
        RData::RRSIG(value) => dnssec::encode_rrsig(value, out, write_name),
        RData::NSEC(value) => dnssec::encode_nsec(value, out, write_name),
        RData::DNSKEY(value) => {
            dnssec::encode_dnskey(value, out);
            Ok(())
        }
        RData::DHCID(value) => {
            dnssec::encode_dhcid(value, out);
            Ok(())
        }
        RData::NSEC3(value) => {
            dnssec::encode_nsec3(value, out);
            Ok(())
        }
        RData::NSEC3PARAM(value) => {
            dnssec::encode_nsec3param(value, out);
            Ok(())
        }
        RData::TLSA(value) => {
            dnssec::encode_tlsa(value, out);
            Ok(())
        }
        RData::SMIMEA(value) => {
            dnssec::encode_smimea(value, out);
            Ok(())
        }
        RData::HIP(value) => dnssec::encode_hip(value, out, write_name),
        RData::NINFO(value) => {
            dnssec::encode_ninfo(value, out);
            Ok(())
        }
        RData::RKEY(value) => {
            dnssec::encode_rkey(value, out);
            Ok(())
        }
        RData::TALINK(value) => dnssec::encode_talink(value, out, write_name),
        RData::CDS(value) => {
            dnssec::encode_cds(value, out);
            Ok(())
        }
        RData::CDNSKEY(value) => {
            dnssec::encode_cdnskey(value, out);
            Ok(())
        }
        RData::OPENPGPKEY(value) => {
            dnssec::encode_openpgpkey(value, out);
            Ok(())
        }
        RData::CSYNC(value) => {
            dnssec::encode_csync(value, out);
            Ok(())
        }
        RData::ZONEMD(value) => {
            dnssec::encode_zonemd(value, out);
            Ok(())
        }
        RData::TKEY(value) => dnssec::encode_tkey(value, out, write_name),
        RData::TSIG(value) => dnssec::encode_tsig(value, out, write_name),
        RData::TA(value) => {
            dnssec::encode_ta(value, out);
            Ok(())
        }
        RData::DLV(value) => {
            dnssec::encode_dlv(value, out);
            Ok(())
        }
        RData::KX(value) => service::encode_kx(value, out, write_name),
        RData::IPSECKEY(value) => {
            service::encode_ipseckey(value, out);
            Ok(())
        }
        RData::SVCB(value) => service::encode_svcb(value, out, write_name),
        RData::HTTPS(value) => service::encode_https(value, out, write_name),
        RData::AMTRELAY(value) => {
            service::encode_amtrelay(value, out);
            Ok(())
        }
        RData::URI(value) => {
            service::encode_uri(value, out);
            Ok(())
        }
        RData::NID(value) => {
            service::encode_nid(value, out);
            Ok(())
        }
        RData::L32(value) => {
            service::encode_l32(value, out);
            Ok(())
        }
        RData::L64(value) => {
            service::encode_l64(value, out);
            Ok(())
        }
        RData::LP(value) => service::encode_lp(value, out, write_name),
        RData::EUI48(value) => {
            service::encode_eui48(value, out);
            Ok(())
        }
        RData::EUI64(value) => {
            service::encode_eui64(value, out);
            Ok(())
        }
        RData::MD(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::MF(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::MB(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::MG(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::MR(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::NULL(value) => {
            legacy::encode_null(value, out);
            Ok(())
        }
        RData::WKS(value) => {
            legacy::encode_wks(value, out);
            Ok(())
        }
        RData::HINFO(value) => legacy::encode_hinfo(value, out),
        RData::MINFO(value) => legacy::encode_minfo(value, out, write_name),
        RData::RP(value) => legacy::encode_rp(value, out, write_name),
        RData::AFSDB(value) => legacy::encode_afsdb(value, out, write_name),
        RData::X25(value) => legacy::encode_x25(value, out),
        RData::NSAP(value) => {
            legacy::encode_nsap(value, out);
            Ok(())
        }
        RData::ISDN(value) => legacy::encode_isdn(value, out),
        RData::RT(value) => legacy::encode_rt(value, out, write_name),
        RData::EID(value) => {
            legacy::encode_eid(value, out);
            Ok(())
        }
        RData::NIMLOC(value) => {
            legacy::encode_nimloc(value, out);
            Ok(())
        }
        RData::NSAPPTR(value) => legacy::encode_name_rr(&value.0, out, write_name, false),
        RData::PX(value) => legacy::encode_px(value, out, write_name),
        RData::GPOS(value) => legacy::encode_gpos(value, out),
        RData::LOC(value) => {
            legacy::encode_loc(value, out);
            Ok(())
        }
        RData::NXT(value) => legacy::encode_nxt(value, out, write_name),
        RData::ATMA(value) => {
            legacy::encode_atma(value, out);
            Ok(())
        }
        RData::A6(value) => legacy::encode_a6(value, out, write_name),
        RData::SINK(value) => {
            legacy::encode_sink(value, out);
            Ok(())
        }
        RData::DNAME(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::APL(value) => legacy::encode_apl(value, out),
        RData::UINFO(value) => {
            legacy::encode_uinfo(value, out);
            Ok(())
        }
        RData::UID(value) => {
            legacy::encode_uid(value, out);
            Ok(())
        }
        RData::GID(value) => {
            legacy::encode_gid(value, out);
            Ok(())
        }
        RData::UNSPEC(value) => {
            legacy::encode_unspec(value, out);
            Ok(())
        }
        RData::ANAME(value) => legacy::encode_name_rr(&value.0, out, write_name, true),
        RData::IXFR(_) | RData::AXFR(_) | RData::MAILB(_) | RData::MAILA(_) | RData::ANY(_) => {
            Ok(())
        }
        RData::Unknown { data, .. } => {
            out.extend_from_slice(data);
            Ok(())
        }
    }
}

/// Encode an OPT pseudo-RR into a dedicated buffer following RFC 6891 section 6.1.
pub(crate) fn encode_edns_record_into_vec(edns: &Edns, ext_rcode: u8) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    encode_edns_record(&mut out, edns, ext_rcode)?;
    Ok(out)
}

/// Encode an OPT pseudo-RR following RFC 6891 section 6.1.2.
pub(crate) fn encode_edns_record(out: &mut Vec<u8>, edns: &Edns, ext_rcode: u8) -> Result<()> {
    out.push(0);
    push_u16(out, u16::from(RecordType::OPT));
    push_u16(out, edns.udp_payload_size());

    let mut ttl: u32 = u32::from(ext_rcode) << 24;
    ttl |= u32::from(edns.version()) << 16;
    ttl |= u32::from(u16::from(*edns.flags()));
    push_u32(out, ttl);

    let rdlen_pos = out.len();
    out.push(0);
    out.push(0);
    let rdata_start = out.len();

    for option in edns.options() {
        basic::encode_edns_option(out, option)?;
    }

    let rdlen = out.len().saturating_sub(rdata_start);
    let rdlen =
        u16::try_from(rdlen).map_err(|_| DnsError::protocol("dns rdata exceeds u16 length"))?;
    out[rdlen_pos] = (rdlen >> 8) as u8;
    out[rdlen_pos + 1] = rdlen as u8;
    Ok(())
}

/// Parse a single domain name and require the RDATA to end exactly at that name boundary.
///
/// This helper is used by RR types whose entire RDATA is a single domain name encoded with the
/// RFC 1035 section 4.1.4 compression rules.
fn parse_name(packet: &[u8], start: usize, end: usize, kind: &str) -> Result<Name> {
    let (name, next) = Name::parse(packet, start)?;
    if next != end {
        return Err(DnsError::protocol(format!("invalid {} rdata length", kind)));
    }
    Ok(name)
}

/// Parse one DNS character-string as defined by RFC 1035 section 3.3.
///
/// The returned offset always points to the first byte after the parsed string so callers can
/// chain multiple strings inside one RDATA blob.
fn parse_character_string(packet: &[u8], start: usize, end: usize) -> Result<(Box<[u8]>, usize)> {
    if start >= end {
        return Err(DnsError::protocol("invalid character-string rdata length"));
    }
    let len = packet[start] as usize;
    let data_start = start + 1;
    let data_end = data_start + len;
    if data_end > end {
        return Err(DnsError::protocol("invalid character-string rdata length"));
    }
    Ok((copy_boxed(packet, data_start, data_end), data_end))
}

/// Parse a single character-string and require exact RDATA exhaustion afterwards.
fn parse_single_character_string(
    packet: &[u8],
    start: usize,
    end: usize,
    kind: &str,
) -> Result<Box<[u8]>> {
    let (value, next) = parse_character_string(packet, start, end)?;
    if next != end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    Ok(value)
}

/// Parse exactly two back-to-back DNS character-strings.
fn parse_two_character_strings(
    packet: &[u8],
    start: usize,
    end: usize,
    kind: &str,
) -> Result<(Box<[u8]>, Box<[u8]>)> {
    let (first, cursor) = parse_character_string(packet, start, end)?;
    let (second, next) = parse_character_string(packet, cursor, end)?;
    if next != end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    Ok((first, second))
}

/// Parse exactly two back-to-back compressed domain names.
fn parse_two_names(packet: &[u8], start: usize, end: usize, kind: &str) -> Result<(Name, Name)> {
    let (a, cursor) = Name::parse(packet, start)?;
    let (b, next) = Name::parse(packet, cursor)?;
    if next != end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    Ok((a, b))
}

/// Parse a leading 16-bit integer followed by one compressed domain name.
fn parse_u16_name(packet: &[u8], start: usize, end: usize, kind: &str) -> Result<(u16, Name)> {
    if start + 2 > end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    let value = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let (name, next) = Name::parse(packet, start + 2)?;
    if next != end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    Ok((value, name))
}

/// Encode a DNS character-string with the one-octet length prefix required by RFC 1035 section 3.3.
fn encode_character_string(out: &mut Vec<u8>, data: &[u8], kind: &str) -> Result<()> {
    if data.len() > u8::MAX as usize {
        return Err(DnsError::protocol(format!("{kind} exceeds 255 bytes")));
    }
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_name_raw(out: &mut Vec<u8>, name: &Name, _compress: bool) -> Result<()> {
        out.extend_from_slice(name.wire());
        Ok(())
    }

    #[test]
    fn parse_encode_rdata_dispatch_roundtrip() {
        let packet = [1, 2, 3, 4];
        let parsed = parse_rdata(
            &packet,
            &Name::from_ascii("owner.example.com.").unwrap(),
            RecordType::A,
            u16::from(crate::message::DNSClass::IN),
            300,
            0,
            packet.len(),
        )
        .unwrap();

        let mut encoded = Vec::new();
        encode_rdata(&parsed, &mut encoded, &mut write_name_raw).unwrap();
        assert_eq!(encoded, packet);
    }

    #[test]
    fn encode_edns_record_helpers_match() {
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1400);
        edns.set_dnssec_ok(true);
        edns.insert(EdnsOption::Unknown(65001, vec![1, 2, 3]));

        let direct = {
            let mut out = Vec::new();
            encode_edns_record(&mut out, &edns, 1).unwrap();
            out
        };
        let via_vec = encode_edns_record_into_vec(&edns, 1).unwrap();

        assert_eq!(direct, via_vec);
    }

    #[test]
    fn shared_parse_helpers_roundtrip() {
        let packet = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ];
        let name = parse_name(&packet, 0, packet.len(), "shared").unwrap();
        assert_eq!(name.wire(), &packet);

        let text = [5, b'h', b'e', b'l', b'l', b'o'];
        let (string, next) = parse_character_string(&text, 0, text.len()).unwrap();
        assert_eq!(&*string, b"hello");
        assert_eq!(next, text.len());

        let pair = [1, b'a', 1, b'b'];
        let (left, right) = parse_two_character_strings(&pair, 0, pair.len(), "pair").unwrap();
        assert_eq!(&*left, b"a");
        assert_eq!(&*right, b"b");

        let names = [1, b'a', 0, 1, b'b', 0];
        let (left_name, right_name) = parse_two_names(&names, 0, names.len(), "pair").unwrap();
        assert_eq!(left_name.to_fqdn(), "a.");
        assert_eq!(right_name.to_fqdn(), "b.");

        let u16_name = [0, 10, 1, b'm', 0];
        let (value, name) = parse_u16_name(&u16_name, 0, u16_name.len(), "u16-name").unwrap();
        assert_eq!(value, 10);
        assert_eq!(name.to_fqdn(), "m.");
    }

    #[test]
    fn shared_parse_helpers_reject_invalid_wire() {
        assert!(parse_name(&[1, b'a'], 0, 2, "bad").is_err());
        assert!(parse_character_string(&[3, b'a'], 0, 2).is_err());
        assert!(parse_single_character_string(&[1, b'a', 1, b'b'], 0, 4, "bad").is_err());
        assert!(parse_two_character_strings(&[1, b'a', 1], 0, 3, "bad").is_err());
        assert!(parse_two_names(&[1, b'a', 0, 1], 0, 4, "bad").is_err());
        assert!(parse_u16_name(&[0, 1], 0, 2, "bad").is_err());
        assert!(encode_character_string(&mut Vec::new(), &[0; 256], "too-long").is_err());
    }
}
