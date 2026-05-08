// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::type_complexity)]

use super::*;

/// Decode MD as a single domain name per RFC 1035 section 3.3.4.
pub(super) fn parse_md(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::MD(MD(parse_name(packet, start, end, "MD")?)))
}

/// Decode MF as a single domain name per RFC 1035 section 3.3.5.
pub(super) fn parse_mf(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::MF(MF(parse_name(packet, start, end, "MF")?)))
}

/// Decode MB as a single domain name per RFC 1035 section 3.3.3.
pub(super) fn parse_mb(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::MB(MB(parse_name(packet, start, end, "MB")?)))
}

/// Decode MG as a single domain name per RFC 1035 section 3.3.6.
pub(super) fn parse_mg(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::MG(MG(parse_name(packet, start, end, "MG")?)))
}

/// Decode MR as a single domain name per RFC 1035 section 3.3.8.
pub(super) fn parse_mr(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::MR(MR(parse_name(packet, start, end, "MR")?)))
}

/// Decode NULL as an opaque octet string per RFC 1035 section 3.3.10.
pub(super) fn parse_null(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NULL(NULL::new(copy_boxed(packet, start, end))))
}

/// Decode WKS address, protocol, and bitmap per RFC 1035 section 3.4.2.
pub(super) fn parse_wks(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::WKS(parse_wks_rdata(packet, start, end)?))
}

/// Decode HINFO CPU and OS character-strings per RFC 1035 section 3.3.2.
pub(super) fn parse_hinfo(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (cpu, os) = parse_two_character_strings(packet, start, end, "HINFO")?;
    Ok(RData::HINFO(HINFO::new(cpu, os)))
}

/// Decode MINFO responsible mailbox and error mailbox names per RFC 1035
/// section 3.3.7.
pub(super) fn parse_minfo(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (rmail, email) = parse_two_names(packet, start, end, "MINFO")?;
    Ok(RData::MINFO(MINFO::new(rmail, email)))
}

/// Decode RP mailbox and TXT-domain names per RFC 1183 section 2.2.
pub(super) fn parse_rp(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (mbox, txt) = parse_two_names(packet, start, end, "RP")?;
    Ok(RData::RP(RP::new(mbox, txt)))
}

/// Decode AFSDB subtype and hostname per RFC 1183 section 1.
pub(super) fn parse_afsdb(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (subtype, hostname) = parse_u16_name(packet, start, end, "AFSDB")?;
    Ok(RData::AFSDB(AFSDB::new(subtype, hostname)))
}

/// Decode X25 PSDN address as a single character-string per RFC 1183 section
/// 3.1.
pub(super) fn parse_x25(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let value = parse_single_character_string(packet, start, end, "X25")?;
    Ok(RData::X25(X25::new(value)))
}

/// Decode NSAP as opaque bytes per RFC 1706 section 5.
pub(super) fn parse_nsap(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NSAP(NSAP(copy_boxed(packet, start, end))))
}

/// Decode ISDN address and optional subaddress character-strings per RFC 1183
/// section 3.2.
pub(super) fn parse_isdn(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (address, sub_address) = parse_isdn_rdata(packet, start, end)?;
    Ok(RData::ISDN(ISDN::new(address, sub_address)))
}

/// Decode RT preference and intermediate host name per RFC 1183 section 3.3.
pub(super) fn parse_rt(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (preference, host) = parse_u16_name(packet, start, end, "RT")?;
    Ok(RData::RT(RT::new(preference, host)))
}

/// Decode EID as opaque bytes per RFC 6742 section 2.5.
pub(super) fn parse_eid(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::EID(EID(copy_boxed(packet, start, end))))
}

/// Decode NIMLOC as opaque bytes per RFC 6742 section 2.6.
pub(super) fn parse_nimloc(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NIMLOC(NIMLOC(copy_boxed(packet, start, end))))
}

/// Decode NSAP-PTR as a single target domain name per RFC 1706 section 6.
pub(super) fn parse_nsapptr(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NSAPPTR(NSAPPTR(parse_name(
        packet, start, end, "NSAPPTR",
    )?)))
}

/// Decode PX preference and the two mapping names per RFC 2163 section 4.
pub(super) fn parse_px(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (preference, map822, mapx400) = parse_px_rdata(packet, start, end)?;
    Ok(RData::PX(PX::new(preference, map822, mapx400)))
}

/// Decode GPOS longitude, latitude, and altitude character-strings per RFC
/// 1712.
pub(super) fn parse_gpos(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::GPOS(parse_gpos_rdata(packet, start, end)?))
}

/// Decode LOC fixed-width version, size, precision, and coordinates per RFC
/// 1876 section 2.
pub(super) fn parse_loc(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::LOC(parse_loc_rdata(packet, start, end)?))
}

/// Decode NXT wire data using the historical RFC 2535 bitmap layout.
pub(super) fn parse_nxt(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NXT(NXT(parse_nxt_rdata(packet, start, end)?)))
}

/// Decode ATMA as opaque bytes per RFC 2225 section 3.
pub(super) fn parse_atma(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::ATMA(ATMA(copy_boxed(packet, start, end))))
}

/// Decode A6 prefix length, suffix, and optional prefix name per RFC 2874
/// section 3.
pub(super) fn parse_a6(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::A6(parse_a6_rdata(packet, start, end)?))
}

/// Decode SINK coding, subcoding, and opaque payload per RFC 7958 appendix B.
pub(super) fn parse_sink(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::SINK(parse_sink_rdata(packet, start, end)?))
}

/// Decode DNAME target name per RFC 6672 section 2.
pub(super) fn parse_dname(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::DNAME(DNAME(parse_name(
        packet, start, end, "DNAME",
    )?)))
}

/// Decode APL address prefix items per RFC 3123 section 4.
pub(super) fn parse_apl(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::APL(parse_apl_rdata(packet, start, end)?))
}

/// Decode UINFO as opaque bytes from the legacy mailbox record family.
pub(super) fn parse_uinfo(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::UINFO(UINFO(copy_boxed(packet, start, end))))
}

/// Decode UID as a single 32-bit integer.
pub(super) fn parse_uid(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    if end - start != 4 {
        return Err(DnsError::protocol("invalid UID rdata length"));
    }
    Ok(RData::UID(UID(u32::from_be_bytes([
        packet[start],
        packet[start + 1],
        packet[start + 2],
        packet[start + 3],
    ]))))
}

/// Decode GID as a single 32-bit integer.
pub(super) fn parse_gid(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    if end - start != 4 {
        return Err(DnsError::protocol("invalid GID rdata length"));
    }
    Ok(RData::GID(GID(u32::from_be_bytes([
        packet[start],
        packet[start + 1],
        packet[start + 2],
        packet[start + 3],
    ]))))
}

/// Decode UNSPEC as opaque bytes from the legacy mailbox record family.
pub(super) fn parse_unspec(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::UNSPEC(UNSPEC(copy_boxed(packet, start, end))))
}

/// Decode ANAME as a target domain name using the same wire form as CNAME-like
/// records.
pub(super) fn parse_aname(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::ANAME(ANAME(parse_name(
        packet, start, end, "ANAME",
    )?)))
}

pub(super) fn parse_ixfr(start: usize, end: usize) -> Result<RData> {
    if start != end {
        return Err(DnsError::protocol("invalid IXFR rdata length"));
    }
    Ok(RData::IXFR(IXFR))
}

pub(super) fn parse_axfr(start: usize, end: usize) -> Result<RData> {
    if start != end {
        return Err(DnsError::protocol("invalid AXFR rdata length"));
    }
    Ok(RData::AXFR(AXFR))
}

pub(super) fn parse_mailb(start: usize, end: usize) -> Result<RData> {
    if start != end {
        return Err(DnsError::protocol("invalid MAILB rdata length"));
    }
    Ok(RData::MAILB(MAILB))
}

pub(super) fn parse_maila(start: usize, end: usize) -> Result<RData> {
    if start != end {
        return Err(DnsError::protocol("invalid MAILA rdata length"));
    }
    Ok(RData::MAILA(MAILA))
}

pub(super) fn parse_any(start: usize, end: usize) -> Result<RData> {
    if start != end {
        return Err(DnsError::protocol("invalid ANY rdata length"));
    }
    Ok(RData::ANY(ANY))
}

/// Encode legacy single-name RDATA variants, optionally with RFC 1035 name
/// compression.
pub(super) fn encode_name_rr<'a>(
    name: &'a Name,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
    compress: bool,
) -> Result<()> {
    write_name(out, name, compress)
}

/// Encode NULL as opaque bytes per RFC 1035 section 3.3.10.
pub(super) fn encode_null(value: &NULL, out: &mut Vec<u8>) {
    out.extend_from_slice(value.data());
}

/// Encode WKS address, protocol, and service bitmap per RFC 1035 section 3.4.2.
pub(super) fn encode_wks(value: &WKS, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.address().octets());
    out.push(value.protocol());
    out.extend_from_slice(value.bitmap());
}

/// Encode HINFO CPU and OS character-strings per RFC 1035 section 3.3.2.
pub(super) fn encode_hinfo(value: &HINFO, out: &mut Vec<u8>) -> Result<()> {
    encode_character_string(out, value.cpu(), "HINFO cpu")?;
    encode_character_string(out, value.os(), "HINFO os")
}

/// Encode MINFO responsible mailbox and error mailbox names per RFC 1035
/// section 3.3.7.
pub(super) fn encode_minfo<'a>(
    value: &'a MINFO,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.rmail(), true)?;
    write_name(out, value.email(), true)
}

/// Encode RP mailbox and TXT-domain names per RFC 1183 section 2.2.
pub(super) fn encode_rp<'a>(
    value: &'a RP,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.mbox(), false)?;
    write_name(out, value.txt(), false)
}

/// Encode AFSDB subtype and hostname per RFC 1183 section 1.
pub(super) fn encode_afsdb<'a>(
    value: &'a AFSDB,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.subtype());
    write_name(out, value.hostname(), false)
}

/// Encode X25 PSDN address as a single character-string per RFC 1183 section
/// 3.1.
pub(super) fn encode_x25(value: &X25, out: &mut Vec<u8>) -> Result<()> {
    encode_character_string(out, value.psdn_address(), "X25")
}

/// Encode NSAP as opaque bytes per RFC 1706 section 5.
pub(super) fn encode_nsap(value: &NSAP, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode ISDN address and optional subaddress character-strings per RFC 1183
/// section 3.2.
pub(super) fn encode_isdn(value: &ISDN, out: &mut Vec<u8>) -> Result<()> {
    encode_character_string(out, value.address(), "ISDN address")?;
    if let Some(sub) = value.sub_address() {
        encode_character_string(out, sub, "ISDN sub-address")?;
    }
    Ok(())
}

/// Encode RT preference and intermediate host name per RFC 1183 section 3.3.
pub(super) fn encode_rt<'a>(
    value: &'a RT,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.preference());
    write_name(out, value.host(), false)
}

/// Encode EID as opaque bytes per RFC 6742 section 2.5.
pub(super) fn encode_eid(value: &EID, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode NIMLOC as opaque bytes per RFC 6742 section 2.6.
pub(super) fn encode_nimloc(value: &NIMLOC, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode PX preference and the two mapping names per RFC 2163 section 4.
pub(super) fn encode_px<'a>(
    value: &'a PX,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.preference());
    write_name(out, value.map822(), false)?;
    write_name(out, value.mapx400(), false)
}

/// Encode GPOS longitude, latitude, and altitude character-strings per RFC
/// 1712.
pub(super) fn encode_gpos(value: &GPOS, out: &mut Vec<u8>) -> Result<()> {
    encode_character_string(out, value.longitude(), "GPOS longitude")?;
    encode_character_string(out, value.latitude(), "GPOS latitude")?;
    encode_character_string(out, value.altitude(), "GPOS altitude")
}

/// Encode LOC fixed-width fields per RFC 1876 section 2.
pub(super) fn encode_loc(value: &LOC, out: &mut Vec<u8>) {
    out.push(value.version());
    out.push(value.size());
    out.push(value.horiz_pre());
    out.push(value.vert_pre());
    push_u32(out, value.latitude());
    push_u32(out, value.longitude());
    push_u32(out, value.altitude());
}

/// Encode NXT wire data using the historical RFC 2535 bitmap layout.
pub(super) fn encode_nxt<'a>(
    value: &'a NXT,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.0.next_domain(), false)?;
    out.extend_from_slice(value.0.type_bitmap());
    Ok(())
}

/// Encode ATMA as opaque bytes per RFC 2225 section 3.
pub(super) fn encode_atma(value: &ATMA, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode A6 prefix length, suffix, and optional prefix name per RFC 2874
/// section 3.
pub(super) fn encode_a6<'a>(
    value: &'a A6,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    out.push(value.prefix_len());
    out.extend_from_slice(value.suffix());
    if let Some(prefix_name) = value.prefix_name() {
        write_name(out, prefix_name, true)?;
    }
    Ok(())
}

/// Encode SINK coding, subcoding, and payload per RFC 7958 appendix B.
pub(super) fn encode_sink(value: &SINK, out: &mut Vec<u8>) {
    out.push(value.coding());
    out.push(value.subcoding());
    out.extend_from_slice(value.data());
}

/// Encode APL prefix items per RFC 3123 section 4.
pub(super) fn encode_apl(value: &APL, out: &mut Vec<u8>) -> Result<()> {
    for prefix in value.prefixes() {
        push_u16(out, prefix.family());
        out.push(prefix.prefix());
        let afd_len = prefix.afd_part().len();
        if afd_len > 0x7F {
            return Err(DnsError::protocol("APL afd part exceeds 127 bytes"));
        }
        let mut len = afd_len as u8;
        if prefix.negation() {
            len |= 0x80;
        }
        out.push(len);
        out.extend_from_slice(prefix.afd_part());
    }
    Ok(())
}

/// Encode UINFO as opaque bytes from the legacy mailbox record family.
pub(super) fn encode_uinfo(value: &UINFO, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode UID as a single 32-bit integer.
pub(super) fn encode_uid(value: &UID, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0.to_be_bytes());
}

/// Encode GID as a single 32-bit integer.
pub(super) fn encode_gid(value: &GID, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0.to_be_bytes());
}

/// Encode UNSPEC as opaque bytes from the legacy mailbox record family.
pub(super) fn encode_unspec(value: &UNSPEC, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Parse one or two ISDN character-strings and require exact RDATA exhaustion.
fn parse_isdn_rdata(
    packet: &[u8],
    start: usize,
    end: usize,
) -> Result<(Box<[u8]>, Option<Box<[u8]>>)> {
    let (address, cursor) = parse_character_string(packet, start, end)?;
    if cursor == end {
        return Ok((address, None));
    }
    let (sub_address, next) = parse_character_string(packet, cursor, end)?;
    if next != end {
        return Err(DnsError::protocol("invalid ISDN rdata length"));
    }
    Ok((address, Some(sub_address)))
}

/// Parse PX preference followed by the RFC 822 and X.400 mapping names.
fn parse_px_rdata(packet: &[u8], start: usize, end: usize) -> Result<(u16, Name, Name)> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid PX rdata length"));
    }
    let preference = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let (map822, cursor) = Name::parse(packet, start + 2)?;
    let (mapx400, next) = Name::parse(packet, cursor)?;
    if next != end {
        return Err(DnsError::protocol("invalid PX rdata length"));
    }
    Ok((preference, map822, mapx400))
}

/// Parse GPOS longitude, latitude, and altitude character-strings.
fn parse_gpos_rdata(packet: &[u8], start: usize, end: usize) -> Result<GPOS> {
    let (longitude, cursor) = parse_character_string(packet, start, end)?;
    let (latitude, cursor) = parse_character_string(packet, cursor, end)?;
    let (altitude, next) = parse_character_string(packet, cursor, end)?;
    if next != end {
        return Err(DnsError::protocol("invalid GPOS rdata length"));
    }
    Ok(GPOS::new(longitude, latitude, altitude))
}

fn parse_nxt_rdata(packet: &[u8], start: usize, end: usize) -> Result<NSEC> {
    let (next_domain, cursor) = Name::parse(packet, start)?;
    if cursor > end {
        return Err(DnsError::protocol("invalid NXT rdata length"));
    }
    Ok(NSEC::new(
        next_domain,
        TypeBitMaps::try_from_wire(copy_boxed(packet, cursor, end))?,
    ))
}

/// Parse LOC fixed-width version, precision, and 32-bit coordinate fields.
fn parse_loc_rdata(packet: &[u8], start: usize, end: usize) -> Result<LOC> {
    if end - start != 16 {
        return Err(DnsError::protocol("invalid LOC rdata length"));
    }
    Ok(LOC::new(
        packet[start],
        packet[start + 1],
        packet[start + 2],
        packet[start + 3],
        u32::from_be_bytes([
            packet[start + 4],
            packet[start + 5],
            packet[start + 6],
            packet[start + 7],
        ]),
        u32::from_be_bytes([
            packet[start + 8],
            packet[start + 9],
            packet[start + 10],
            packet[start + 11],
        ]),
        u32::from_be_bytes([
            packet[start + 12],
            packet[start + 13],
            packet[start + 14],
            packet[start + 15],
        ]),
    ))
}

/// Parse APL prefix tuples with family, prefix length, negation bit, and
/// truncated address part.
fn parse_apl_rdata(packet: &[u8], start: usize, end: usize) -> Result<APL> {
    let mut cursor = start;
    let mut prefixes = Vec::new();
    while cursor < end {
        if cursor + 4 > end {
            return Err(DnsError::protocol("invalid APL rdata length"));
        }
        let family = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let prefix = packet[cursor + 2];
        let afd_len = packet[cursor + 3] & 0x7F;
        let negation = (packet[cursor + 3] & 0x80) != 0;
        let afd_start = cursor + 4;
        let afd_end = afd_start + afd_len as usize;
        if afd_end > end {
            return Err(DnsError::protocol("invalid APL rdata length"));
        }
        prefixes.push(AplPrefix::new(
            family,
            prefix,
            negation,
            copy_boxed(packet, afd_start, afd_end),
        ));
        cursor = afd_end;
    }
    Ok(APL::new(prefixes))
}

/// Parse WKS address, protocol, and a trailing bitmap of services.
fn parse_wks_rdata(packet: &[u8], start: usize, end: usize) -> Result<WKS> {
    if end - start < 5 {
        return Err(DnsError::protocol("invalid WKS rdata length"));
    }
    Ok(WKS::new(
        Ipv4Addr::new(
            packet[start],
            packet[start + 1],
            packet[start + 2],
            packet[start + 3],
        ),
        packet[start + 4],
        copy_boxed(packet, start + 5, end),
    ))
}

/// Parse A6 prefix length, suffix bytes, and optional prefix name.
fn parse_a6_rdata(packet: &[u8], start: usize, end: usize) -> Result<A6> {
    if start >= end {
        return Err(DnsError::protocol("invalid A6 rdata length"));
    }
    let prefix_len = packet[start];
    if prefix_len > 128 {
        return Err(DnsError::protocol("invalid A6 prefix length"));
    }
    let suffix_len = usize::from(128u16.saturating_sub(prefix_len as u16)).div_ceil(8);
    let suffix_start = start + 1;
    let suffix_end = suffix_start + suffix_len;
    if suffix_end > end {
        return Err(DnsError::protocol("invalid A6 rdata length"));
    }
    let prefix_name = if prefix_len > 0 {
        let (name, next) = Name::parse(packet, suffix_end)?;
        if next != end {
            return Err(DnsError::protocol("invalid A6 rdata length"));
        }
        Some(name)
    } else {
        if suffix_end != end {
            return Err(DnsError::protocol("invalid A6 rdata length"));
        }
        None
    };
    Ok(A6::new(
        prefix_len,
        copy_boxed(packet, suffix_start, suffix_end),
        prefix_name,
    ))
}

/// Parse SINK coding, subcoding, and trailing opaque payload.
fn parse_sink_rdata(packet: &[u8], start: usize, end: usize) -> Result<SINK> {
    if end - start < 2 {
        return Err(DnsError::protocol("invalid SINK rdata length"));
    }
    Ok(SINK::new(
        packet[start],
        packet[start + 1],
        copy_boxed(packet, start + 2, end),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_name_raw(out: &mut Vec<u8>, name: &Name, _compress: bool) -> Result<()> {
        out.extend_from_slice(name.wire());
        Ok(())
    }

    #[test]
    fn legacy_rdata_parse_encode_roundtrip() {
        let cases: Vec<(&[u8], fn(&[u8], usize, usize) -> Result<RData>)> = vec![
            (&[2, b'm', b'd', 0], parse_md),
            (&[2, b'm', b'f', 0], parse_mf),
            (&[2, b'm', b'b', 0], parse_mb),
            (&[2, b'm', b'g', 0], parse_mg),
            (&[2, b'm', b'r', 0], parse_mr),
            (&[1, 2, 3], parse_null),
            (&[1, 2, 3, 4, 6, 0x10], parse_wks),
            (&[3, b'c', b'p', b'u', 2, b'o', b's'], parse_hinfo),
            (
                &[
                    5, b'r', b'm', b'a', b'i', b'l', 0, 5, b'e', b'm', b'a', b'i', b'l', 0,
                ],
                parse_minfo,
            ),
            (
                &[4, b'm', b'b', b'o', b'x', 0, 3, b't', b'x', b't', 0],
                parse_rp,
            ),
            (&[0, 1, 5, b'h', b'o', b's', b't', b'1', 0], parse_afsdb),
            (
                &[
                    12, b'3', b'1', b'1', b'0', b'6', b'1', b'7', b'0', b'0', b'9', b'5', b'6',
                ],
                parse_x25,
            ),
            (&[0x47, 0x00], parse_nsap),
            (
                &[
                    15, b'1', b'5', b'0', b'8', b'6', b'2', b'0', b'2', b'8', b'0', b'0', b'3',
                    b'2', b'1', b'7', 3, b'0', b'0', b'4',
                ],
                parse_isdn,
            ),
            (&[0, 1, 2, b'r', b't', 0], parse_rt),
            (&[1, 2], parse_eid),
            (&[3, 4], parse_nimloc),
            (&[6, b'n', b's', b'a', b'p', b't', b'r', 0], parse_nsapptr),
            (
                &[
                    0, 1, 6, b'm', b'a', b'p', b'8', b'2', b'2', 0, 7, b'm', b'a', b'p', b'x',
                    b'4', b'0', b'0', 0,
                ],
                parse_px,
            ),
            (
                &[
                    6, b'-', b'0', b'.', b'0', b'0', b'1', 7, b'5', b'1', b'.', b'4', b'7', b'7',
                    b'8', 4, b'4', b'5', b'.', b'0',
                ],
                parse_gpos,
            ),
            (
                &[
                    0, 0x12, 0x13, 0x14, 0x81, 0x23, 0x45, 0x67, 0x84, 0x56, 0x78, 0x90, 0x00,
                    0x98, 0x97, 0x3B,
                ],
                parse_loc,
            ),
            (&[3, b'n', b'x', b't', 0, 0, 1, 0x40], parse_nxt),
            (&[0x47, 0x00, 0x10], parse_atma),
            (
                &[
                    64, 0, 1, 2, 3, 4, 5, 6, 7, 6, b'p', b'r', b'e', b'f', b'i', b'x', 0,
                ],
                parse_a6,
            ),
            (&[1, 2, 3, 4, 5], parse_sink),
            (&[6, b't', b'a', b'r', b'g', b'e', b't', 0], parse_dname),
            (&[0, 1, 24, 3, 192, 0, 2], parse_apl),
            (
                &[9, b'u', b's', b'e', b'r', b' ', b'i', b'n', b'f', b'o'],
                parse_uinfo,
            ),
            (&[0, 0, 3, 232], parse_uid),
            (&[0, 0, 3, 232], parse_gid),
            (&[0xAA, 0xBB], parse_unspec),
            (&[5, b'a', b'n', b'a', b'm', b'e', 0], parse_aname),
            (&[], |_p, s, e| parse_ixfr(s, e)),
            (&[], |_p, s, e| parse_axfr(s, e)),
            (&[], |_p, s, e| parse_mailb(s, e)),
            (&[], |_p, s, e| parse_maila(s, e)),
            (&[], |_p, s, e| parse_any(s, e)),
        ];

        for (packet, parse) in cases {
            let parsed = parse(packet, 0, packet.len()).unwrap();
            let mut encoded = Vec::new();
            match &parsed {
                RData::MD(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::MF(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::MB(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::MG(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::MR(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::NULL(value) => encode_null(value, &mut encoded),
                RData::WKS(value) => encode_wks(value, &mut encoded),
                RData::HINFO(value) => encode_hinfo(value, &mut encoded).unwrap(),
                RData::MINFO(value) => {
                    encode_minfo(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::RP(value) => encode_rp(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::AFSDB(value) => {
                    encode_afsdb(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::X25(value) => encode_x25(value, &mut encoded).unwrap(),
                RData::NSAP(value) => encode_nsap(value, &mut encoded),
                RData::ISDN(value) => encode_isdn(value, &mut encoded).unwrap(),
                RData::RT(value) => encode_rt(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::EID(value) => encode_eid(value, &mut encoded),
                RData::NIMLOC(value) => encode_nimloc(value, &mut encoded),
                RData::NSAPPTR(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, false).unwrap()
                }
                RData::PX(value) => encode_px(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::GPOS(value) => encode_gpos(value, &mut encoded).unwrap(),
                RData::LOC(value) => encode_loc(value, &mut encoded),
                RData::NXT(value) => encode_nxt(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::ATMA(value) => encode_atma(value, &mut encoded),
                RData::A6(value) => encode_a6(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::SINK(value) => encode_sink(value, &mut encoded),
                RData::DNAME(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::APL(value) => encode_apl(value, &mut encoded).unwrap(),
                RData::UINFO(value) => encode_uinfo(value, &mut encoded),
                RData::UID(value) => encode_uid(value, &mut encoded),
                RData::GID(value) => encode_gid(value, &mut encoded),
                RData::UNSPEC(value) => encode_unspec(value, &mut encoded),
                RData::ANAME(value) => {
                    encode_name_rr(&value.0, &mut encoded, &mut write_name_raw, true).unwrap()
                }
                RData::IXFR(_)
                | RData::AXFR(_)
                | RData::MAILB(_)
                | RData::MAILA(_)
                | RData::ANY(_) => {}
                other => panic!("unexpected legacy rdata variant: {other:?}"),
            }
            assert_eq!(encoded, packet);
        }
    }

    #[test]
    fn legacy_rdata_rejects_invalid_wire_matrix() {
        let cases: Vec<(&str, Result<RData>)> = vec![
            ("wks too short", parse_wks(&[1, 2, 3, 4], 0, 4)),
            ("hinfo truncated", parse_hinfo(&[3, b'c', b'p'], 0, 3)),
            ("minfo truncated", parse_minfo(&[2, b'r', b'm', 0], 0, 4)),
            ("rp truncated", parse_rp(&[2, b'm', b'b', 0], 0, 4)),
            ("afsdb truncated", parse_afsdb(&[0, 1], 0, 2)),
            ("x25 empty", parse_x25(&[], 0, 0)),
            ("isdn truncated", parse_isdn(&[3, b'1', b'2'], 0, 3)),
            ("rt truncated", parse_rt(&[0, 1], 0, 2)),
            ("px truncated", parse_px(&[0, 1, 2, b'm'], 0, 4)),
            ("gpos truncated", parse_gpos(&[3, b'1', b'.', b'0'], 0, 4)),
            ("loc wrong length", parse_loc(&[0; 15], 0, 15)),
            (
                "nxt invalid bitmap",
                parse_nxt(&[3, b'n', b'e', b'x', 0, 0, 0], 0, 7),
            ),
            ("a6 prefix too long", parse_a6(&[129], 0, 1)),
            ("sink truncated", parse_sink(&[0], 0, 1)),
            ("apl header truncated", parse_apl(&[0, 1, 24], 0, 3)),
            ("uid short", parse_uid(&[0, 1, 2], 0, 3)),
            ("gid short", parse_gid(&[0, 1, 2], 0, 3)),
            ("ixfr non-empty", parse_ixfr(0, 1)),
            ("axfr non-empty", parse_axfr(0, 1)),
            ("mailb non-empty", parse_mailb(0, 1)),
            ("maila non-empty", parse_maila(0, 1)),
            ("any non-empty", parse_any(0, 1)),
        ];

        for (name, result) in cases {
            assert!(result.is_err(), "{name} should fail");
        }
    }
}
