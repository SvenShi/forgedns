/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use super::*;

/// Decode an IPv4 address RDATA from exactly 4 octets as defined by RFC 1035 section 3.4.1.
pub(super) fn parse_a(packet: &[u8], start: usize, end: usize) -> Result<RData> {
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

/// Decode an IPv6 address RDATA from exactly 16 octets as defined by RFC 3596 section 2.2.
pub(super) fn parse_aaaa(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    if end - start != 16 {
        return Err(DnsError::protocol("invalid AAAA rdata length"));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&packet[start..end]);
    Ok(RData::AAAA(AAAA(Ipv6Addr::from(bytes))))
}

/// Decode a compressed domain-name-only RDATA such as CNAME per RFC 1035 section 3.3.1.
pub(super) fn parse_cname(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::CNAME(CNAME(parse_name(
        packet, start, end, "CNAME",
    )?)))
}

/// Decode an NS target name per RFC 1035 section 3.3.11.
pub(super) fn parse_ns(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NS(NS(parse_name(packet, start, end, "NS")?)))
}

/// Decode a PTR target name per RFC 1035 section 3.3.12.
pub(super) fn parse_ptr(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::PTR(PTR(parse_name(packet, start, end, "PTR")?)))
}

/// Decode MX preference plus exchange name per RFC 1035 section 3.3.9.
pub(super) fn parse_mx(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (preference, exchange) = parse_mx_rdata(packet, start, end)?;
    Ok(RData::MX(MX::new(preference, exchange)))
}

/// Decode SRV priority, weight, port, and target name per RFC 2782 section 3.
pub(super) fn parse_srv(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (priority, weight, port, target) = parse_srv_rdata(packet, start, end)?;
    Ok(RData::SRV(SRV::new(priority, weight, port, target)))
}

/// Decode NAPTR order, preference, character-strings, and replacement name per RFC 3403 section 4.1.
pub(super) fn parse_naptr(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (order, preference, flags, services, regexp, replacement) =
        parse_naptr_rdata(packet, start, end)?;
    Ok(RData::NAPTR(NAPTR::new(
        order,
        preference,
        flags,
        services,
        regexp,
        replacement,
    )))
}

/// Decode CAA flags, tag, and value per RFC 8659 section 4.1.
pub(super) fn parse_caa(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (flag, tag, value) = parse_caa_rdata(packet, start, end)?;
    Ok(RData::CAA(CAA::new(flag, tag, value)))
}

/// Decode TXT RDATA as a raw sequence of DNS character-strings per RFC 1035 section 3.3.14.
pub(super) fn parse_txt(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::TXT(parse_txt_wire(packet, start, end)?))
}

/// Decode SPF using the TXT wire format from RFC 7208 section 3.3.
pub(super) fn parse_spf(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::SPF(SPF(parse_txt_wire(packet, start, end)?)))
}

/// Decode AVC using the TXT-like wire format carried in DNS character-strings.
pub(super) fn parse_avc(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::AVC(AVC(parse_txt_wire(packet, start, end)?)))
}

/// Decode RESINFO using the TXT-like wire format from RFC 9606 section 4.1.
pub(super) fn parse_resinfo(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::RESINFO(RESINFO(parse_txt_wire(packet, start, end)?)))
}

/// Decode DOA as an opaque octet string payload per RFC 8495 section 2.
pub(super) fn parse_doa(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::DOA(DOA(copy_boxed(packet, start, end))))
}

/// Decode SOA names and timers per RFC 1035 section 3.3.13.
pub(super) fn parse_soa(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (mname, rname, serial, refresh, retry, expire, minimum) =
        parse_soa_rdata(packet, start, end)?;
    Ok(RData::SOA(SOA::new(
        mname, rname, serial, refresh, retry, expire, minimum,
    )))
}

/// Decode OPT RDATA and its surrounding pseudo-RR metadata per RFC 6891 section 6.1.2.
pub(super) fn parse_opt(
    packet: &[u8],
    owner_name: &Name,
    class: u16,
    ttl: u32,
    start: usize,
    end: usize,
) -> Result<RData> {
    if !owner_name.is_root() {
        return Err(DnsError::protocol("invalid OPT owner name"));
    }
    Ok(RData::OPT(OPT(parse_opt_rdata(
        packet, class, ttl, start, end,
    )?)))
}

/// Encode an IPv4 address RDATA as 4 octets per RFC 1035 section 3.4.1.
pub(super) fn encode_a(addr: &A, out: &mut Vec<u8>) {
    out.extend_from_slice(&addr.0.octets());
}

/// Encode an IPv6 address RDATA as 16 octets per RFC 3596 section 2.2.
pub(super) fn encode_aaaa(addr: &AAAA, out: &mut Vec<u8>) {
    out.extend_from_slice(&addr.0.octets());
}

/// Encode a single domain-name RDATA field, optionally enabling RFC 1035 name compression.
pub(super) fn encode_name_rdata<'a>(
    out: &mut Vec<u8>,
    name: &'a Name,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
    compress: bool,
) -> Result<()> {
    write_name(out, name, compress)
}

/// Encode MX preference + exchange wire data per RFC 1035 section 3.3.9.
/// Encode MX preference and exchange name per RFC 1035 section 3.3.9.
pub(super) fn encode_mx<'a>(
    value: &'a MX,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.preference());
    write_name(out, value.exchange(), true)
}

/// Encode SRV priority/weight/port/target wire data per RFC 2782 section 3.
/// Encode SRV priority, weight, port, and uncompressed target name per RFC 2782 section 3.
pub(super) fn encode_srv<'a>(
    value: &'a SRV,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.priority());
    push_u16(out, value.weight());
    push_u16(out, value.port());
    write_name(out, value.target(), false)
}

/// Encode NAPTR wire data per RFC 3403 section 4.1.
/// Encode NAPTR order, preference, character-strings, and replacement name per RFC 3403 section 4.1.
pub(super) fn encode_naptr<'a>(
    value: &'a NAPTR,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.order());
    push_u16(out, value.preference());
    encode_character_string(out, value.flags(), "NAPTR flags")?;
    encode_character_string(out, value.services(), "NAPTR services")?;
    encode_character_string(out, value.regexp(), "NAPTR regexp")?;
    write_name(out, value.replacement(), false)
}

/// Encode CAA flag, tag length, tag, and value per RFC 8659 section 4.1.
pub(super) fn encode_caa(value: &CAA, out: &mut Vec<u8>) -> Result<()> {
    if value.tag().is_empty() || value.tag().len() > u8::MAX as usize {
        return Err(DnsError::protocol("invalid CAA tag length"));
    }
    out.push(value.flag());
    out.push(value.tag().len() as u8);
    out.extend_from_slice(value.tag());
    out.extend_from_slice(value.value());
    Ok(())
}

/// Encode TXT wire data as the original DNS character-string sequence per RFC 1035 section 3.3.14.
pub(super) fn encode_txt(value: &TXT, out: &mut Vec<u8>) {
    out.extend_from_slice(value.wire_data());
}

/// Encode SPF using the TXT-compatible wire representation from RFC 7208 section 3.3.
pub(super) fn encode_spf(value: &SPF, out: &mut Vec<u8>) {
    out.extend_from_slice(value.0.wire_data());
}

/// Encode AVC using the stored TXT-compatible character-string wire data.
pub(super) fn encode_avc(value: &AVC, out: &mut Vec<u8>) {
    out.extend_from_slice(value.0.wire_data());
}

/// Encode RESINFO using the stored TXT-compatible character-string wire data.
pub(super) fn encode_resinfo(value: &RESINFO, out: &mut Vec<u8>) {
    out.extend_from_slice(value.0.wire_data());
}

/// Encode DOA as its opaque octet payload per RFC 8495 section 2.
pub(super) fn encode_doa(value: &DOA, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode SOA wire data per RFC 1035 section 3.3.13.
pub(super) fn encode_soa<'a>(
    value: &'a SOA,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.mname(), true)?;
    write_name(out, value.rname(), true)?;
    push_u32(out, value.serial());
    push_u32(out, value.refresh() as u32);
    push_u32(out, value.retry() as u32);
    push_u32(out, value.expire() as u32);
    push_u32(out, value.minimum());
    Ok(())
}

/// Encode OPT option data per RFC 6891 section 6.1.2.
pub(super) fn encode_opt(value: &OPT, out: &mut Vec<u8>) -> Result<()> {
    for option in value.options() {
        encode_edns_option(out, option)?;
    }
    Ok(())
}

/// Parse MX preference and exchange while requiring the RDATA to end exactly after the name.
fn parse_mx_rdata(packet: &[u8], start: usize, end: usize) -> Result<(u16, Name)> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid MX rdata length"));
    }
    let preference = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let (exchange, next) = Name::parse(packet, start + 2)?;
    if next != end {
        return Err(DnsError::protocol("invalid MX rdata length"));
    }
    Ok((preference, exchange))
}

/// Parse SOA MNAME, RNAME, and the five 32-bit timer fields per RFC 1035 section 3.3.13.
fn parse_soa_rdata(
    packet: &[u8],
    start: usize,
    end: usize,
) -> Result<(Name, Name, u32, i32, i32, i32, u32)> {
    let (mname, next) = Name::parse(packet, start)?;
    let (rname, cursor) = Name::parse(packet, next)?;
    if cursor + 20 != end {
        return Err(DnsError::protocol("invalid SOA rdata length"));
    }
    Ok((
        mname,
        rname,
        u32::from_be_bytes([
            packet[cursor],
            packet[cursor + 1],
            packet[cursor + 2],
            packet[cursor + 3],
        ]),
        u32::from_be_bytes([
            packet[cursor + 4],
            packet[cursor + 5],
            packet[cursor + 6],
            packet[cursor + 7],
        ]) as i32,
        u32::from_be_bytes([
            packet[cursor + 8],
            packet[cursor + 9],
            packet[cursor + 10],
            packet[cursor + 11],
        ]) as i32,
        u32::from_be_bytes([
            packet[cursor + 12],
            packet[cursor + 13],
            packet[cursor + 14],
            packet[cursor + 15],
        ]) as i32,
        u32::from_be_bytes([
            packet[cursor + 16],
            packet[cursor + 17],
            packet[cursor + 18],
            packet[cursor + 19],
        ]),
    ))
}

/// Parse SRV priority, weight, port, and target name per RFC 2782 section 3.
fn parse_srv_rdata(packet: &[u8], start: usize, end: usize) -> Result<(u16, u16, u16, Name)> {
    if start + 6 > end {
        return Err(DnsError::protocol("invalid SRV rdata length"));
    }
    let priority = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let weight = u16::from_be_bytes([packet[start + 2], packet[start + 3]]);
    let port = u16::from_be_bytes([packet[start + 4], packet[start + 5]]);
    let (target, next) = Name::parse(packet, start + 6)?;
    if next != end {
        return Err(DnsError::protocol("invalid SRV rdata length"));
    }
    Ok((priority, weight, port, target))
}

/// Parse NAPTR fixed-width fields, three character-strings, and a replacement name per RFC 3403.
fn parse_naptr_rdata(
    packet: &[u8],
    start: usize,
    end: usize,
) -> Result<(u16, u16, Box<[u8]>, Box<[u8]>, Box<[u8]>, Name)> {
    if start + 4 > end {
        return Err(DnsError::protocol("invalid NAPTR rdata length"));
    }
    let order = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let preference = u16::from_be_bytes([packet[start + 2], packet[start + 3]]);
    let (flags, cursor) = parse_character_string(packet, start + 4, end)?;
    let (services, cursor) = parse_character_string(packet, cursor, end)?;
    let (regexp, cursor) = parse_character_string(packet, cursor, end)?;
    let (replacement, next) = Name::parse(packet, cursor)?;
    if next != end {
        return Err(DnsError::protocol("invalid NAPTR rdata length"));
    }
    Ok((order, preference, flags, services, regexp, replacement))
}

/// Parse CAA flag, tag-length-prefixed tag, and trailing value bytes per RFC 8659 section 4.1.
fn parse_caa_rdata(packet: &[u8], start: usize, end: usize) -> Result<(u8, Box<[u8]>, Box<[u8]>)> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid CAA rdata length"));
    }
    let flag = packet[start];
    let tag_len = packet[start + 1] as usize;
    let tag_start = start + 2;
    let tag_end = tag_start + tag_len;
    if tag_len == 0 || tag_end > end {
        return Err(DnsError::protocol("invalid CAA rdata length"));
    }
    Ok((
        flag,
        copy_boxed(packet, tag_start, tag_end),
        copy_boxed(packet, tag_end, end),
    ))
}

fn parse_txt_wire(packet: &[u8], start: usize, end: usize) -> Result<TXT> {
    let mut cursor = start;
    while cursor < end {
        let len = *packet
            .get(cursor)
            .ok_or_else(|| DnsError::protocol("invalid TXT rdata length"))?
            as usize;
        cursor += 1;
        if cursor + len > end {
            return Err(DnsError::protocol("invalid TXT rdata length"));
        }
        cursor += len;
    }
    Ok(TXT::new(copy_boxed(packet, start, end)))
}

/// Parse an OPT pseudo-RR payload from CLASS, TTL, and EDNS options per RFC 6891 section 6.1.2.
fn parse_opt_rdata(packet: &[u8], class: u16, ttl: u32, start: usize, end: usize) -> Result<Edns> {
    let mut edns = Edns::new();
    edns.set_udp_payload_size(class);
    edns.set_ext_rcode((ttl >> 24) as u8);
    edns.set_version((ttl >> 16) as u8);
    let flags = EdnsFlags::from((ttl & 0x0000_FFFFu32) as u16);
    *edns.flags_mut() = flags;
    let mut cursor = start;
    while cursor < end {
        if cursor + 4 > end {
            return Err(DnsError::protocol("invalid OPT rdata length"));
        }
        let code = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let len = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]) as usize;
        let data_start = cursor + 4;
        let data_end = data_start + len;
        if data_end > end {
            return Err(DnsError::protocol("invalid OPT rdata length"));
        }
        edns.insert(parse_edns_option(code, &packet[data_start..data_end]));
        cursor = data_end;
    }
    Ok(edns)
}

fn parse_edns_option(code: u16, data: &[u8]) -> EdnsOption {
    match EdnsCode::from(code) {
        EdnsCode::Llq => parse_llq(data)
            .map(EdnsOption::Llq)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::UpdateLease => parse_update_lease(data)
            .map(EdnsOption::UpdateLease)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::Nsid => EdnsOption::Nsid(EdnsNsid::new(data.to_vec())),
        EdnsCode::Esu => EdnsOption::Esu(EdnsEsu::new(data.to_vec())),
        EdnsCode::Dau => EdnsOption::Dau(EdnsAlgorithmList::new(data.to_vec())),
        EdnsCode::Dhu => EdnsOption::Dhu(EdnsAlgorithmList::new(data.to_vec())),
        EdnsCode::N3u => EdnsOption::N3u(EdnsAlgorithmList::new(data.to_vec())),
        EdnsCode::Subnet => parse_client_subnet(data)
            .map(EdnsOption::Subnet)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::Expire => parse_expire(data)
            .map(EdnsOption::Expire)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::Cookie => EdnsOption::Cookie(EdnsCookie::new(data.to_vec())),
        EdnsCode::TcpKeepalive => parse_tcp_keepalive(data)
            .map(EdnsOption::TcpKeepalive)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::Padding => EdnsOption::Padding(EdnsPadding::new(data.to_vec())),
        EdnsCode::ExtendedDnsError => parse_extended_dns_error(data)
            .map(EdnsOption::ExtendedDnsError)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::ReportChannel => parse_report_channel(data)
            .map(EdnsOption::ReportChannel)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::ZoneVersion => parse_zone_version(data)
            .map(EdnsOption::ZoneVersion)
            .unwrap_or_else(|| EdnsOption::Local(EdnsLocal::new(code, data.to_vec()))),
        EdnsCode::Reserved
        | EdnsCode::Chain
        | EdnsCode::KeyTag
        | EdnsCode::ClientTag
        | EdnsCode::ServerTag
        | EdnsCode::Unknown(_) => EdnsOption::Local(EdnsLocal::new(code, data.to_vec())),
    }
}

fn parse_llq(data: &[u8]) -> Option<EdnsLlq> {
    if data.len() < 18 {
        return None;
    }
    Some(EdnsLlq::new(
        read_u16_be(data, 0),
        read_u16_be(data, 2),
        read_u16_be(data, 4),
        u64::from_be_bytes(data[6..14].try_into().ok()?),
        u32::from_be_bytes(data[14..18].try_into().ok()?),
    ))
}

fn parse_update_lease(data: &[u8]) -> Option<EdnsUpdateLease> {
    match data.len() {
        4 => Some(EdnsUpdateLease::new(
            u32::from_be_bytes(data[0..4].try_into().ok()?),
            None,
        )),
        8 => Some(EdnsUpdateLease::new(
            u32::from_be_bytes(data[0..4].try_into().ok()?),
            Some(u32::from_be_bytes(data[4..8].try_into().ok()?)),
        )),
        _ => None,
    }
}

fn parse_client_subnet(data: &[u8]) -> Option<ClientSubnet> {
    if data.len() < 4 {
        return None;
    }
    let family = u16::from_be_bytes([data[0], data[1]]);
    let source_prefix = data[2];
    let scope_prefix = data[3];
    let max_prefix = match family {
        1 => 32u8,
        2 => 128u8,
        _ => return None,
    };
    if source_prefix > max_prefix || scope_prefix > max_prefix {
        return None;
    }
    let required_len = usize::from(source_prefix).div_ceil(8);
    let address = &data[4..];
    if address.len() != required_len {
        return None;
    }
    let addr = parse_subnet_addr(family, address)?;
    Some(ClientSubnet::new(addr, source_prefix, scope_prefix))
}

fn parse_subnet_addr(family: u16, address: &[u8]) -> Option<IpAddr> {
    match family {
        1 => {
            if address.len() > 4 {
                return None;
            }
            let mut octets = [0u8; 4];
            octets[..address.len()].copy_from_slice(address);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        2 => {
            if address.len() > 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets[..address.len()].copy_from_slice(address);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_expire(data: &[u8]) -> Option<EdnsExpire> {
    match data.len() {
        0 => Some(EdnsExpire::empty()),
        4 => Some(EdnsExpire::new(u32::from_be_bytes(
            data[0..4].try_into().ok()?,
        ))),
        _ => None,
    }
}

fn parse_tcp_keepalive(data: &[u8]) -> Option<EdnsTcpKeepalive> {
    match data.len() {
        0 => Some(EdnsTcpKeepalive::new(None)),
        2 => Some(EdnsTcpKeepalive::new(Some(read_u16_be(data, 0)))),
        _ => None,
    }
}

fn parse_extended_dns_error(data: &[u8]) -> Option<EdnsExtendedDnsError> {
    if data.len() < 2 {
        return None;
    }
    Some(EdnsExtendedDnsError::new(
        read_u16_be(data, 0),
        data[2..].to_vec(),
    ))
}

fn parse_report_channel(data: &[u8]) -> Option<EdnsReportChannel> {
    let (agent_domain, next) = Name::parse(data, 0).ok()?;
    if next != data.len() {
        return None;
    }
    Some(EdnsReportChannel::new(agent_domain))
}

fn parse_zone_version(data: &[u8]) -> Option<EdnsZoneVersion> {
    if data.len() < 2 {
        return None;
    }
    Some(EdnsZoneVersion::new(data[0], data[1], data[2..].to_vec()))
}

/// Encode a single EDNS option as code, length, and option payload per RFC 6891 section 6.1.2.
pub(super) fn encode_edns_option(out: &mut Vec<u8>, option: &EdnsOption) -> Result<()> {
    match option {
        EdnsOption::Llq(value) => {
            push_u16(out, u16::from(EdnsCode::Llq));
            push_u16(out, 18);
            push_u16(out, value.version());
            push_u16(out, value.opcode());
            push_u16(out, value.error());
            out.extend_from_slice(&value.id().to_be_bytes());
            push_u32(out, value.lease_life());
        }
        EdnsOption::UpdateLease(value) => {
            push_u16(out, u16::from(EdnsCode::UpdateLease));
            push_u16(out, if value.key_lease().is_some() { 8 } else { 4 });
            push_u32(out, value.lease());
            if let Some(key_lease) = value.key_lease() {
                push_u32(out, key_lease);
            }
        }
        EdnsOption::Nsid(value) => {
            push_u16(out, u16::from(EdnsCode::Nsid));
            push_u16(
                out,
                u16::try_from(value.nsid().len())
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.extend_from_slice(value.nsid());
        }
        EdnsOption::Esu(value) => {
            push_u16(out, u16::from(EdnsCode::Esu));
            push_u16(
                out,
                u16::try_from(value.uri().len())
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.extend_from_slice(value.uri());
        }
        EdnsOption::Dau(value) => encode_edns_algorithm_option(out, EdnsCode::Dau, value)?,
        EdnsOption::Dhu(value) => encode_edns_algorithm_option(out, EdnsCode::Dhu, value)?,
        EdnsOption::N3u(value) => encode_edns_algorithm_option(out, EdnsCode::N3u, value)?,
        EdnsOption::Subnet(value) => {
            push_u16(out, u16::from(EdnsCode::Subnet));
            let (family, max_prefix) = match value.addr() {
                IpAddr::V4(_) => (1u16, 32u8),
                IpAddr::V6(_) => (2u16, 128u8),
            };
            let source_prefix = value.source_prefix().min(max_prefix);
            let scope_prefix = value.scope_prefix().min(max_prefix);
            let required_len = usize::from(source_prefix).div_ceil(8);
            let data_len = 4usize
                .checked_add(required_len)
                .ok_or_else(|| DnsError::protocol("edns subnet option length overflow"))?;
            push_u16(
                out,
                u16::try_from(data_len)
                    .map_err(|_| DnsError::protocol("edns subnet option too long"))?,
            );
            push_u16(out, family);
            out.push(source_prefix);
            out.push(scope_prefix);
            match value.addr() {
                IpAddr::V4(addr) => {
                    write_masked_addr_prefix(out, &addr.octets(), required_len, source_prefix)
                }
                IpAddr::V6(addr) => {
                    write_masked_addr_prefix(out, &addr.octets(), required_len, source_prefix)
                }
            }
        }
        EdnsOption::Expire(value) => {
            push_u16(out, u16::from(EdnsCode::Expire));
            if value.is_empty() {
                push_u16(out, 0);
            } else {
                push_u16(out, 4);
                push_u32(out, value.expire());
            }
        }
        EdnsOption::Cookie(value) => {
            push_u16(out, u16::from(EdnsCode::Cookie));
            push_u16(
                out,
                u16::try_from(value.cookie().len())
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.extend_from_slice(value.cookie());
        }
        EdnsOption::TcpKeepalive(value) => {
            push_u16(out, u16::from(EdnsCode::TcpKeepalive));
            if let Some(timeout) = value.timeout() {
                push_u16(out, 2);
                push_u16(out, timeout);
            } else {
                push_u16(out, 0);
            }
        }
        EdnsOption::Padding(value) => {
            push_u16(out, u16::from(EdnsCode::Padding));
            push_u16(
                out,
                u16::try_from(value.padding().len())
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.extend_from_slice(value.padding());
        }
        EdnsOption::ExtendedDnsError(value) => {
            push_u16(out, u16::from(EdnsCode::ExtendedDnsError));
            let data_len = 2usize
                .checked_add(value.extra_text().len())
                .ok_or_else(|| DnsError::protocol("edns option payload too long"))?;
            push_u16(
                out,
                u16::try_from(data_len)
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            push_u16(out, value.info_code());
            out.extend_from_slice(value.extra_text());
        }
        EdnsOption::ReportChannel(value) => {
            push_u16(out, u16::from(EdnsCode::ReportChannel));
            push_u16(
                out,
                u16::try_from(value.agent_domain().bytes_len())
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.extend_from_slice(value.agent_domain().wire());
        }
        EdnsOption::ZoneVersion(value) => {
            push_u16(out, u16::from(EdnsCode::ZoneVersion));
            let data_len = 2usize
                .checked_add(value.version().len())
                .ok_or_else(|| DnsError::protocol("edns option payload too long"))?;
            push_u16(
                out,
                u16::try_from(data_len)
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.push(value.label_count());
            out.push(value.version_type());
            out.extend_from_slice(value.version());
        }
        EdnsOption::Local(local) => {
            push_u16(out, local.code());
            push_u16(
                out,
                u16::try_from(local.data().len())
                    .map_err(|_| DnsError::protocol("edns option payload too long"))?,
            );
            out.extend_from_slice(local.data());
        }
    }
    Ok(())
}

fn encode_edns_algorithm_option(
    out: &mut Vec<u8>,
    code: EdnsCode,
    value: &EdnsAlgorithmList,
) -> Result<()> {
    push_u16(out, u16::from(code));
    push_u16(
        out,
        u16::try_from(value.algorithms().len())
            .map_err(|_| DnsError::protocol("edns option payload too long"))?,
    );
    out.extend_from_slice(value.algorithms());
    Ok(())
}

fn write_masked_addr_prefix(
    out: &mut Vec<u8>,
    octets: &[u8],
    required_len: usize,
    source_prefix: u8,
) {
    if required_len == 0 {
        return;
    }
    if required_len > 1 {
        out.extend_from_slice(&octets[..required_len - 1]);
    }
    let mut last = octets[required_len - 1];
    let tail_bits = source_prefix % 8;
    if tail_bits != 0 {
        let mask = (!0u8) << (8 - tail_bits);
        last &= mask;
    }
    out.push(last);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_name_raw(out: &mut Vec<u8>, name: &Name, _compress: bool) -> Result<()> {
        out.extend_from_slice(name.wire());
        Ok(())
    }

    #[test]
    fn basic_rdata_parse_encode_roundtrip() {
        let cases: Vec<(&[u8], fn(&[u8], usize, usize) -> Result<RData>)> = vec![
            (&[1, 2, 3, 4], parse_a),
            (
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                parse_aaaa,
            ),
            (&[5, b'a', b'l', b'i', b'a', b's', 0], parse_cname),
            (&[2, b'n', b's', 0], parse_ns),
            (&[3, b'p', b't', b'r', 0], parse_ptr),
            (&[0, 10, 2, b'm', b'x', 0], parse_mx),
            (&[0, 1, 0, 2, 1, 187, 3, b's', b'r', b'v', 0], parse_srv),
            (
                &[
                    0, 10, 0, 20, 1, b'U', 7, b'E', b'2', b'U', b'+', b's', b'i', b'p', 4, b'r',
                    b'e', b'g', b'e', 4, b'n', b'a', b'p', b't', 0,
                ],
                parse_naptr,
            ),
            (&[0, 5, b'i', b's', b's', b'u', b'e', b'v'], parse_caa),
            (&[5, b'h', b'e', b'l', b'l', b'o'], parse_txt),
            (
                &[
                    11, b'v', b'=', b's', b'p', b'f', b'1', b' ', b'-', b'a', b'l', b'l',
                ],
                parse_spf,
            ),
            (&[3, b'a', b'v', b'c'], parse_avc),
            (
                &[7, b'r', b'e', b's', b'i', b'n', b'f', b'o'],
                parse_resinfo,
            ),
            (&[0xde, 0xad], parse_doa),
            (
                &[
                    2, b'n', b's', 0, 10, b'h', b'o', b's', b't', b'm', b'a', b's', b't', b'e',
                    b'r', 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
                ],
                parse_soa,
            ),
        ];

        for (packet, parse) in cases {
            let parsed = parse(packet, 0, packet.len()).unwrap();
            let mut encoded = Vec::new();
            match &parsed {
                RData::A(value) => encode_a(value, &mut encoded),
                RData::AAAA(value) => encode_aaaa(value, &mut encoded),
                RData::CNAME(value) => {
                    encode_name_rdata(&mut encoded, &value.0, &mut write_name_raw, true).unwrap()
                }
                RData::NS(value) => {
                    encode_name_rdata(&mut encoded, &value.0, &mut write_name_raw, true).unwrap()
                }
                RData::PTR(value) => {
                    encode_name_rdata(&mut encoded, &value.0, &mut write_name_raw, true).unwrap()
                }
                RData::MX(value) => encode_mx(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::SRV(value) => encode_srv(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::NAPTR(value) => {
                    encode_naptr(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::CAA(value) => encode_caa(value, &mut encoded).unwrap(),
                RData::TXT(value) => encode_txt(value, &mut encoded),
                RData::SPF(value) => encode_spf(value, &mut encoded),
                RData::AVC(value) => encode_avc(value, &mut encoded),
                RData::RESINFO(value) => encode_resinfo(value, &mut encoded),
                RData::DOA(value) => encode_doa(value, &mut encoded),
                RData::SOA(value) => encode_soa(value, &mut encoded, &mut write_name_raw).unwrap(),
                other => panic!("unexpected basic rdata variant: {other:?}"),
            }
            assert_eq!(encoded, packet);
        }
    }

    #[test]
    fn opt_rdata_parse_encode_roundtrip() {
        let packet = [
            0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 24, 0, 192, 0, 2, // ECS
            0xfd, 0xe9, 0x00, 0x03, 1, 2, 3, // unknown
        ];
        let parsed = parse_opt(&packet, &Name::root(), 1400, 0x8000, 0, packet.len()).unwrap();
        let mut encoded = Vec::new();
        match &parsed {
            RData::OPT(value) => encode_opt(value, &mut encoded).unwrap(),
            other => panic!("unexpected opt variant: {other:?}"),
        }
        assert_eq!(encoded, packet);
    }

    #[test]
    fn edns_option_parse_encode_roundtrip() {
        let cases: &[(u16, &[u8])] = &[
            (0x0008, &[0x00, 0x01, 24, 0, 192, 0, 2]),
            (0xfde9, &[1, 2, 3, 4]),
        ];

        for (code, data) in cases {
            let parsed = parse_edns_option(*code, data);
            let mut encoded = Vec::new();
            encode_edns_option(&mut encoded, &parsed).unwrap();

            let mut expected = Vec::new();
            push_u16(&mut expected, *code);
            push_u16(&mut expected, data.len() as u16);
            expected.extend_from_slice(data);

            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn parse_opt_preserves_ttl_fields() {
        let parsed = parse_opt(&[], &Name::root(), 1232, 0xABCD_8000, 0, 0).unwrap();
        let RData::OPT(value) = parsed else {
            panic!("expected OPT");
        };

        assert_eq!(value.0.udp_payload_size(), 1232);
        assert_eq!(value.0.ext_rcode(), 0xAB);
        assert_eq!(value.0.version(), 0xCD);
        assert!(value.0.flags().dnssec_ok);
    }

    #[test]
    fn basic_rdata_rejects_invalid_wire_matrix() {
        let root = Name::root();
        let non_root = Name::from_ascii("example.com.").unwrap();
        let cases: Vec<(&str, Result<RData>)> = vec![
            ("a short", parse_a(&[1, 2, 3], 0, 3)),
            ("aaaa short", parse_aaaa(&[0; 15], 0, 15)),
            ("mx truncated", parse_mx(&[0, 10], 0, 2)),
            (
                "mx trailing bytes",
                parse_mx(&[0, 10, 2, b'm', b'x', 0, 1], 0, 7),
            ),
            (
                "srv truncated fixed header",
                parse_srv(&[0, 1, 0, 2, 0], 0, 5),
            ),
            (
                "srv truncated target",
                parse_srv(&[0, 1, 0, 2, 0, 80, 3, b's'], 0, 8),
            ),
            (
                "naptr truncated",
                parse_naptr(&[0, 1, 0, 2, 1, b'U', 1], 0, 7),
            ),
            ("caa empty tag", parse_caa(&[0, 0], 0, 2)),
            ("txt bad string len", parse_txt(&[5, b'h', b'e'], 0, 3)),
            (
                "soa truncated",
                parse_soa(&[2, b'n', b's', 0, 0, 0, 0], 0, 7),
            ),
            (
                "opt non-root owner",
                parse_opt(&[], &non_root, 1232, 0, 0, 0),
            ),
            (
                "opt option overrun",
                parse_opt(&[0, 8, 0, 10, 1, 2], &root, 1232, 0, 0, 6),
            ),
        ];

        for (name, result) in cases {
            assert!(result.is_err(), "{name} should fail");
        }
    }
}
