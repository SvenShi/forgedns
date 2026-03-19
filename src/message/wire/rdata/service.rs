/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use super::*;

fn validate_svc_param_key_order(last_key: Option<u16>, key: u16) -> Result<()> {
    if key == u16::MAX {
        return Err(DnsError::protocol("svcparamkey 65535 is reserved"));
    }
    if last_key.is_some_and(|prev| key <= prev) {
        return Err(DnsError::protocol(
            "SVCB parameter keys must be strictly increasing",
        ));
    }
    Ok(())
}

/// Canonically encode a single SvcParam value according to its key-specific wire format from RFC 9460.
fn encode_svc_param_wire(param: &SvcParam) -> Result<Box<[u8]>> {
    let value = match param.parsed() {
        SvcParamValue::Mandatory(keys) => {
            let mut keys = keys.clone();
            keys.sort_unstable();
            let mut out = Vec::with_capacity(keys.len() * 2);
            for key in keys {
                push_u16(&mut out, key);
            }
            out.into_boxed_slice()
        }
        SvcParamValue::Alpn(ids) => {
            let mut out = Vec::new();
            for id in ids {
                encode_character_string(&mut out, id, "SVCB ALPN id")?;
            }
            out.into_boxed_slice()
        }
        SvcParamValue::NoDefaultAlpn | SvcParamValue::Ohttp => Box::default(),
        SvcParamValue::Port(port) => Box::from(port.to_be_bytes()),
        SvcParamValue::Ipv4Hint(hints) => {
            let mut out = Vec::with_capacity(hints.len() * 4);
            for hint in hints {
                out.extend_from_slice(&hint.octets());
            }
            out.into_boxed_slice()
        }
        SvcParamValue::Ech(data) => data.clone(),
        SvcParamValue::Ipv6Hint(hints) => {
            let mut out = Vec::with_capacity(hints.len() * 16);
            for hint in hints {
                out.extend_from_slice(&hint.octets());
            }
            out.into_boxed_slice()
        }
        SvcParamValue::DohPath(path) => path.clone(),
        SvcParamValue::Unknown => param.value().into(),
    };
    Ok(value)
}

/// Encode the shared SVCB/HTTPS body format: priority, target name, then canonically ordered params.
fn encode_svcb_like<'a>(
    priority: u16,
    target: &'a Name,
    params: &'a [SvcParam],
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, priority);
    write_name(out, target, false)?;

    let mut params: Vec<_> = params.iter().collect();
    params.sort_unstable_by_key(|param| param.key());

    let mut last_key = None;
    for param in params {
        validate_svc_param_key_order(last_key, param.key())?;
        let value = encode_svc_param_wire(param)?;
        push_u16(out, param.key());
        push_u16(
            out,
            u16::try_from(value.len())
                .map_err(|_| DnsError::protocol("SVCB parameter exceeds u16 length"))?,
        );
        out.extend_from_slice(&value);
        last_key = Some(param.key());
    }

    Ok(())
}

/// Decode KX preference plus exchanger name per RFC 2230 section 3.
pub(super) fn parse_kx(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (preference, exchanger) = parse_u16_name(packet, start, end, "KX")?;
    Ok(RData::KX(KX::new(preference, exchanger)))
}

/// Decode IPSECKEY precedence, gateway selector, and public key per RFC 4025 section 2.1.
pub(super) fn parse_ipseckey(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::IPSECKEY(parse_ipseckey_like_rdata(
        packet, start, end, "IPSECKEY",
    )?))
}

/// Decode SVCB wire data per RFC 9460 section 2.
pub(super) fn parse_svcb(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::SVCB(parse_svcb_rdata(packet, start, end)?))
}

/// Decode HTTPS wire data per RFC 9460 section 9.
pub(super) fn parse_https(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::HTTPS(HTTPS(parse_svcb_rdata(packet, start, end)?)))
}

/// Decode AMTRELAY precedence, gateway selector, and gateway bytes per RFC 8777 section 4.2.
pub(super) fn parse_amtrelay(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::AMTRELAY(parse_amtrelay_rdata(packet, start, end)?))
}

/// Decode URI priority, weight, and target octets per RFC 7553 section 4.
pub(super) fn parse_uri(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::URI(parse_uri_rdata(packet, start, end)?))
}

/// Decode NID preference and 64-bit node identifier per RFC 6742 section 2.1.
pub(super) fn parse_nid(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NID(parse_nid_rdata(packet, start, end)?))
}

/// Decode L32 preference and IPv4 locator per RFC 6742 section 2.2.
pub(super) fn parse_l32(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::L32(parse_l32_rdata(packet, start, end)?))
}

/// Decode L64 preference and 64-bit locator per RFC 6742 section 2.3.
pub(super) fn parse_l64(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::L64(parse_l64_rdata(packet, start, end)?))
}

/// Decode LP preference and FQDN per RFC 6742 section 2.4.
pub(super) fn parse_lp(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::LP(parse_lp_rdata(packet, start, end)?))
}

/// Decode an EUI-48 identifier from exactly 6 octets per RFC 7043 section 4.
pub(super) fn parse_eui48(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::EUI48(parse_eui48_rdata(packet, start, end)?))
}

/// Decode an EUI-64 identifier from exactly 8 octets per RFC 7043 section 4.
pub(super) fn parse_eui64(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::EUI64(parse_eui64_rdata(packet, start, end)?))
}

/// Encode KX preference and exchanger name per RFC 2230 section 3.
pub(super) fn encode_kx<'a>(
    value: &'a KX,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.preference());
    write_name(out, value.exchanger(), false)
}

/// Encode IPSECKEY precedence, gateway selector bytes, and public key per RFC 4025 section 2.1.
pub(super) fn encode_ipseckey(value: &IPSECKEY, out: &mut Vec<u8>) {
    out.push(value.precedence());
    out.push(value.gateway_type());
    out.push(value.algorithm());
    out.extend_from_slice(value.gateway());
    out.extend_from_slice(value.public_key());
}

/// Encode SVCB wire data using canonical parameter ordering from RFC 9460 section 2.2.
pub(super) fn encode_svcb<'a>(
    value: &'a SVCB,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    encode_svcb_like(
        value.priority(),
        value.target(),
        value.params(),
        out,
        write_name,
    )
}

/// Encode HTTPS wire data using the SVCB parameter rules from RFC 9460 section 9.
pub(super) fn encode_https<'a>(
    value: &'a HTTPS,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    encode_svcb_like(
        value.0.priority(),
        value.0.target(),
        value.0.params(),
        out,
        write_name,
    )
}

/// Encode AMTRELAY precedence, gateway type, and gateway bytes per RFC 8777 section 4.2.
pub(super) fn encode_amtrelay(value: &AMTRELAY, out: &mut Vec<u8>) {
    out.push(value.precedence());
    out.push(value.gateway_type());
    out.extend_from_slice(value.gateway());
}

/// Encode URI priority, weight, and target bytes per RFC 7553 section 4.
pub(super) fn encode_uri(value: &URI, out: &mut Vec<u8>) {
    push_u16(out, value.priority());
    push_u16(out, value.weight());
    out.extend_from_slice(value.target());
}

/// Encode NID preference and 64-bit node identifier per RFC 6742 section 2.1.
pub(super) fn encode_nid(value: &NID, out: &mut Vec<u8>) {
    push_u16(out, value.preference());
    out.extend_from_slice(&value.node_id().to_be_bytes());
}

/// Encode L32 preference and IPv4 locator per RFC 6742 section 2.2.
pub(super) fn encode_l32(value: &L32, out: &mut Vec<u8>) {
    push_u16(out, value.preference());
    out.extend_from_slice(&value.locator().octets());
}

/// Encode L64 preference and 64-bit locator per RFC 6742 section 2.3.
pub(super) fn encode_l64(value: &L64, out: &mut Vec<u8>) {
    push_u16(out, value.preference());
    out.extend_from_slice(&value.locator().to_be_bytes());
}

/// Encode LP preference and target FQDN per RFC 6742 section 2.4.
pub(super) fn encode_lp<'a>(
    value: &'a LP,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.preference());
    write_name(out, value.fqdn(), false)
}

/// Encode an EUI-48 identifier as 6 octets per RFC 7043 section 4.
pub(super) fn encode_eui48(value: &EUI48, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0.to_be_bytes()[2..]);
}

/// Encode an EUI-64 identifier as 8 octets per RFC 7043 section 4.
pub(super) fn encode_eui64(value: &EUI64, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0.to_be_bytes());
}

/// Parse NID preference and a fixed-width 64-bit node identifier.
fn parse_nid_rdata(packet: &[u8], start: usize, end: usize) -> Result<NID> {
    if end - start != 10 {
        return Err(DnsError::protocol("invalid NID rdata length"));
    }
    Ok(NID::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        u64::from_be_bytes([
            packet[start + 2],
            packet[start + 3],
            packet[start + 4],
            packet[start + 5],
            packet[start + 6],
            packet[start + 7],
            packet[start + 8],
            packet[start + 9],
        ]),
    ))
}

/// Parse L32 preference and a fixed-width IPv4 locator.
fn parse_l32_rdata(packet: &[u8], start: usize, end: usize) -> Result<L32> {
    if end - start != 6 {
        return Err(DnsError::protocol("invalid L32 rdata length"));
    }
    Ok(L32::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        Ipv4Addr::new(
            packet[start + 2],
            packet[start + 3],
            packet[start + 4],
            packet[start + 5],
        ),
    ))
}

/// Parse L64 preference and a fixed-width 64-bit locator.
fn parse_l64_rdata(packet: &[u8], start: usize, end: usize) -> Result<L64> {
    if end - start != 10 {
        return Err(DnsError::protocol("invalid L64 rdata length"));
    }
    Ok(L64::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        u64::from_be_bytes([
            packet[start + 2],
            packet[start + 3],
            packet[start + 4],
            packet[start + 5],
            packet[start + 6],
            packet[start + 7],
            packet[start + 8],
            packet[start + 9],
        ]),
    ))
}

/// Parse LP preference followed by a single domain name.
fn parse_lp_rdata(packet: &[u8], start: usize, end: usize) -> Result<LP> {
    let (preference, fqdn) = parse_u16_name(packet, start, end, "LP")?;
    Ok(LP::new(preference, fqdn))
}

/// Parse an EUI-48 identifier from exactly 6 wire octets.
fn parse_eui48_rdata(packet: &[u8], start: usize, end: usize) -> Result<EUI48> {
    if end - start != 6 {
        return Err(DnsError::protocol("invalid EUI48 rdata length"));
    }
    let mut bytes = [0u8; 8];
    bytes[2..].copy_from_slice(&packet[start..end]);
    Ok(EUI48(u64::from_be_bytes(bytes)))
}

/// Parse an EUI-64 identifier from exactly 8 wire octets.
fn parse_eui64_rdata(packet: &[u8], start: usize, end: usize) -> Result<EUI64> {
    if end - start != 8 {
        return Err(DnsError::protocol("invalid EUI64 rdata length"));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&packet[start..end]);
    Ok(EUI64(u64::from_be_bytes(bytes)))
}

/// Parse URI priority, weight, and an opaque target byte string.
fn parse_uri_rdata(packet: &[u8], start: usize, end: usize) -> Result<URI> {
    if start + 4 > end {
        return Err(DnsError::protocol("invalid URI rdata length"));
    }
    Ok(URI::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        u16::from_be_bytes([packet[start + 2], packet[start + 3]]),
        copy_boxed(packet, start + 4, end),
    ))
}

/// Parse SVCB/HTTPS parameter blocks with the strict ordering and duplicate-key rules from
/// RFC 9460 section 2.2.
fn parse_svcb_rdata(packet: &[u8], start: usize, end: usize) -> Result<SVCB> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid SVCB rdata length"));
    }
    let priority = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let (target, mut cursor) = Name::parse(packet, start + 2)?;
    let mut params = Vec::new();
    let mut last_key = None;
    while cursor < end {
        if cursor + 4 > end {
            return Err(DnsError::protocol("invalid SVCB rdata length"));
        }
        let key = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        validate_svc_param_key_order(last_key, key)?;
        let len = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]) as usize;
        let value_start = cursor + 4;
        let value_end = value_start + len;
        if value_end > end {
            return Err(DnsError::protocol("invalid SVCB rdata length"));
        }
        params.push(SvcParam::new(
            key,
            copy_boxed(packet, value_start, value_end),
        ));
        cursor = value_end;
        last_key = Some(key);
    }
    Ok(SVCB::new(priority, target, params))
}

/// Parse IPSECKEY or AMTRELAY-style gateway selector records that carry a variable gateway field.
fn parse_ipseckey_like_rdata(
    packet: &[u8],
    start: usize,
    end: usize,
    kind: &str,
) -> Result<IPSECKEY> {
    if start + 3 > end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    let precedence = packet[start];
    let gateway_type = packet[start + 1];
    let algorithm = packet[start + 2];
    let mut cursor = start + 3;
    let gateway_len = match gateway_type & 0x7f {
        0 => 0,
        1 => 4,
        2 => 16,
        3 => {
            let (_, next) = Name::parse(packet, cursor)?;
            next - cursor
        }
        _ => return Err(DnsError::protocol(format!("invalid {kind} gateway type"))),
    };
    let gateway_end = cursor + gateway_len;
    if gateway_end > end {
        return Err(DnsError::protocol(format!("invalid {kind} rdata length")));
    }
    let gateway = copy_boxed(packet, cursor, gateway_end);
    cursor = gateway_end;
    Ok(IPSECKEY::new(
        precedence,
        gateway_type,
        algorithm,
        gateway,
        copy_boxed(packet, cursor, end),
    ))
}

/// Parse AMTRELAY gateway selector plus gateway bytes per RFC 8777 section 4.2.
fn parse_amtrelay_rdata(packet: &[u8], start: usize, end: usize) -> Result<AMTRELAY> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid AMTRELAY rdata length"));
    }
    let precedence = packet[start];
    let gateway_type = packet[start + 1];
    let cursor = start + 2;
    let gateway_len = match gateway_type & 0x7f {
        0 => 0,
        1 => 4,
        2 => 16,
        3 => {
            let (_, next) = Name::parse(packet, cursor)?;
            next - cursor
        }
        _ => return Err(DnsError::protocol("invalid AMTRELAY gateway type")),
    };
    if cursor + gateway_len != end {
        return Err(DnsError::protocol("invalid AMTRELAY rdata length"));
    }
    Ok(AMTRELAY::new(
        precedence,
        gateway_type,
        copy_boxed(packet, cursor, end),
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
    fn service_rdata_parse_encode_roundtrip() {
        let cases: Vec<(&[u8], fn(&[u8], usize, usize) -> Result<RData>)> = vec![
            (&[0, 10, 2, b'k', b'x', 0], parse_kx),
            (&[10, 1, 2, 1, 2, 3, 4, 9, 9], parse_ipseckey),
            (
                &[
                    0, 1, 3, b's', b'v', b'c', 0, 0, 1, 0, 2, b'h', b'2', 0, 3, 0, 2, 1, 187,
                ],
                parse_svcb,
            ),
            (
                &[
                    0, 1, 5, b'h', b't', b't', b'p', b's', 0, 0, 3, 0, 2, 0x20, 0xfb,
                ],
                parse_https,
            ),
            (&[1, 1, 10, 0, 0, 1], parse_amtrelay),
            (&[0, 1, 0, 2, b'h', b'i'], parse_uri),
            (&[0, 1, 1, 2, 3, 4, 5, 6, 7, 8], parse_nid),
            (&[0, 1, 1, 2, 3, 4], parse_l32),
            (&[0, 1, 1, 2, 3, 4, 5, 6, 7, 8], parse_l64),
            (&[0, 1, 2, b'l', b'p', 0], parse_lp),
            (&[0, 1, 2, 3, 4, 5], parse_eui48),
            (&[0, 1, 2, 3, 4, 5, 6, 7], parse_eui64),
        ];

        for (packet, parse) in cases {
            let parsed = parse(packet, 0, packet.len()).unwrap();
            let mut encoded = Vec::new();
            match &parsed {
                RData::KX(value) => encode_kx(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::IPSECKEY(value) => encode_ipseckey(value, &mut encoded),
                RData::SVCB(value) => {
                    encode_svcb(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::HTTPS(value) => {
                    encode_https(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::AMTRELAY(value) => encode_amtrelay(value, &mut encoded),
                RData::URI(value) => encode_uri(value, &mut encoded),
                RData::NID(value) => encode_nid(value, &mut encoded),
                RData::L32(value) => encode_l32(value, &mut encoded),
                RData::L64(value) => encode_l64(value, &mut encoded),
                RData::LP(value) => encode_lp(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::EUI48(value) => encode_eui48(value, &mut encoded),
                RData::EUI64(value) => encode_eui64(value, &mut encoded),
                other => panic!("unexpected service rdata variant: {other:?}"),
            }
            assert_eq!(encoded, packet);
        }
    }

    #[test]
    fn service_rdata_rejects_invalid_wire_matrix() {
        let cases: Vec<(&str, Result<RData>)> = vec![
            ("kx truncated", parse_kx(&[0, 10], 0, 2)),
            ("ipseckey short header", parse_ipseckey(&[10, 1], 0, 2)),
            ("svcb missing target", parse_svcb(&[0, 1], 0, 2)),
            (
                "svcb unsorted keys",
                parse_svcb(
                    &[
                        0, 1, 3, b's', b'v', b'c', 0, 0, 3, 0, 2, 1, 187, 0, 1, 0, 2, b'h', b'2',
                    ],
                    0,
                    19,
                ),
            ),
            (
                "svcb reserved key",
                parse_svcb(&[0, 1, 3, b's', b'v', b'c', 0, 0xff, 0xff, 0, 0], 0, 11),
            ),
            ("amtrelay bad gateway type", parse_amtrelay(&[1, 99], 0, 2)),
            ("uri truncated", parse_uri(&[0, 1, 0], 0, 3)),
            ("nid short", parse_nid(&[0, 1, 1, 2], 0, 4)),
            ("l32 short", parse_l32(&[0, 1, 1, 2, 3], 0, 5)),
            ("l64 short", parse_l64(&[0, 1, 1, 2, 3, 4], 0, 6)),
            ("lp truncated", parse_lp(&[0, 1], 0, 2)),
            ("eui48 short", parse_eui48(&[0, 1, 2, 3, 4], 0, 5)),
            ("eui64 short", parse_eui64(&[0, 1, 2, 3, 4, 5, 6], 0, 7)),
        ];

        for (name, result) in cases {
            assert!(result.is_err(), "{name} should fail");
        }
    }
}
