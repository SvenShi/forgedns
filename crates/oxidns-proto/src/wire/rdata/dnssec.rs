// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::type_complexity)]

use super::*;

/// Decode SIG(0) wire data using the SIG/RRSIG layout from RFC 2931 and RFC
/// 4034.
pub(super) fn parse_sig(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::SIG(SIG(parse_rrsig_rdata(packet, start, end)?)))
}

/// Decode KEY wire data using the DNSKEY-like fixed header plus opaque key
/// bytes.
pub(super) fn parse_key(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::KEY(KEY(parse_dnskey_rdata(packet, start, end)?)))
}

/// Decode DS key tag, algorithm, digest type, and digest bytes per RFC 4034
/// section 5.1.
pub(super) fn parse_ds(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::DS(parse_ds_rdata(packet, start, end)?))
}

/// Decode SSHFP algorithm, fingerprint type, and fingerprint bytes per RFC 4255
/// section 3.1.
pub(super) fn parse_sshfp(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::SSHFP(parse_sshfp_rdata(packet, start, end)?))
}

/// Decode CERT certificate type, key tag, algorithm, and certificate bytes per
/// RFC 4398 section 2.1.
pub(super) fn parse_cert(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::CERT(parse_cert_rdata(packet, start, end)?))
}

pub(super) fn parse_rrsig(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::RRSIG(parse_rrsig_rdata(packet, start, end)?))
}

/// Decode NSEC wire data per RFC 4034 section 4.
pub(super) fn parse_nsec(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NSEC(parse_nsec_rdata(packet, start, end)?))
}

/// Decode DNSKEY flags, protocol, algorithm, and public key bytes per RFC 4034
/// section 2.1.
pub(super) fn parse_dnskey(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::DNSKEY(parse_dnskey_rdata(packet, start, end)?))
}

/// Decode DHCID as opaque bytes per RFC 4701 section 3.
pub(super) fn parse_dhcid(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::DHCID(DHCID(copy_boxed(packet, start, end))))
}

/// Decode NSEC3 wire data per RFC 5155 section 3.2.
pub(super) fn parse_nsec3(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NSEC3(parse_nsec3_rdata(packet, start, end)?))
}

/// Decode NSEC3PARAM hash algorithm, flags, iterations, and salt per RFC 5155
/// section 4.
pub(super) fn parse_nsec3param(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NSEC3PARAM(parse_nsec3param_rdata(
        packet, start, end,
    )?))
}

/// Decode TLSA certificate usage, selector, matching type, and association data
/// per RFC 6698 section 2.1.
pub(super) fn parse_tlsa(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::TLSA(parse_tlsa_like_rdata(packet, start, end)?))
}

/// Decode SMIMEA using the TLSA wire layout from RFC 8162 section 2.1.
pub(super) fn parse_smimea(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::SMIMEA(SMIMEA(parse_tlsa_like_rdata(
        packet, start, end,
    )?)))
}

/// Decode HIP fixed fields, HIT, public key, and rendezvous server names per
/// RFC 8005 section 4.1.
pub(super) fn parse_hip(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::HIP(parse_hip_rdata(packet, start, end)?))
}

/// Decode NINFO as opaque bytes per RFC 8145 appendix A.
pub(super) fn parse_ninfo(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::NINFO(NINFO(copy_boxed(packet, start, end))))
}

/// Decode RKEY as opaque bytes per RFC 4034 appendix A compatibility handling.
pub(super) fn parse_rkey(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::RKEY(RKEY(copy_boxed(packet, start, end))))
}

/// Decode TALINK previous and next owner names per RFC 6698 appendix B.
pub(super) fn parse_talink(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    let (prev, next) = parse_two_names(packet, start, end, "TALINK")?;
    Ok(RData::TALINK(TALINK::new(prev, next)))
}

/// Decode CDS using the DS wire layout from RFC 7344 section 3.1.
pub(super) fn parse_cds(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::CDS(CDS(parse_ds_rdata(packet, start, end)?)))
}

/// Decode CDNSKEY using the DNSKEY wire layout from RFC 7344 section 3.2.
pub(super) fn parse_cdnskey(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::CDNSKEY(CDNSKEY(parse_dnskey_rdata(
        packet, start, end,
    )?)))
}

/// Decode OPENPGPKEY as opaque public-key bytes per RFC 7929 section 2.
pub(super) fn parse_openpgpkey(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::OPENPGPKEY(OPENPGPKEY(copy_boxed(
        packet, start, end,
    ))))
}

/// Decode CSYNC wire data per RFC 7477 section 2.1.1.
pub(super) fn parse_csync(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::CSYNC(parse_csync_rdata(packet, start, end)?))
}

/// Decode ZONEMD serial, scheme, hash algorithm, and digest bytes per RFC 8976
/// section 2.
pub(super) fn parse_zonemd(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::ZONEMD(parse_zonemd_rdata(packet, start, end)?))
}

/// Decode TKEY algorithm name, inception/expiration, mode, error, key data, and
/// other data per RFC 2930 section 2.
pub(super) fn parse_tkey(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::TKEY(parse_tkey_rdata(packet, start, end)?))
}

/// Decode TSIG algorithm name, time fields, MAC, original ID, error, and other
/// data per RFC 8945 section 4.2.
pub(super) fn parse_tsig(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::TSIG(parse_tsig_rdata(packet, start, end)?))
}

/// Decode TA using the DS wire layout used by trust-anchor signaling.
pub(super) fn parse_ta(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::TA(TA(parse_ds_rdata(packet, start, end)?)))
}

/// Decode DLV using the DS wire layout from RFC 4431 section 2.
pub(super) fn parse_dlv(packet: &[u8], start: usize, end: usize) -> Result<RData> {
    Ok(RData::DLV(DLV(parse_ds_rdata(packet, start, end)?)))
}

/// Encode SIG(0) fields using the SIG/RRSIG wire layout.
pub(super) fn encode_sig<'a>(
    value: &'a SIG,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.0.type_covered());
    out.push(value.0.algorithm());
    out.push(value.0.labels());
    push_u32(out, value.0.orig_ttl());
    push_u32(out, value.0.expiration());
    push_u32(out, value.0.inception());
    push_u16(out, value.0.key_tag());
    write_name(out, value.0.signer_name(), false)?;
    out.extend_from_slice(value.0.signature());
    Ok(())
}

/// Encode KEY flags, protocol, algorithm, and key bytes.
pub(super) fn encode_key(value: &KEY, out: &mut Vec<u8>) {
    push_u16(out, value.0.flags());
    out.push(value.0.protocol());
    out.push(value.0.algorithm());
    out.extend_from_slice(value.0.public_key());
}

/// Encode DS key tag, algorithm, digest type, and digest bytes per RFC 4034
/// section 5.1.
pub(super) fn encode_ds(value: &DS, out: &mut Vec<u8>) {
    push_u16(out, value.key_tag());
    out.push(value.algorithm());
    out.push(value.digest_type());
    out.extend_from_slice(value.digest());
}

/// Encode SSHFP algorithm, fingerprint type, and fingerprint bytes per RFC 4255
/// section 3.1.
pub(super) fn encode_sshfp(value: &SSHFP, out: &mut Vec<u8>) {
    out.push(value.algorithm());
    out.push(value.fp_type());
    out.extend_from_slice(value.fingerprint());
}

/// Encode CERT certificate type, key tag, algorithm, and certificate bytes per
/// RFC 4398 section 2.1.
pub(super) fn encode_cert(value: &CERT, out: &mut Vec<u8>) {
    push_u16(out, value.cert_type());
    push_u16(out, value.key_tag());
    out.push(value.algorithm());
    out.extend_from_slice(value.certificate());
}

/// Encode RRSIG wire data per RFC 4034 section 3.1.
pub(super) fn encode_rrsig<'a>(
    value: &'a RRSIG,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    push_u16(out, value.type_covered());
    out.push(value.algorithm());
    out.push(value.labels());
    push_u32(out, value.orig_ttl());
    push_u32(out, value.expiration());
    push_u32(out, value.inception());
    push_u16(out, value.key_tag());
    write_name(out, value.signer_name(), false)?;
    out.extend_from_slice(value.signature());
    Ok(())
}

/// Encode NSEC wire data per RFC 4034 section 4.
pub(super) fn encode_nsec<'a>(
    value: &'a NSEC,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.next_domain(), false)?;
    out.extend_from_slice(value.type_bitmap());
    Ok(())
}

/// Encode DNSKEY flags, protocol, algorithm, and public key bytes per RFC 4034
/// section 2.1.
pub(super) fn encode_dnskey(value: &DNSKEY, out: &mut Vec<u8>) {
    push_u16(out, value.flags());
    out.push(value.protocol());
    out.push(value.algorithm());
    out.extend_from_slice(value.public_key());
}

/// Encode DHCID as opaque bytes per RFC 4701 section 3.
pub(super) fn encode_dhcid(value: &DHCID, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode NSEC3 wire data per RFC 5155 section 3.2.
pub(super) fn encode_nsec3(value: &NSEC3, out: &mut Vec<u8>) {
    out.push(value.hash());
    out.push(value.flags());
    push_u16(out, value.iterations());
    out.push(value.salt().len() as u8);
    out.extend_from_slice(value.salt());
    out.push(value.next_domain().len() as u8);
    out.extend_from_slice(value.next_domain());
    out.extend_from_slice(value.type_bitmap());
}

/// Encode NSEC3PARAM hash algorithm, flags, iterations, and salt per RFC 5155
/// section 4.
pub(super) fn encode_nsec3param(value: &NSEC3PARAM, out: &mut Vec<u8>) {
    out.push(value.hash());
    out.push(value.flags());
    push_u16(out, value.iterations());
    out.push(value.salt().len() as u8);
    out.extend_from_slice(value.salt());
}

/// Encode HIP fixed fields, HIT, public key, and rendezvous server names per
/// RFC 8005 section 4.1.
pub(super) fn encode_hip<'a>(
    value: &'a HIP,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    out.push(value.hit().len() as u8);
    out.push(value.public_key_algorithm());
    push_u16(out, value.public_key().len() as u16);
    out.extend_from_slice(value.hit());
    out.extend_from_slice(value.public_key());
    for name in value.rendezvous_servers() {
        write_name(out, name, false)?;
    }
    Ok(())
}

/// Encode NINFO as opaque bytes.
pub(super) fn encode_ninfo(value: &NINFO, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode RKEY as opaque bytes.
pub(super) fn encode_rkey(value: &RKEY, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode TALINK previous and next owner names.
pub(super) fn encode_talink<'a>(
    value: &'a TALINK,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.previous_name(), true)?;
    write_name(out, value.next_name(), true)?;
    Ok(())
}

/// Encode CDS using the DS wire layout from RFC 7344 section 3.1.
pub(super) fn encode_cds(value: &CDS, out: &mut Vec<u8>) {
    encode_ds(&value.0, out);
}

/// Encode DLV using the DS wire layout from RFC 4431 section 2.
pub(super) fn encode_dlv(value: &DLV, out: &mut Vec<u8>) {
    encode_ds(&value.0, out);
}

/// Encode CDNSKEY using the DNSKEY wire layout from RFC 7344 section 3.2.
pub(super) fn encode_cdnskey(value: &CDNSKEY, out: &mut Vec<u8>) {
    encode_dnskey(&value.0, out);
}

/// Encode OPENPGPKEY as opaque public-key bytes per RFC 7929 section 2.
pub(super) fn encode_openpgpkey(value: &OPENPGPKEY, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

/// Encode CSYNC wire data per RFC 7477 section 2.1.1.
pub(super) fn encode_csync(value: &CSYNC, out: &mut Vec<u8>) {
    push_u32(out, value.serial());
    push_u16(out, value.flags());
    out.extend_from_slice(value.type_bitmap());
}

/// Encode ZONEMD serial, scheme, hash algorithm, and digest bytes per RFC 8976
/// section 2.
pub(super) fn encode_zonemd(value: &ZONEMD, out: &mut Vec<u8>) {
    push_u32(out, value.serial());
    out.push(value.scheme());
    out.push(value.hash());
    out.extend_from_slice(value.digest());
}

/// Encode TKEY algorithm name, time fields, key data, and other data per RFC
/// 2930 section 2.
pub(super) fn encode_tkey<'a>(
    value: &'a TKEY,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.algorithm(), false)?;
    push_u32(out, value.inception());
    push_u32(out, value.expiration());
    push_u16(out, value.mode());
    push_u16(out, value.error());
    push_u16(out, value.key().len() as u16);
    out.extend_from_slice(value.key());
    push_u16(out, value.other_data().len() as u16);
    out.extend_from_slice(value.other_data());
    Ok(())
}

/// Encode TSIG algorithm name, time fields, MAC, original ID, error, and other
/// data per RFC 8945 section 4.2.
pub(super) fn encode_tsig<'a>(
    value: &'a TSIG,
    out: &mut Vec<u8>,
    write_name: &mut dyn FnMut(&mut Vec<u8>, &'a Name, bool) -> Result<()>,
) -> Result<()> {
    write_name(out, value.algorithm(), false)?;
    let t = value.time_signed();
    out.push(((t >> 40) & 0xFF) as u8);
    out.push(((t >> 32) & 0xFF) as u8);
    out.push(((t >> 24) & 0xFF) as u8);
    out.push(((t >> 16) & 0xFF) as u8);
    out.push(((t >> 8) & 0xFF) as u8);
    out.push((t & 0xFF) as u8);
    push_u16(out, value.fudge());
    push_u16(out, value.mac().len() as u16);
    out.extend_from_slice(value.mac());
    push_u16(out, value.orig_id());
    push_u16(out, value.error());
    push_u16(out, value.other_data().len() as u16);
    out.extend_from_slice(value.other_data());
    Ok(())
}

/// Encode TA using the DS wire layout.
pub(super) fn encode_ta(value: &TA, out: &mut Vec<u8>) {
    encode_ds(&value.0, out);
}

/// Encode TLSA certificate usage, selector, matching type, and association data
/// per RFC 6698 section 2.1.
pub(super) fn encode_tlsa(value: &TLSA, out: &mut Vec<u8>) {
    out.push(value.usage());
    out.push(value.selector());
    out.push(value.matching_type());
    out.extend_from_slice(value.certificate());
}

/// Encode SMIMEA using the TLSA wire layout from RFC 8162 section 2.1.
pub(super) fn encode_smimea(value: &SMIMEA, out: &mut Vec<u8>) {
    out.push(value.0.usage());
    out.push(value.0.selector());
    out.push(value.0.matching_type());
    out.extend_from_slice(value.0.certificate());
}

/// Parse the shared DS-family layout of key tag, algorithm, digest type, and
/// digest bytes.
fn parse_ds_rdata(packet: &[u8], start: usize, end: usize) -> Result<DS> {
    if start + 4 > end {
        return Err(DnsError::protocol("invalid DS rdata length"));
    }
    Ok(DS::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        packet[start + 2],
        packet[start + 3],
        copy_boxed(packet, start + 4, end),
    ))
}

/// Parse SSHFP algorithm, fingerprint type, and trailing fingerprint bytes.
fn parse_sshfp_rdata(packet: &[u8], start: usize, end: usize) -> Result<SSHFP> {
    if start + 2 > end {
        return Err(DnsError::protocol("invalid SSHFP rdata length"));
    }
    Ok(SSHFP::new(
        packet[start],
        packet[start + 1],
        copy_boxed(packet, start + 2, end),
    ))
}

/// Parse the DNSKEY/KEY fixed header and trailing public key bytes.
fn parse_dnskey_rdata(packet: &[u8], start: usize, end: usize) -> Result<DNSKEY> {
    if start + 4 > end {
        return Err(DnsError::protocol("invalid DNSKEY rdata length"));
    }
    Ok(DNSKEY::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        packet[start + 2],
        packet[start + 3],
        copy_boxed(packet, start + 4, end),
    ))
}

/// Parse the TLSA/SMIMEA fixed 3-byte header and trailing certificate
/// association data.
fn parse_tlsa_like_rdata(packet: &[u8], start: usize, end: usize) -> Result<TLSA> {
    if start + 3 > end {
        return Err(DnsError::protocol("invalid TLSA/SMIMEA rdata length"));
    }
    Ok(TLSA::new(
        packet[start],
        packet[start + 1],
        packet[start + 2],
        copy_boxed(packet, start + 3, end),
    ))
}

/// Parse the CSYNC type bitmap using RFC 4034 / RFC 5155 validation rules.
fn parse_csync_rdata(packet: &[u8], start: usize, end: usize) -> Result<CSYNC> {
    if start + 6 > end {
        return Err(DnsError::protocol("invalid CSYNC rdata length"));
    }
    Ok(CSYNC::new(
        u32::from_be_bytes([
            packet[start],
            packet[start + 1],
            packet[start + 2],
            packet[start + 3],
        ]),
        u16::from_be_bytes([packet[start + 4], packet[start + 5]]),
        TypeBitMaps::try_from_wire(copy_boxed(packet, start + 6, end))?,
    ))
}

/// Parse ZONEMD fixed-width header fields and trailing digest bytes.
fn parse_zonemd_rdata(packet: &[u8], start: usize, end: usize) -> Result<ZONEMD> {
    if start + 6 > end {
        return Err(DnsError::protocol("invalid ZONEMD rdata length"));
    }
    Ok(ZONEMD::new(
        u32::from_be_bytes([
            packet[start],
            packet[start + 1],
            packet[start + 2],
            packet[start + 3],
        ]),
        packet[start + 4],
        packet[start + 5],
        copy_boxed(packet, start + 6, end),
    ))
}

/// Parse CERT certificate type, key tag, algorithm, and trailing certificate
/// bytes.
fn parse_cert_rdata(packet: &[u8], start: usize, end: usize) -> Result<CERT> {
    if start + 5 > end {
        return Err(DnsError::protocol("invalid CERT rdata length"));
    }
    Ok(CERT::new(
        u16::from_be_bytes([packet[start], packet[start + 1]]),
        u16::from_be_bytes([packet[start + 2], packet[start + 3]]),
        packet[start + 4],
        copy_boxed(packet, start + 5, end),
    ))
}

/// Parse RRSIG fixed fields, signer name, and trailing signature bytes per RFC
/// 4034 section 3.1.
fn parse_rrsig_rdata(packet: &[u8], start: usize, end: usize) -> Result<RRSIG> {
    if start + 18 > end {
        return Err(DnsError::protocol("invalid RRSIG rdata length"));
    }
    let type_covered = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let algorithm = packet[start + 2];
    let labels = packet[start + 3];
    let orig_ttl = u32::from_be_bytes([
        packet[start + 4],
        packet[start + 5],
        packet[start + 6],
        packet[start + 7],
    ]);
    let expiration = u32::from_be_bytes([
        packet[start + 8],
        packet[start + 9],
        packet[start + 10],
        packet[start + 11],
    ]);
    let inception = u32::from_be_bytes([
        packet[start + 12],
        packet[start + 13],
        packet[start + 14],
        packet[start + 15],
    ]);
    let key_tag = u16::from_be_bytes([packet[start + 16], packet[start + 17]]);
    let (signer_name, cursor) = Name::parse(packet, start + 18)?;
    if cursor > end {
        return Err(DnsError::protocol("invalid RRSIG rdata length"));
    }
    Ok(RRSIG {
        type_covered,
        algorithm,
        labels,
        orig_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        signature: copy_boxed(packet, cursor, end),
    })
}

/// Parse the NSEC next domain name and type bitmap per RFC 4034 section 4.
fn parse_nsec_rdata(packet: &[u8], start: usize, end: usize) -> Result<NSEC> {
    let (next_domain, cursor) = Name::parse(packet, start)?;
    if cursor > end {
        return Err(DnsError::protocol("invalid NSEC rdata length"));
    }
    Ok(NSEC::new(
        next_domain,
        TypeBitMaps::try_from_wire(copy_boxed(packet, cursor, end))?,
    ))
}

/// Parse NSEC3 salt/next owner/type bitmap data per RFC 5155 section 3.2.
fn parse_nsec3_rdata(packet: &[u8], start: usize, end: usize) -> Result<NSEC3> {
    if start + 5 > end {
        return Err(DnsError::protocol("invalid NSEC3 rdata length"));
    }
    let hash = packet[start];
    let flags = packet[start + 1];
    let iterations = u16::from_be_bytes([packet[start + 2], packet[start + 3]]);
    let salt_len = packet[start + 4] as usize;
    let salt_start = start + 5;
    let salt_end = salt_start + salt_len;
    if salt_end + 1 > end {
        return Err(DnsError::protocol("invalid NSEC3 rdata length"));
    }
    let next_len = packet[salt_end] as usize;
    let next_start = salt_end + 1;
    let next_end = next_start + next_len;
    if next_end > end {
        return Err(DnsError::protocol("invalid NSEC3 rdata length"));
    }
    Ok(NSEC3::new(
        hash,
        flags,
        iterations,
        copy_boxed(packet, salt_start, salt_end),
        copy_boxed(packet, next_start, next_end),
        TypeBitMaps::try_from_wire(copy_boxed(packet, next_end, end))?,
    ))
}

/// Parse NSEC3PARAM fixed fields and variable-length salt.
fn parse_nsec3param_rdata(packet: &[u8], start: usize, end: usize) -> Result<NSEC3PARAM> {
    if start + 5 > end {
        return Err(DnsError::protocol("invalid NSEC3PARAM rdata length"));
    }
    let salt_len = packet[start + 4] as usize;
    let salt_start = start + 5;
    let salt_end = salt_start + salt_len;
    if salt_end != end {
        return Err(DnsError::protocol("invalid NSEC3PARAM rdata length"));
    }
    Ok(NSEC3PARAM::new(
        packet[start],
        packet[start + 1],
        u16::from_be_bytes([packet[start + 2], packet[start + 3]]),
        copy_boxed(packet, salt_start, salt_end),
    ))
}

/// Parse HIP fixed-length header, variable HIT/public key blocks, and trailing
/// rendezvous names.
fn parse_hip_rdata(packet: &[u8], start: usize, end: usize) -> Result<HIP> {
    if start + 4 > end {
        return Err(DnsError::protocol("invalid HIP rdata length"));
    }
    let hit_len = packet[start] as usize;
    let algorithm = packet[start + 1];
    let pk_len = u16::from_be_bytes([packet[start + 2], packet[start + 3]]) as usize;
    let hit_start = start + 4;
    let hit_end = hit_start + hit_len;
    let pk_start = hit_end;
    let pk_end = pk_start + pk_len;
    if pk_end > end {
        return Err(DnsError::protocol("invalid HIP rdata length"));
    }
    let mut cursor = pk_end;
    let mut rendezvous_servers = Vec::new();
    while cursor < end {
        let (name, next) = Name::parse(packet, cursor)?;
        if next <= cursor || next > end {
            return Err(DnsError::protocol("invalid HIP rdata length"));
        }
        rendezvous_servers.push(name);
        cursor = next;
    }
    Ok(HIP::new(
        copy_boxed(packet, hit_start, hit_end),
        algorithm,
        copy_boxed(packet, pk_start, pk_end),
        rendezvous_servers,
    ))
}

/// Parse TKEY algorithm name, time fields, key data, and other data blocks per
/// RFC 2930 section 2.
fn parse_tkey_rdata(packet: &[u8], start: usize, end: usize) -> Result<TKEY> {
    let (algorithm, cursor) = Name::parse(packet, start)?;
    if cursor + 14 > end {
        return Err(DnsError::protocol("invalid TKEY rdata length"));
    }
    let inception = u32::from_be_bytes([
        packet[cursor],
        packet[cursor + 1],
        packet[cursor + 2],
        packet[cursor + 3],
    ]);
    let expiration = u32::from_be_bytes([
        packet[cursor + 4],
        packet[cursor + 5],
        packet[cursor + 6],
        packet[cursor + 7],
    ]);
    let mode = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]);
    let error = u16::from_be_bytes([packet[cursor + 10], packet[cursor + 11]]);
    let key_len = u16::from_be_bytes([packet[cursor + 12], packet[cursor + 13]]) as usize;
    let key_start = cursor + 14;
    let key_end = key_start + key_len;
    if key_end + 2 > end {
        return Err(DnsError::protocol("invalid TKEY rdata length"));
    }
    let other_len = u16::from_be_bytes([packet[key_end], packet[key_end + 1]]) as usize;
    let other_start = key_end + 2;
    let other_end = other_start + other_len;
    if other_end != end {
        return Err(DnsError::protocol("invalid TKEY rdata length"));
    }
    Ok(TKEY::new(
        algorithm,
        inception,
        expiration,
        mode,
        error,
        copy_boxed(packet, key_start, key_end),
        copy_boxed(packet, other_start, other_end),
    ))
}

/// Parse TSIG algorithm name, 48-bit signing time, MAC, original ID, error, and
/// other data per RFC 8945.
fn parse_tsig_rdata(packet: &[u8], start: usize, end: usize) -> Result<TSIG> {
    let (algorithm, cursor) = Name::parse(packet, start)?;
    if cursor + 12 > end {
        return Err(DnsError::protocol("invalid TSIG rdata length"));
    }
    let time_signed = ((packet[cursor] as u64) << 40)
        | ((packet[cursor + 1] as u64) << 32)
        | ((packet[cursor + 2] as u64) << 24)
        | ((packet[cursor + 3] as u64) << 16)
        | ((packet[cursor + 4] as u64) << 8)
        | packet[cursor + 5] as u64;
    let fudge = u16::from_be_bytes([packet[cursor + 6], packet[cursor + 7]]);
    let mac_len = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
    let mac_start = cursor + 10;
    let mac_end = mac_start + mac_len;
    if mac_end + 6 > end {
        return Err(DnsError::protocol("invalid TSIG rdata length"));
    }
    let orig_id = u16::from_be_bytes([packet[mac_end], packet[mac_end + 1]]);
    let error = u16::from_be_bytes([packet[mac_end + 2], packet[mac_end + 3]]);
    let other_len = u16::from_be_bytes([packet[mac_end + 4], packet[mac_end + 5]]) as usize;
    let other_start = mac_end + 6;
    let other_end = other_start + other_len;
    if other_end != end {
        return Err(DnsError::protocol("invalid TSIG rdata length"));
    }
    Ok(TSIG::new(
        algorithm,
        time_signed,
        fudge,
        copy_boxed(packet, mac_start, mac_end),
        orig_id,
        error,
        copy_boxed(packet, other_start, other_end),
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
    fn dnssec_rdata_parse_encode_roundtrip() {
        let cases: Vec<(&[u8], fn(&[u8], usize, usize) -> Result<RData>)> = vec![
            (
                &[
                    0, 1, 8, 2, 0, 0, 1, 44, 0, 0, 1, 144, 0, 0, 0, 200, 0, 1, 3, b's', b'i', b'g',
                    0, 1, 2,
                ],
                parse_sig,
            ),
            (&[1, 0, 3, 8, 1, 2, 3], parse_key),
            (&[0, 1, 8, 2, 1, 2, 3], parse_ds),
            (&[1, 1, 2, 3], parse_sshfp),
            (&[0, 1, 0, 2, 8, 1, 2, 3], parse_cert),
            (
                &[
                    0, 28, 8, 2, 0, 0, 1, 44, 0, 0, 1, 144, 0, 0, 0, 200, 0, 1, 5, b'r', b'r',
                    b's', b'i', b'g', 0, 9, 8, 7,
                ],
                parse_rrsig,
            ),
            (&[4, b'n', b'e', b'x', b't', 0, 0, 1, 0x40], parse_nsec),
            (&[1, 1, 2, 3], parse_dnskey),
            (&[1, 2, 3], parse_dhcid),
            (&[1, 0, 0, 10, 1, 0xAA, 1, 0xBB, 0, 1, 0x20], parse_nsec3),
            (&[1, 0, 0, 10, 1, 0xAA], parse_nsec3param),
            (&[3, 1, 1, 1, 2, 3], parse_tlsa),
            (&[3, 1, 1, 4, 5, 6], parse_smimea),
            (
                &[4, 1, 0, 3, 1, 2, 3, 4, 5, 6, 7, 2, b'r', b'v', 0],
                parse_hip,
            ),
            (&[1, 2], parse_ninfo),
            (&[3, 4], parse_rkey),
            (
                &[4, b'p', b'r', b'e', b'v', 0, 4, b'n', b'e', b'x', b't', 0],
                parse_talink,
            ),
            (&[0, 1, 8, 2, 1, 2], parse_cds),
            (&[1, 1, 3, 8, 8, 9], parse_cdnskey),
            (&[0xAA, 0xBB], parse_openpgpkey),
            (&[0, 0, 0, 9, 0, 1, 0, 1, 0x40], parse_csync),
            (&[0, 0, 0, 1, 1, 1, 1, 2, 3], parse_zonemd),
            (
                &[
                    8, b'g', b's', b's', b'-', b't', b's', b'i', b'g', 0, 0, 0, 0, 1, 0, 0, 0, 2,
                    0, 3, 0, 4, 0, 2, 5, 6, 0, 2, 7, 8,
                ],
                parse_tkey,
            ),
            (
                &[
                    11, b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'5', b'6', 0, 1, 2,
                    3, 4, 5, 6, 1, 44, 0, 3, 1, 2, 3, 0, 1, 0, 0, 0, 2, 4, 5,
                ],
                parse_tsig,
            ),
            (&[0, 11, 8, 2, 6, 7], parse_ta),
            (&[0, 12, 8, 2, 8, 9], parse_dlv),
        ];

        for (packet, parse) in cases {
            let parsed = parse(packet, 0, packet.len()).unwrap();
            let mut encoded = Vec::new();
            match &parsed {
                RData::SIG(value) => encode_sig(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::KEY(value) => encode_key(value, &mut encoded),
                RData::DS(value) => encode_ds(value, &mut encoded),
                RData::SSHFP(value) => encode_sshfp(value, &mut encoded),
                RData::CERT(value) => encode_cert(value, &mut encoded),
                RData::RRSIG(value) => {
                    encode_rrsig(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::NSEC(value) => {
                    encode_nsec(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::DNSKEY(value) => encode_dnskey(value, &mut encoded),
                RData::DHCID(value) => encode_dhcid(value, &mut encoded),
                RData::NSEC3(value) => encode_nsec3(value, &mut encoded),
                RData::NSEC3PARAM(value) => encode_nsec3param(value, &mut encoded),
                RData::TLSA(value) => encode_tlsa(value, &mut encoded),
                RData::SMIMEA(value) => encode_smimea(value, &mut encoded),
                RData::HIP(value) => encode_hip(value, &mut encoded, &mut write_name_raw).unwrap(),
                RData::NINFO(value) => encode_ninfo(value, &mut encoded),
                RData::RKEY(value) => encode_rkey(value, &mut encoded),
                RData::TALINK(value) => {
                    encode_talink(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::CDS(value) => encode_cds(value, &mut encoded),
                RData::CDNSKEY(value) => encode_cdnskey(value, &mut encoded),
                RData::OPENPGPKEY(value) => encode_openpgpkey(value, &mut encoded),
                RData::CSYNC(value) => encode_csync(value, &mut encoded),
                RData::ZONEMD(value) => encode_zonemd(value, &mut encoded),
                RData::TKEY(value) => {
                    encode_tkey(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::TSIG(value) => {
                    encode_tsig(value, &mut encoded, &mut write_name_raw).unwrap()
                }
                RData::TA(value) => encode_ta(value, &mut encoded),
                RData::DLV(value) => encode_dlv(value, &mut encoded),
                other => panic!("unexpected dnssec rdata variant: {other:?}"),
            }
            assert_eq!(encoded, packet);
        }
    }

    #[test]
    fn dnssec_rdata_rejects_invalid_wire_matrix() {
        let cases: Vec<(&str, Result<RData>)> = vec![
            ("ds too short", parse_ds(&[0, 1, 8], 0, 3)),
            ("sshfp too short", parse_sshfp(&[1], 0, 1)),
            ("cert too short", parse_cert(&[0, 1, 0, 2], 0, 4)),
            ("rrsig too short", parse_rrsig(&[0, 1, 8, 2, 0], 0, 5)),
            (
                "nsec truncated bitmap",
                parse_nsec(&[4, b'n', b'e', b'x', b't', 0, 0], 0, 7),
            ),
            ("dnskey too short", parse_dnskey(&[1, 1, 3], 0, 3)),
            (
                "nsec3 zero bitmap len",
                parse_nsec3(&[1, 0, 0, 1, 1, 0xAA, 1, 0xBB, 0, 0], 0, 10),
            ),
            (
                "nsec3param truncated salt",
                parse_nsec3param(&[1, 0, 0, 1, 2, 0xAA], 0, 6),
            ),
            ("tlsa too short", parse_tlsa(&[3, 1], 0, 2)),
            (
                "hip truncated rendezvous",
                parse_hip(&[4, 1, 0, 3, 1, 2, 3, 4, 5, 6, 7, 2], 0, 12),
            ),
            (
                "talink truncated",
                parse_talink(&[4, b'p', b'r', b'e', b'v', 0, 4], 0, 7),
            ),
            (
                "csync invalid bitmap",
                parse_csync(&[0, 0, 0, 9, 0, 1, 0, 0], 0, 8),
            ),
            ("zonemd too short", parse_zonemd(&[0, 0, 0, 1, 1], 0, 5)),
            (
                "tkey truncated",
                parse_tkey(&[1, b'a', 0, 0, 0, 0, 1], 0, 7),
            ),
            ("tsig truncated", parse_tsig(&[1, b'a', 0, 1, 2, 3], 0, 6)),
        ];

        for (name, result) in cases {
            assert!(result.is_err(), "{name} should fail");
        }
    }
}
