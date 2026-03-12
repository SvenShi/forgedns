/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Encode the owned message model back into wire format.

use crate::core::error::{DnsError, Result};
use crate::message::model::data::rdata::opt::{EdnsCode, EdnsOption};
use crate::message::model::data::rdata::{A, AAAA};
use crate::message::model::data::{Name, RData, Record};
use crate::message::model::enums::MessageType;
use crate::message::model::message::MessageData;
use crate::message::wire::flags::{
    DNS_HEADER_LEN, FLAG_AA, FLAG_AD, FLAG_CD, FLAG_QR, FLAG_RA, FLAG_RD, FLAG_TC,
};
use ahash::AHashMap;
use std::net::IpAddr;

/// Encode a decoded message into a newly allocated byte vector.
pub(crate) fn encode_owned(message: &MessageData, max_size: Option<usize>) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    encode_owned_into(message, max_size, &mut out)?;
    Ok(out)
}

/// Encode a decoded message into `out`, truncating if `max_size` requires it.
pub(crate) fn encode_owned_into(
    message: &MessageData,
    max_size: Option<usize>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let limit = max_size.unwrap_or(usize::MAX);
    out.clear();
    out.resize(DNS_HEADER_LEN, 0);
    let mut compression = CompressionState::default();

    for question in &message.questions {
        encode_name(out, question.name(), &mut compression)?;
        out.extend_from_slice(&u16::from(question.question_type).to_be_bytes());
        out.extend_from_slice(&u16::from(question.question_class).to_be_bytes());
    }

    let mut ancount = 0u16;
    let mut nscount = 0u16;
    let mut arcount = 0u16;
    let mut truncated = message.header.truncated;
    let opt_record = message
        .additionals
        .iter()
        .find(|record| matches!(record.data(), RData::OPT(_)));
    // Reserve space for the OPT record up front so truncation drops regular RRs
    // before it drops EDNS metadata and the extended RCODE carrier.
    let opt_wire = opt_record
        .map(encode_record_without_compression)
        .transpose()?
        .unwrap_or_default();
    let non_opt_limit = if opt_record.is_some() {
        limit.saturating_sub(opt_wire.len())
    } else {
        limit
    };

    if !encode_section(
        out,
        &message.answers,
        non_opt_limit,
        &mut ancount,
        &mut compression,
    )? {
        truncated = true;
    } else if !encode_section(
        out,
        &message.name_servers,
        non_opt_limit,
        &mut nscount,
        &mut compression,
    )? {
        truncated = true;
    } else {
        let mut truncated_non_opt = false;
        for record in &message.additionals {
            if matches!(record.data(), RData::OPT(_)) {
                continue;
            }
            let start = out.len();
            encode_record(out, record, &mut compression)?;
            if out.len() > non_opt_limit {
                out.truncate(start);
                truncated_non_opt = true;
                break;
            }
            arcount = arcount
                .checked_add(1)
                .ok_or_else(|| DnsError::protocol("too many dns records"))?;
        }
        if truncated_non_opt {
            truncated = true;
        }
    }

    if !opt_wire.is_empty() {
        if out.len() + opt_wire.len() <= limit {
            out.extend_from_slice(&opt_wire);
            arcount = arcount
                .checked_add(1)
                .ok_or_else(|| DnsError::protocol("too many dns records"))?;
        } else {
            truncated = true;
        }
    } else if out.len() > limit {
        truncated = true;
    }

    let response_code = u16::from(message.header.response_code);
    let mut flags = response_code & 0x000f;
    if matches!(message.header.message_type, MessageType::Response) {
        flags |= FLAG_QR;
    }
    flags |= u16::from(u8::from(message.header.op_code) & 0x0f) << 11;
    if message.header.authoritative {
        flags |= FLAG_AA;
    }
    if truncated {
        flags |= FLAG_TC;
    }
    if message.header.recursion_desired {
        flags |= FLAG_RD;
    }
    if message.header.recursion_available {
        flags |= FLAG_RA;
    }
    if message.header.authentic_data {
        flags |= FLAG_AD;
    }
    if message.header.checking_disabled {
        flags |= FLAG_CD;
    }

    out[0..2].copy_from_slice(&message.header.id.to_be_bytes());
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[4..6].copy_from_slice(
        &u16::try_from(message.questions.len())
            .map_err(|_| DnsError::protocol("too many dns questions"))?
            .to_be_bytes(),
    );
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    out[8..10].copy_from_slice(&nscount.to_be_bytes());
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    Ok(())
}

/// Encode one resource-record section until `limit` is reached.
fn encode_section(
    out: &mut Vec<u8>,
    records: &[Record],
    limit: usize,
    count: &mut u16,
    compression: &mut CompressionState,
) -> Result<bool> {
    for record in records {
        let start = out.len();
        encode_record(out, record, compression)?;
        if out.len() > limit {
            out.truncate(start);
            return Ok(false);
        }
        *count = count
            .checked_add(1)
            .ok_or_else(|| DnsError::protocol("too many dns records"))?;
    }
    Ok(true)
}

/// DNS name-compression state shared while encoding one message.
#[derive(Debug, Default)]
struct CompressionState {
    /// Map from encoded suffix to the packet offset where it was first emitted.
    suffix_map: AHashMap<Vec<u8>, u16>,
}

impl CompressionState {
    /// Return the first suffix already emitted in the packet.
    ///
    /// The returned index is the first label that can be replaced by a pointer.
    fn pointer_for(&self, labels: &[&[u8]]) -> Option<(usize, u16)> {
        for index in 0..labels.len() {
            let suffix = encode_suffix(labels, index);
            if let Some(&offset) = self.suffix_map.get(&suffix) {
                return Some((index, offset));
            }
        }
        None
    }

    /// Remember all newly emitted suffixes that can legally be referenced.
    fn remember_name(&mut self, labels: &[&[u8]], emitted_positions: &[u16]) {
        for (index, &position) in emitted_positions.iter().enumerate() {
            if position >= 0x4000 {
                continue;
            }
            self.suffix_map
                .insert(encode_suffix(labels, index), position);
        }
    }
}

/// Encode a suffix of `labels` into canonical wire format for compression lookup.
fn encode_suffix(labels: &[&[u8]], start: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for label in &labels[start..] {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

/// Encode one owner name using DNS compression whenever possible.
fn encode_name(out: &mut Vec<u8>, name: &Name, compression: &mut CompressionState) -> Result<()> {
    if name.is_root() {
        out.push(0);
        return Ok(());
    }

    let labels = name.iter_label_bytes().collect::<Vec<_>>();
    // Reuse the longest suffix that has already been emitted so repeated owner
    // names and RDATA names stay compact across the whole message.
    let match_suffix = compression.pointer_for(&labels);
    let raw_label_count = match_suffix.map(|(index, _)| index).unwrap_or(labels.len());
    let mut emitted_positions = Vec::with_capacity(raw_label_count);

    for label in labels.iter().take(raw_label_count) {
        if label.len() > 63 {
            return Err(DnsError::protocol("dns label exceeds 63 bytes"));
        }
        emitted_positions.push(out.len() as u16);
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }

    if let Some((_, ptr)) = match_suffix {
        out.extend_from_slice(&(0xC000 | ptr).to_be_bytes());
    } else {
        out.push(0);
    }
    compression.remember_name(&labels, &emitted_positions);
    Ok(())
}

/// Encode one full resource record into wire format.
fn encode_record(
    out: &mut Vec<u8>,
    record: &Record,
    compression: &mut CompressionState,
) -> Result<()> {
    encode_name(out, record.name(), compression)?;
    let record_type = u16::from(record.record_type());
    out.extend_from_slice(&record_type.to_be_bytes());

    let data = record.data();
    let (class, ttl) = match data {
        RData::OPT(value) => (value.udp_payload_size(), value.raw_ttl()),
        _ => (u16::from(record.dns_class()), record.ttl()),
    };
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    let rdlen_pos = out.len();
    out.extend_from_slice(&0u16.to_be_bytes());
    let rdata_start = out.len();

    match data {
        RData::A(A(addr)) => {
            out.extend_from_slice(&addr.octets());
        }
        RData::AAAA(AAAA(addr)) => {
            out.extend_from_slice(&addr.octets());
        }
        RData::CNAME(value) => {
            encode_name(out, &value.0, compression)?;
        }
        RData::NS(value) => {
            encode_name(out, &value.0, compression)?;
        }
        RData::PTR(value) => {
            encode_name(out, &value.0, compression)?;
        }
        RData::MX(value) => {
            out.extend_from_slice(&value.preference().to_be_bytes());
            encode_name(out, value.exchange(), compression)?;
        }
        RData::TXT(value) => {
            for part in value.txt_data() {
                if part.len() > u8::MAX as usize {
                    return Err(DnsError::protocol("dns txt chunk exceeds 255 bytes"));
                }
                out.push(part.len() as u8);
                out.extend_from_slice(part.as_bytes());
            }
        }
        RData::SOA(value) => {
            encode_name(out, value.mname(), compression)?;
            encode_name(out, value.rname(), compression)?;
            out.extend_from_slice(&value.serial().to_be_bytes());
            out.extend_from_slice(&(value.refresh() as u32).to_be_bytes());
            out.extend_from_slice(&(value.retry() as u32).to_be_bytes());
            out.extend_from_slice(&(value.expire() as u32).to_be_bytes());
            out.extend_from_slice(&value.minimum().to_be_bytes());
        }
        RData::OPT(value) => {
            for option in value.options() {
                encode_edns_option(out, option)?;
            }
        }
        RData::Unknown { data, .. } => {
            out.extend_from_slice(data);
        }
    }

    let rdlen = out.len().saturating_sub(rdata_start);
    out[rdlen_pos..rdlen_pos + 2].copy_from_slice(
        &u16::try_from(rdlen)
            .map_err(|_| DnsError::protocol("dns rdata exceeds u16 length"))?
            .to_be_bytes(),
    );
    Ok(())
}

/// Encode one record without reusing compression pointers from prior names.
fn encode_record_without_compression(record: &Record) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    encode_record(&mut out, record, &mut CompressionState::default())?;
    Ok(out)
}

/// Encode one owned EDNS option into wire format.
fn encode_edns_option(out: &mut Vec<u8>, option: &EdnsOption) -> Result<()> {
    match option {
        EdnsOption::Subnet(value) => {
            let code = u16::from(EdnsCode::Subnet);
            let (family, addr_bytes, max_prefix) = match value.addr() {
                IpAddr::V4(addr) => (1u16, addr.octets().to_vec(), 32u8),
                IpAddr::V6(addr) => (2u16, addr.octets().to_vec(), 128u8),
            };
            let prefix = value.source_prefix().min(max_prefix);
            let network_len = usize::from(prefix.div_ceil(8));
            let mut truncated = addr_bytes[..network_len].to_vec();
            if let Some(last) = truncated.last_mut() {
                let remaining_bits = prefix % 8;
                if remaining_bits != 0 {
                    *last &= 0xFFu8 << (8 - remaining_bits);
                }
            }
            out.extend_from_slice(&code.to_be_bytes());
            let len_pos = out.len();
            out.extend_from_slice(&0u16.to_be_bytes());
            let body_start = out.len();
            out.extend_from_slice(&family.to_be_bytes());
            out.push(prefix);
            out.push(value.scope_prefix().min(max_prefix));
            out.extend_from_slice(&truncated);
            let body_len = out.len().saturating_sub(body_start);
            out[len_pos..len_pos + 2].copy_from_slice(
                &u16::try_from(body_len)
                    .map_err(|_| DnsError::protocol("edns option too large"))?
                    .to_be_bytes(),
            );
        }
        EdnsOption::Unknown(code, data) => {
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(
                &u16::try_from(data.len())
                    .map_err(|_| DnsError::protocol("edns option too large"))?
                    .to_be_bytes(),
            );
            out.extend_from_slice(data);
        }
    }
    Ok(())
}
