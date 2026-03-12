/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Packet-level response scanners that avoid full message materialization.

use crate::core::error::Result;
use crate::message::Packet;
use crate::message::wire::constants::TYPE_OPT;
use crate::message::wire::record::{RecordView, RecordsIter};
use smallvec::SmallVec;
use std::net::IpAddr;

pub(crate) type ResponseTtlOffsets = SmallVec<[usize; 16]>;

#[derive(Debug, Clone, Default)]
pub(crate) struct ResponseScanSummary {
    response_code: u16,
    truncated: bool,
    answer_ips: SmallVec<[IpAddr; 8]>,
    answer_ip_ttls: SmallVec<[(IpAddr, u32); 8]>,
    cnames: SmallVec<[String; 4]>,
    answer_types: SmallVec<[u16; 8]>,
    min_answer_ttl: Option<u32>,
    negative_ttl_from_soa: Option<u32>,
    ttl_offsets: ResponseTtlOffsets,
}

impl ResponseScanSummary {
    #[inline]
    pub(crate) fn response_code(&self) -> u16 {
        self.response_code
    }

    #[inline]
    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    #[inline]
    pub(crate) fn answer_ips(&self) -> &SmallVec<[IpAddr; 8]> {
        &self.answer_ips
    }

    #[inline]
    pub(crate) fn answer_ip_ttls(&self) -> &SmallVec<[(IpAddr, u32); 8]> {
        &self.answer_ip_ttls
    }

    #[inline]
    pub(crate) fn cnames(&self) -> &SmallVec<[String; 4]> {
        &self.cnames
    }

    #[inline]
    pub(crate) fn answer_types(&self) -> &SmallVec<[u16; 8]> {
        &self.answer_types
    }

    #[inline]
    pub(crate) fn min_answer_ttl(&self) -> Option<u32> {
        self.min_answer_ttl
    }

    #[inline]
    pub(crate) fn negative_ttl_from_soa(&self) -> Option<u32> {
        self.negative_ttl_from_soa
    }

    #[inline]
    pub(crate) fn ttl_offsets(&self) -> &[usize] {
        &self.ttl_offsets
    }
}

pub(crate) fn scan_response(packet: &Packet) -> Result<ResponseScanSummary> {
    let parsed = packet.parse()?;
    let mut response_code = u16::from(parsed.header().response_code());
    if let Some(edns) = parsed.edns() {
        response_code |= u16::from(edns.ext_rcode()) << 4;
    }

    let mut summary = ResponseScanSummary {
        response_code,
        truncated: parsed.header().truncated(),
        ..ResponseScanSummary::default()
    };

    visit_records(parsed.answer_records(), |record| {
        summary.answer_types.push(record.rr_type());
        summary.min_answer_ttl = Some(match summary.min_answer_ttl {
            Some(current) => current.min(record.ttl()),
            None => record.ttl(),
        });
        summary.ttl_offsets.push(record.ttl_offset());

        if let Some(ip) = record.ip_addr() {
            summary.answer_ips.push(ip);
            summary.answer_ip_ttls.push((ip, record.ttl()));
        }
        if let Some(target) = record.cname_target() {
            summary.cnames.push(target.normalized());
        }
        Ok(())
    })?;

    visit_records(parsed.authority_records(), |record| {
        summary.ttl_offsets.push(record.ttl_offset());
        if let Some(ttl) = record.negative_ttl_from_soa() {
            summary.negative_ttl_from_soa = Some(match summary.negative_ttl_from_soa {
                Some(current) => current.min(ttl),
                None => ttl,
            });
        }
        if let Some(target) = record.cname_target() {
            summary.cnames.push(target.normalized());
        }
        Ok(())
    })?;

    visit_records(parsed.additional_records(), |record| {
        if record.rr_type() != TYPE_OPT {
            summary.ttl_offsets.push(record.ttl_offset());
        }
        if let Some(target) = record.cname_target() {
            summary.cnames.push(target.normalized());
        }
        Ok(())
    })?;

    Ok(summary)
}

/// Return the full response code, including EDNS extended bits when present.
pub fn response_rcode(packet: &Packet) -> Result<u16> {
    let parsed = packet.parse()?;
    let mut rcode = u16::from(parsed.header().response_code());
    if let Some(edns) = parsed.edns() {
        rcode |= u16::from(edns.ext_rcode()) << 4;
    }
    Ok(rcode)
}

/// Report whether the answer section contains any RR whose type is in `wanted`.
pub fn response_has_answer_type(packet: &Packet, wanted: &[u16]) -> Result<bool> {
    let parsed = packet.parse()?;
    let mut matched = false;
    visit_records_until(parsed.answer_records(), |record| {
        if wanted.contains(&record.rr_type()) {
            matched = true;
            return Ok(false);
        }
        Ok(true)
    })?;
    Ok(matched)
}

/// Report whether any answer-section IP satisfies `pred`.
pub fn response_answer_any_ip(
    packet: &Packet,
    mut pred: impl FnMut(IpAddr) -> bool,
) -> Result<bool> {
    let parsed = packet.parse()?;
    let mut matched = false;
    visit_records_until(parsed.answer_records(), |record| {
        if let Some(ip) = record.ip_addr()
            && pred(ip)
        {
            matched = true;
            return Ok(false);
        }
        Ok(true)
    })?;
    Ok(matched)
}

/// Collect all `A` and `AAAA` addresses from the answer section.
pub fn response_answer_ips(packet: &Packet) -> Result<SmallVec<[IpAddr; 8]>> {
    let parsed = packet.parse()?;
    let mut ips = SmallVec::<[IpAddr; 8]>::new();
    visit_records(parsed.answer_records(), |record| {
        if let Some(ip) = record.ip_addr() {
            ips.push(ip);
        }
        Ok(())
    })?;
    Ok(ips)
}

/// Collect all `A` and `AAAA` addresses from answer, authority, and additional sections.
pub fn response_ips(packet: &Packet) -> Result<SmallVec<[IpAddr; 8]>> {
    let parsed = packet.parse()?;
    let mut ips = SmallVec::<[IpAddr; 8]>::new();
    visit_records(parsed.answer_records(), |record| {
        if let Some(ip) = record.ip_addr() {
            ips.push(ip);
        }
        Ok(())
    })?;
    visit_records(parsed.authority_records(), |record| {
        if let Some(ip) = record.ip_addr() {
            ips.push(ip);
        }
        Ok(())
    })?;
    visit_records(parsed.additional_records(), |record| {
        if let Some(ip) = record.ip_addr() {
            ips.push(ip);
        }
        Ok(())
    })?;
    Ok(ips)
}

/// Collect answer-section IPs together with their TTLs.
pub fn response_answer_ip_ttls(packet: &Packet) -> Result<SmallVec<[(IpAddr, u32); 8]>> {
    let parsed = packet.parse()?;
    let mut out = SmallVec::<[(IpAddr, u32); 8]>::new();
    visit_records(parsed.answer_records(), |record| {
        if let Some(ip) = record.ip_addr() {
            out.push((ip, record.ttl()));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Return the minimum TTL among answer-section records.
pub fn response_min_answer_ttl(packet: &Packet) -> Result<Option<u32>> {
    let parsed = packet.parse()?;
    let mut best: Option<u32> = None;
    visit_records(parsed.answer_records(), |record| {
        best = Some(match best {
            Some(current) => current.min(record.ttl()),
            None => record.ttl(),
        });
        Ok(())
    })?;
    Ok(best)
}

/// Return the best negative-cache TTL derived from authority-section SOA records.
pub fn response_negative_ttl_from_soa(packet: &Packet) -> Result<Option<u32>> {
    let parsed = packet.parse()?;
    let mut best: Option<u32> = None;
    visit_records(parsed.authority_records(), |record| {
        let Some(ttl) = record.negative_ttl_from_soa() else {
            return Ok(());
        };
        best = Some(match best {
            Some(current) => current.min(ttl),
            None => ttl,
        });
        Ok(())
    })?;
    Ok(best)
}

/// Collect canonical CNAME targets from all sections.
pub fn response_cnames(packet: &Packet) -> Result<SmallVec<[String; 4]>> {
    let parsed = packet.parse()?;
    let mut out = SmallVec::<[String; 4]>::new();
    visit_records(parsed.answer_records(), |record| {
        if let Some(target) = record.cname_target() {
            out.push(target.normalized());
        }
        Ok(())
    })?;
    visit_records(parsed.authority_records(), |record| {
        if let Some(target) = record.cname_target() {
            out.push(target.normalized());
        }
        Ok(())
    })?;
    visit_records(parsed.additional_records(), |record| {
        if let Some(target) = record.cname_target() {
            out.push(target.normalized());
        }
        Ok(())
    })?;
    Ok(out)
}

/// Visit all records yielded by the iterator.
pub(crate) fn visit_records(
    records: RecordsIter<'_>,
    mut visitor: impl FnMut(RecordView<'_>) -> Result<()>,
) -> Result<()> {
    for record in records {
        visitor(record?)?;
    }
    Ok(())
}

/// Visit records until the visitor asks to stop.
fn visit_records_until(
    records: RecordsIter<'_>,
    mut visitor: impl FnMut(RecordView<'_>) -> Result<bool>,
) -> Result<bool> {
    // Matchers often only need the first hit. Stopping early here avoids both
    // extra parsing work and spurious errors from malformed records that appear
    // after the match has already been decided.
    for record in records {
        if !visitor(record?)? {
            return Ok(false);
        }
    }
    Ok(true)
}
