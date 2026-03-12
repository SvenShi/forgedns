/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Packet-level response rewrites that patch validated wire bytes in place.

use crate::core::error::Result;
use crate::message::Packet;
use crate::message::response::scan::visit_records;
use crate::message::wire::constants::TYPE_OPT;
use smallvec::SmallVec;

/// Rewrite all response TTL fields except the OPT pseudo-record TTL.
pub fn rewrite_response_ttls(
    packet: &Packet,
    mut update: impl FnMut(u32) -> u32,
) -> Result<Packet> {
    let parsed = packet.parse()?;
    let mut patches = SmallVec::<[(usize, u32); 16]>::new();

    visit_records(parsed.answer_records(), |record| {
        patches.push((record.ttl_offset(), update(record.ttl())));
        Ok(())
    })?;
    visit_records(parsed.authority_records(), |record| {
        patches.push((record.ttl_offset(), update(record.ttl())));
        Ok(())
    })?;
    visit_records(parsed.additional_records(), |record| {
        if record.rr_type() != TYPE_OPT {
            patches.push((record.ttl_offset(), update(record.ttl())));
        }
        Ok(())
    })?;

    let mut bytes = packet.as_slice().to_vec();
    for (offset, ttl) in patches {
        bytes[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
    }
    Ok(Packet::from_vec(bytes))
}

/// Rewrite only the DNS message identifier.
pub fn rewrite_response_id(packet: &Packet, id: u16) -> Packet {
    let mut bytes = packet.as_slice().to_vec();
    bytes[0..2].copy_from_slice(&id.to_be_bytes());
    Packet::from_vec(bytes)
}
