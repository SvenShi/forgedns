/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Wire-level DNS message encoding, decoding, truncation, and length helpers.

mod codec;
mod compression;
mod length;
mod rdata;

pub(crate) use codec::*;
pub(crate) use compression::*;
pub(crate) use length::*;
pub(crate) use rdata::*;

pub fn decode_rdata_from_wire(
    rr_type: crate::RecordType,
    data: &[u8],
) -> crate::Result<crate::RData> {
    parse_rdata(
        data,
        &crate::Name::root(),
        rr_type,
        u16::from(crate::DNSClass::IN),
        0,
        0,
        data.len(),
    )
}
