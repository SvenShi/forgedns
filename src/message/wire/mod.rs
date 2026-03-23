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
