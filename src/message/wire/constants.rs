/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS wire constants shared across packet parsers and encoders.
//!
//! This module intentionally keeps only the small subset of type/class/rcode
//! constants that ForgeDNS currently needs on the packet-first path. The owned
//! enums in [`crate::message::model::data`] and [`crate::message::model`] should
//! be used for public APIs whenever possible.

/// Internet (`IN`) DNS class.
pub const CLASS_IN: u16 = 1;

/// `A` record type.
pub const TYPE_A: u16 = 1;
/// `NS` record type.
pub const TYPE_NS: u16 = 2;
/// `CNAME` record type.
pub const TYPE_CNAME: u16 = 5;
/// `SOA` record type.
pub const TYPE_SOA: u16 = 6;
/// `PTR` record type.
pub const TYPE_PTR: u16 = 12;
/// `MX` record type.
pub const TYPE_MX: u16 = 15;
/// `TXT` record type.
pub const TYPE_TXT: u16 = 16;
/// `AAAA` record type.
pub const TYPE_AAAA: u16 = 28;
/// `OPT` pseudo-record type for EDNS.
pub const TYPE_OPT: u16 = 41;
/// Wildcard `ANY` query type.
pub const TYPE_ANY: u16 = 255;

/// `NOERROR` response code value.
pub const RCODE_NOERROR: u8 = 0;
