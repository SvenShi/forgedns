/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared DNS wire header and EDNS flag constants.

/// Length in bytes of the fixed DNS header.
pub const DNS_HEADER_LEN: usize = 12;

/// Bit mask for the DNS `QR` flag.
pub const FLAG_QR: u16 = 0x8000;
/// Bit mask for the DNS `AA` flag.
pub const FLAG_AA: u16 = 0x0400;
/// Bit mask for the DNS `TC` flag.
pub const FLAG_TC: u16 = 0x0200;
/// Bit mask for the DNS `RD` flag.
pub const FLAG_RD: u16 = 0x0100;
/// Bit mask for the DNS `RA` flag.
pub const FLAG_RA: u16 = 0x0080;
/// Bit mask for the DNS `AD` flag.
pub const FLAG_AD: u16 = 0x0020;
/// Bit mask for the DNS `CD` flag.
pub const FLAG_CD: u16 = 0x0010;

/// Bit mask for the EDNS `DO` flag.
pub const EDNS_FLAG_DO: u16 = 0x8000;
