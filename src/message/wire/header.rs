/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Zero-copy DNS header view.
//!
//! The [`Header`] type is a small decoded projection of the 12-byte DNS header.
//! It is intentionally read-only and cheap to copy so packet helpers can query
//! flags and counters without touching the rest of the message.

use crate::core::error::{DnsError, Result};
use crate::message::wire::flags::{
    DNS_HEADER_LEN, FLAG_AA, FLAG_AD, FLAG_CD, FLAG_QR, FLAG_RA, FLAG_RD, FLAG_TC,
};

/// Parsed DNS header fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Header {
    /// Message identifier used to correlate requests and responses.
    id: u16,
    /// Raw 16-bit DNS flags field.
    flags: u16,
    /// Question count (`QDCOUNT`).
    qdcount: u16,
    /// Answer count (`ANCOUNT`).
    ancount: u16,
    /// Authority record count (`NSCOUNT`).
    nscount: u16,
    /// Additional record count (`ARCOUNT`).
    arcount: u16,
}

impl Header {
    /// Parse the fixed 12-byte DNS header from `packet`.
    pub fn parse(packet: &[u8]) -> Result<Self> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(DnsError::protocol("dns packet shorter than header"));
        }

        Ok(Self {
            id: u16::from_be_bytes([packet[0], packet[1]]),
            flags: u16::from_be_bytes([packet[2], packet[3]]),
            qdcount: u16::from_be_bytes([packet[4], packet[5]]),
            ancount: u16::from_be_bytes([packet[6], packet[7]]),
            nscount: u16::from_be_bytes([packet[8], packet[9]]),
            arcount: u16::from_be_bytes([packet[10], packet[11]]),
        })
    }

    #[inline]
    /// Return the DNS message identifier.
    pub fn id(&self) -> u16 {
        self.id
    }

    #[inline]
    /// Return the raw 16-bit DNS flags field.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    #[inline]
    /// Return the 4-bit operation code.
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    #[inline]
    /// Return the low 4 bits of the response code field.
    pub fn response_code(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    #[inline]
    /// Report whether the `QR` bit marks this header as a response.
    pub fn is_response(&self) -> bool {
        (self.flags & FLAG_QR) != 0
    }

    #[inline]
    /// Report whether the `AA` bit is set.
    pub fn authoritative(&self) -> bool {
        (self.flags & FLAG_AA) != 0
    }

    #[inline]
    /// Report whether the `TC` bit is set.
    pub fn truncated(&self) -> bool {
        (self.flags & FLAG_TC) != 0
    }

    #[inline]
    /// Report whether the `RD` bit is set.
    pub fn recursion_desired(&self) -> bool {
        (self.flags & FLAG_RD) != 0
    }

    #[inline]
    /// Report whether the `RA` bit is set.
    pub fn recursion_available(&self) -> bool {
        (self.flags & FLAG_RA) != 0
    }

    #[inline]
    /// Report whether the `AD` bit is set.
    pub fn authentic_data(&self) -> bool {
        (self.flags & FLAG_AD) != 0
    }

    #[inline]
    /// Report whether the `CD` bit is set.
    pub fn checking_disabled(&self) -> bool {
        (self.flags & FLAG_CD) != 0
    }

    #[inline]
    /// Return `QDCOUNT`.
    pub fn qdcount(&self) -> u16 {
        self.qdcount
    }

    #[inline]
    /// Return `ANCOUNT`.
    pub fn ancount(&self) -> u16 {
        self.ancount
    }

    #[inline]
    /// Return `NSCOUNT`.
    pub fn nscount(&self) -> u16 {
        self.nscount
    }

    #[inline]
    /// Return `ARCOUNT`.
    pub fn arcount(&self) -> u16 {
        self.arcount
    }
}
