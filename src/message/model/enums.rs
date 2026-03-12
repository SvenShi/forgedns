/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS message enums shared by packet-backed and owned message modes.

/// DNS message direction.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum MessageType {
    /// Query message sent by a client or intermediate resolver.
    Query,
    /// Response message sent back to the requester.
    Response,
}

/// DNS operation code.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum OpCode {
    /// Standard query opcode.
    Query,
    /// Inverse query opcode retained for completeness.
    IQuery,
    /// Server status query opcode.
    Status,
    /// DNS NOTIFY opcode.
    Notify,
    /// Dynamic update opcode.
    Update,
    /// Any other opcode preserved numerically.
    Unknown(u8),
}

impl From<u8> for OpCode {
    /// Convert a numeric opcode into the owned enum.
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            other => Self::Unknown(other),
        }
    }
}

impl From<OpCode> for u8 {
    /// Convert an owned opcode back into its numeric representation.
    fn from(value: OpCode) -> Self {
        match value {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::Unknown(other) => other,
        }
    }
}

/// DNS response code values supported by ForgeDNS.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ResponseCode {
    /// Successful response.
    NoError,
    /// Format error.
    FormErr,
    /// Server failure.
    ServFail,
    /// Non-existent domain.
    NXDomain,
    /// Unsupported operation.
    NotImp,
    /// Refused by policy.
    Refused,
    /// Name exists when it should not.
    YXDomain,
    /// RR set exists when it should not.
    YXRRSet,
    /// RR set does not exist when it should.
    NXRRSet,
    /// Not authoritative.
    NotAuth,
    /// Name not contained in zone.
    NotZone,
    /// TSIG bad signature / EDNS bad version alias.
    BADSIG,
    /// TSIG bad key.
    BADKEY,
    /// TSIG bad time.
    BADTIME,
    /// TKEY bad mode.
    BADMODE,
    /// Duplicate key name.
    BADNAME,
    /// Unsupported algorithm.
    BADALG,
    /// Bad truncation.
    BADTRUNC,
    /// Bad cookie.
    BADCOOKIE,
    /// EDNS bad version.
    BADVERS,
    /// Any other response code preserved numerically.
    Unknown(u16),
}

impl From<u16> for ResponseCode {
    /// Convert a numeric RCODE into the owned enum.
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            16 => Self::BADVERS,
            17 => Self::BADKEY,
            18 => Self::BADTIME,
            19 => Self::BADMODE,
            20 => Self::BADNAME,
            21 => Self::BADALG,
            22 => Self::BADTRUNC,
            23 => Self::BADCOOKIE,
            other => Self::Unknown(other),
        }
    }
}

impl From<ResponseCode> for u16 {
    /// Convert an owned response code back into its numeric representation.
    fn from(value: ResponseCode) -> Self {
        match value {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NXDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::YXDomain => 6,
            ResponseCode::YXRRSet => 7,
            ResponseCode::NXRRSet => 8,
            ResponseCode::NotAuth => 9,
            ResponseCode::NotZone => 10,
            ResponseCode::BADVERS => 16,
            ResponseCode::BADSIG => 16,
            ResponseCode::BADKEY => 17,
            ResponseCode::BADTIME => 18,
            ResponseCode::BADMODE => 19,
            ResponseCode::BADNAME => 20,
            ResponseCode::BADALG => 21,
            ResponseCode::BADTRUNC => 22,
            ResponseCode::BADCOOKIE => 23,
            ResponseCode::Unknown(other) => other,
        }
    }
}
