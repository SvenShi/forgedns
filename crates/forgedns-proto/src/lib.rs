/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS protocol model and wire-format codec.

pub mod buffer_pool;
pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod rdata;
pub mod record;
pub mod types;
pub mod wire;

pub(crate) use wire as codec;

pub use error::{ProtoError, Result};
pub use header::Header;
pub use message::Message;
pub use name::{Name, ParsedArpaName};
pub use question::Question;
pub use rdata::*;
pub use record::Record;
pub use types::{DNSClass, MessageType, Opcode, Rcode, RecordType};

pub fn decode_rdata_from_wire(rr_type: RecordType, data: &[u8]) -> Result<RData> {
    wire::decode_rdata_from_wire(rr_type, data)
}

pub mod core {
    pub mod error {
        pub use crate::error::{ProtoError as DnsError, Result};
    }
}

pub mod network {
    pub mod buffer_pool {
        pub use crate::buffer_pool::{PooledWireBuffer, WireBufferPool, wire_buffer_pool};
    }
}

pub mod proto {
    pub use crate::header::Header;
    pub use crate::message::Message;
    pub use crate::name::{Name, ParsedArpaName};
    pub use crate::question::Question;
    pub use crate::rdata;
    pub use crate::rdata::*;
    pub use crate::record::Record;
    pub use crate::types::{DNSClass, MessageType, Opcode, Rcode, RecordType};
    pub use crate::wire;

    pub(crate) use crate::codec;
}
