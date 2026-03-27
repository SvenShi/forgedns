/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS message types and codec helpers.

pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod rdata;
pub mod record;
pub mod types;
pub mod wire;

pub(crate) use wire as codec;

pub use header::Header;
pub use message::Message;
pub use name::{Name, ParsedArpaName};
pub use question::Question;
pub use rdata::*;
pub use record::Record;
pub use types::{DNSClass, MessageType, Opcode, Rcode, RecordType};
