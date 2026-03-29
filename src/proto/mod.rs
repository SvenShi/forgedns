/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS protocol model and wire-format codec.
//!
//! This module is ForgeDNS's internal DNS representation. It avoids depending
//! on an external message type in the hot path and keeps protocol semantics
//! explicit inside the project.
//!
//! It contains:
//!
//! - message structure types such as [`Message`], [`Header`], [`Question`], and
//!   [`Record`];
//! - owned name and RDATA representations suitable for caching and rewriting;
//! - enums for standard DNS classes, opcodes, rcodes, and record types; and
//! - wire encoding / decoding helpers used by servers and upstream clients.
//!
//! Most higher-level modules should depend on these owned types instead of raw
//! byte buffers except at transport boundaries.

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
