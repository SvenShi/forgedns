/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Wire-first DNS message types and parsers.
//!
//! The module is organized by responsibility:
//!
//! - `wire`: packet-backed DNS views and parsers.
//! - `model`: owned DNS message and RR data model.
//! - `response`: response plans and packet-level response helpers.
//! - `read`: unified read-only accessors over packet-backed and owned data.

/// Shared owned-message encoders and decoders.
pub(crate) mod codec;
/// Owned DNS message model and record data model.
pub mod model;
/// Unified read-only accessors over packet-backed and owned message state.
pub mod read;
/// Packet-level response helpers and lazy response plans.
pub mod response;
/// Zero-copy wire-level packet parser and borrowed views.
pub mod wire;

/// Re-export owned RDATA helpers under a flat module path.
pub use model::data::rdata::{self as rdata, Edns};
/// Re-export owned message enums and types.
pub use model::message::Message;
/// Re-export owned record-related types.
pub use model::{DNSClass, Name, ParsedArpaName, RData, Record, RecordType};
pub use model::{MessageType, OpCode, Question, ResponseCode};
/// Re-export unified read-only accessors.
pub use read::{EdnsAccess, EdnsOptionAccess, EdnsOptionAccessIter, NameAccess, QuestionAccess};
/// Re-export packet-level response builders and scanners.
pub use response::{
    RejectResponsePlan, ResponsePlan, build_address_response_packet, build_response_packet,
    response_answer_any_ip, response_answer_ip_ttls, response_answer_ips, response_cnames,
    response_has_answer_type, response_ips, response_min_answer_ttl,
    response_negative_ttl_from_soa, response_rcode, rewrite_response_id, rewrite_response_ttls,
};
/// Re-export borrowed wire constants.
pub use wire::constants::*;
/// Re-export borrowed EDNS views.
pub use wire::edns::{ClientSubnetRef, EdnsOptionRef, EdnsOptionsIter, EdnsRef};
/// Re-export shared wire flag constants.
pub use wire::flags::*;
/// Re-export the parsed DNS header type.
pub use wire::header::Header;
/// Re-export borrowed DNS name views.
pub use wire::name::{LabelRef, NameRef};
/// Re-export packet and parsed view types.
pub use wire::packet::{Packet, ParsedMessage, SectionOffsets};
/// Re-export the packet parser entrypoint.
pub use wire::parser::parse_message;
/// Re-export borrowed question views.
pub use wire::question::QuestionRef;
/// Re-export borrowed record views.
pub use wire::record::{
    MxView, RDataView, RecordSection, RecordView, RecordsIter, SoaView, TxtChunksIter, TxtView,
};
