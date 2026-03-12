/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned and packet-backed DNS message model.
//!
//! `Message` is the bridge between ForgeDNS's packet-first hot path and the
//! plugin ecosystem that expects structured DNS sections. A message starts in
//! one of two representations:
//!
//! - `Packet`, which keeps validated wire bytes and only exposes cheap header
//!   metadata up front.
//! - `Owned`, which fully decodes questions and resource records.
//!
//! Read-only operations stay on the packet-backed representation when possible.
//! Any mutation that cannot be expressed safely on raw wire bytes triggers a
//! one-way transition to the owned representation.

use crate::core::error::Result;
use crate::message::codec::{decode_owned, encode_owned, encode_owned_into};
use crate::message::model::data::rdata::{Edns, OPT};
use crate::message::model::data::{DNSClass, Name, RData, Record, RecordType};
use crate::message::model::enums::{MessageType, OpCode, ResponseCode};
use crate::message::model::question::Question;
use crate::message::read::{EdnsAccess, QuestionAccess};
use crate::message::wire::edns::EdnsRef;
use crate::message::wire::header::Header;
use crate::message::wire::meta::{EdnsMeta, QuestionMeta};
use crate::message::wire::packet::{Packet, SectionOffsets};
use crate::message::wire::parser::parse_message;
use crate::message::wire::question::QuestionRef;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, OnceLock};

/// Internal decoded header state shared by packet-backed and owned messages.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct MessageHeaderData {
    /// Message identifier.
    pub(crate) id: u16,
    /// Query or response direction.
    pub(crate) message_type: MessageType,
    /// DNS operation code.
    pub(crate) op_code: OpCode,
    /// `AA` flag.
    pub(crate) authoritative: bool,
    /// `TC` flag.
    pub(crate) truncated: bool,
    /// `RD` flag.
    pub(crate) recursion_desired: bool,
    /// `RA` flag.
    pub(crate) recursion_available: bool,
    /// `AD` flag.
    pub(crate) authentic_data: bool,
    /// `CD` flag.
    pub(crate) checking_disabled: bool,
    /// Decoded DNS response code.
    pub(crate) response_code: ResponseCode,
}

impl Default for MessageHeaderData {
    /// Construct a default query header with all flags cleared.
    fn default() -> Self {
        Self {
            id: 0,
            message_type: MessageType::Query,
            op_code: OpCode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
        }
    }
}

impl MessageHeaderData {
    /// Decode internal header state from a parsed wire header and EDNS ext-rcode.
    pub(crate) fn from_header(header: Header, ext_rcode: u8) -> Self {
        let raw_rcode = u16::from(header.response_code()) | (u16::from(ext_rcode) << 4);
        Self {
            id: header.id(),
            message_type: if header.is_response() {
                MessageType::Response
            } else {
                MessageType::Query
            },
            op_code: OpCode::from(header.opcode()),
            authoritative: header.authoritative(),
            truncated: header.truncated(),
            recursion_desired: header.recursion_desired(),
            recursion_available: header.recursion_available(),
            authentic_data: header.authentic_data(),
            checking_disabled: header.checking_disabled(),
            response_code: ResponseCode::from(raw_rcode),
        }
    }
}

/// Fully decoded owned message sections.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct MessageData {
    /// Decoded header state.
    pub(crate) header: MessageHeaderData,
    /// Question section.
    pub(crate) questions: Vec<Question>,
    /// Answer section.
    pub(crate) answers: Vec<Record>,
    /// Authority section.
    pub(crate) name_servers: Vec<Record>,
    /// Additional section.
    pub(crate) additionals: Vec<Record>,
}

impl MessageData {
    /// Construct an empty decoded message body.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Return the maximum UDP payload size implied by any OPT record.
    pub(crate) fn max_payload(&self) -> u16 {
        self.additionals
            .iter()
            .find_map(|record| match record.data() {
                RData::OPT(opt) => Some(opt.0.udp_payload_size().max(512)),
                _ => None,
            })
            .unwrap_or(512)
    }
}

/// Packet-backed state used on the hot path.
///
/// `packet` always holds validated DNS wire bytes. `header` and `max_payload`
/// are extracted eagerly so common accessors do not need to decode records. The
/// fully decoded form is cached lazily in `decoded` and only built when a
/// caller asks for owned sections or mutable access.
struct PacketMessage {
    /// Original validated wire bytes.
    packet: Packet,
    /// Parsed header metadata cached eagerly.
    header: MessageHeaderData,
    /// Original question count from the header.
    question_count: u16,
    /// Cached first-question metadata.
    question: Option<QuestionMeta>,
    /// Cached EDNS metadata.
    edns: Option<EdnsMeta>,
    /// Cached section offsets.
    sections: SectionOffsets,
    /// Cached maximum payload size.
    max_payload: u16,
    /// Lazily decoded owned form for callers that need full record access.
    decoded: OnceLock<Arc<MessageData>>,
}

impl PacketMessage {
    /// Return the lazily decoded owned message state.
    fn decoded(&self) -> &MessageData {
        self.decoded
            .get_or_init(|| {
                Arc::new(
                    decode_owned(self.packet.as_slice())
                        .expect("packet-backed message should come from validated wire bytes"),
                )
            })
            .as_ref()
    }

    /// Rebuild the first question as a borrowed packet view.
    fn first_question_ref(&self) -> Option<QuestionRef<'_>> {
        self.question
            .as_ref()
            .map(|question| question.as_question_ref(self.packet.as_slice()))
    }

    /// Rebuild the cached EDNS metadata as a borrowed packet view.
    fn edns_ref(&self) -> Option<EdnsRef<'_>> {
        self.edns
            .as_ref()
            .map(|edns| edns.as_edns_ref(self.packet.as_slice()))
    }
}

impl Clone for PacketMessage {
    /// Clone packet-backed state while preserving the decoded cache if present.
    fn clone(&self) -> Self {
        let decoded = OnceLock::new();
        if let Some(existing) = self.decoded.get() {
            let _ = decoded.set(existing.clone());
        }
        Self {
            packet: self.packet.clone(),
            header: self.header.clone(),
            question_count: self.question_count,
            question: self.question.clone(),
            edns: self.edns.clone(),
            sections: self.sections,
            max_payload: self.max_payload,
            decoded,
        }
    }
}

impl Debug for PacketMessage {
    /// Debug-print packet-backed message metadata without forcing decode.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketMessage")
            .field("header", &self.header)
            .field("packet_len", &self.packet.as_slice().len())
            .field("question_count", &self.question_count)
            .field("decoded", &self.decoded.get().is_some())
            .finish()
    }
}

/// Internal storage mode of a [`Message`].
#[derive(Debug, Clone)]
enum MessageRepr {
    /// Fully decoded message used after any structural mutation.
    Owned(Arc<MessageData>),
    /// Zero-copy view over validated wire bytes used by the hot path.
    Packet(PacketMessage),
}

/// DNS message that can stay packet-backed until mutation requires ownership.
#[derive(Clone)]
pub struct Message {
    /// Current backing representation.
    repr: MessageRepr,
    /// Monotonic revision used to invalidate derived caches such as `query_view`.
    version: u64,
}

impl PartialEq for Message {
    /// Compare packet-backed messages by bytes and owned messages by decoded data.
    fn eq(&self, other: &Self) -> bool {
        match (&self.repr, &other.repr) {
            (MessageRepr::Packet(left), MessageRepr::Packet(right)) => {
                left.packet.as_slice() == right.packet.as_slice()
            }
            _ => self.decoded() == other.decoded(),
        }
    }
}

impl Eq for Message {}

impl Debug for Message {
    /// Debug-print the current representation without forcing decode.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.repr {
            MessageRepr::Owned(data) => f
                .debug_struct("Message")
                .field("mode", &"owned")
                .field("header", &data.header)
                .field("questions", &data.questions.len())
                .field("answers", &data.answers.len())
                .field("name_servers", &data.name_servers.len())
                .field("additionals", &data.additionals.len())
                .finish(),
            MessageRepr::Packet(packet) => f
                .debug_struct("Message")
                .field("mode", &"packet")
                .field("packet", packet)
                .finish(),
        }
    }
}

impl Default for Message {
    /// Construct an empty query message.
    fn default() -> Self {
        Self::new()
    }
}

impl Message {
    /// Construct a new empty query message in owned form.
    pub fn new() -> Self {
        Self {
            repr: MessageRepr::Owned(Arc::new(MessageData::new())),
            version: 0,
        }
    }

    /// Decode a fully owned message from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            repr: MessageRepr::Owned(Arc::new(decode_owned(bytes)?)),
            version: 0,
        })
    }

    /// Build a packet-backed message from already validated or ForgeDNS-generated wire bytes.
    ///
    /// This only parses header/question-section metadata up front and defers
    /// full RR decoding until a caller requests owned sections or mutable access.
    pub fn from_packet(packet: Packet) -> Result<Self> {
        let parsed = parse_message(packet.as_slice())?;
        let ext_rcode = parsed.edns().map(|edns| edns.ext_rcode()).unwrap_or(0);
        let header = MessageHeaderData::from_header(parsed.header(), ext_rcode);
        let question = parsed.first_question_meta().cloned();
        let edns = parsed.edns_meta().cloned();
        let max_payload = parsed
            .edns()
            .map(|edns| edns.udp_payload_size().max(512))
            .unwrap_or(512);
        let question_count = parsed.header().qdcount();
        let sections = parsed.sections();
        Ok(Self {
            repr: MessageRepr::Packet(PacketMessage {
                packet,
                header,
                question_count,
                question,
                edns,
                sections,
                max_payload,
                decoded: OnceLock::new(),
            }),
            version: 0,
        })
    }

    #[inline]
    /// Borrow the original packet when this message is still packet-backed.
    pub fn packet(&self) -> Option<&Packet> {
        match &self.repr {
            MessageRepr::Packet(packet) => Some(&packet.packet),
            MessageRepr::Owned(_) => None,
        }
    }

    /// Consume the message and encode or return its packet representation.
    pub fn into_packet(self) -> Result<Packet> {
        match self.repr {
            MessageRepr::Packet(packet) => Ok(packet.packet),
            MessageRepr::Owned(data) => Ok(Packet::from_vec(encode_owned(data.as_ref(), None)?)),
        }
    }

    /// Encode the message into a newly allocated byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_bytes_with_limit(usize::MAX)
    }

    /// Encode the message into a newly allocated byte vector while honoring `max_size`.
    pub fn to_bytes_with_limit(&self, max_size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        self.encode_into_with_limit(max_size, &mut out)?;
        Ok(out)
    }

    /// Encode the message into `out` without an explicit size cap.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_into_with_limit(usize::MAX, out)
    }

    /// Encode the message into `out`, preserving raw packet bytes when possible.
    ///
    /// Packet-backed messages can skip re-encoding entirely if the original
    /// packet already fits within `max_size`. Once the size limit would force a
    /// truncation decision, we fall back to owned encoding so counts, flags, and
    /// compression stay consistent.
    pub fn encode_into_with_limit(&self, max_size: usize, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        match &self.repr {
            MessageRepr::Packet(packet) if packet.packet.as_slice().len() <= max_size => {
                out.extend_from_slice(packet.packet.as_slice());
                Ok(())
            }
            MessageRepr::Packet(packet) => encode_owned_into(packet.decoded(), Some(max_size), out),
            MessageRepr::Owned(data) => encode_owned_into(data.as_ref(), Some(max_size), out),
        }
    }

    #[inline]
    /// Borrow the decoded internal header state.
    fn header(&self) -> &MessageHeaderData {
        match &self.repr {
            MessageRepr::Owned(data) => &data.header,
            MessageRepr::Packet(packet) => &packet.header,
        }
    }

    /// Materialize packet-backed data into the owned representation.
    ///
    /// This transition is intentionally one-way. Once a caller mutates a field
    /// that is not safe to patch directly in the raw packet, future operations
    /// operate on the owned form and re-encode on demand.
    fn ensure_owned_mut(&mut self) -> &mut MessageData {
        if matches!(self.repr, MessageRepr::Packet(_)) {
            let decoded = match std::mem::replace(
                &mut self.repr,
                MessageRepr::Owned(Arc::new(MessageData::new())),
            ) {
                MessageRepr::Packet(packet) => Arc::clone(packet.decoded.get_or_init(|| {
                    Arc::new(
                        decode_owned(packet.packet.as_slice())
                            .expect("packet-backed message should come from validated wire bytes"),
                    )
                })),
                MessageRepr::Owned(data) => data,
            };
            self.repr = MessageRepr::Owned(decoded);
        }

        match &mut self.repr {
            MessageRepr::Owned(data) => Arc::make_mut(data),
            MessageRepr::Packet(_) => unreachable!("message should be owned after materialization"),
        }
    }

    /// Borrow the fully decoded internal message state.
    fn decoded(&self) -> &MessageData {
        match &self.repr {
            MessageRepr::Owned(data) => data.as_ref(),
            MessageRepr::Packet(packet) => packet.decoded(),
        }
    }

    #[inline]
    /// Increment the internal revision counter after a mutation.
    fn bump_version(&mut self) {
        self.version = self.version.wrapping_add(1);
    }

    #[inline]
    /// Return the current mutation revision of this message.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Return the DNS message identifier.
    pub fn id(&self) -> u16 {
        self.header().id
    }

    /// Update the DNS message identifier.
    pub fn set_id(&mut self, id: u16) {
        self.bump_version();
        match &mut self.repr {
            MessageRepr::Owned(data) => {
                Arc::make_mut(data).header.id = id;
            }
            MessageRepr::Packet(packet) => {
                packet.header.id = id;
                let mut bytes = packet.packet.as_slice().to_vec();
                bytes[0..2].copy_from_slice(&id.to_be_bytes());
                packet.packet = Packet::from_vec(bytes);
                if let Some(decoded) = packet.decoded.get_mut() {
                    Arc::make_mut(decoded).header.id = id;
                }
            }
        }
    }

    /// Rewrite the first question type without materializing the whole message.
    ///
    /// This is used by query-rewrite paths that only need to patch the first
    /// wire question. The method returns `false` when the packet has no
    /// question, and it keeps packet-backed mode intact when the rewrite
    /// succeeds.
    pub fn set_first_question_type_fast(&mut self, question_type: RecordType) -> bool {
        self.bump_version();
        match &mut self.repr {
            MessageRepr::Owned(data) => {
                let Some(question) = Arc::make_mut(data).questions.first_mut() else {
                    return false;
                };
                question.question_type = question_type;
                true
            }
            MessageRepr::Packet(packet) => {
                let Some(question) = packet.question.as_mut() else {
                    return false;
                };
                let qtype_offset = question.wire_range.end as usize - 4;
                let mut bytes = packet.packet.as_slice().to_vec();
                bytes[qtype_offset..qtype_offset + 2]
                    .copy_from_slice(&u16::from(question_type).to_be_bytes());
                packet.packet = Packet::from_vec(bytes);
                question.qtype = u16::from(question_type);
                if let Some(decoded) = packet.decoded.get_mut() {
                    let Some(question) = Arc::make_mut(decoded).questions.first_mut() else {
                        return false;
                    };
                    question.question_type = question_type;
                }
                true
            }
        }
    }

    /// Return whether this is a query or response message.
    pub fn message_type(&self) -> MessageType {
        self.header().message_type
    }

    /// Update the message direction.
    pub fn set_message_type(&mut self, message_type: MessageType) {
        self.bump_version();
        self.ensure_owned_mut().header.message_type = message_type;
    }

    /// Return the DNS operation code.
    pub fn op_code(&self) -> OpCode {
        self.header().op_code
    }

    /// Update the DNS operation code.
    pub fn set_op_code(&mut self, op_code: OpCode) {
        self.bump_version();
        self.ensure_owned_mut().header.op_code = op_code;
    }

    /// Return the `AA` flag state.
    pub fn authoritative(&self) -> bool {
        self.header().authoritative
    }

    /// Update the `AA` flag state.
    pub fn set_authoritative(&mut self, value: bool) {
        self.bump_version();
        self.ensure_owned_mut().header.authoritative = value;
    }

    /// Return the `TC` flag state.
    pub fn truncated(&self) -> bool {
        self.header().truncated
    }

    /// Update the `TC` flag state.
    pub fn set_truncated(&mut self, value: bool) {
        self.bump_version();
        self.ensure_owned_mut().header.truncated = value;
    }

    /// Return the `RD` flag state.
    pub fn recursion_desired(&self) -> bool {
        self.header().recursion_desired
    }

    /// Update the `RD` flag state.
    pub fn set_recursion_desired(&mut self, value: bool) {
        self.bump_version();
        self.ensure_owned_mut().header.recursion_desired = value;
    }

    /// Return the `RA` flag state.
    pub fn recursion_available(&self) -> bool {
        self.header().recursion_available
    }

    /// Update the `RA` flag state.
    pub fn set_recursion_available(&mut self, value: bool) {
        self.bump_version();
        self.ensure_owned_mut().header.recursion_available = value;
    }

    /// Return the `AD` flag state.
    pub fn authentic_data(&self) -> bool {
        self.header().authentic_data
    }

    /// Update the `AD` flag state.
    pub fn set_authentic_data(&mut self, value: bool) {
        self.bump_version();
        self.ensure_owned_mut().header.authentic_data = value;
    }

    /// Return the `CD` flag state.
    pub fn checking_disabled(&self) -> bool {
        self.header().checking_disabled
    }

    /// Update the `CD` flag state.
    pub fn set_checking_disabled(&mut self, value: bool) {
        self.bump_version();
        self.ensure_owned_mut().header.checking_disabled = value;
    }

    /// Return the decoded DNS response code.
    pub fn response_code(&self) -> ResponseCode {
        self.header().response_code
    }

    /// Update the decoded DNS response code.
    pub fn set_response_code(&mut self, response_code: ResponseCode) {
        self.bump_version();
        self.ensure_owned_mut().header.response_code = response_code;
    }

    /// Borrow the first decoded question, if present.
    pub fn question(&self) -> Option<&Question> {
        self.decoded().questions.first()
    }

    #[inline]
    /// Return the original question count without forcing full decode when packet-backed.
    pub fn question_count(&self) -> u16 {
        match &self.repr {
            MessageRepr::Owned(data) => data.questions.len() as u16,
            MessageRepr::Packet(packet) => packet.question_count,
        }
    }

    /// Return a unified read-only view of the first question.
    pub fn first_question_access(&self) -> Option<QuestionAccess<'_>> {
        match &self.repr {
            MessageRepr::Owned(data) => data.questions.first().map(QuestionAccess::Owned),
            MessageRepr::Packet(packet) => packet.first_question_ref().map(QuestionAccess::Wire),
        }
    }

    #[inline]
    /// Return the first question type without forcing full decode when possible.
    pub fn first_question_type(&self) -> Option<RecordType> {
        match &self.repr {
            MessageRepr::Owned(data) => data
                .questions
                .first()
                .map(|question| question.question_type),
            MessageRepr::Packet(packet) => packet
                .question
                .as_ref()
                .map(|question| RecordType::from(question.qtype)),
        }
    }

    #[inline]
    /// Return the first question class without forcing full decode when possible.
    pub fn first_question_class(&self) -> Option<DNSClass> {
        match &self.repr {
            MessageRepr::Owned(data) => data
                .questions
                .first()
                .map(|question| question.question_class),
            MessageRepr::Packet(packet) => packet
                .question
                .as_ref()
                .map(|question| DNSClass::from(question.qclass)),
        }
    }

    /// Return the first question name as an owned [`Name`].
    pub fn first_question_name_owned(&self) -> Option<Name> {
        match &self.repr {
            MessageRepr::Owned(data) => data
                .questions
                .first()
                .map(|question| question.name().clone()),
            MessageRepr::Packet(packet) => packet.question.as_ref().map(|question| {
                Name::from_wire_ref(&question.name.as_name_ref(packet.packet.as_slice()))
            }),
        }
    }

    /// Borrow the decoded question section.
    pub fn questions(&self) -> &[Question] {
        &self.decoded().questions
    }

    /// Mutably borrow the decoded question section, materializing if needed.
    pub fn questions_mut(&mut self) -> &mut Vec<Question> {
        self.bump_version();
        &mut self.ensure_owned_mut().questions
    }

    /// Append one question to the message.
    pub fn add_question(&mut self, question: Question) {
        self.bump_version();
        self.ensure_owned_mut().questions.push(question);
    }

    /// Take ownership of the decoded question section.
    pub fn take_questions(&mut self) -> Vec<Question> {
        self.bump_version();
        std::mem::take(&mut self.ensure_owned_mut().questions)
    }

    /// Borrow the decoded answer section.
    pub fn answers(&self) -> &[Record] {
        &self.decoded().answers
    }

    /// Mutably borrow the decoded answer section, materializing if needed.
    pub fn answers_mut(&mut self) -> &mut Vec<Record> {
        self.bump_version();
        &mut self.ensure_owned_mut().answers
    }

    /// Append one record to the answer section.
    pub fn add_answer(&mut self, record: Record) {
        self.bump_version();
        self.ensure_owned_mut().answers.push(record);
    }

    /// Borrow the decoded authority section.
    pub fn name_servers(&self) -> &[Record] {
        &self.decoded().name_servers
    }

    /// Mutably borrow the decoded authority section, materializing if needed.
    pub fn name_servers_mut(&mut self) -> &mut Vec<Record> {
        self.bump_version();
        &mut self.ensure_owned_mut().name_servers
    }

    /// Append one record to the authority section.
    pub fn add_name_server(&mut self, record: Record) {
        self.bump_version();
        self.ensure_owned_mut().name_servers.push(record);
    }

    /// Borrow the decoded additional section.
    pub fn additionals(&self) -> &[Record] {
        &self.decoded().additionals
    }

    /// Mutably borrow the decoded additional section, materializing if needed.
    pub fn additionals_mut(&mut self) -> &mut Vec<Record> {
        self.bump_version();
        &mut self.ensure_owned_mut().additionals
    }

    /// Append one record to the additional section.
    pub fn add_additional(&mut self, record: Record) {
        self.bump_version();
        self.ensure_owned_mut().additionals.push(record);
    }

    /// Borrow the first owned OPT payload, if present.
    pub fn edns(&self) -> Option<&Edns> {
        self.additionals()
            .iter()
            .find_map(|record| match record.data() {
                RData::OPT(opt) => Some(&opt.0),
                _ => None,
            })
    }

    /// Mutably borrow the first owned OPT payload, materializing if needed.
    pub fn edns_mut(&mut self) -> Option<&mut Edns> {
        self.additionals_mut()
            .iter_mut()
            .find_map(|record| match record.data_mut() {
                RData::OPT(opt) => Some(&mut opt.0),
                _ => None,
            })
    }

    /// Insert or replace the owned EDNS state.
    pub fn set_edns(&mut self, edns: Edns) {
        self.bump_version();
        if let Some(existing) = self.edns_mut() {
            *existing = edns;
            return;
        }
        self.add_additional(Record::from_rdata(Name::root(), 0, RData::OPT(OPT(edns))));
    }

    /// Return a unified read-only EDNS view.
    pub fn edns_access(&self) -> Option<EdnsAccess<'_>> {
        match &self.repr {
            MessageRepr::Owned(data) => {
                data.additionals
                    .iter()
                    .find_map(|record| match record.data() {
                        RData::OPT(opt) => Some(EdnsAccess::Owned(&opt.0)),
                        _ => None,
                    })
            }
            MessageRepr::Packet(packet) => packet.edns_ref().map(EdnsAccess::Wire),
        }
    }

    /// Return the negotiated maximum payload size for this message.
    pub fn max_payload(&self) -> u16 {
        match &self.repr {
            MessageRepr::Packet(packet) => packet.max_payload,
            MessageRepr::Owned(data) => data.max_payload(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::model::data::rdata::A;
    use crate::message::model::data::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
    use std::net::{IpAddr, Ipv4Addr};

    /// Build a one-question query packet used by packet-backed message tests.
    fn build_query_packet(id: u16, query_type: RecordType) -> Packet {
        let mut message = Message::new();
        message.set_id(id);
        message.set_recursion_desired(true);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should be valid"),
            query_type,
        ));
        Packet::from_vec(message.to_bytes().expect("message should encode"))
    }

    #[test]
    /// Ensure rewriting the message ID patches wire bytes without forcing ownership.
    fn packet_backed_set_id_rewrites_wire_without_materializing() {
        let mut message = Message::from_packet(build_query_packet(0x1234, RecordType::A))
            .expect("packet-backed message should parse");

        message.set_id(0xBEEF);

        assert!(message.packet().is_some());
        assert_eq!(message.id(), 0xBEEF);
        assert_eq!(
            &message.to_bytes().expect("message should encode")[0..2],
            &0xBEEFu16.to_be_bytes()
        );
    }

    #[test]
    /// Ensure first-question type rewrites stay packet-backed when only wire bytes change.
    fn packet_backed_fast_question_type_rewrite_updates_wire_question() {
        let mut message = Message::from_packet(build_query_packet(7, RecordType::A))
            .expect("packet-backed message should parse");

        assert!(message.set_first_question_type_fast(RecordType::AAAA));
        assert!(message.packet().is_some());
        assert_eq!(
            message
                .question()
                .expect("question should exist")
                .question_type(),
            RecordType::AAAA
        );

        let reparsed = message
            .packet()
            .expect("message should stay packet-backed")
            .parse()
            .expect("packet should parse");
        assert_eq!(
            reparsed
                .first_question()
                .expect("question should exist")
                .qtype(),
            u16::from(RecordType::AAAA)
        );
    }

    #[test]
    /// Structural header mutations should materialize the owned message representation.
    fn packet_backed_structural_mutation_materializes_owned_message() {
        let mut message = Message::from_packet(build_query_packet(7, RecordType::A))
            .expect("packet-backed message should parse");

        message.set_response_code(ResponseCode::ServFail);

        assert!(message.packet().is_none());
        assert_eq!(message.response_code(), ResponseCode::ServFail);
    }

    #[test]
    /// Repeated owner names should be compressed to a pointer during encoding.
    fn encoder_compresses_repeated_owner_name() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should be valid"),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").expect("answer name should be valid"),
            300,
            RData::A(A::new(1, 1, 1, 1)),
        ));

        let bytes = message.to_bytes().expect("message should encode");

        assert!(bytes.windows(2).any(|window| window == [0xC0, 0x0C]));
        assert_eq!(
            Message::from_bytes(&bytes)
                .expect("message should decode")
                .answers()
                .len(),
            1
        );
    }

    #[test]
    /// ECS encoding must mask host bits beyond the requested source prefix length.
    fn ecs_encoder_masks_partial_byte() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should be valid"),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 129)),
            25,
            0,
        )));
        message.set_edns(edns);

        let decoded = Message::from_bytes(
            &message
                .to_bytes()
                .expect("message with ecs should encode successfully"),
        )
        .expect("message with ecs should decode successfully");
        let subnet = match decoded
            .edns()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
        {
            Some(EdnsOption::Subnet(subnet)) => subnet,
            other => panic!("expected ecs subnet, got {other:?}"),
        };

        assert_eq!(subnet.addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 128)));
    }
}
