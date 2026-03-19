/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS message model.

use crate::core::error::{DnsError, Result};
use crate::message::rdata::{A, AAAA, Edns};
use crate::message::wire::{
    decode_message, edns_record_len, encode_message_into, encode_message_with_limit_into,
};
use crate::message::{
    DNSClass, Header, MessageType, Name, Opcode, Question, RData, Rcode, Record, RecordType,
};
use std::net::IpAddr;

/// Owned DNS message that flows directly through the pipeline.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Message {
    header: Header,
    compress: bool,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    signature: Vec<Record>,
    edns: Option<Edns>,
}

#[allow(dead_code)]
impl Message {
    /// Construct a new empty query message.
    pub fn new() -> Self {
        Message {
            header: Header::default(),
            compress: false,
            questions: Vec::new(),
            answers: Vec::default(),
            authorities: Vec::default(),
            additionals: Vec::default(),
            signature: Vec::default(),
            edns: None,
        }
    }

    pub(crate) fn new_with_params(
        header: Header,
        compress: bool,
        questions: Vec<Question>,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
        signature: Vec<Record>,
        edns: Option<Edns>,
    ) -> Message {
        Message {
            header,
            compress,
            questions,
            answers,
            authorities,
            additionals,
            signature,
            edns,
        }
    }

    /// Decode a DNS message from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_message(bytes)
    }

    /// Encode the message into a newly allocated byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1024);
        encode_message_into(self, self.id(), &mut out)?;
        Ok(out)
    }

    /// Append the encoded wire message to the provided buffer.
    ///
    /// This method preserves any bytes that are already present in `out` and
    /// writes the DNS header and body after the current end of the buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_message_into(self, self.id(), out)
    }

    /// Append the encoded wire message to the provided buffer without clearing it first.
    pub fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_message_into(self, self.id(), out)
    }

    /// Encode the message into a newly allocated byte vector with an overridden ID.
    pub fn to_bytes_with_id(&self, id: u16) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        encode_message_into(self, id, &mut out)?;
        Ok(out)
    }

    /// Append the encoded wire message with an overridden ID to the provided buffer.
    ///
    /// This method preserves any bytes that are already present in `out` and
    /// writes the DNS header and body after the current end of the buffer.
    pub fn encode_into_with_id(&self, id: u16, out: &mut Vec<u8>) -> Result<()> {
        encode_message_into(self, id, out)
    }

    /// Append the encoded wire message with an overridden ID to the provided buffer.
    pub fn append_to_with_id(&self, id: u16, out: &mut Vec<u8>) -> Result<()> {
        encode_message_into(self, id, out)
    }

    /// Encode the message into a newly allocated byte vector while honoring `max_size`.
    pub fn to_bytes_with_limit(&self, max_size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        encode_message_with_limit_into(self, Some(max_size), self.id(), &mut out)?;
        Ok(out)
    }

    /// Encode the message into a newly allocated byte vector with an overridden ID and size cap.
    pub fn to_bytes_with_limit_and_id(&self, max_size: usize, id: u16) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        encode_message_with_limit_into(self, Some(max_size), id, &mut out)?;
        Ok(out)
    }

    /// Truncate this message in-place to the requested UDP payload budget.
    ///
    /// Behavior matches miekg/dns `Msg.Truncate` semantics:
    /// - skips truncation when TSIG is present,
    /// - treats sizes below 512 as 512,
    /// - disables compression when uncompressed payload already fits,
    /// - otherwise truncates `Answer`, then `Authority`, then `Additional`,
    /// - preserves a single OPT RR at the end when present,
    /// - sets TC if any RR is omitted.
    pub fn truncate(&mut self, max_size: usize) {
        if !self.signature.is_empty() {
            return;
        }

        let mut size = max_size.max(512);
        let uncompressed_len = self.bytes_len_with_compression(false);
        if uncompressed_len <= size {
            self.set_compress(false);
            self.set_truncated(false);
            return;
        }

        self.set_compress(true);

        if let Some(edns) = self.edns.as_ref() {
            size = size.saturating_sub(edns_record_len(edns));
        }

        let mut compression = crate::message::codec::LenCompressionMap::new(true);

        let mut len = crate::message::codec::DNS_HEADER_LEN;
        for question in self.questions() {
            len += question.bytes_len(len, &mut compression);
        }

        let mut answer_count = 0usize;
        if len < size {
            answer_count = crate::message::wire::truncate_loop(
                self.answers(),
                size,
                &mut len,
                &mut compression,
            );
        }

        let mut authority_count = 0usize;
        if len < size {
            authority_count = crate::message::wire::truncate_loop(
                self.authorities(),
                size,
                &mut len,
                &mut compression,
            );
        }

        let mut additional_count = 0usize;
        if len < size {
            additional_count = crate::message::wire::truncate_loop(
                self.additionals(),
                size,
                &mut len,
                &mut compression,
            );
        }

        let omitted = self.answers().len() > answer_count
            || self.authorities().len() > authority_count
            || self.additionals().len() > additional_count;
        self.set_truncated(omitted);

        self.answers.truncate(answer_count);
        self.authorities.truncate(authority_count);
        self.additionals.truncate(additional_count);
    }

    /// Return whether name compression is enabled when encoding.
    pub fn compressed(&self) -> bool {
        self.compress
    }

    /// miekg/dns-compatible naming: return compression switch for packing.
    pub fn compress(&self) -> bool {
        self.compress
    }

    /// miekg/dns-compatible naming: set compression switch for packing.
    pub fn set_compress(&mut self, compress: bool) {
        self.compress = compress;
    }

    pub(crate) fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    pub fn id(&self) -> u16 {
        self.header.id()
    }

    pub fn set_id(&mut self, id: u16) {
        self.header.set_id(id);
    }

    pub fn message_type(&self) -> MessageType {
        self.header.message_type()
    }

    pub fn set_message_type(&mut self, kind: MessageType) {
        self.header.set_message_type(kind);
    }

    pub fn opcode(&self) -> Opcode {
        self.header.opcode()
    }

    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.header.set_opcode(opcode);
    }

    pub fn authoritative(&self) -> bool {
        self.header.authoritative()
    }

    pub fn set_authoritative(&mut self, value: bool) {
        self.header.set_authoritative(value);
    }

    pub fn truncated(&self) -> bool {
        self.header.truncated()
    }

    pub fn set_truncated(&mut self, value: bool) {
        self.header.set_truncated(value);
    }

    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired()
    }

    pub fn set_recursion_desired(&mut self, value: bool) {
        self.header.set_recursion_desired(value);
    }

    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available()
    }

    pub fn set_recursion_available(&mut self, value: bool) {
        self.header.set_recursion_available(value);
    }

    pub fn authentic_data(&self) -> bool {
        self.header.authentic_data()
    }

    pub fn set_authentic_data(&mut self, value: bool) {
        self.header.set_authentic_data(value);
    }

    pub fn checking_disabled(&self) -> bool {
        self.header.checking_disabled()
    }

    pub fn set_checking_disabled(&mut self, value: bool) {
        self.header.set_checking_disabled(value);
    }

    pub fn rcode(&self) -> Rcode {
        self.header.rcode()
    }

    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.header.set_rcode(rcode);
        self.sync_edns_ext_rcode();
    }

    pub fn question_count(&self) -> u16 {
        self.questions.len() as u16
    }

    pub fn answer_count(&self) -> u16 {
        self.answers.len() as u16
    }

    pub fn authority_count(&self) -> u16 {
        self.authorities.len() as u16
    }
    pub fn additional_count(&self) -> u16 {
        self.additionals.len() as u16
            + self.signature.len() as u16
            + if self.edns.is_some() { 1 } else { 0 }
    }

    fn sync_edns_ext_rcode(&mut self) {
        let ext_rcode = (u16::from(self.rcode()) >> 4) as u8;
        if let Some(edns) = self.edns_mut() {
            edns.set_ext_rcode(ext_rcode);
        }
    }

    pub fn first_question(&self) -> Option<&Question> {
        self.questions.first()
    }

    pub fn first_question_mut(&mut self) -> Option<&mut Question> {
        self.questions.first_mut()
    }

    pub fn first_qtype(&self) -> Option<RecordType> {
        self.first_question().map(Question::qtype)
    }

    pub fn first_qclass(&self) -> Option<DNSClass> {
        self.first_question().map(Question::qclass)
    }

    pub fn set_first_qtype(&mut self, qtype: RecordType) -> bool {
        let Some(question) = self.first_question_mut() else {
            return false;
        };
        question.set_qtype(qtype);
        true
    }

    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    pub fn questions_mut(&mut self) -> &mut Vec<Question> {
        &mut self.questions
    }

    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
    }

    pub fn take_questions(&mut self) -> Vec<Question> {
        std::mem::take(&mut self.questions)
    }

    pub fn answers(&self) -> &[Record] {
        &self.answers
    }

    pub fn answers_mut(&mut self) -> &mut Vec<Record> {
        &mut self.answers
    }

    pub fn add_answer(&mut self, record: Record) {
        self.answers.push(record);
    }

    pub fn take_answers(&mut self) -> Vec<Record> {
        std::mem::take(&mut self.answers)
    }
    pub fn authorities(&self) -> &[Record] {
        &self.authorities
    }

    pub fn authorities_mut(&mut self) -> &mut Vec<Record> {
        &mut self.authorities
    }

    pub fn add_authority(&mut self, record: Record) {
        self.authorities.push(record);
    }

    pub fn take_authorities(&mut self) -> Vec<Record> {
        std::mem::take(&mut self.authorities)
    }

    pub fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    pub fn additionals_mut(&mut self) -> &mut Vec<Record> {
        &mut self.additionals
    }

    pub fn add_additional(&mut self, record: Record) {
        self.additionals.push(record);
    }

    pub fn take_additionals(&mut self) -> Vec<Record> {
        std::mem::take(&mut self.additionals)
    }

    pub fn edns(&self) -> &Option<Edns> {
        &self.edns
    }

    pub fn edns_mut(&mut self) -> &mut Option<Edns> {
        &mut self.edns
    }

    pub fn ensure_edns_mut(&mut self) -> &mut Edns {
        if self.edns().is_none() {
            self.set_edns(Edns::new());
        }
        self.edns.as_mut().unwrap()
    }

    pub fn set_edns(&mut self, edns: Edns) {
        let mut edns = edns;
        edns.set_ext_rcode((u16::from(self.rcode()) >> 4) as u8);
        self.edns_mut().replace(edns);
    }

    pub fn signature(&self) -> &[Record] {
        &self.signature
    }

    pub fn signature_mut(&mut self) -> &mut Vec<Record> {
        &mut self.signature
    }

    pub fn take_signature(&mut self) -> Vec<Record> {
        std::mem::take(&mut self.signature)
    }

    pub fn max_payload(&self) -> u16 {
        self.edns
            .as_ref()
            .map(|e| e.udp_payload_size().max(512))
            .unwrap_or(512)
    }

    pub fn response(&self, rcode: Rcode) -> Message {
        let mut response = Message::new();
        response.set_id(self.id());
        response.set_opcode(self.opcode());
        response.set_message_type(MessageType::Response);
        response.set_recursion_desired(self.recursion_desired());
        response.set_checking_disabled(self.checking_disabled());
        response.set_rcode(rcode);
        response.questions = self.questions.clone();
        if let Some(request_edns) = self.edns() {
            let mut edns = Edns::new();
            edns.set_udp_payload_size(request_edns.udp_payload_size());
            edns.set_version(request_edns.version());
            *edns.flags_mut() = *request_edns.flags();
            edns.set_ext_rcode((u16::from(rcode) >> 4) as u8);
            response.set_edns(edns);
        } else if u16::from(rcode) > 0x0f {
            let mut edns = Edns::new();
            edns.set_ext_rcode((u16::from(rcode) >> 4) as u8);
            response.set_edns(edns);
        }
        response
    }

    pub fn address_response(
        &self,
        question: &Question,
        ttl: u32,
        addresses: &[IpAddr],
    ) -> Result<Message> {
        let mut response = self.response(Rcode::NoError);
        let qname = question.name();
        let qtype = question.qtype();
        for &addr in addresses {
            match (qtype, addr) {
                (RecordType::A, IpAddr::V4(v4)) => {
                    response.add_answer(Record::from_rdata(qname.clone(), ttl, RData::A(A(v4))));
                }
                (RecordType::AAAA, IpAddr::V6(v6)) => {
                    response.add_answer(Record::from_rdata(
                        qname.clone(),
                        ttl,
                        RData::AAAA(AAAA(v6)),
                    ));
                }
                (RecordType::A, IpAddr::V6(_)) | (RecordType::AAAA, IpAddr::V4(_)) => {}
                _ => {
                    return Err(DnsError::protocol(
                        "synthetic address response only supports A/AAAA questions",
                    ));
                }
            }
        }
        Ok(response)
    }

    pub fn answer_ips(&self) -> Vec<IpAddr> {
        self.answers.iter().filter_map(Record::ip_addr).collect()
    }

    pub fn has_answer_ip(&self, mut pred: impl FnMut(IpAddr) -> bool) -> bool {
        self.answers
            .iter()
            .filter_map(Record::ip_addr)
            .any(&mut pred)
    }

    pub fn answer_ip_ttls(&self) -> Vec<(IpAddr, u32)> {
        let mut out = Vec::new();
        for record in &self.answers {
            if let Some(ip) = record.ip_addr() {
                out.push((ip, record.ttl()));
            }
        }
        out
    }

    pub fn cnames(&self) -> Vec<&Name> {
        self.answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
            .filter_map(|record| record.cname_target().map(|name| name))
            .collect()
    }

    pub fn has_answer_types(&self, wanted: &[RecordType]) -> bool {
        self.answers
            .iter()
            .any(|record| wanted.contains(&record.rr_type()))
    }
    pub fn has_answer_type(&self, wanted: RecordType) -> bool {
        self.answers.iter().any(|record| wanted == record.rr_type())
    }

    pub fn min_answer_ttl(&self) -> Option<u32> {
        self.answers.iter().map(Record::ttl).min()
    }

    pub fn negative_ttl_from_soa(&self) -> Option<u32> {
        self.authorities
            .iter()
            .filter_map(|record| match record.data() {
                RData::SOA(soa) => Some(record.ttl().min(soa.minimum())),
                _ => None,
            })
            .min()
    }

    pub fn bytes_len(&self) -> usize {
        self.bytes_len_with_compression(self.compress())
    }

    pub(crate) fn bytes_len_with_compression(&self, compress_enabled: bool) -> usize {
        let can_compress = compress_enabled
            && (self.questions().len() > 1
                || !self.answers().is_empty()
                || !self.authorities().is_empty()
                || !self.additionals().is_empty()
                || !self.signature().is_empty()
                || self.edns().is_some());

        let mut compression = crate::message::codec::LenCompressionMap::new(can_compress);
        let mut len = crate::message::codec::DNS_HEADER_LEN;

        for question in self.questions() {
            len += question.bytes_len(len, &mut compression);
        }

        for record in self.answers() {
            len += record.bytes_len(len, &mut compression);
        }
        for record in self.authorities() {
            len += record.bytes_len(len, &mut compression);
        }
        for record in self.additionals() {
            len += record.bytes_len(len, &mut compression);
        }
        if let Some(edns) = self.edns() {
            len += edns_record_len(edns);
        }
        for record in self.signature() {
            len += record.bytes_len(len, &mut compression);
        }

        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::rdata::{Edns, TXT};

    #[test]
    // Verifies the classic DNS truncation rule that TC must be set and OPT must remain
    // attached when space allows.
    fn truncate_retains_edns_and_sets_tc() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        for index in 0..8 {
            let owner = format!("node{index}.example.com.");
            message.add_answer(Record::from_rdata(
                Name::from_ascii(&owner).unwrap(),
                300,
                RData::TXT(TXT::new(
                    std::iter::once(100u8)
                        .chain(std::iter::repeat_n(b'a' + (index as u8), 100))
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )),
            ));
        }
        message.set_edns(Edns::new());

        message.truncate(512);

        assert!(message.truncated());
        assert!(message.edns().is_some());
    }

    #[test]
    // A previous truncate call must not leave stale TC behind once the message fits again.
    fn truncate_clears_tc_when_message_now_fits() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        message.set_truncated(true);

        message.truncate(4096);

        assert!(!message.truncated());
        assert!(!message.compress());
    }

    #[test]
    // Mirrors miekg/dns-style EDNS truncation expectations: stay inside budget and keep
    // OPT available to the decoder.
    fn truncate_keeps_edns_last_and_honors_limit() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("large.example.com.").unwrap(),
            RecordType::SRV,
            DNSClass::IN,
        ));

        for index in 0..64 {
            let owner = Name::from_ascii("large.example.com.").unwrap();
            let target = Name::from_ascii(&format!("pod-{index}.svc.example.com.")).unwrap();
            message.add_answer(Record::from_rdata(
                owner,
                10,
                RData::SRV(crate::message::rdata::SRV::new(0, 0, 80, target)),
            ));
        }

        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        edns.set_dnssec_ok(true);
        message.set_edns(edns);

        message.truncate(1232);
        let encoded = message.to_bytes().unwrap();

        assert!(message.truncated());
        assert!(encoded.len() <= 1232);
        let decoded = Message::from_bytes(&encoded).unwrap();
        assert!(decoded.edns().is_some());
        assert_eq!(decoded.additional_count(), message.additional_count());
    }

    #[test]
    // Length prediction is used by truncate and preallocation; it should continue to
    // match the actual encoder across common message shapes.
    fn bytes_len_matches_encoded_size_matrix() {
        let mut query = Message::new();
        query.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        let mut response = query.response(Rcode::NoError);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A::new(1, 2, 3, 4)),
        ));

        let mut with_edns = response.clone();
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1400);
        with_edns.set_edns(edns);

        let mut compressed = with_edns.clone();
        compressed.set_compress(true);
        compressed.add_additional(Record::from_rdata(
            Name::from_ascii("alias.example.com.").unwrap(),
            60,
            RData::CNAME(crate::message::rdata::CNAME(
                Name::from_ascii("example.com.").unwrap(),
            )),
        ));

        for message in [query, response, with_edns, compressed] {
            let encoded = message.to_bytes().unwrap();
            assert_eq!(message.bytes_len(), encoded.len());
        }
    }

    #[test]
    // A small size sweep gives us confidence that truncation remains monotonic across
    // the most common UDP payload budgets.
    fn truncate_size_sweep_stays_within_budget() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("large.example.com.").unwrap(),
            RecordType::SRV,
            DNSClass::IN,
        ));

        for index in 0..32 {
            let owner = Name::from_ascii("large.example.com.").unwrap();
            let target = Name::from_ascii(&format!("pod-{index}.svc.example.com.")).unwrap();
            message.add_answer(Record::from_rdata(
                owner,
                10,
                RData::SRV(crate::message::rdata::SRV::new(0, 0, 80, target)),
            ));
        }
        for index in 0..16 {
            message.add_additional(Record::from_rdata(
                Name::from_ascii(&format!("pod-{index}.svc.example.com.")).unwrap(),
                10,
                RData::A(A::new(10, 0, 0, index as u8)),
            ));
        }

        let mut edns = Edns::new();
        edns.set_udp_payload_size(1400);
        message.set_edns(edns);

        for limit in [512usize, 600, 700, 900, 1232, 1400] {
            let mut copy = message.clone();
            copy.truncate(limit);
            let encoded = copy.to_bytes().unwrap();
            assert!(encoded.len() <= limit.max(512), "limit {limit} exceeded");
            if copy.edns().is_some() {
                let decoded = Message::from_bytes(&encoded).unwrap();
                assert!(decoded.edns().is_some(), "edns missing for limit {limit}");
            }
        }
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}
