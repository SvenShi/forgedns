/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS message model.

use crate::core::error::{DnsError, Result};
use crate::network::buffer_pool::{PooledWireBuffer, wire_buffer_pool};
use crate::proto::rdata::{A, AAAA, Edns};
use crate::proto::wire::{
    DNS_HEADER_LEN, decode_message, edns_record_len, encode_message_into, encode_message_with_limit,
};
use crate::proto::{
    DNSClass, Header, MessageType, Name, Opcode, Question, RData, Rcode, Record, RecordType,
};
use std::net::IpAddr;
use std::sync::Arc;

/// Owned DNS message that flows directly through the pipeline.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Message {
    pub(super) header: Header,
    pub(super) compress: bool,
    pub(super) questions: Vec<Question>,
    pub(super) answers: Vec<Record>,
    pub(super) authorities: Vec<Record>,
    pub(super) additionals: Vec<Record>,
    pub(super) signature: Vec<Record>,
    pub(super) edns: Option<Edns>,
}

#[allow(dead_code)]
impl Message {
    #[inline]
    fn pooled_capacity_for_limit(max_size: usize) -> usize {
        max_size.max(DNS_HEADER_LEN)
    }

    #[inline]
    fn init_response(&self, rcode: Rcode, answer_capacity: usize) -> Message {
        let (recursion_desired, checking_disabled) = if self.opcode() == Opcode::Query {
            (self.recursion_desired(), self.checking_disabled())
        } else {
            (false, false)
        };

        let header = Header {
            id: self.header.id(),
            message_type: MessageType::Response,
            opcode: self.header.opcode(),
            authoritative: false,
            truncated: false,
            recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled,
            rcode,
        };

        Message {
            header,
            compress: false,
            questions: self.questions.clone(),
            answers: Vec::with_capacity(answer_capacity),
            authorities: Vec::default(),
            additionals: Vec::default(),
            signature: Vec::default(),
            edns: None,
        }
    }

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

    /// Encode the message into a pooled wire buffer for short-lived immediate use.
    pub fn to_pooled_bytes(&self) -> Result<PooledWireBuffer<'static>> {
        let mut out = wire_buffer_pool().acquire(1024);
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

    /// Encode the message into a pooled wire buffer with an overridden ID.
    pub fn to_pooled_bytes_with_id(&self, id: u16) -> Result<PooledWireBuffer<'static>> {
        let mut out = wire_buffer_pool().acquire(512);
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

    /// Append the encoded wire message while honoring `max_size`.
    pub fn append_to_with_limit(&self, max_size: usize, out: &mut Vec<u8>) -> Result<()> {
        encode_message_with_limit(self, Some(max_size), self.id(), out)
    }

    /// Append the encoded wire message with an overridden ID while honoring `max_size`.
    pub fn append_to_with_limit_and_id(
        &self,
        max_size: usize,
        id: u16,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        encode_message_with_limit(self, Some(max_size), id, out)
    }

    /// Encode the message into a newly allocated byte vector while honoring `max_size`.
    pub fn to_bytes_with_limit(&self, max_size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        encode_message_with_limit(self, Some(max_size), self.id(), &mut out)?;
        Ok(out)
    }

    /// Encode the message into a pooled wire buffer while honoring `max_size`.
    pub fn to_pooled_bytes_with_limit(&self, max_size: usize) -> Result<PooledWireBuffer<'static>> {
        let mut out = wire_buffer_pool().acquire(Self::pooled_capacity_for_limit(max_size));
        encode_message_with_limit(self, Some(max_size), self.id(), &mut out)?;
        Ok(out)
    }

    /// Encode the message into a newly allocated byte vector with an overridden ID and size cap.
    pub fn to_bytes_with_limit_and_id(&self, max_size: usize, id: u16) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        encode_message_with_limit(self, Some(max_size), id, &mut out)?;
        Ok(out)
    }

    /// Encode the message into a pooled wire buffer with an overridden ID and size cap.
    pub fn to_pooled_bytes_with_limit_and_id(
        &self,
        max_size: usize,
        id: u16,
    ) -> Result<PooledWireBuffer<'static>> {
        let mut out = wire_buffer_pool().acquire(Self::pooled_capacity_for_limit(max_size));
        encode_message_with_limit(self, Some(max_size), id, &mut out)?;
        Ok(out)
    }

    /// Truncate this message in-place to the requested UDP payload budget.
    ///
    /// Behavior:
    /// - treats sizes below 512 as 512,
    /// - disables compression when the uncompressed payload already fits,
    /// - otherwise prefers compressed full message if it fits,
    /// - otherwise keeps prefix records while dropping from `Additional`, then `Authority`,
    ///   then `Answer`,
    /// - always preserves the EDNS OPT pseudo-RR when present,
    /// - always preserves detached signature records in the trailer block,
    /// - sets TC if any RR is omitted,
    /// - returns an error if the required trailer (OPT/signature) cannot fit.
    pub fn truncate(&mut self, max_size: usize) -> Result<()> {
        let size = max_size.max(512);

        // Fast path 1: the full uncompressed message already fits the UDP budget.
        if self.bytes_len_with_compression(false) <= size {
            self.compress = false;
            self.header.set_truncated(false);
            return Ok(());
        }

        // Fast path 2: the fully compressed message fits, so no RR elision is needed.
        let lens = self.compute_truncation_lens(true);
        if lens.total_len <= size {
            self.compress = true;
            self.header.set_truncated(false);
            return Ok(());
        }

        self.compress = true;

        let answer_len_full = Self::prefix_total(
            &lens.answers_prefix_lens,
            self.answers.len(),
            lens.questions_end_len,
        );
        let authority_len_full = Self::prefix_total(
            &lens.authorities_prefix_lens,
            self.authorities.len(),
            answer_len_full,
        );

        let _ = Self::prefix_total(
            &lens.additionals_prefix_lens,
            self.additionals.len(),
            authority_len_full,
        );

        // Even the smallest valid truncated response must keep the header, questions,
        // and the trailer block (OPT plus detached signature records).
        let minimal_len = lens.questions_end_len + lens.trailer_len;
        if minimal_len > size {
            return Err(DnsError::protocol(
                "dns message cannot fit within UDP payload while preserving EDNS/signature trailer",
            ));
        }

        // Preserve a contiguous prefix of each section while dropping from the tail in
        // DNS truncation priority order: Additional, then Authority, then Answer.
        //
        // The search therefore tries, in order:
        // 1. all answers + all authorities + the largest fitting additional prefix,
        // 2. all answers + the largest fitting authority prefix,
        // 3. the largest fitting answer prefix.

        let trailer_len = lens.trailer_len;

        let (answer_count, authority_count, additional_count) =
            if authority_len_full + trailer_len <= size {
                let additional_count = Self::max_fitting_prefix_count(
                    &lens.additionals_prefix_lens,
                    authority_len_full,
                    size - trailer_len,
                )
                .unwrap_or(0);

                (self.answers.len(), self.authorities.len(), additional_count)
            } else if answer_len_full + trailer_len <= size {
                let authority_count = Self::max_fitting_prefix_count(
                    &lens.authorities_prefix_lens,
                    answer_len_full,
                    size - trailer_len,
                )
                .unwrap_or(0);

                (self.answers.len(), authority_count, 0)
            } else {
                let answer_count = Self::max_fitting_prefix_count(
                    &lens.answers_prefix_lens,
                    lens.questions_end_len,
                    size - trailer_len,
                )
                .unwrap_or(0);

                (answer_count, 0, 0)
            };

        let omitted = answer_count < self.answers.len()
            || authority_count < self.authorities.len()
            || additional_count < self.additionals.len();

        self.answers.truncate(answer_count);
        self.authorities.truncate(authority_count);
        self.additionals.truncate(additional_count);
        self.header.set_truncated(omitted);

        debug_assert!(self.bytes_len_with_compression(true) <= size);

        Ok(())
    }

    /// Return whether name compression is enabled when encoding.
    pub fn compressed(&self) -> bool {
        self.compress
    }

    /// Return the compression switch used during wire encoding.
    pub fn compress(&self) -> bool {
        self.compress
    }

    /// Set the compression switch used during wire encoding.
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
        let ext_rcode = self.rcode().high();
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
        edns.set_ext_rcode(self.rcode().high());
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
        self.init_response(rcode, 3)
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

    pub fn address_response_rdata(
        &self,
        question: &Question,
        ttl: u32,
        rdatas: &[Arc<RData>],
    ) -> Result<Message> {
        let mut response = self.init_response(Rcode::NoError, rdatas.len());
        let qname = question.name();
        if let [rdata] = rdatas {
            response
                .answers
                .push(Record::from_arc_rdata(qname.clone(), ttl, rdata.clone()));
            return Ok(response);
        }

        for rdata in rdatas {
            response
                .answers
                .push(Record::from_arc_rdata(qname.clone(), ttl, rdata.clone()));
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

    pub fn cnames(&self) -> Vec<&Name> {
        self.answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
            .filter_map(|record| record.cname_target())
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

        let mut compression = crate::proto::codec::LenCompressionMap::new(can_compress);
        let mut len = crate::proto::codec::DNS_HEADER_LEN;

        for question in self.questions() {
            len += question.bytes_len(&mut compression);
        }

        for record in self.answers() {
            len += record.bytes_len(&mut compression);
        }
        for record in self.authorities() {
            len += record.bytes_len(&mut compression);
        }
        for record in self.additionals() {
            len += record.bytes_len(&mut compression);
        }
        if let Some(edns) = self.edns() {
            len += edns_record_len(edns);
        }
        for record in self.signature() {
            len += record.bytes_len(&mut compression);
        }

        len
    }

    #[inline]
    fn prefix_total(prefix_lens: &[usize], count: usize, empty_base: usize) -> usize {
        if count == 0 {
            empty_base
        } else {
            prefix_lens[count - 1]
        }
    }

    #[inline]
    fn max_fitting_prefix_count(
        prefix_lens: &[usize],
        empty_base: usize,
        limit: usize,
    ) -> Option<usize> {
        if empty_base > limit {
            return None;
        }
        if prefix_lens.is_empty() {
            return Some(0);
        }
        if prefix_lens[0] > limit {
            return Some(0);
        }

        let mut left = 0usize;
        let mut right = prefix_lens.len(); // exclusive

        while left < right {
            let mid = (left + right) >> 1;
            if prefix_lens[mid] <= limit {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        Some(left)
    }

    pub(crate) fn compute_truncation_lens(&self, compress_enabled: bool) -> TruncationLens {
        let can_compress = compress_enabled
            && (self.questions.len() > 1
                || !self.answers.is_empty()
                || !self.authorities.is_empty()
                || !self.additionals.is_empty()
                || !self.signature.is_empty()
                || self.edns.is_some());

        let mut compression = crate::proto::codec::LenCompressionMap::new(can_compress);
        let mut len = crate::proto::codec::DNS_HEADER_LEN;

        for question in &self.questions {
            len += question.bytes_len(&mut compression);
        }
        let questions_end_len = len;

        let mut answers_prefix_lens = Vec::with_capacity(self.answers.len());
        for record in &self.answers {
            len += record.bytes_len(&mut compression);
            answers_prefix_lens.push(len);
        }

        let mut authorities_prefix_lens = Vec::with_capacity(self.authorities.len());
        for record in &self.authorities {
            len += record.bytes_len(&mut compression);
            authorities_prefix_lens.push(len);
        }

        let mut additionals_prefix_lens = Vec::with_capacity(self.additionals.len());
        for record in &self.additionals {
            len += record.bytes_len(&mut compression);
            additionals_prefix_lens.push(len);
        }

        let before_trailer_len = len;

        if let Some(edns) = &self.edns {
            len += edns_record_len(edns);
        }

        compression.disable();

        for record in &self.signature {
            len += record.bytes_len(&mut compression);
        }

        let trailer_len = len - before_trailer_len;

        TruncationLens {
            questions_end_len,
            answers_prefix_lens,
            authorities_prefix_lens,
            additionals_prefix_lens,
            trailer_len,
            total_len: len,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct TruncationLens {
    /// Total length after encoding the header and all questions.
    pub questions_end_len: usize,
    /// Total length after keeping the first `i + 1` answers, excluding later sections.
    pub answers_prefix_lens: Vec<usize>,
    /// Total length after keeping all answers and the first `i + 1` authority records.
    pub authorities_prefix_lens: Vec<usize>,
    /// Total length after keeping all answers, all authorities, and the first `i + 1`
    /// additional records.
    pub additionals_prefix_lens: Vec<usize>,
    /// Fixed trailer length contributed by EDNS and detached signature records.
    pub trailer_len: usize,
    /// Full message length when encoded with compression enabled.
    pub total_len: usize,
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rdata::{Edns, TXT};

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

        message.truncate(512).unwrap();

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

        message.truncate(4096).unwrap();

        assert!(!message.truncated());
        assert!(!message.compress());
    }

    #[test]
    // Verifies that truncation stays inside the requested budget while preserving
    // the OPT record for the decoder.
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
                RData::SRV(crate::proto::rdata::SRV::new(0, 0, 80, target)),
            ));
        }

        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        edns.set_dnssec_ok(true);
        message.set_edns(edns);

        message.truncate(1232).unwrap();
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
            RData::CNAME(crate::proto::rdata::CNAME(
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
                RData::SRV(crate::proto::rdata::SRV::new(0, 0, 80, target)),
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
            copy.truncate(limit).unwrap();
            let encoded = copy.to_bytes().unwrap();
            assert!(encoded.len() <= limit.max(512), "limit {limit} exceeded");
            if copy.edns().is_some() {
                let decoded = Message::from_bytes(&encoded).unwrap();
                assert!(decoded.edns().is_some(), "edns missing for limit {limit}");
            }
        }
    }

    #[test]
    fn truncate_preserves_signature_records_within_udp_limit() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.add_question(Question::new(
            Name::from_ascii("large.example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        for index in 0..48 {
            message.add_answer(Record::from_rdata(
                Name::from_ascii("large.example.com.").unwrap(),
                60,
                RData::TXT(TXT::new(
                    std::iter::once(120u8)
                        .chain(std::iter::repeat_n(b'a' + (index as u8 % 26), 120))
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )),
            ));
        }

        message.signature_mut().push(Record::from_rdata(
            Name::from_ascii("large.example.com.").unwrap(),
            0,
            RData::SIG(crate::proto::rdata::SIG(crate::proto::rdata::RRSIG {
                type_covered: u16::from(RecordType::A),
                algorithm: 8,
                labels: 2,
                orig_ttl: 300,
                expiration: 400,
                inception: 200,
                key_tag: 1234,
                signer_name: Name::from_ascii("sig.example.com.").unwrap(),
                signature: vec![1, 2, 3, 4].into_boxed_slice(),
            })),
        ));

        message.truncate(512).unwrap();
        let encoded = message.to_bytes().unwrap();
        let decoded = Message::from_bytes(&encoded).unwrap();

        assert!(message.truncated());
        assert!(encoded.len() <= 512);
        assert_eq!(decoded.signature().len(), 1);
    }

    #[test]
    fn response_edns_mutation_does_not_change_original_request() {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        edns.insert(crate::proto::EdnsOption::Local(
            crate::proto::EdnsLocal::new(65001, vec![1, 2, 3]),
        ));
        request.set_edns(edns);

        let mut response = request.response(Rcode::NoError);
        let response_edns = response.ensure_edns_mut();
        response_edns.set_udp_payload_size(4096);
        response_edns.flags_mut().z = 9;
        response_edns.insert(crate::proto::EdnsOption::Local(
            crate::proto::EdnsLocal::new(65001, vec![9, 9, 9]),
        ));

        let request_edns = request.edns().as_ref().expect("request edns should exist");
        assert_eq!(request_edns.udp_payload_size(), 1232);
        assert_eq!(request_edns.flags().z, 0);
        let Some(crate::proto::EdnsOption::Local(local)) =
            request_edns.option(crate::proto::EdnsCode::Unknown(65001))
        else {
            panic!("expected request local edns option");
        };
        assert_eq!(local.data(), &[1, 2, 3]);

        let response_edns = response
            .edns()
            .as_ref()
            .expect("response edns should exist");
        assert_eq!(response_edns.udp_payload_size(), 4096);
        assert_eq!(response_edns.flags().z, 9);
        let Some(crate::proto::EdnsOption::Local(local)) =
            response_edns.option(crate::proto::EdnsCode::Unknown(65001))
        else {
            panic!("expected response local edns option");
        };
        assert_eq!(local.data(), &[9, 9, 9]);
    }

    #[test]
    fn append_to_with_limit_matches_owned_encoding_for_small_message() {
        let mut query = Message::new();
        query.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        let response = query
            .address_response(
                query.first_question().unwrap(),
                60,
                &[IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))],
            )
            .unwrap();

        let expected = response.to_bytes_with_limit(1232).unwrap();
        let mut actual = Vec::with_capacity(512);
        response.append_to_with_limit(1232, &mut actual).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn append_to_with_limit_matches_owned_encoding_for_truncated_message() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("large.example.com.").unwrap(),
            RecordType::SRV,
            DNSClass::IN,
        ));

        for index in 0..32 {
            let target = Name::from_ascii(&format!("pod-{index}.svc.example.com.")).unwrap();
            message.add_answer(Record::from_rdata(
                Name::from_ascii("large.example.com.").unwrap(),
                10,
                RData::SRV(crate::proto::rdata::SRV::new(0, 0, 80, target)),
            ));
        }

        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        message.set_edns(edns);

        let expected = message.to_bytes_with_limit(512).unwrap();
        let mut actual = Vec::with_capacity(512);
        message.append_to_with_limit(512, &mut actual).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn to_pooled_bytes_matches_owned_encoding() {
        let mut query = Message::new();
        query.add_question(Question::new(
            Name::from_ascii("pooled.example.com.").unwrap(),
            RecordType::AAAA,
            DNSClass::IN,
        ));
        let response = query
            .address_response(
                query.first_question().unwrap(),
                120,
                &[IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
            )
            .unwrap();

        let expected = response.to_bytes().unwrap();
        let actual = response.to_pooled_bytes().unwrap();

        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn to_pooled_bytes_with_limit_matches_owned_encoding_for_truncated_message() {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii("pooled-limit.example.com.").unwrap(),
            RecordType::SRV,
            DNSClass::IN,
        ));

        for index in 0..32 {
            let target = Name::from_ascii(&format!("pod-{index}.svc.example.com.")).unwrap();
            message.add_answer(Record::from_rdata(
                Name::from_ascii("pooled-limit.example.com.").unwrap(),
                10,
                RData::SRV(crate::proto::rdata::SRV::new(0, 0, 80, target)),
            ));
        }

        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        message.set_edns(edns);

        let expected = message.to_bytes_with_limit(512).unwrap();
        let actual = message.to_pooled_bytes_with_limit(512).unwrap();

        assert_eq!(actual.as_slice(), expected.as_slice());
    }
}
