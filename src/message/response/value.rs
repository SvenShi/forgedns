/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS response value with private materialization strategy.

use super::{
    build_response_message_from_request, build_response_packet, response_answer_any_ip,
    response_answer_ip_ttls, response_answer_ips, response_cnames, response_has_answer_type,
    response_rcode,
};
use crate::core::error::Result;
use crate::message::Packet;
use crate::message::model::ResponseCode;
use crate::message::model::message::Message;
use smallvec::SmallVec;
use std::net::IpAddr;

/// Private lazy template for synthesizing a response from a request.
#[derive(Debug, Clone)]
struct SyntheticResponse {
    /// Original request used as the response template.
    request: Message,
    /// RCODE to place into the synthesized response.
    rcode: ResponseCode,
}

impl SyntheticResponse {
    /// Create a new synthetic response template.
    #[inline]
    pub fn new(request: Message, rcode: ResponseCode) -> Self {
        Self { request, rcode }
    }

    #[inline]
    /// Return the response code that will be synthesized.
    pub fn rcode(&self) -> ResponseCode {
        self.rcode
    }

    /// Try to render the synthetic response as a packet without full decoding.
    fn render_packet(&self) -> Result<Option<Packet>> {
        let Some(packet) = self.request.packet() else {
            return Ok(None);
        };
        Ok(Some(build_response_packet(packet, u16::from(self.rcode))?))
    }

    /// Render the synthetic response as an owned message.
    fn render_message(&self) -> Message {
        build_response_message_from_request(&self.request, self.rcode)
    }
}

/// DNS response carrier used by transports and server plugins.
#[derive(Debug, Clone)]
pub struct Response {
    repr: ResponseRepr,
}

#[derive(Debug, Clone)]
enum ResponseRepr {
    /// Reuse already encoded wire bytes.
    Packet(Packet),
    /// Carry an owned message that may still be re-encoded later.
    Message(Message),
    /// Carry a lazy synthetic response that can be rendered as packet or message.
    Synthetic(SyntheticResponse),
}

impl Response {
    /// Wrap already encoded DNS wire bytes.
    #[inline]
    pub fn from_packet(packet: Packet) -> Self {
        Self {
            repr: ResponseRepr::Packet(packet),
        }
    }

    /// Wrap an owned DNS message.
    #[inline]
    pub fn from_message(message: Message) -> Self {
        Self {
            repr: ResponseRepr::Message(message),
        }
    }

    /// Build a lazy response from a request template and response code.
    #[inline]
    pub fn from_request(request: &Message, rcode: ResponseCode) -> Self {
        Self {
            repr: ResponseRepr::Synthetic(SyntheticResponse::new(request.clone(), rcode)),
        }
    }

    /// Borrow the packet representation when one is already available.
    #[inline]
    pub fn packet(&self) -> Option<&Packet> {
        match &self.repr {
            ResponseRepr::Packet(packet) => Some(packet),
            ResponseRepr::Message(message) => message.packet(),
            ResponseRepr::Synthetic(_) => None,
        }
    }

    /// Borrow the owned message representation when it already exists.
    #[inline]
    pub fn message(&self) -> Option<&Message> {
        match &self.repr {
            ResponseRepr::Message(message) => Some(message),
            _ => None,
        }
    }

    /// Return a cheap best-effort response code hint.
    #[inline]
    pub fn response_code_hint(&self) -> Option<ResponseCode> {
        match &self.repr {
            ResponseRepr::Synthetic(plan) => Some(plan.rcode()),
            ResponseRepr::Message(message) => Some(message.response_code()),
            ResponseRepr::Packet(packet) => response_rcode(packet).ok().map(ResponseCode::from),
        }
    }

    /// Return the response code when it can be read or derived.
    #[inline]
    pub fn response_code(&self) -> Option<ResponseCode> {
        if let Some(code) = self.response_code_hint() {
            return Some(code);
        }
        self.packet()
            .and_then(|packet| response_rcode(packet).ok().map(ResponseCode::from))
    }

    /// Return a cheap best-effort encoded length hint.
    #[inline]
    pub fn response_len_hint(&self) -> Option<usize> {
        match &self.repr {
            ResponseRepr::Packet(packet) => Some(packet.as_slice().len()),
            ResponseRepr::Message(message) => {
                message.packet().map(|packet| packet.as_slice().len())
            }
            ResponseRepr::Synthetic(_) => None,
        }
    }

    /// Materialize the response into an owned message and return a mutable borrow.
    pub fn ensure_message(&mut self) -> Result<&mut Message> {
        if !matches!(self.repr, ResponseRepr::Message(_)) {
            let rendered =
                match std::mem::replace(&mut self.repr, ResponseRepr::Message(Message::new())) {
                    ResponseRepr::Packet(packet) => Message::from_packet(packet)?,
                    ResponseRepr::Message(message) => message,
                    ResponseRepr::Synthetic(plan) => plan.render_message(),
                };
            self.repr = ResponseRepr::Message(rendered);
        }

        match &mut self.repr {
            ResponseRepr::Message(message) => Ok(message),
            _ => unreachable!("response should be materialized as message"),
        }
    }

    /// Clone or render this response as an owned message.
    pub fn to_message(&self) -> Result<Message> {
        match &self.repr {
            ResponseRepr::Packet(packet) => Message::from_packet(packet.clone()),
            ResponseRepr::Message(message) => Ok(message.clone()),
            ResponseRepr::Synthetic(plan) => Ok(plan.render_message()),
        }
    }

    /// Consume the response and materialize it as an owned message.
    pub fn into_message(self) -> Result<Message> {
        match self.repr {
            ResponseRepr::Packet(packet) => Message::from_packet(packet),
            ResponseRepr::Message(message) => Ok(message),
            ResponseRepr::Synthetic(plan) => Ok(plan.render_message()),
        }
    }

    /// Consume the response and materialize it as an encoded packet.
    pub fn into_packet(self) -> Result<Packet> {
        match self.repr {
            ResponseRepr::Packet(packet) => Ok(packet),
            ResponseRepr::Message(message) => message.into_packet(),
            ResponseRepr::Synthetic(plan) => {
                if let Some(packet) = plan.render_packet()? {
                    Ok(packet)
                } else {
                    plan.render_message().into_packet()
                }
            }
        }
    }

    /// Return whether the response is currently marked truncated.
    pub fn truncated(&self) -> bool {
        match &self.repr {
            ResponseRepr::Packet(packet) => packet
                .parse()
                .map(|parsed| parsed.header().truncated())
                .unwrap_or(false),
            ResponseRepr::Message(message) => message.truncated(),
            ResponseRepr::Synthetic(_) => false,
        }
    }

    /// Collect answer-section IPs from this response.
    pub fn answer_ips(&self) -> SmallVec<[IpAddr; 8]> {
        if let Some(packet) = self.packet() {
            return response_answer_ips(packet).unwrap_or_default();
        }
        self.message()
            .into_iter()
            .flat_map(|message| message.answers().iter())
            .filter_map(|record| record.ip_addr())
            .collect()
    }

    /// Report whether any answer-section IP matches `pred`.
    pub fn has_answer_ip(&self, mut pred: impl FnMut(IpAddr) -> bool) -> bool {
        if let Some(packet) = self.packet() {
            return response_answer_any_ip(packet, pred).unwrap_or(false);
        }
        self.message()
            .into_iter()
            .flat_map(|message| message.answers().iter())
            .filter_map(|record| record.ip_addr())
            .any(&mut pred)
    }

    /// Collect answer-section IPs together with their TTLs.
    pub fn answer_ip_ttls(&self) -> SmallVec<[(IpAddr, u32); 8]> {
        if let Some(packet) = self.packet() {
            return response_answer_ip_ttls(packet).unwrap_or_default();
        }
        let mut out = SmallVec::<[(IpAddr, u32); 8]>::new();
        for record in self
            .message()
            .into_iter()
            .flat_map(|message| message.answers().iter())
        {
            if let Some(ip) = record.ip_addr() {
                out.push((ip, record.ttl()));
            }
        }
        out
    }

    /// Collect normalized CNAME targets from all response sections.
    pub fn cnames(&self) -> SmallVec<[String; 4]> {
        if let Some(packet) = self.packet() {
            return response_cnames(packet).unwrap_or_default();
        }
        self.message()
            .into_iter()
            .flat_map(|message| {
                message
                    .answers()
                    .iter()
                    .chain(message.name_servers().iter())
                    .chain(message.additionals().iter())
            })
            .filter_map(|record| record.cname_target().map(|name| name.normalized()))
            .collect()
    }

    /// Report whether the answer section contains any RR of a wanted type.
    pub fn has_answer_type(&self, wanted: &[u16]) -> bool {
        if let Some(packet) = self.packet() {
            return response_has_answer_type(packet, wanted).unwrap_or(false);
        }
        self.message()
            .into_iter()
            .flat_map(|message| message.answers().iter())
            .any(|record| wanted.contains(&u16::from(record.record_type())))
    }

    /// Encode the response into `out` while respecting `max_size`.
    pub fn encode_into_with_limit(&self, max_size: usize, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        match &self.repr {
            ResponseRepr::Packet(packet) if packet.as_slice().len() <= max_size => {
                out.extend_from_slice(packet.as_slice());
                Ok(())
            }
            ResponseRepr::Packet(packet) => {
                let message = Message::from_packet(packet.clone())?;
                message.encode_into_with_limit(max_size, out)
            }
            ResponseRepr::Message(message) => message.encode_into_with_limit(max_size, out),
            ResponseRepr::Synthetic(plan) => {
                if let Some(packet) = plan.render_packet()? {
                    if packet.as_slice().len() <= max_size {
                        out.extend_from_slice(packet.as_slice());
                        return Ok(());
                    }
                }
                plan.render_message().encode_into_with_limit(max_size, out)
            }
        }
    }

    /// Encode the response into `out` with no explicit size limit.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_into_with_limit(usize::MAX, out)
    }

    /// Encode the response into a newly allocated byte vector with a size cap.
    pub fn to_bytes_with_limit(&self, max_size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.response_len_hint().unwrap_or(512).max(512));
        self.encode_into_with_limit(max_size, &mut out)?;
        Ok(out)
    }

    /// Encode the response into a newly allocated byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_bytes_with_limit(usize::MAX)
    }
}

/// Convert an already encoded packet into a DNS response.
impl From<Packet> for Response {
    /// Wrap encoded wire bytes as a packet-backed response.
    fn from(value: Packet) -> Self {
        Self::from_packet(value)
    }
}

/// Convert an owned message into a DNS response.
impl From<Message> for Response {
    /// Wrap an owned message as a message-backed response.
    fn from(value: Message) -> Self {
        Self::from_message(value)
    }
}
