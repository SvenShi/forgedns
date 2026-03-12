/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Lazy response materialization plans.

use super::{build_response_packet, response_rcode};
use crate::core::dns_utils::build_response_from_request;
use crate::core::error::Result;
use crate::message::Packet;
use crate::message::model::ResponseCode;
use crate::message::model::message::Message;

/// Lazy plan for generating a synthetic reject response from a request.
#[derive(Debug, Clone)]
pub struct RejectResponsePlan {
    /// Original request used as the response template.
    request: Message,
    /// RCODE to place into the synthesized response.
    rcode: ResponseCode,
}

impl RejectResponsePlan {
    /// Create a new reject response plan.
    #[inline]
    pub fn new(request: Message, rcode: ResponseCode) -> Self {
        Self { request, rcode }
    }

    #[inline]
    /// Return the request used as the response template.
    pub fn request(&self) -> &Message {
        &self.request
    }

    #[inline]
    /// Return the response code that will be synthesized.
    pub fn rcode(&self) -> ResponseCode {
        self.rcode
    }

    /// Try to render the reject response as a packet without full decoding.
    fn render_packet(&self) -> Result<Option<Packet>> {
        let Some(packet) = self.request.packet() else {
            return Ok(None);
        };
        Ok(Some(build_response_packet(packet, u16::from(self.rcode))?))
    }

    /// Render the reject response as an owned message.
    fn render_message(&self) -> Message {
        build_response_from_request(&self.request, self.rcode)
    }
}

/// Response carrier used by transports and server plugins.
#[derive(Debug, Clone)]
pub enum ResponsePlan {
    /// Reuse already encoded wire bytes.
    Packet(Packet),
    /// Carry an owned message that may still be re-encoded later.
    Message(Message),
    /// Carry a lazy reject plan that can be rendered as packet or message.
    Reject(RejectResponsePlan),
}

impl ResponsePlan {
    /// Borrow the packet representation when one is already available.
    #[inline]
    pub fn packet(&self) -> Option<&Packet> {
        match self {
            Self::Packet(packet) => Some(packet),
            Self::Message(message) => message.packet(),
            Self::Reject(_) => None,
        }
    }

    /// Borrow the owned message representation when it already exists.
    #[inline]
    pub fn message(&self) -> Option<&Message> {
        match self {
            Self::Message(message) => Some(message),
            _ => None,
        }
    }

    /// Return a cheap best-effort response code hint.
    #[inline]
    pub fn response_code_hint(&self) -> Option<ResponseCode> {
        match self {
            Self::Reject(plan) => Some(plan.rcode()),
            Self::Message(message) => Some(message.response_code()),
            Self::Packet(packet) => response_rcode(packet).ok().map(ResponseCode::from),
        }
    }

    /// Return a cheap best-effort encoded length hint.
    #[inline]
    pub fn response_len_hint(&self) -> Option<usize> {
        match self {
            Self::Packet(packet) => Some(packet.as_slice().len()),
            Self::Message(message) => message.packet().map(|packet| packet.as_slice().len()),
            Self::Reject(_) => None,
        }
    }

    /// Materialize the plan into an owned message and return a mutable borrow.
    pub fn ensure_message(&mut self) -> Result<&mut Message> {
        if !matches!(self, Self::Message(_)) {
            let rendered = match std::mem::replace(self, Self::Message(Message::new())) {
                Self::Packet(packet) => Message::from_packet(packet)?,
                Self::Message(message) => message,
                Self::Reject(plan) => plan.render_message(),
            };
            *self = Self::Message(rendered);
        }

        match self {
            Self::Message(message) => Ok(message),
            _ => unreachable!("response plan should be materialized as message"),
        }
    }

    /// Clone or render this plan as an owned message.
    pub fn to_message(&self) -> Result<Message> {
        match self {
            Self::Packet(packet) => Message::from_packet(packet.clone()),
            Self::Message(message) => Ok(message.clone()),
            Self::Reject(plan) => Ok(plan.render_message()),
        }
    }

    /// Consume the plan and materialize it as an owned message.
    pub fn into_message(self) -> Result<Message> {
        match self {
            Self::Packet(packet) => Message::from_packet(packet),
            Self::Message(message) => Ok(message),
            Self::Reject(plan) => Ok(plan.render_message()),
        }
    }

    /// Consume the plan and materialize it as an encoded packet.
    pub fn into_packet(self) -> Result<Packet> {
        match self {
            Self::Packet(packet) => Ok(packet),
            Self::Message(message) => message.into_packet(),
            Self::Reject(plan) => {
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
        match self {
            Self::Packet(packet) => packet
                .parse()
                .map(|parsed| parsed.header().truncated())
                .unwrap_or(false),
            Self::Message(message) => message.truncated(),
            Self::Reject(_) => false,
        }
    }

    /// Encode the response into `out` while respecting `max_size`.
    pub fn encode_into_with_limit(&self, max_size: usize, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        match self {
            Self::Packet(packet) if packet.as_slice().len() <= max_size => {
                out.extend_from_slice(packet.as_slice());
                Ok(())
            }
            Self::Packet(packet) => {
                let message = Message::from_packet(packet.clone())?;
                message.encode_into_with_limit(max_size, out)
            }
            Self::Message(message) => message.encode_into_with_limit(max_size, out),
            Self::Reject(plan) => {
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

/// Convert an already encoded packet into a response plan.
impl From<Packet> for ResponsePlan {
    /// Wrap encoded wire bytes as a packet-based response plan.
    fn from(value: Packet) -> Self {
        Self::Packet(value)
    }
}

/// Convert an owned message into a response plan.
impl From<Message> for ResponsePlan {
    /// Wrap an owned message as a message-based response plan.
    fn from(value: Message) -> Self {
        Self::Message(value)
    }
}

/// Convert a reject plan into a response plan.
impl From<RejectResponsePlan> for ResponsePlan {
    /// Wrap a lazy reject plan as a response plan variant.
    fn from(value: RejectResponsePlan) -> Self {
        Self::Reject(value)
    }
}
