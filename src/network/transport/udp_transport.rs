/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::buffer_pool::ReusableBuffer;
use crate::message::Message;
use crate::message::Response;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use crate::core::error::{DnsError, Result};
use crate::message::Packet;

/// UDP transport wrapper for DNS messages.
///
/// Designed to be consistent with other transport modules: provides
/// `write_message` and `read_message` methods operating on ForgeDNS messages.
///
/// Supports both connected-client style I/O (`read_message`/`write_message`)
/// and unconnected-server style I/O (`read_message_from`/`write_message_to`).
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Serialize and send a DNS message as a single UDP datagram.
    /// Ensures the entire datagram is sent; otherwise returns a protocol error.
    #[inline]
    pub async fn write_message(&self, msg: &Message) -> Result<()> {
        let mut bytes = ReusableBuffer::with_capacity(message_buffer_capacity_hint(msg));
        encode_message_with_max_payload_into(msg, u16::MAX, bytes.as_mut_vec())?;

        let n = self
            .socket
            .send(bytes.as_slice())
            .await
            .map_err(|e| DnsError::protocol(format!("UDP send error: {}", e)))?;

        if n != bytes.as_slice().len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send: sent {} of {} bytes",
                n,
                bytes.as_slice().len()
            )));
        }
        Ok(())
    }

    #[inline]
    pub async fn write_response(&self, response: &Response) -> Result<()> {
        let mut bytes = ReusableBuffer::with_capacity(response_buffer_capacity_hint(response));
        encode_response_with_max_payload_into(response, u16::MAX, bytes.as_mut_vec())?;

        let n = self
            .socket
            .send(bytes.as_slice())
            .await
            .map_err(|e| DnsError::protocol(format!("UDP send error: {}", e)))?;

        if n != bytes.as_slice().len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send: sent {} of {} bytes",
                n,
                bytes.as_slice().len()
            )));
        }
        Ok(())
    }

    /// Receive one UDP datagram and decode it as a DNS message.
    /// Blocks until a datagram arrives or the socket errors.
    #[inline]
    pub async fn read_message(&self, buf: &mut [u8]) -> Result<Message> {
        self.read_message_with_packet(buf).await.map(|(msg, _)| msg)
    }

    /// Receive one UDP datagram and return both decoded message and raw packet.
    #[inline]
    pub async fn read_message_with_packet(&self, buf: &mut [u8]) -> Result<(Message, Packet)> {
        let n = self
            .socket
            .recv(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("UDP recv error: {}", e)))?;

        let packet = Packet::from_vec(buf[..n].to_vec());
        let msg = Message::from_packet(packet.clone()).map_err(|e| {
            DnsError::protocol(format!("Failed to parse DNS message from UDP: {}", e))
        })?;
        Ok((msg, packet))
    }

    /// Receive one UDP datagram from any peer and decode it as DNS message.
    #[inline]
    pub async fn read_message_from(&self, buf: &mut [u8]) -> Result<(Message, SocketAddr)> {
        self.read_message_with_packet_from(buf)
            .await
            .map(|(msg, _, addr)| (msg, addr))
    }

    /// Receive one UDP datagram from any peer and return both decoded message and raw packet.
    #[inline]
    pub async fn read_message_with_packet_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(Message, Packet, SocketAddr)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {}", e)))?;

        let packet = Packet::from_vec(buf[..n].to_vec());
        let msg = Message::from_packet(packet.clone()).map_err(|e| {
            DnsError::protocol(format!("Failed to parse DNS message from UDP: {}", e))
        })?;
        Ok((msg, packet, addr))
    }

    #[inline]
    pub async fn write_message_to(
        &self,
        msg: &Message,
        to: SocketAddr,
        max_payload: u16,
    ) -> Result<()> {
        let mut bytes = ReusableBuffer::with_capacity(
            message_buffer_capacity_hint(msg).min(usize::from(max_payload.max(512))),
        );
        encode_message_with_max_payload_into(msg, max_payload, bytes.as_mut_vec())?;

        let n = self
            .socket
            .send_to(bytes.as_slice(), to)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {}", e)))?;
        if n != bytes.as_slice().len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send_to: sent {} of {} bytes",
                n,
                bytes.as_slice().len()
            )));
        }
        Ok(())
    }

    #[inline]
    pub async fn write_response_to(
        &self,
        response: &Response,
        to: SocketAddr,
        max_payload: u16,
    ) -> Result<()> {
        let mut bytes = ReusableBuffer::with_capacity(
            response_buffer_capacity_hint(response).min(usize::from(max_payload.max(512))),
        );
        encode_response_with_max_payload_into(response, max_payload, bytes.as_mut_vec())?;

        let n = self
            .socket
            .send_to(bytes.as_slice(), to)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {}", e)))?;
        if n != bytes.as_slice().len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send_to: sent {} of {} bytes",
                n,
                bytes.as_slice().len()
            )));
        }
        Ok(())
    }
}
#[inline]
#[cfg(test)]
fn encode_message_with_max_payload(msg: &Message, max_payload: u16) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    encode_message_with_max_payload_into(msg, max_payload, &mut bytes)?;
    Ok(bytes)
}

#[inline]
fn encode_message_with_max_payload_into(
    msg: &Message,
    max_payload: u16,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    msg.encode_into_with_limit(usize::from(max_payload.max(512)), bytes)
}

#[inline]
fn encode_response_with_max_payload_into(
    response: &Response,
    max_payload: u16,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    response.encode_into_with_limit(usize::from(max_payload.max(512)), bytes)
}

#[inline]
fn message_buffer_capacity_hint(message: &Message) -> usize {
    message
        .packet()
        .map(|packet| packet.as_slice().len())
        .unwrap_or(512)
        .max(512)
}

#[inline]
fn response_buffer_capacity_hint(response: &Response) -> usize {
    response.response_len_hint().unwrap_or(512).max(512)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Question;
    use crate::message::rdata::A;
    use crate::message::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;

    fn make_message(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should be valid"),
            RecordType::A,
        ));
        message
    }

    #[test]
    fn test_encode_message_with_max_payload_round_trips_simple_message() {
        let message = make_message(9);

        let bytes = encode_message_with_max_payload(&message, 128)
            .expect("message encoding should succeed");
        let decoded =
            Message::from_bytes(&bytes).expect("encoded message should decode successfully");

        assert_eq!(decoded.id(), 9);
        assert_eq!(
            decoded
                .question()
                .expect("question should exist")
                .name()
                .to_utf8(),
            "example.com."
        );
    }

    #[test]
    fn test_encode_message_with_small_payload_cap_sets_truncation_with_rfc_minimum() {
        let mut message = make_message(15);
        for octet in 1..=40 {
            message.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").expect("answer name should be valid"),
                300,
                RData::A(A::from(Ipv4Addr::new(192, 0, 2, octet))),
            ));
        }

        let bytes =
            encode_message_with_max_payload(&message, 1).expect("message encoding should succeed");
        let decoded =
            Message::from_bytes(&bytes).expect("encoded message should decode successfully");

        assert!(bytes.len() <= 512);
        assert!(decoded.truncated());
    }
}
