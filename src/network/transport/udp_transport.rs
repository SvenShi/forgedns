/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use crate::core::error::{DnsError, Result};

/// UDP transport wrapper for DNS messages.
///
/// Designed to be consistent with other transport modules: provides
/// `write_message` and `read_message` methods operating on Hickory `Message`.
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
        let bytes = msg
            .to_bytes()
            .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;

        let n = self
            .socket
            .send(&bytes)
            .await
            .map_err(|e| DnsError::protocol(format!("UDP send error: {}", e)))?;

        if n != bytes.len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send: sent {} of {} bytes",
                n,
                bytes.len()
            )));
        }
        Ok(())
    }

    /// Receive one UDP datagram and decode it as a DNS message.
    /// Blocks until a datagram arrives or the socket errors.
    #[inline]
    pub async fn read_message(&self, buf: &mut [u8]) -> Result<Message> {
        let n = self
            .socket
            .recv(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("UDP recv error: {}", e)))?;

        Message::from_bytes(&buf[..n])
            .map_err(|e| DnsError::protocol(format!("Failed to parse DNS message from UDP: {}", e)))
    }

    /// Receive one UDP datagram from any peer and decode it as DNS message.
    #[inline]
    pub async fn read_message_from(&self, buf: &mut [u8]) -> Result<(Message, SocketAddr)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {}", e)))?;

        let msg = Message::from_bytes(&buf[..n]).map_err(|e| {
            DnsError::protocol(format!("Failed to parse DNS message from UDP: {}", e))
        })?;
        Ok((msg, addr))
    }

    #[inline]
    pub async fn write_message_to(
        &self,
        msg: &Message,
        to: SocketAddr,
        max_payload: u16,
    ) -> Result<()> {
        let bytes = encode_message_with_max_payload(msg, max_payload)?;

        let n = self
            .socket
            .send_to(&bytes, to)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {}", e)))?;
        if n != bytes.len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send_to: sent {} of {} bytes",
                n,
                bytes.len()
            )));
        }
        Ok(())
    }
}
#[inline]
fn encode_message_with_max_payload(msg: &Message, max_payload: u16) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    // RFC-compliant minimum UDP DNS payload is 512 bytes even when peer advertises
    // a smaller EDNS value. Hickory encoder will set TC when records exceed this cap.
    encoder.set_max_size(max_payload.max(512));
    msg.emit(&mut encoder)
        .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;

    fn make_message(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.add_query(Query::query(
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
                .query()
                .expect("query should exist")
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
