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
