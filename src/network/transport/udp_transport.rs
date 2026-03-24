/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::message::Message;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use crate::core::error::{DnsError, Result};

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

    /// Serialize and send a DNS message while overriding the wire ID.
    #[inline]
    pub async fn write_message_with_id(&self, msg: &Message, id: u16) -> Result<()> {
        let bytes = msg.to_bytes_with_id(id)?;

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

    #[inline]
    pub async fn write_message_to(
        &self,
        msg: &Message,
        to: SocketAddr,
        max_payload: u16,
    ) -> Result<()> {
        let bytes = msg.to_bytes_with_limit(max_payload as usize)?;
        let n = self
            .socket
            .send_to(&bytes, to)
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
