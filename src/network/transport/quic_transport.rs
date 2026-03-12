/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::buffer_pool::ReusableBuffer;
use crate::core::error::{DnsError, Result};
use crate::message::Message;
use crate::message::Packet;
use crate::message::Response;
use bytes::BytesMut;
use quinn::{Connection, ConnectionError, RecvStream, SendStream};

/// QUIC connection transport that can accept or open bidirectional streams
/// and yield reader/writer wrappers compatible with TCP transport interface.
pub struct QuicTransport {
    conn: Connection,
}

impl QuicTransport {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// Accept a bidirectional stream from the peer (server-side).
    /// Returns reader and writer wrappers for framed DNS messages.
    #[inline]
    pub async fn accept_bi(&self) -> Result<(QuicTransportReader, QuicTransportWriter)> {
        match self.conn.accept_bi().await {
            Ok((send, recv)) => Ok((QuicTransportReader { recv }, QuicTransportWriter { send })),
            Err(e) => Err(DnsError::protocol(format!(
                "Failed to accept QUIC bidirectional stream: {}",
                e
            ))),
        }
    }

    /// Open a bidirectional stream to the peer (client-side).
    /// Returns reader and writer wrappers for framed DNS messages.
    #[inline]
    pub async fn open_bi(&self) -> Result<(QuicTransportReader, QuicTransportWriter)> {
        match self.conn.open_bi().await {
            Ok((send, recv)) => Ok((QuicTransportReader { recv }, QuicTransportWriter { send })),
            Err(e) => Err(DnsError::protocol(format!(
                "Failed to open QUIC bidirectional stream: {}",
                e
            ))),
        }
    }

    /// Close the underlying QUIC connection gracefully.
    #[inline]
    pub fn close(&self, reason: &[u8]) {
        // Application code 0 (no error)
        self.conn.close(0u32.into(), reason);
    }

    #[inline]
    pub async fn closed(&self) -> ConnectionError {
        self.conn.closed().await
    }
}

/// Writer wrapper over a QUIC SendStream that frames DNS messages
/// with 2-byte big-endian length prefix before writing.
pub struct QuicTransportWriter {
    send: SendStream,
}

impl QuicTransportWriter {
    /// Write a single DNS message as a length-prefixed frame.
    #[inline]
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        let mut body = ReusableBuffer::with_capacity(message_buffer_capacity_hint(msg));
        encode_message_into(msg, body.as_mut_vec())?;
        let body_len = body.as_slice().len();
        if body_len > u16::MAX as usize {
            return Err(DnsError::protocol(format!(
                "DNS message too large for DoQ: {} bytes (max 65535)",
                body_len
            )));
        }
        let len_prefix = (body_len as u16).to_be_bytes();
        self.send
            .write_all(&len_prefix)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write QUIC DNS frame: {}", e)))?;
        self.send
            .write_all(body.as_slice())
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write QUIC DNS frame: {}", e)))?;
        Ok(())
    }

    #[inline]
    pub async fn write_response(&mut self, response: &Response) -> Result<()> {
        let mut body = ReusableBuffer::with_capacity(response_buffer_capacity_hint(response));
        encode_response_into(response, body.as_mut_vec())?;
        let body_len = body.as_slice().len();
        if body_len > u16::MAX as usize {
            return Err(DnsError::protocol(format!(
                "DNS message too large for DoQ: {} bytes (max 65535)",
                body_len
            )));
        }
        let len_prefix = (body_len as u16).to_be_bytes();
        self.send
            .write_all(&len_prefix)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write QUIC DNS frame: {}", e)))?;
        self.send
            .write_all(body.as_slice())
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write QUIC DNS frame: {}", e)))?;
        Ok(())
    }

    /// Half-close the send stream (finish) to signal end of request.
    #[inline]
    pub fn finish(&mut self) -> Result<()> {
        self.send
            .finish()
            .map_err(|e| DnsError::protocol(format!("Failed to finish QUIC send stream: {}", e)))
    }
}

/// Reader wrapper over a QUIC RecvStream that reads one framed
/// DNS message (2-byte big-endian length + body) and decodes it.
pub struct QuicTransportReader {
    recv: RecvStream,
}

impl QuicTransportReader {
    #[inline]
    pub async fn read_message(&mut self) -> Result<Message> {
        self.read_message_with_packet().await.map(|(msg, _)| msg)
    }

    #[inline]
    pub async fn read_message_with_packet(&mut self) -> Result<(Message, Packet)> {
        // Read 2-byte length prefix
        let mut len_prefix = [0u8; 2];
        self.recv
            .read_exact(&mut len_prefix)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to read QUIC length prefix: {}", e)))?;
        let msg_len = u16::from_be_bytes(len_prefix) as usize;
        if msg_len == 0 {
            return Err(DnsError::protocol(
                "Invalid zero-length DNS message over QUIC",
            ));
        }

        // Read DNS message body exactly
        let mut bytes = BytesMut::with_capacity(msg_len);
        self.recv
            .read_exact(&mut bytes)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to read QUIC DNS body: {}", e)))?;
        let packet = Packet::from_vec(bytes.to_vec());
        let msg = Message::from_packet(packet.clone())
            .map_err(|e| DnsError::protocol(format!("Invalid DNS message over QUIC: {}", e)))?;
        Ok((msg, packet))
    }
}

#[inline]
fn encode_message_into(message: &Message, body: &mut Vec<u8>) -> Result<()> {
    message.encode_into(body)
}

#[inline]
fn encode_response_into(response: &Response, body: &mut Vec<u8>) -> Result<()> {
    response.encode_into(body)
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
