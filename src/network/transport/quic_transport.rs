/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::error::{DnsError, Result};
use bytes::{Bytes, BytesMut};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
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
    pub fn close(&self, reason: &[u8]) {
        // Application code 0 (no error)
        self.conn.close(0u32.into(), reason);
    }

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
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        let body = msg
            .to_bytes()
            .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;
        if body.len() > u16::MAX as usize {
            return Err(DnsError::protocol(format!(
                "DNS message too large for DoQ: {} bytes (max 65535)",
                body.len()
            )));
        }
        let len = (body.len() as u16).to_be_bytes();

        // Merge length prefix and body into one write using QUIC chunks
        let mut chunks = [Bytes::copy_from_slice(&len), Bytes::from(body)];
        self.send
            .write_all_chunks(&mut chunks)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write QUIC DNS frame: {}", e)))?;
        Ok(())
    }

    /// Half-close the send stream (finish) to signal end of request.
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
    pub async fn read_message(&mut self) -> Result<Message> {
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
        Message::from_bytes(&bytes)
            .map_err(|e| DnsError::protocol(format!("Invalid DNS message over QUIC: {}", e)))
    }
}
