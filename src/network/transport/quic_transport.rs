/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::error::{DnsError, Result};
use crate::message::Message;
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
            Ok((send, recv)) => Ok((
                QuicTransportReader {
                    recv,
                    read_buf: Vec::with_capacity(2048),
                },
                QuicTransportWriter {
                    send,
                    write_buf: Vec::with_capacity(2048),
                },
            )),
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
            Ok((send, recv)) => Ok((
                QuicTransportReader {
                    recv,
                    read_buf: Vec::with_capacity(2048),
                },
                QuicTransportWriter {
                    send,
                    write_buf: Vec::with_capacity(2048),
                },
            )),
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
    write_buf: Vec<u8>,
}

impl QuicTransportWriter {
    /// Write a single DNS message as a length-prefixed frame.
    #[inline]
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        self.write_buf.clear();
        self.write_buf.extend_from_slice(&[0, 0]);

        msg.append_to(&mut self.write_buf)?;

        let body_len = self.write_buf.len() - 2;

        debug_assert!(body_len < u16::MAX as usize);

        self.write_buf[..2].copy_from_slice(&(body_len as u16).to_be_bytes());

        self.send
            .write_all(&self.write_buf)
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
    read_buf: Vec<u8>,
}
impl QuicTransportReader {
    #[inline]
    pub async fn read_message(&mut self) -> Result<Message> {
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

        self.read_buf.resize(msg_len, 0);
        self.recv
            .read_exact(&mut self.read_buf[..msg_len])
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to read QUIC DNS body: {}", e)))?;

        Message::from_bytes(&self.read_buf[..msg_len])
            .map_err(|e| DnsError::protocol(format!("Invalid DNS message over QUIC: {}", e)))
    }
}
