/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::error::{DnsError, Result};
use bytes::BytesMut;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};

pub struct TcpTransport<S> {
    stream: S,
}

impl<S> TcpTransport<S>
where
    S: AsyncRead + AsyncWrite,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_split(self) -> (TcpTransportReader<S>, TcpTransportWriter<S>) {
        let (reader, writer) = split(self.stream);
        (
            TcpTransportReader {
                reader,
                buf: BytesMut::with_capacity(8192),
            },
            TcpTransportWriter { writer },
        )
    }
}

pub struct TcpTransportWriter<S> {
    writer: WriteHalf<S>,
}

impl<S> TcpTransportWriter<S>
where
    S: AsyncWrite,
{
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        let bytes = msg
            .to_bytes()
            .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;

        // Merge length prefix and body into a single frame for one write
        let mut frame = BytesMut::with_capacity(2 + bytes.len());
        let len_prefix = (bytes.len() as u16).to_be_bytes();
        frame.extend_from_slice(&len_prefix);
        frame.extend_from_slice(&bytes);

        self.writer
            .write_all(frame.as_ref())
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write DNS frame: {}", e)))?;
        Ok(())
    }
}

pub struct TcpTransportReader<S> {
    reader: ReadHalf<S>,
    buf: BytesMut,
}

impl<S> TcpTransportReader<S>
where
    S: AsyncRead,
{
    pub async fn read_message(&mut self) -> Result<Message> {
        loop {
            // Try parse from accumulated buffer first (may contain multiple messages)
            if self.buf.len() >= 2 {
                let msg_len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;

                if msg_len == 0 {
                    // Skip zero-length and continue
                    let _ = self.buf.split_to(2);
                    continue;
                }

                if self.buf.len() >= 2 + msg_len {
                    // We have a full message frame
                    let msg_slice = &self.buf[2..2 + msg_len];
                    match Message::from_bytes(msg_slice) {
                        Ok(msg) => {
                            // Drain the consumed frame (length prefix + body)
                            let _ = self.buf.split_to(2 + msg_len);
                            return Ok(msg);
                        }
                        Err(_) => {
                            // Malformed message: drop this frame and continue
                            let _ = self.buf.split_to(2 + msg_len);
                            continue;
                        }
                    }
                }
            }

            // Need more bytes; read from stream directly into buffer
            self.buf.reserve(4096);
            let n = self
                .reader
                .read_buf(&mut self.buf)
                .await
                .map_err(|e| DnsError::protocol(format!("TCP read error: {}", e)))?;

            if n == 0 {
                return Err(DnsError::protocol("TCP connection closed (EOF)"));
            }
        }
    }
}
