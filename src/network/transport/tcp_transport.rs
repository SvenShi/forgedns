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
    #[inline]
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
    #[inline]
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn make_message(id: u16, qname: &str) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.add_query(Query::query(
            Name::from_ascii(qname).expect("query name should be valid"),
            RecordType::A,
        ));
        message
    }

    fn encode_frame(message: &Message) -> Vec<u8> {
        let body = message
            .to_bytes()
            .expect("message should serialize successfully");
        let mut frame = Vec::with_capacity(2 + body.len());
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[tokio::test]
    async fn test_writer_prepends_two_byte_length_prefix() {
        let (client, mut server) = duplex(1024);
        let transport = TcpTransport::new(client);
        let (_reader, mut writer) = transport.into_split();
        let message = make_message(1, "example.com.");

        writer
            .write_message(&message)
            .await
            .expect("write_message should succeed");

        let body = message
            .to_bytes()
            .expect("message should serialize successfully");
        let mut frame = vec![0u8; 2 + body.len()];
        server
            .read_exact(&mut frame)
            .await
            .expect("server side should receive framed message");

        assert_eq!(&frame[..2], &(body.len() as u16).to_be_bytes());
        assert_eq!(&frame[2..], body.as_slice());
    }

    #[tokio::test]
    async fn test_reader_decodes_complete_dns_frame() {
        let (client, server) = duplex(1024);
        let transport = TcpTransport::new(client);
        let (mut reader, _writer) = transport.into_split();
        let message = make_message(7, "example.com.");
        let frame = encode_frame(&message);

        tokio::spawn(async move {
            let mut server = server;
            server
                .write_all(&frame)
                .await
                .expect("server side should write frame");
        });

        let decoded = reader
            .read_message()
            .await
            .expect("reader should decode full frame");

        assert_eq!(decoded.id(), 7);
        assert_eq!(
            decoded
                .query()
                .expect("query should exist")
                .name()
                .to_ascii(),
            "example.com."
        );
    }

    #[tokio::test]
    async fn test_reader_skips_zero_length_frame_before_next_message() {
        let (client, server) = duplex(1024);
        let transport = TcpTransport::new(client);
        let (mut reader, _writer) = transport.into_split();
        let message = make_message(11, "zero-length.example.");
        let mut payload = vec![0u8, 0u8];
        payload.extend_from_slice(&encode_frame(&message));

        tokio::spawn(async move {
            let mut server = server;
            server
                .write_all(&payload)
                .await
                .expect("server side should write payload");
        });

        let decoded = reader
            .read_message()
            .await
            .expect("reader should skip zero-length frame");

        assert_eq!(decoded.id(), 11);
        assert_eq!(
            decoded
                .query()
                .expect("query should exist")
                .name()
                .to_ascii(),
            "zero-length.example."
        );
    }

    #[tokio::test]
    async fn test_reader_skips_malformed_frame_before_valid_message() {
        let (client, server) = duplex(1024);
        let transport = TcpTransport::new(client);
        let (mut reader, _writer) = transport.into_split();
        let message = make_message(13, "valid-after-bad.example.");
        let mut payload = vec![0u8, 3u8, 0xff, 0x00, 0x7f];
        payload.extend_from_slice(&encode_frame(&message));

        tokio::spawn(async move {
            let mut server = server;
            server
                .write_all(&payload)
                .await
                .expect("server side should write payload");
        });

        let decoded = reader
            .read_message()
            .await
            .expect("reader should skip malformed frame");

        assert_eq!(decoded.id(), 13);
        assert_eq!(
            decoded
                .query()
                .expect("query should exist")
                .name()
                .to_ascii(),
            "valid-after-bad.example."
        );
    }

    #[tokio::test]
    async fn test_reader_returns_error_when_stream_hits_eof() {
        let (client, server) = duplex(1024);
        let transport = TcpTransport::new(client);
        let (mut reader, _writer) = transport.into_split();
        drop(server);

        let err = reader
            .read_message()
            .await
            .expect_err("EOF should return an error");

        assert!(err.to_string().contains("TCP connection closed"));
    }
}
