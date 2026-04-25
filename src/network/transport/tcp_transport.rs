// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};

use crate::core::error::{DnsError, Result};
use crate::proto::Message;

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
            TcpTransportWriter {
                writer,
                write_buf: Vec::with_capacity(1234),
            },
        )
    }
}

pub struct TcpTransportWriter<S> {
    writer: WriteHalf<S>,
    write_buf: Vec<u8>,
}

impl<S> TcpTransportWriter<S>
where
    S: AsyncWrite,
{
    #[inline]
    #[hotpath::measure]
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        self.write_buf.clear();
        self.write_buf.extend_from_slice(&[0, 0]);

        msg.append_to(&mut self.write_buf)?;

        let body_len = self.write_buf.len() - 2;

        self.write_buf[..2].copy_from_slice(&(body_len as u16).to_be_bytes());

        self.writer
            .write_all(&self.write_buf)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write TCP DNS frame: {}", e)))?;
        Ok(())
    }

    #[inline]
    #[hotpath::measure]
    pub async fn write_message_with_id(&mut self, msg: &Message, id: u16) -> Result<()> {
        self.write_buf.clear();
        self.write_buf.extend_from_slice(&[0, 0]);

        msg.append_to_with_id(id, &mut self.write_buf)
            .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;

        let body_len = self.write_buf.len() - 2;

        debug_assert!(body_len < u16::MAX as usize);

        self.write_buf[..2].copy_from_slice(&(body_len as u16).to_be_bytes());

        self.writer
            .write_all(&self.write_buf)
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
    #[hotpath::measure]
    pub async fn read_message(&mut self) -> Result<Message> {
        loop {
            let buf_len = self.buf.len();
            if buf_len >= 2 {
                let msg_len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                let frame_len = 2 + msg_len;

                if msg_len == 0 {
                    let _ = self.buf.split_to(2);
                    continue;
                }

                if buf_len >= frame_len {
                    let body = &self.buf[2..frame_len];
                    match Message::from_bytes(body) {
                        Ok(msg) => {
                            let _ = self.buf.split_to(frame_len);
                            return Ok(msg);
                        }
                        Err(_) => {
                            let _ = self.buf.split_to(frame_len);
                            continue;
                        }
                    }
                }
            }

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
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;
    use crate::proto::{DNSClass, Name, Question, RecordType};

    fn make_message(id: u16, qname: &str) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.add_question(Question::new(
            Name::from_ascii(qname).expect("query name should be valid"),
            RecordType::A,
            DNSClass::IN,
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
                .first_question()
                .expect("question should exist")
                .name()
                .to_fqdn(),
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
                .first_question()
                .expect("question should exist")
                .name()
                .to_fqdn(),
            "zero-length.example."
        );
    }

    #[tokio::test]
    async fn test_reader_skips_malformed_frame_before_valid_message() {
        let (client, server) = duplex(1024);
        let transport = TcpTransport::new(client);
        let (mut reader, _writer) = transport.into_split();
        let message = make_message(13, "valid-after-bad.example.");
        let mut payload = vec![0u8, 3u8, 0xFF, 0x00, 0x7F];
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
                .first_question()
                .expect("question should exist")
                .name()
                .to_fqdn(),
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
