/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS transport helpers for stream and socket oriented protocols.
//!
//! This module provides minimal, dependency-light helpers that convert between
//! Hickory `Message` and wire bytes, and perform framed I/O for stream-based
//! transports (length-prefixed), as well as QUIC stream helpers.

use bytes::BytesMut;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::core::error::{DnsError, Result};

/// Stream framing使用 2 字节大端长度 + DNS 负载（TCP/DoT/DoQ 通用）
pub async fn read_from_async_io<R>(reader: &mut R) -> Result<Message>
where
    R: AsyncRead + Unpin,
{
    let mut len_prefix = [0u8; 2];
    reader
        .read_exact(&mut len_prefix)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to read length prefix: {}", e)))?;
    let msg_len = u16::from_be_bytes(len_prefix) as usize;

    let mut buf = BytesMut::with_capacity(msg_len);
    buf.resize(msg_len, 0);
    reader
        .read_exact(&mut buf[..])
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to read DNS message body: {}", e)))?;

    Message::from_bytes(&buf).map_err(|e| DnsError::protocol(format!("Invalid DNS message: {}", e)))
}

pub async fn write_to_async_io<W>(writer: &mut W, msg: &Message) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = msg
        .to_bytes()
        .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;
    if bytes.len() > u16::MAX as usize {
        return Err(DnsError::protocol(format!(
            "DNS message too large: {} bytes (max 65535)",
            bytes.len()
        )));
    }
    let len_prefix = (bytes.len() as u16).to_be_bytes();
    writer
        .write_all(&len_prefix)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to write length prefix: {}", e)))?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to write DNS message body: {}", e)))?;
    Ok(())
}

/// Receive one UDP datagram and return its size and source address.
/// The datagram is expected to contain a full DNS message in wire format.
#[inline]
async fn recv_from_udp(socket: &UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
    socket
        .recv_from(buf)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {}", e)))
}

/// Receive a UDP datagram and decode it into a DNS Message.
pub async fn recv_message_from_udp(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> Result<(Message, SocketAddr)> {
    let (len, addr) = recv_from_udp(socket, buf).await?;
    let msg = Message::from_bytes(&buf[..len])
        .map_err(|e| DnsError::protocol(format!("Failed to parse DNS message from UDP: {}", e)))?;
    Ok((msg, addr))
}

/// Serialize DNS Message and send as UDP datagram.
pub async fn send_message_udp(socket: &UdpSocket, msg: &Message) -> Result<usize> {
    let bytes = msg
        .to_bytes()
        .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;
    socket
        .send(&bytes)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {}", e)))
}

/// Serialize DNS Message and send as UDP datagram.
pub async fn send_message_to_udp(
    socket: &UdpSocket,
    msg: &Message,
    to: SocketAddr,
) -> Result<usize> {
    let bytes = msg
        .to_bytes()
        .map_err(|e| DnsError::protocol(format!("Failed to serialize DNS message: {}", e)))?;
    socket
        .send_to(&bytes, to)
        .await
        .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {}", e)))
}
