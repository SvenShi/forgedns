// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared listen-address and socket helpers for management and server
//! endpoints.

use std::io::Error;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::str::FromStr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

use crate::core::error::{DnsError, Result};

/// Parse a listen address.
///
/// Besides standard `SocketAddr` inputs, this also accepts `:port` shorthand
/// and expands it to `[::]:port`.
pub fn parse_listen_addr(listen: &str) -> Result<SocketAddr> {
    let listen = listen.trim();

    if let Ok(addr) = SocketAddr::from_str(listen) {
        return Ok(addr);
    }

    if let Some(port) = listen.strip_prefix(':') {
        let port = port.parse::<u16>().map_err(|err| {
            DnsError::Io(Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid listen address {}: {}", listen, err),
            ))
        })?;
        return Ok(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)));
    }

    Err(DnsError::Io(Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "Invalid listen address {}: expected ip:port, [ipv6]:port, or :port",
            listen
        ),
    )))
}

/// Build a non-blocking TCP listener socket for an already parsed listen
/// address.
///
/// IPv6 sockets are explicitly configured with `IPV6_V6ONLY=false` before
/// binding, so a wildcard listen address produced from `:port` can accept both
/// IPv6 and IPv4-mapped connections on platforms that support dual-stack
/// sockets.
pub fn build_tcp_listener(
    addr: SocketAddr,
    backlog: i32,
    configure: impl FnOnce(&Socket),
) -> Result<TcpListener> {
    let sock = build_listen_socket(addr, Type::STREAM, Some(Protocol::TCP))?;

    configure(&sock);
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;

    Ok(TcpListener::from_std(sock.into())?)
}

/// Build a non-blocking UDP socket for an already parsed listen address.
///
/// IPv6 sockets are explicitly configured with `IPV6_V6ONLY=false` before
/// binding, so a wildcard listen address produced from `:port` can receive both
/// IPv6 and IPv4-mapped datagrams on platforms that support dual-stack sockets.
pub fn build_udp_socket(addr: SocketAddr, configure: impl FnOnce(&Socket)) -> Result<StdUdpSocket> {
    let sock = build_listen_socket(addr, Type::DGRAM, Some(Protocol::UDP))?;

    configure(&sock);
    sock.bind(&addr.into())?;

    Ok(sock.into())
}

fn build_listen_socket(
    addr: SocketAddr,
    socket_type: Type,
    protocol: Option<Protocol>,
) -> Result<Socket> {
    let sock = Socket::new(Domain::for_address(addr), socket_type, protocol)?;

    if addr.is_ipv6() {
        sock.set_only_v6(false)?;
    }
    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);

    Ok(sock)
}
