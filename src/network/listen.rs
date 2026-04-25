// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared listen-address parsing helpers for management and server endpoints.

use std::io::Error;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::core::error::{DnsError, Result};

/// Parse a listen address.
///
/// Besides standard `SocketAddr` inputs, this also accepts `:port` shorthand
/// and expands it to `0.0.0.0:port`.
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
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }

    Err(DnsError::Io(Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "Invalid listen address {}: expected ip:port, [ipv6]:port, or :port",
            listen
        ),
    )))
}
