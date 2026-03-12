/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS name model.

use crate::core::error::{DnsError, Result};
use crate::message::wire::name::{NameRef, normalize_label_bytes};
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Owned DNS domain name in canonical lowercased presentation form.
#[derive(Debug, Clone)]
pub struct Name {
    /// Fully-qualified presentation form, always ending in `.` for non-root names.
    fqdn: String,
    /// Original label bytes preserved for names that came from packet-backed input.
    wire_labels: Option<Box<[Box<[u8]>]>>,
}

impl Name {
    /// Parse an ASCII domain name and normalize it into canonical form.
    pub fn from_ascii(raw: &str) -> Result<Self> {
        Self::parse(raw)
    }

    /// Return the DNS root name.
    pub fn root() -> Self {
        Self {
            fqdn: ".".to_string(),
            wire_labels: None,
        }
    }

    /// Return the canonical ASCII presentation form.
    pub fn to_ascii(&self) -> String {
        self.fqdn.clone()
    }

    /// Return the canonical UTF-8 presentation form.
    ///
    /// ForgeDNS currently stores names as ASCII-only canonical strings, so
    /// this is equivalent to [`Self::to_ascii`].
    pub fn to_utf8(&self) -> String {
        self.fqdn.clone()
    }

    /// Report whether the name is the DNS root.
    pub fn is_root(&self) -> bool {
        self.fqdn == "."
    }

    /// Iterate labels in presentation order.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.fqdn
            .trim_end_matches('.')
            .split('.')
            .filter(|label| !label.is_empty())
    }

    /// Return the matcher-friendly normalized form without a trailing dot.
    pub fn normalized(&self) -> String {
        normalize_label_bytes(self.iter_label_bytes())
    }

    /// Iterate raw label bytes, preferring preserved wire labels when present.
    pub(crate) fn iter_label_bytes(&self) -> NameLabelBytesIter<'_> {
        match self.wire_labels.as_deref() {
            Some(labels) => NameLabelBytesIter::Wire(labels.iter()),
            None => NameLabelBytesIter::Ascii(
                self.fqdn
                    .trim_end_matches('.')
                    .split('.')
                    .filter(|label| !label.is_empty()),
            ),
        }
    }

    /// Parse `in-addr.arpa` and `ip6.arpa` names into concrete IP addresses.
    pub fn parse_arpa_name(&self) -> Result<ParsedArpaName> {
        let raw = self.fqdn.trim_end_matches('.').to_ascii_lowercase();

        if let Some(prefix) = raw.strip_suffix(".in-addr.arpa") {
            let mut parts = prefix
                .split('.')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(DnsError::protocol("invalid in-addr.arpa name"));
            }
            parts.reverse();
            let mut octets = [0u8; 4];
            for (idx, part) in parts.into_iter().enumerate() {
                octets[idx] = part
                    .parse::<u8>()
                    .map_err(|_| DnsError::protocol("invalid in-addr.arpa octet"))?;
            }
            return Ok(ParsedArpaName {
                addr: IpAddr::V4(Ipv4Addr::from(octets)),
            });
        }

        if let Some(prefix) = raw.strip_suffix(".ip6.arpa") {
            let nibbles = prefix
                .split('.')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            if nibbles.len() != 32 {
                return Err(DnsError::protocol("invalid ip6.arpa name"));
            }

            let mut hex = String::with_capacity(32);
            for nibble in nibbles.iter().rev() {
                if nibble.len() != 1 || !nibble.as_bytes()[0].is_ascii_hexdigit() {
                    return Err(DnsError::protocol("invalid ip6.arpa nibble"));
                }
                hex.push_str(nibble);
            }

            let mut bytes = [0u8; 16];
            for idx in 0..16 {
                bytes[idx] = u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16)
                    .map_err(|_| DnsError::protocol("invalid ip6.arpa nibble"))?;
            }
            return Ok(ParsedArpaName {
                addr: IpAddr::V6(Ipv6Addr::from(bytes)),
            });
        }

        Err(DnsError::protocol("name is not a supported arpa name"))
    }

    /// Convert a borrowed packet-backed name into an owned name.
    pub(crate) fn from_wire_ref(name: &NameRef<'_>) -> Self {
        if name.is_root() {
            return Self::root();
        }

        let mut fqdn = name.normalized();
        fqdn.push('.');
        let wire_labels = name
            .iter_label_bytes()
            .map(|label| label.to_vec().into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            fqdn,
            wire_labels: Some(wire_labels),
        }
    }

    /// Parse and validate an ASCII DNS name.
    fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "." {
            return Ok(Self::root());
        }

        let with_dot = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{}.", trimmed)
        };

        let mut normalized = String::with_capacity(with_dot.len());
        for label in with_dot.trim_end_matches('.').split('.') {
            if label.is_empty() {
                return Err(DnsError::protocol("dns name contains empty label"));
            }
            if label.len() > 63 {
                return Err(DnsError::protocol("dns label exceeds 63 bytes"));
            }
            if !label.is_ascii() {
                return Err(DnsError::protocol("non-ascii dns names are not supported"));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(DnsError::protocol("dns label contains invalid characters"));
            }
            if !normalized.is_empty() {
                normalized.push('.');
            }
            normalized.push_str(&label.to_ascii_lowercase());
        }
        normalized.push('.');

        if normalized.len() > 255 {
            return Err(DnsError::protocol("dns name exceeds 255 bytes"));
        }

        Ok(Self {
            fqdn: normalized,
            wire_labels: None,
        })
    }
}

impl PartialEq for Name {
    /// Compare names by their canonical fully-qualified string form.
    fn eq(&self, other: &Self) -> bool {
        self.fqdn == other.fqdn
    }
}

impl Eq for Name {}

impl Hash for Name {
    /// Hash the canonical fully-qualified string form.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fqdn.hash(state);
    }
}

impl Display for Name {
    /// Format the canonical fully-qualified presentation form.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.fqdn)
    }
}

impl FromStr for Name {
    type Err = DnsError;

    /// Parse a DNS name from presentation format.
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Internal iterator over raw label bytes from owned names.
pub(crate) enum NameLabelBytesIter<'a> {
    /// Labels derived from the canonical ASCII presentation form.
    Ascii(std::iter::Filter<std::str::Split<'a, char>, fn(&&str) -> bool>),
    /// Labels preserved from the original packet bytes.
    Wire(std::slice::Iter<'a, Box<[u8]>>),
}

impl<'a> Iterator for NameLabelBytesIter<'a> {
    type Item = &'a [u8];

    /// Return the next label as raw bytes.
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            NameLabelBytesIter::Ascii(iter) => iter.next().map(str::as_bytes),
            NameLabelBytesIter::Wire(iter) => iter.next().map(Box::as_ref),
        }
    }
}

/// Parsed reverse-lookup name converted back into an IP address.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ParsedArpaName {
    /// Address reconstructed from the reverse lookup owner name.
    addr: IpAddr,
}

impl ParsedArpaName {
    /// Return the parsed IP address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }
}
