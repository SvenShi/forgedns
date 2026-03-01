/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Linux netfilter netlink helpers shared by `ipset` and `nftset` plugins.
//!
//! Transport and packet framing are backed by `neli`; protocol-specific
//! nfnetlink/NLA payload layout is still explicitly encoded here.

use crate::core::error::{DnsError, Result};
use neli::consts::{nl::NlmF, socket::NlFamily};
use neli::nl::{NlPayload, NlmsghdrBuilder};
use neli::socket::synchronous::NlSocketHandle;
use neli::types::Buffer;
use neli::utils::Groups;

const NFGENMSG_LEN: usize = 4;
const NLA_HDR_LEN: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NFNETLINK_V0: u8 = 0;

#[inline]
fn align4(v: usize) -> usize {
    (v + 3) & !3
}

#[inline]
fn push_u16_ne(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_ne_bytes());
}

#[inline]
fn push_u32_ne(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_ne_bytes());
}

/// Mutable netfilter netlink socket.
pub struct NfNetlinkSocket {
    socket: NlSocketHandle,
    seq: u32,
}

impl std::fmt::Debug for NfNetlinkSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfNetlinkSocket")
            .field("seq", &self.seq)
            .field("pid", &self.socket.pid())
            .finish()
    }
}

impl NfNetlinkSocket {
    pub fn open() -> Result<Self> {
        let socket = NlSocketHandle::connect(NlFamily::Netfilter, None, Groups::empty())
            .map_err(|e| DnsError::plugin(format!("failed to open netfilter netlink: {}", e)))?;
        Ok(Self { socket, seq: 0 })
    }

    /// Send nfnetlink request and return all non-ack payload messages.
    pub fn request(
        &mut self,
        subsystem: u8,
        msg: u8,
        flags: u16,
        family: u8,
        attrs: &[u8],
        ignore_eexist: bool,
    ) -> Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }

        let nlmsg_type = ((subsystem as u16) << 8) | msg as u16;
        let mut payload = Vec::with_capacity(NFGENMSG_LEN + attrs.len());
        payload.push(family);
        payload.push(NFNETLINK_V0);
        push_u16_ne(&mut payload, 0); // res_id
        payload.extend_from_slice(attrs);

        let nlmsg = NlmsghdrBuilder::default()
            .nl_type(nlmsg_type)
            .nl_flags(NlmF::from(flags))
            .nl_seq(self.seq)
            .nl_pid(0)
            .nl_payload(NlPayload::Payload(Buffer::from(payload)))
            .build()
            .map_err(|e| DnsError::plugin(format!("failed to build netlink message: {}", e)))?;

        self.socket
            .send(&nlmsg)
            .map_err(|e| DnsError::plugin(format!("failed to send netlink request: {}", e)))?;

        self.read_reply(self.seq, ignore_eexist)
    }

    fn read_reply(&mut self, seq: u32, ignore_eexist: bool) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            let (iter, _) = self
                .socket
                .recv::<u16, Buffer>()
                .map_err(|e| DnsError::plugin(format!("failed to recv netlink reply: {}", e)))?;

            for next in iter {
                let nlmsg = next.map_err(|e| {
                    DnsError::plugin(format!("failed to parse netlink response: {}", e))
                })?;

                if *nlmsg.nl_seq() != seq {
                    continue;
                }

                match nlmsg.nl_payload() {
                    NlPayload::Ack(_) | NlPayload::Empty => return Ok(out),
                    NlPayload::Err(err) => {
                        let code = *err.error();
                        if code == 0 {
                            return Ok(out);
                        }
                        let errno = (-code).max(1);
                        if ignore_eexist && errno == libc::EEXIST {
                            return Ok(out);
                        }
                        return Err(DnsError::plugin(format!(
                            "netlink kernel error: {}",
                            std::io::Error::from_raw_os_error(errno)
                        )));
                    }
                    NlPayload::Payload(payload) => out.push(Vec::from(payload.clone())),
                    NlPayload::DumpExtAck(_) => {}
                }
            }
        }
    }
}

#[inline]
pub fn nla_put(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = NLA_HDR_LEN + payload.len();
    push_u16_ne(buf, len as u16);
    push_u16_ne(buf, attr_type);
    buf.extend_from_slice(payload);
    let aligned = align4(len);
    if aligned > len {
        buf.resize(buf.len() + (aligned - len), 0);
    }
}

#[inline]
pub fn nla_put_u8(buf: &mut Vec<u8>, attr_type: u16, v: u8) {
    nla_put(buf, attr_type, &[v]);
}

#[inline]
pub fn nla_put_u32(buf: &mut Vec<u8>, attr_type: u16, v: u32) {
    nla_put(buf, attr_type, &v.to_ne_bytes());
}

#[inline]
pub fn nla_put_strz(buf: &mut Vec<u8>, attr_type: u16, s: &str) {
    let mut bytes = Vec::with_capacity(s.len() + 1);
    bytes.extend_from_slice(s.as_bytes());
    bytes.push(0);
    nla_put(buf, attr_type, &bytes);
}

#[inline]
pub fn nla_put_nested(buf: &mut Vec<u8>, attr_type: u16, nested_payload: &[u8]) {
    nla_put(buf, attr_type | NLA_F_NESTED, nested_payload);
}
