//! Netlink protocol utilities for ipset/nftset operations.

#![allow(dead_code)]

use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use std::{io, mem};

// Compile-time size assertions to ensure struct layouts match kernel
// expectations These are architecture-independent and will fail compilation if
// sizes don't match
const _: () = assert!(size_of::<NlMsgHdr>() == 16);
const _: () = assert!(size_of::<NfGenMsg>() == 4);
const _: () = assert!(size_of::<NlAttr>() == 4);

// Netlink constants
pub const NETLINK_NETFILTER: i32 = 12;
pub const AF_NETLINK: i32 = libc::AF_NETLINK;

// Netlink message header flags
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

// Netlink message types
pub const NLMSG_ERROR: u16 = 0x02;
pub const NLMSG_DONE: u16 = 0x03;
pub const NLMSG_MIN_TYPE: u16 = 0x10;

// Netlink attribute flags
pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

// Netfilter netlink subsystems
pub const NFNL_SUBSYS_IPSET: u8 = 6;
pub const NFNL_SUBSYS_NFTABLES: u8 = 10;

// Netfilter batch messages
pub const NFNL_MSG_BATCH_BEGIN: u16 = NLMSG_MIN_TYPE;
pub const NFNL_MSG_BATCH_END: u16 = NLMSG_MIN_TYPE + 1;

// Alignment macros
pub const NLMSG_ALIGNTO: usize = 4;
pub const NLA_ALIGNTO: usize = 4;

#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[inline]
pub fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

/// Netlink message header (struct nlmsghdr)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    pub const SIZE: usize = size_of::<NlMsgHdr>();
}

/// Netfilter generic message header (struct nfgenmsg)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16, // Network byte order
}

impl NfGenMsg {
    pub const SIZE: usize = size_of::<NfGenMsg>();
}

/// Netlink attribute header (struct nlattr)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NlAttr {
    pub nla_len: u16,
    pub nla_type: u16,
}

impl NlAttr {
    pub const SIZE: usize = size_of::<NlAttr>();
}

/// Netlink error response (struct nlmsgerr)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlMsgErr {
    pub error: i32,
    pub msg: NlMsgHdr,
}

/// A netlink socket for communicating with the kernel.
pub struct NetlinkSocket {
    fd: RawFd,
}

impl NetlinkSocket {
    /// Create a new netlink socket for netfilter operations.
    pub fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Bind the socket
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Send a netlink message and receive the response.
    pub fn send_recv(&self, msg: &[u8], recv_buf: &mut [u8]) -> io::Result<usize> {
        // Destination address
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // Kernel
        addr.nl_groups = 0;

        // Send with retry
        let mut retries = 3;
        loop {
            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    size_of::<libc::sockaddr_nl>() as u32,
                )
            };

            if sent < 0 {
                let err = io::Error::last_os_error();
                if retries > 0
                    && (err.raw_os_error() == Some(libc::EAGAIN)
                        || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                        || err.raw_os_error() == Some(libc::EINTR))
                {
                    retries -= 1;
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(err);
            }

            if sent as usize != msg.len() {
                return Err(io::Error::other("incomplete send"));
            }
            break;
        }

        // Receive with retry
        let mut retries = 3;
        loop {
            let received = unsafe {
                libc::recv(
                    self.fd,
                    recv_buf.as_mut_ptr() as *mut libc::c_void,
                    recv_buf.len(),
                    0,
                )
            };

            if received < 0 {
                let err = io::Error::last_os_error();
                if retries > 0
                    && (err.raw_os_error() == Some(libc::EAGAIN)
                        || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                        || err.raw_os_error() == Some(libc::EINTR))
                {
                    retries -= 1;
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(err);
            }

            return Ok(received as usize);
        }
    }

    /// Send a netlink message without waiting for response.
    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        let sent = unsafe {
            libc::sendto(
                self.fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        if sent as usize != msg.len() {
            return Err(io::Error::other("incomplete send"));
        }

        Ok(())
    }

    /// Receive a netlink message.
    pub fn recv(&self, recv_buf: &mut [u8]) -> io::Result<usize> {
        let received = unsafe {
            libc::recv(
                self.fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                0,
            )
        };

        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(received as usize)
    }
}

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Buffer for building netlink messages.
pub struct MsgBuffer {
    data: Vec<u8>,
}

impl MsgBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Add raw bytes to the buffer.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Add a u8 value.
    pub fn put_u8(&mut self, val: u8) {
        self.data.push(val);
    }

    /// Add a u16 value in native byte order.
    pub fn put_u16(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_ne_bytes());
    }

    /// Add a u32 value in native byte order.
    pub fn put_u32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_ne_bytes());
    }

    /// Add a u64 value in native byte order.
    pub fn put_u64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_ne_bytes());
    }

    /// Add a u16 value in network byte order.
    pub fn put_u16_be(&mut self, val: u16) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Add a u32 value in network byte order.
    pub fn put_u32_be(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Add a u64 value in network byte order.
    pub fn put_u64_be(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Pad to alignment.
    pub fn align(&mut self) {
        let aligned = nla_align(self.data.len());
        self.data.resize(aligned, 0);
    }

    /// Add the netlink message header.
    pub fn put_nlmsghdr(&mut self, msg_type: u16, flags: u16, seq: u32) {
        let hdr = NlMsgHdr {
            nlmsg_len: 0, // Will be updated later
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let bytes: [u8; NlMsgHdr::SIZE] = unsafe { mem::transmute(hdr) };
        self.put_bytes(&bytes);
    }

    /// Add the netfilter generic message header.
    pub fn put_nfgenmsg(&mut self, family: u8, version: u8, res_id: u16) {
        let msg = NfGenMsg {
            nfgen_family: family,
            version,
            res_id: res_id.to_be(),
        };
        let bytes: [u8; NfGenMsg::SIZE] = unsafe { mem::transmute(msg) };
        self.put_bytes(&bytes);
    }

    /// Add a netlink attribute with u8 value.
    pub fn put_attr_u8(&mut self, attr_type: u16, val: u8) {
        let len = NlAttr::SIZE + 1;
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_u8(val);
        self.align();
    }

    /// Add a netlink attribute with u16 value.
    pub fn put_attr_u16(&mut self, attr_type: u16, val: u16) {
        let len = NlAttr::SIZE + 2;
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_u16(val);
        self.align();
    }

    /// Add a netlink attribute with u32 value.
    pub fn put_attr_u32(&mut self, attr_type: u16, val: u32) {
        let len = NlAttr::SIZE + 4;
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_u32(val);
        self.align();
    }

    /// Add a netlink attribute with u64 value.
    pub fn put_attr_u64(&mut self, attr_type: u16, val: u64) {
        let len = NlAttr::SIZE + 8;
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_u64(val);
        self.align();
    }

    /// Add a netlink attribute with u32 value in network byte order.
    /// Sets the NLA_F_NET_BYTEORDER flag on the attribute type.
    pub fn put_attr_u32_be(&mut self, attr_type: u16, val: u32) {
        let len = NlAttr::SIZE + 4;
        self.put_u16(len as u16);
        self.put_u16(attr_type | NLA_F_NET_BYTEORDER);
        self.put_u32_be(val);
        self.align();
    }

    /// Add a netlink attribute with u64 value in network byte order.
    /// Sets the NLA_F_NET_BYTEORDER flag on the attribute type.
    pub fn put_attr_u64_be(&mut self, attr_type: u16, val: u64) {
        let len = NlAttr::SIZE + 8;
        self.put_u16(len as u16);
        self.put_u16(attr_type | NLA_F_NET_BYTEORDER);
        self.put_u64_be(val);
        self.align();
    }

    /// Add a netlink attribute with u32 value in network byte order (for
    /// nftables). Does NOT set the NLA_F_NET_BYTEORDER flag.
    pub fn put_attr_u32_nft(&mut self, attr_type: u16, val: u32) {
        let len = NlAttr::SIZE + 4;
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_u32_be(val);
        self.align();
    }

    /// Add a netlink attribute with u64 value in network byte order (for
    /// nftables). Does NOT set the NLA_F_NET_BYTEORDER flag.
    pub fn put_attr_u64_nft(&mut self, attr_type: u16, val: u64) {
        let len = NlAttr::SIZE + 8;
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_u64_be(val);
        self.align();
    }

    /// Add a netlink attribute with string value (null-terminated).
    pub fn put_attr_str(&mut self, attr_type: u16, val: &str) {
        let bytes = val.as_bytes();
        let len = NlAttr::SIZE + bytes.len() + 1; // +1 for null terminator
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_bytes(bytes);
        self.put_u8(0); // Null terminator
        self.align();
    }

    /// Add a netlink attribute with binary data.
    pub fn put_attr_bytes(&mut self, attr_type: u16, val: &[u8]) {
        let len = NlAttr::SIZE + val.len();
        self.put_u16(len as u16);
        self.put_u16(attr_type);
        self.put_bytes(val);
        self.align();
    }

    /// Start a nested attribute. Returns the offset where the length will be
    /// stored.
    pub fn start_nested(&mut self, attr_type: u16) -> usize {
        let offset = self.data.len();
        self.put_u16(0); // Placeholder for length
        self.put_u16(attr_type | NLA_F_NESTED);
        offset
    }

    /// End a nested attribute by updating its length.
    pub fn end_nested(&mut self, offset: usize) {
        let len = (self.data.len() - offset) as u16;
        self.data[offset..offset + 2].copy_from_slice(&len.to_ne_bytes());
    }

    /// Update the netlink message header length at the beginning of the buffer.
    pub fn finalize_nlmsg(&mut self) {
        let len = self.data.len() as u32;
        self.data[0..4].copy_from_slice(&len.to_ne_bytes());
    }

    /// Update the netlink message header length at a specific offset.
    pub fn finalize_nlmsg_at(&mut self, offset: usize) {
        let len = (self.data.len() - offset) as u32;
        self.data[offset..offset + 4].copy_from_slice(&len.to_ne_bytes());
    }
}

/// Parse a netlink error response.
pub fn parse_nlmsg_error(buf: &[u8]) -> Option<i32> {
    if buf.len() < NlMsgHdr::SIZE {
        return None;
    }

    let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };

    if hdr.nlmsg_type != NLMSG_ERROR {
        return None;
    }

    if buf.len() < NlMsgHdr::SIZE + 4 {
        return None;
    }

    let error: i32 =
        unsafe { std::ptr::read_unaligned(buf[NlMsgHdr::SIZE..].as_ptr() as *const i32) };

    Some(error)
}

/// Check if a netlink response is NLMSG_DONE.
pub fn is_nlmsg_done(buf: &[u8]) -> bool {
    if buf.len() < NlMsgHdr::SIZE {
        return false;
    }

    let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };
    hdr.nlmsg_type == NLMSG_DONE
}

/// Get the netlink message type from a response.
pub fn get_nlmsg_type(buf: &[u8]) -> Option<u16> {
    if buf.len() < NlMsgHdr::SIZE {
        return None;
    }

    let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };
    Some(hdr.nlmsg_type)
}
