//! ipset operations via netlink.
//!
//! This module provides functions to add, test, and delete IP addresses
//! and CIDR networks from Linux ipset using the netlink protocol.

use std::net::IpAddr;

use crate::netlink::{
    MsgBuffer, NFNL_SUBSYS_IPSET, NLA_F_NESTED, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
    NetlinkSocket, NfGenMsg, NlAttr, NlMsgHdr, is_nlmsg_done, nla_align, parse_nlmsg_error,
};
use crate::{IpAddrBytes, IpCidr, IpEntry, IpSetError, IpTarget, Result};

// ipset protocol constants
const IPSET_PROTOCOL: u8 = 7;
const IPSET_MAXNAMELEN: usize = 32;

// ipset commands
const IPSET_CMD_CREATE: u8 = 2;
const IPSET_CMD_DESTROY: u8 = 3;
const IPSET_CMD_FLUSH: u8 = 4;
const IPSET_CMD_LIST: u8 = 7;
const IPSET_CMD_ADD: u8 = 9;
const IPSET_CMD_DEL: u8 = 10;
const IPSET_CMD_TEST: u8 = 11;

// ipset attributes at command level
const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_TYPENAME: u16 = 3;
const IPSET_ATTR_REVISION: u16 = 4;
const IPSET_ATTR_FAMILY: u16 = 5;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_LINENO: u16 = 9;

// ipset CADT attributes (inside IPSET_ATTR_DATA)
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_CIDR: u16 = 3;
const IPSET_ATTR_TIMEOUT: u16 = 6;
const IPSET_ATTR_CADT_MAX: u16 = 16;
const IPSET_ATTR_HASHSIZE: u16 = IPSET_ATTR_CADT_MAX + 2; // 18
const IPSET_ATTR_MAXELEM: u16 = IPSET_ATTR_CADT_MAX + 3; // 19

// ipset ADT attributes (for element lists)
const IPSET_ATTR_ADT: u16 = 8;

// IP address attributes
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

const BUFF_SZ: usize = 1024;

/// Build the netlink message type for ipset commands.
fn ipset_msg_type(cmd: u8) -> u16 {
    ((NFNL_SUBSYS_IPSET as u16) << 8) | (cmd as u16)
}

/// Internal function to perform ipset operations.
fn ipset_operate(setname: &str, entry: &IpEntry, cmd: u8) -> Result<()> {
    // Validate setname
    if setname.is_empty() || setname.len() >= IPSET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    // Determine address family
    let addr = entry.target.family();
    let (family, addr_type, addr_bytes): (u8, u16, IpAddrBytes) = match addr {
        IpAddr::V4(v4) => (
            libc::AF_INET as u8,
            IPSET_ATTR_IPADDR_IPV4,
            IpAddrBytes::V4(v4.octets()),
        ),
        IpAddr::V6(v6) => (
            libc::AF_INET6 as u8,
            IPSET_ATTR_IPADDR_IPV6,
            IpAddrBytes::V6(v6.octets()),
        ),
    };

    // Build the netlink message
    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Netlink message header
    buf.put_nlmsghdr(ipset_msg_type(cmd), NLM_F_REQUEST | NLM_F_ACK, 0);

    // Netfilter generic message header
    buf.put_nfgenmsg(family, 0, 0);

    // IPSET_ATTR_PROTOCOL
    buf.put_attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);

    // IPSET_ATTR_SETNAME
    buf.put_attr_str(IPSET_ATTR_SETNAME, setname);

    // IPSET_ATTR_DATA (nested)
    let data_offset = buf.start_nested(IPSET_ATTR_DATA);

    // IPSET_ATTR_IP (nested)
    let ip_offset = buf.start_nested(IPSET_ATTR_IP);

    // IP address (IPv4 or IPv6)
    let addr_bytes = addr_bytes.as_slice();
    let len = NlAttr::SIZE + addr_bytes.len();
    buf.put_u16(len as u16);
    buf.put_u16(addr_type | crate::netlink::NLA_F_NET_BYTEORDER);
    buf.put_bytes(addr_bytes);
    buf.align();

    buf.end_nested(ip_offset);

    if let IpTarget::Cidr(cidr) = entry.target {
        buf.put_attr_u8(IPSET_ATTR_CIDR, cidr.prefix_len);
    }

    // IPSET_ATTR_TIMEOUT (optional)
    if let Some(timeout) = entry.timeout {
        buf.put_attr_u32_be(IPSET_ATTR_TIMEOUT, timeout);
    }

    // IPSET_ATTR_LINENO (required for some operations)
    buf.put_attr_u32(IPSET_ATTR_LINENO, 0);

    buf.end_nested(data_offset);

    // Finalize message length
    buf.finalize_nlmsg();

    // Create socket and send/receive
    let socket = NetlinkSocket::new()?;
    let mut recv_buf = [0u8; BUFF_SZ];
    let recv_len = socket.send_recv(buf.as_slice(), &mut recv_buf)?;

    // Parse response
    if recv_len < NlMsgHdr::SIZE {
        return Err(IpSetError::ProtocolError);
    }

    if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
        if error == 0 {
            return Ok(());
        }

        // Handle specific errors
        return match -error {
            libc::ENOENT => {
                if cmd == IPSET_CMD_TEST {
                    return Err(IpSetError::ElementNotFound);
                }
                Err(IpSetError::SetNotFound(setname.to_string()))
            }
            libc::EEXIST => Err(IpSetError::ElementExists),
            libc::IPSET_ERR_EXIST => {
                if cmd == IPSET_CMD_TEST {
                    // For TEST command, IPSET_ERR_EXIST means element NOT in set
                    return Err(IpSetError::ElementNotFound);
                }
                // For ADD command, this means element already exists
                Err(IpSetError::ElementExists)
            }
            libc::IPSET_ERR_INVALID_CIDR => {
                Err(IpSetError::UnsupportedEntry(entry.target.to_string()))
            }
            libc::IPSET_ERR_TYPE_MISMATCH => {
                Err(IpSetError::UnsupportedEntry(entry.target.to_string()))
            }
            _ => Err(IpSetError::NetlinkError(-error)),
        };
    }

    Err(IpSetError::ProtocolError)
}

// Custom error codes for ipset (from kernel include/uapi/linux/netfilter/ipset/ip_set.h)
mod libc {
    pub use ::libc::*;
    // IPSET_ERR_PRIVATE = 4096, then PROTOCOL=4097, FIND_TYPE=4098, MAX_SETS=4099,
    // BUSY=4100, EXIST_SETNAME2=4101, TYPE_MISMATCH=4102, EXIST=4103
    pub const IPSET_ERR_EXIST: i32 = 4103;
    pub const IPSET_ERR_INVALID_CIDR: i32 = 4104;
    pub const IPSET_ERR_TYPE_MISMATCH: i32 = 4102;
}

/// ipset type for hash:ip sets
#[derive(Clone, Copy, Debug)]
pub enum IpSetType {
    /// hash:ip - stores IP addresses
    HashIp,
    /// hash:net - stores network addresses (CIDR)
    HashNet,
}

impl IpSetType {
    fn as_str(&self) -> &'static str {
        match self {
            IpSetType::HashIp => "hash:ip",
            IpSetType::HashNet => "hash:net",
        }
    }

    fn revision(&self) -> u8 {
        // Use revision 4 which is widely supported across kernel versions
        // (5.10+ kernels support revision 4 for hash:ip and hash:net)
        // Higher revisions (5, 6) require newer kernels
        match self {
            IpSetType::HashIp => 4,
            IpSetType::HashNet => 4,
        }
    }
}

/// Address family for ipset
#[derive(Clone, Copy, Debug)]
pub enum IpSetFamily {
    /// IPv4 addresses
    Inet,
    /// IPv6 addresses
    Inet6,
}

impl IpSetFamily {
    fn as_u8(&self) -> u8 {
        match self {
            IpSetFamily::Inet => libc::AF_INET as u8,
            IpSetFamily::Inet6 => libc::AF_INET6 as u8,
        }
    }
}

/// Options for creating an ipset
#[derive(Clone, Debug)]
pub struct IpSetCreateOptions {
    pub set_type: IpSetType,
    pub family: IpSetFamily,
    pub hashsize: Option<u32>,
    pub maxelem: Option<u32>,
    pub timeout: Option<u32>,
}

impl Default for IpSetCreateOptions {
    fn default() -> Self {
        Self {
            set_type: IpSetType::HashIp,
            family: IpSetFamily::Inet,
            hashsize: None,
            maxelem: None,
            timeout: None,
        }
    }
}

/// Create an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset to create
/// * `options` - Creation options (type, family, etc.)
///
/// # Example
///
/// ```no_run
/// use ripset::{ipset_create, IpSetCreateOptions, IpSetType, IpSetFamily};
///
/// let opts = IpSetCreateOptions {
///     set_type: IpSetType::HashIp,
///     family: IpSetFamily::Inet,
///     ..Default::default()
/// };
/// ipset_create("myset", &opts).unwrap();
/// ```
pub fn ipset_create(setname: &str, options: &IpSetCreateOptions) -> Result<()> {
    if setname.is_empty() || setname.len() >= IPSET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(
        ipset_msg_type(IPSET_CMD_CREATE),
        NLM_F_REQUEST | NLM_F_ACK,
        0,
    );
    buf.put_nfgenmsg(options.family.as_u8(), 0, 0);

    buf.put_attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    buf.put_attr_str(IPSET_ATTR_SETNAME, setname);
    buf.put_attr_str(IPSET_ATTR_TYPENAME, options.set_type.as_str());
    buf.put_attr_u8(IPSET_ATTR_REVISION, options.set_type.revision());
    buf.put_attr_u8(IPSET_ATTR_FAMILY, options.family.as_u8());

    // Data attributes (nested)
    let data_offset = buf.start_nested(IPSET_ATTR_DATA);

    if let Some(hashsize) = options.hashsize {
        buf.put_attr_u32(IPSET_ATTR_HASHSIZE, hashsize);
    }
    if let Some(maxelem) = options.maxelem {
        buf.put_attr_u32(IPSET_ATTR_MAXELEM, maxelem);
    }
    if let Some(timeout) = options.timeout {
        // Timeout must be in network byte order with NLA_F_NET_BYTEORDER flag
        buf.put_attr_u32_be(IPSET_ATTR_TIMEOUT, timeout);
    }

    buf.end_nested(data_offset);
    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    let mut recv_buf = [0u8; BUFF_SZ];
    let recv_len = socket.send_recv(buf.as_slice(), &mut recv_buf)?;

    if recv_len < NlMsgHdr::SIZE {
        return Err(IpSetError::ProtocolError);
    }

    if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
        if error == 0 {
            return Ok(());
        }
        return match -error {
            libc::EEXIST => Err(IpSetError::ElementExists),
            _ => Err(IpSetError::NetlinkError(-error)),
        };
    }

    Err(IpSetError::ProtocolError)
}

/// Destroy an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset to destroy
///
/// # Example
///
/// ```no_run
/// use ripset::ipset_destroy;
///
/// ipset_destroy("myset").unwrap();
/// ```
pub fn ipset_destroy(setname: &str) -> Result<()> {
    if setname.is_empty() || setname.len() >= IPSET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(
        ipset_msg_type(IPSET_CMD_DESTROY),
        NLM_F_REQUEST | NLM_F_ACK,
        0,
    );
    buf.put_nfgenmsg(libc::AF_INET as u8, 0, 0);

    buf.put_attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    buf.put_attr_str(IPSET_ATTR_SETNAME, setname);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    let mut recv_buf = [0u8; BUFF_SZ];
    let recv_len = socket.send_recv(buf.as_slice(), &mut recv_buf)?;

    if recv_len < NlMsgHdr::SIZE {
        return Err(IpSetError::ProtocolError);
    }

    if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
        if error == 0 {
            return Ok(());
        }
        return match -error {
            libc::ENOENT => Err(IpSetError::SetNotFound(setname.to_string())),
            libc::EBUSY => Err(IpSetError::NetlinkError(-error)), // Set is in use
            _ => Err(IpSetError::NetlinkError(-error)),
        };
    }

    Err(IpSetError::ProtocolError)
}

/// Flush (remove all elements from) an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset to flush
///
/// # Example
///
/// ```no_run
/// use ripset::ipset_flush;
///
/// ipset_flush("myset").unwrap();
/// ```
pub fn ipset_flush(setname: &str) -> Result<()> {
    if setname.is_empty() || setname.len() >= IPSET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let mut buf = MsgBuffer::new(BUFF_SZ);

    buf.put_nlmsghdr(
        ipset_msg_type(IPSET_CMD_FLUSH),
        NLM_F_REQUEST | NLM_F_ACK,
        0,
    );
    buf.put_nfgenmsg(libc::AF_INET as u8, 0, 0);

    buf.put_attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    buf.put_attr_str(IPSET_ATTR_SETNAME, setname);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    let mut recv_buf = [0u8; BUFF_SZ];
    let recv_len = socket.send_recv(buf.as_slice(), &mut recv_buf)?;

    if recv_len < NlMsgHdr::SIZE {
        return Err(IpSetError::ProtocolError);
    }

    if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
        if error == 0 {
            return Ok(());
        }
        return match -error {
            libc::ENOENT => Err(IpSetError::SetNotFound(setname.to_string())),
            _ => Err(IpSetError::NetlinkError(-error)),
        };
    }

    Err(IpSetError::ProtocolError)
}

/// Add an IP address to an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset
/// * `entry` - The IP entry to add (can be created from IpAddr)
///
/// # Example
///
/// ```no_run
/// use std::net::IpAddr;
/// use ripset::ipset_add;
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// ipset_add("myset", addr).unwrap();
/// ```
pub fn ipset_add<E: Into<IpEntry>>(setname: &str, entry: E) -> Result<()> {
    ipset_operate(setname, &entry.into(), IPSET_CMD_ADD)
}

/// Delete an IP address from an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset
/// * `entry` - The IP entry to delete (can be created from IpAddr)
///
/// # Example
///
/// ```no_run
/// use std::net::IpAddr;
/// use ripset::ipset_del;
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// ipset_del("myset", addr).unwrap();
/// ```
pub fn ipset_del<E: Into<IpEntry>>(setname: &str, entry: E) -> Result<()> {
    ipset_operate(setname, &entry.into(), IPSET_CMD_DEL)
}

/// Test if an IP address exists in an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset
/// * `entry` - The IP entry to test (can be created from IpAddr)
///
/// # Returns
///
/// * `Ok(true)` - The IP address exists in the set
/// * `Ok(false)` - The IP address does not exist in the set
/// * `Err(_)` - An error occurred
///
/// # Example
///
/// ```no_run
/// use std::net::IpAddr;
/// use ripset::ipset_test;
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// let exists = ipset_test("myset", addr).unwrap();
/// ```
pub fn ipset_test<E: Into<IpEntry>>(setname: &str, entry: E) -> Result<bool> {
    match ipset_operate(setname, &entry.into(), IPSET_CMD_TEST) {
        Ok(()) => Ok(true),
        Err(IpSetError::ElementNotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

/// List all IP addresses or networks in an ipset.
///
/// # Arguments
///
/// * `setname` - The name of the ipset
///
/// # Returns
///
/// A vector of IP addresses currently in the set.
///
/// # Example
///
/// ```no_run
/// use ripset::ipset_list;
///
/// let entries = ipset_list("myset").unwrap();
/// for entry in entries {
///     println!("{}", entry);
/// }
/// ```
pub fn ipset_list(setname: &str) -> Result<Vec<IpEntry>> {
    if setname.is_empty() || setname.len() >= IPSET_MAXNAMELEN {
        return Err(IpSetError::InvalidSetName(setname.to_string()));
    }

    let mut buf = MsgBuffer::new(BUFF_SZ);

    // Build LIST request with DUMP flag
    buf.put_nlmsghdr(
        ipset_msg_type(IPSET_CMD_LIST),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP,
        0,
    );
    buf.put_nfgenmsg(libc::AF_INET as u8, 0, 0);

    buf.put_attr_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    buf.put_attr_str(IPSET_ATTR_SETNAME, setname);

    buf.finalize_nlmsg();

    let socket = NetlinkSocket::new()?;
    socket.send(buf.as_slice())?;

    let mut result = Vec::new();
    let mut recv_buf = [0u8; 8192]; // Larger buffer for dump responses

    loop {
        let recv_len = socket.recv(&mut recv_buf)?;
        if recv_len < NlMsgHdr::SIZE {
            break;
        }

        // Process all messages in the buffer
        let mut offset = 0;
        while offset + NlMsgHdr::SIZE <= recv_len {
            let hdr: NlMsgHdr =
                unsafe { std::ptr::read_unaligned(recv_buf[offset..].as_ptr() as *const NlMsgHdr) };

            if hdr.nlmsg_len as usize > recv_len - offset {
                break;
            }

            // Check for NLMSG_DONE
            if is_nlmsg_done(&recv_buf[offset..]) {
                return Ok(result);
            }

            // Check for error
            if let Some(error) =
                parse_nlmsg_error(&recv_buf[offset..offset + hdr.nlmsg_len as usize])
            {
                if error != 0 {
                    return match -error {
                        libc::ENOENT => Err(IpSetError::SetNotFound(setname.to_string())),
                        _ => Err(IpSetError::NetlinkError(-error)),
                    };
                }
            } else {
                // Parse the message for IP addresses
                let msg_end = offset + hdr.nlmsg_len as usize;
                let attr_start = offset + NlMsgHdr::SIZE + NfGenMsg::SIZE;
                parse_ipset_list_attrs(&recv_buf[attr_start..msg_end], &mut result);
            }

            offset += nla_align(hdr.nlmsg_len as usize);
        }
    }

    Ok(result)
}

/// Parse attributes from ipset LIST response to extract IP addresses or networks.
fn parse_ipset_list_attrs(data: &[u8], result: &mut Vec<IpEntry>) {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]);

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        let attr_type_masked = attr_type & !NLA_F_NESTED;

        // IPSET_ATTR_ADT contains the element list
        if attr_type_masked == IPSET_ATTR_ADT && (attr_type & NLA_F_NESTED) != 0 {
            parse_ipset_adt_attrs(&data[offset + NlAttr::SIZE..offset + attr_len], result);
        }

        offset += nla_align(attr_len);
    }
}

/// Parse ADT (element list) attributes.
fn parse_ipset_adt_attrs(data: &[u8], result: &mut Vec<IpEntry>) {
    let mut offset = 0;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]);

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        // Each element is nested under IPSET_ATTR_DATA
        if (attr_type & NLA_F_NESTED) != 0 {
            parse_ipset_data_attrs(&data[offset + NlAttr::SIZE..offset + attr_len], result);
        }

        offset += nla_align(attr_len);
    }
}

/// Parse DATA attributes to extract IP address or CIDR.
fn parse_ipset_data_attrs(data: &[u8], result: &mut Vec<IpEntry>) {
    let mut offset = 0;
    let mut addr = None;
    let mut cidr = None;

    while offset + NlAttr::SIZE <= data.len() {
        let attr_len = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]);

        if attr_len < NlAttr::SIZE || offset + attr_len > data.len() {
            break;
        }

        let attr_type_masked = attr_type & !NLA_F_NESTED;

        // IPSET_ATTR_IP contains the IP address (nested)
        if attr_type_masked == IPSET_ATTR_IP && (attr_type & NLA_F_NESTED) != 0 {
            addr = parse_ipset_ip_attr(&data[offset + NlAttr::SIZE..offset + attr_len]);
        } else if attr_type_masked == IPSET_ATTR_CIDR && attr_len > NlAttr::SIZE {
            cidr = Some(data[offset + NlAttr::SIZE]);
        }

        offset += nla_align(attr_len);
    }

    if let Some(addr) = addr {
        let entry = match cidr {
            Some(prefix_len) => IpCidr::new(addr, prefix_len).map(IpEntry::from),
            None => Ok(IpEntry::from(addr)),
        };
        if let Ok(entry) = entry {
            result.push(entry);
        }
    }
}

/// Parse IP attribute to extract the actual IP address.
fn parse_ipset_ip_attr(data: &[u8]) -> Option<IpAddr> {
    if data.len() < NlAttr::SIZE {
        return None;
    }

    let attr_len = u16::from_ne_bytes([data[0], data[1]]) as usize;
    let attr_type = u16::from_ne_bytes([data[2], data[3]])
        & !NLA_F_NESTED
        & !crate::netlink::NLA_F_NET_BYTEORDER;

    if attr_len < NlAttr::SIZE {
        return None;
    }

    let payload = &data[NlAttr::SIZE..attr_len.min(data.len())];

    match attr_type {
        IPSET_ATTR_IPADDR_IPV4 if payload.len() >= 4 => {
            let octets: [u8; 4] = payload[..4].try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        IPSET_ATTR_IPADDR_IPV6 if payload.len() >= 16 => {
            let octets: [u8; 16] = payload[..16].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ipset_msg_type() {
        assert_eq!(ipset_msg_type(IPSET_CMD_ADD), (6 << 8) | 9);
        assert_eq!(ipset_msg_type(IPSET_CMD_DEL), (6 << 8) | 10);
        assert_eq!(ipset_msg_type(IPSET_CMD_TEST), (6 << 8) | 11);
    }

    #[test]
    fn test_invalid_setname() {
        let addr: IpAddr = "192.168.1.1".parse().unwrap();

        // Empty name
        assert!(matches!(
            ipset_add("", addr),
            Err(IpSetError::InvalidSetName(_))
        ));

        // Name too long
        let long_name = "a".repeat(IPSET_MAXNAMELEN);
        assert!(matches!(
            ipset_add(&long_name, addr),
            Err(IpSetError::InvalidSetName(_))
        ));
    }

    // Integration tests require root privileges and actual ipset setup
    // Run with: sudo cargo test --package ruhop-ipset -- --ignored

    #[test]
    #[ignore]
    fn test_ipset_add_ipv4() {
        // Requires: sudo ipset create test_set hash:ip
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        ipset_add("test_set", addr).expect("Failed to add IP to ipset");
    }

    #[test]
    #[ignore]
    fn test_ipset_test_ipv4() {
        // Requires: sudo ipset create test_set hash:ip
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let exists = ipset_test("test_set", addr).expect("Failed to test IP in ipset");
        println!("IP exists in set: {}", exists);
    }

    #[test]
    #[ignore]
    fn test_ipset_del_ipv4() {
        // Requires: sudo ipset create test_set hash:ip
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        ipset_del("test_set", addr).expect("Failed to delete IP from ipset");
    }

    #[test]
    #[ignore]
    fn test_ipset_add_ipv6() {
        // Requires: sudo ipset create test_set6 hash:ip family inet6
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        ipset_add("test_set6", addr).expect("Failed to add IPv6 to ipset");
    }

    #[test]
    #[ignore]
    fn test_ipset_with_timeout() {
        // Requires: sudo ipset create test_set_timeout hash:ip timeout 300
        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let entry = IpEntry::with_timeout(addr, 60);
        ipset_add("test_set_timeout", entry).expect("Failed to add IP with timeout");
    }
}
