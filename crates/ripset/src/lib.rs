//! Pure Rust implementation of ipset/nftset operations via netlink.
//!
//! This crate provides functions to add, check, and remove IP addresses
//! from Linux ipset and nftables sets using the netlink protocol.
//!
//! On non-Linux platforms, all operations return
//! `Err(IpSetError::UnsupportedPlatform)`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[cfg(target_os = "linux")]
pub use ipset::{
    IpSetCreateOptions, IpSetFamily, IpSetType, ipset_add, ipset_create, ipset_del, ipset_destroy,
    ipset_flush, ipset_list, ipset_test,
};
#[cfg(target_os = "linux")]
pub use nftset::{
    NftSetCreateOptions, NftSetType, nftset_add, nftset_create_set, nftset_create_table,
    nftset_del, nftset_delete_set, nftset_delete_table, nftset_list, nftset_list_tables,
    nftset_test,
};
#[cfg(not(target_os = "linux"))]
pub use stub::*;
use thiserror::Error;

#[cfg(target_os = "linux")]
mod netlink;

#[cfg(target_os = "linux")]
pub mod ipset;
#[cfg(target_os = "linux")]
pub mod nftset;

// Stub implementations for non-Linux platforms
#[cfg(not(target_os = "linux"))]
mod stub;

/// Error type for ipset/nftset operations.
#[derive(Error, Debug)]
pub enum IpSetError {
    #[error("Invalid set name: {0}")]
    InvalidSetName(String),

    #[error("Invalid address family")]
    InvalidAddressFamily,

    #[error("Socket error: {0}")]
    SocketError(#[from] std::io::Error),

    #[error("Netlink error: {0}")]
    NetlinkError(i32),

    #[error("Set not found: {0}")]
    SetNotFound(String),

    #[error("Element not found")]
    ElementNotFound,

    #[error("Element already exists")]
    ElementExists,

    #[error("Invalid table name: {0}")]
    InvalidTableName(String),

    #[error("Send/receive error")]
    SendRecvError,

    #[error("Protocol error")]
    ProtocolError,

    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),

    #[error("Unsupported entry for set type: {0}")]
    UnsupportedEntry(String),

    #[error("Unsupported platform: ipset/nftset operations are only available on Linux")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, IpSetError>;

/// IP network in CIDR notation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpCidr {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self> {
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return Err(IpSetError::InvalidCidr(format!("{addr}/{prefix_len}")));
        }

        Ok(Self {
            network: normalize_ip(addr, prefix_len),
            prefix_len,
        })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        if !same_family(self.network, addr) {
            return false;
        }
        normalize_ip(addr, self.prefix_len) == self.network
    }

    pub fn range_start(&self) -> IpAddr {
        self.network
    }

    pub fn range_end_exclusive(&self) -> Option<IpAddr> {
        ip_after_last(self.network, self.prefix_len)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for IpCidr {
    type Err = IpSetError;

    fn from_str(s: &str) -> Result<Self> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| IpSetError::InvalidCidr(s.to_string()))?;
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| IpSetError::InvalidCidr(s.to_string()))?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|_| IpSetError::InvalidCidr(s.to_string()))?;
        Self::new(addr, prefix_len)
    }
}

/// Public target type for set operations and list responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpTarget {
    Addr(IpAddr),
    Cidr(IpCidr),
}

impl IpTarget {
    pub fn family(&self) -> IpAddr {
        match self {
            Self::Addr(addr) => *addr,
            Self::Cidr(cidr) => cidr.network,
        }
    }

    pub fn range_start(&self) -> IpAddr {
        match self {
            Self::Addr(addr) => *addr,
            Self::Cidr(cidr) => cidr.range_start(),
        }
    }

    pub fn range_end_exclusive(&self) -> Option<IpAddr> {
        match self {
            Self::Addr(addr) => increment_ip(*addr),
            Self::Cidr(cidr) => cidr.range_end_exclusive(),
        }
    }
}

impl fmt::Display for IpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(addr) => write!(f, "{addr}"),
            Self::Cidr(cidr) => write!(f, "{cidr}"),
        }
    }
}

impl From<IpAddr> for IpTarget {
    fn from(addr: IpAddr) -> Self {
        Self::Addr(addr)
    }
}

impl From<IpCidr> for IpTarget {
    fn from(cidr: IpCidr) -> Self {
        Self::Cidr(cidr)
    }
}

impl FromStr for IpTarget {
    type Err = IpSetError;

    fn from_str(s: &str) -> Result<Self> {
        if s.contains('/') {
            return Ok(Self::Cidr(s.parse()?));
        }
        let addr = s
            .parse::<IpAddr>()
            .map_err(|_| IpSetError::InvalidCidr(s.to_string()))?;
        Ok(Self::Addr(addr))
    }
}

/// IP address or network with optional timeout for set operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpEntry {
    pub target: IpTarget,
    pub timeout: Option<u32>,
}

impl IpEntry {
    pub fn new(addr: IpAddr) -> Self {
        Self {
            target: IpTarget::Addr(addr),
            timeout: None,
        }
    }

    pub fn new_cidr(cidr: IpCidr) -> Self {
        Self {
            target: IpTarget::Cidr(cidr),
            timeout: None,
        }
    }

    pub fn with_timeout(addr: IpAddr, timeout: u32) -> Self {
        Self {
            target: IpTarget::Addr(addr),
            timeout: Some(timeout),
        }
    }

    pub fn with_cidr_timeout(cidr: IpCidr, timeout: u32) -> Self {
        Self {
            target: IpTarget::Cidr(cidr),
            timeout: Some(timeout),
        }
    }
}

impl fmt::Display for IpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.target)
    }
}

impl From<IpAddr> for IpEntry {
    fn from(addr: IpAddr) -> Self {
        Self::new(addr)
    }
}

impl From<IpCidr> for IpEntry {
    fn from(cidr: IpCidr) -> Self {
        Self::new_cidr(cidr)
    }
}

impl From<IpTarget> for IpEntry {
    fn from(target: IpTarget) -> Self {
        Self {
            target,
            timeout: None,
        }
    }
}

impl FromStr for IpEntry {
    type Err = IpSetError;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self::from(s.parse::<IpTarget>()?))
    }
}

pub(crate) fn same_family(a: IpAddr, b: IpAddr) -> bool {
    matches!(
        (a, b),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

pub(crate) fn normalize_ip(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let shift = 32_u32.saturating_sub(prefix_len as u32);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << shift
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let shift = 128_u32.saturating_sub(prefix_len as u32);
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << shift
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

pub(crate) fn increment_ip(addr: IpAddr) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(v4) => {
            let value = u32::from(v4);
            if value == u32::MAX {
                None
            } else {
                Some(IpAddr::V4(Ipv4Addr::from(value + 1)))
            }
        }
        IpAddr::V6(v6) => {
            let value = u128::from(v6);
            if value == u128::MAX {
                None
            } else {
                Some(IpAddr::V6(Ipv6Addr::from(value + 1)))
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) enum IpAddrBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[allow(dead_code)]
impl IpAddrBytes {
    pub(crate) fn from_ip(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => Self::V6(v6.octets()),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::V4(bytes) => bytes,
            Self::V6(bytes) => bytes,
        }
    }
}

pub(crate) fn ip_after_last(network: IpAddr, prefix_len: u8) -> Option<IpAddr> {
    match network {
        IpAddr::V4(v4) => {
            let host_bits = 32_u32.saturating_sub(prefix_len as u32);
            let size = 1u128.checked_shl(host_bits)?;
            let end = u32::from(v4) as u128 + size;
            if end > u32::MAX as u128 {
                None
            } else {
                Some(IpAddr::V4(Ipv4Addr::from(end as u32)))
            }
        }
        IpAddr::V6(v6) => {
            let host_bits = 128_u32.saturating_sub(prefix_len as u32);
            let size = 1u128.checked_shl(host_bits)?;
            let end = u128::from(v6).checked_add(size)?;
            Some(IpAddr::V6(Ipv6Addr::from(end)))
        }
    }
}

#[allow(dead_code)]
pub(crate) fn range_to_target(start: IpAddr, end_exclusive: Option<IpAddr>) -> Result<IpTarget> {
    let Some(end_exclusive) = end_exclusive else {
        return Ok(IpTarget::Addr(start));
    };

    if !same_family(start, end_exclusive) {
        return Err(IpSetError::ProtocolError);
    }

    let prefix = match (start, end_exclusive) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let start = u32::from(start) as u128;
            let end = u32::from(end) as u128;
            cidr_prefix_from_range(start, end, 32)?
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            let start = u128::from(start);
            let end = u128::from(end);
            cidr_prefix_from_range(start, end, 128)?
        }
        _ => return Err(IpSetError::ProtocolError),
    };

    let cidr = IpCidr::new(start, prefix)?;
    if cidr.range_end_exclusive() == Some(end_exclusive) {
        if prefix == 32 || prefix == 128 {
            Ok(IpTarget::Addr(start))
        } else {
            Ok(IpTarget::Cidr(cidr))
        }
    } else {
        Err(IpSetError::ProtocolError)
    }
}

fn cidr_prefix_from_range(start: u128, end_exclusive: u128, bits: u8) -> Result<u8> {
    if end_exclusive <= start {
        return Err(IpSetError::ProtocolError);
    }

    let size = end_exclusive - start;
    if !size.is_power_of_two() {
        return Err(IpSetError::ProtocolError);
    }
    if !start.is_multiple_of(size) {
        return Err(IpSetError::ProtocolError);
    }

    let host_bits = size.trailing_zeros() as u8;
    if host_bits > bits {
        return Err(IpSetError::ProtocolError);
    }
    Ok(bits - host_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_ipv4_cidr() {
        let cidr: IpCidr = "10.0.0.42/24".parse().unwrap();
        assert_eq!(cidr.network, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(cidr.to_string(), "10.0.0.0/24");
    }

    #[test]
    fn parses_and_normalizes_ipv6_cidr() {
        let cidr: IpCidr = "2001:db8::1234/64".parse().unwrap();
        assert_eq!(cidr.network, "2001:db8::".parse::<IpAddr>().unwrap());
        assert_eq!(cidr.prefix_len, 64);
        assert_eq!(cidr.to_string(), "2001:db8::/64");
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!(matches!(
            "10.0.0.1/33".parse::<IpCidr>(),
            Err(IpSetError::InvalidCidr(_))
        ));
    }

    #[test]
    fn converts_single_host_range_back_to_ip() {
        let target = range_to_target("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().ok()).unwrap();
        assert_eq!(target, IpTarget::Addr("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn converts_network_range_back_to_cidr() {
        let target = range_to_target("10.0.0.0".parse().unwrap(), "10.0.1.0".parse().ok()).unwrap();
        assert_eq!(target, IpTarget::Cidr("10.0.0.0/24".parse().unwrap()));
    }
}
