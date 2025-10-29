/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Upstream DNS resolver infrastructure
//!
//! Provides comprehensive support for various DNS protocols with connection
//! pooling, automatic failover, and performance optimizations.
//!
//! # Supported Protocols
//! - **UDP**: Standard DNS over UDP (port 53)
//! - **TCP**: DNS over TCP (port 53) with pipelining support
//! - **DoT**: DNS over TLS (port 853)
//! - **DoQ**: DNS over QUIC (port 853)
//! - **DoH**: DNS over HTTPS via HTTP/2 or HTTP/3 (port 443)
//!
//! # Connection Management
//! - **Pipeline Pool**: Multiple concurrent requests per connection
//! - **Reuse Pool**: Connection recycling with idle timeout
//! - **Bootstrap**: Efficient hostname resolution for upstream servers
//! - **Fallback**: UDP → TCP fallback for truncated responses
//!
//! # Performance Features
//! - Lock-free connection pooling
//! - Automatic connection scaling
//! - Request pipelining for TCP/TLS
//! - Connection reuse with idle management
//! - Zero-copy DNS message handling where possible

use crate::core::error::{DnsError, Result};
use crate::network::upstream::bootstrap::Bootstrap;
use crate::network::upstream::pool::conn_h2::{H2Connection, H2ConnectionBuilder};
use crate::network::upstream::pool::conn_h3::{H3Connection, H3ConnectionBuilder};
use crate::network::upstream::pool::conn_quic::{QuicConnection, QuicConnectionBuilder};
use crate::network::upstream::pool::conn_tcp::{TcpConnection, TcpConnectionBuilder};
use crate::network::upstream::pool::conn_udp::{UdpConnection, UdpConnectionBuilder};
use crate::network::upstream::pool::pool_pipeline::PipelinePool;
use crate::network::upstream::pool::pool_reuse::ReusePool;
use crate::network::upstream::pool::{Connection, ConnectionBuilder, ConnectionPool};
use crate::network::upstream::utils::try_lookup_server_name;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::Message;
use serde::Deserialize;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

mod bootstrap;
mod pool;
mod tls_client_config;
mod utils;

/// Supported upstream connection types
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionType {
    UDP,
    TCP,
    DoT,
    DoQ,
    DoH,
}

#[allow(unused)]
impl ConnectionType {
    /// Returns the default port for each connection type
    pub fn default_port(&self) -> u16 {
        match self {
            ConnectionType::UDP => 53,
            ConnectionType::TCP => 53,
            ConnectionType::DoT => 853,
            ConnectionType::DoQ => 853,
            ConnectionType::DoH => 443,
        }
    }

    /// Returns all supported URL schemes for this connection type
    pub fn schemes(&self) -> Vec<&str> {
        match self {
            ConnectionType::UDP => vec!["udp", ""],
            ConnectionType::TCP => vec!["tcp"],
            ConnectionType::DoT => vec!["tls"],
            ConnectionType::DoQ => vec!["doq", "quic"],
            ConnectionType::DoH => vec!["doh", "https"],
        }
    }
}

/// Configuration for building an upstream DNS server connection
///
/// This structure is typically deserialized from YAML/JSON configuration files
/// and contains all parameters needed to establish a connection to an upstream DNS server.
///
/// # Examples
///
/// Basic UDP configuration:
/// ```yaml
/// addr: "8.8.8.8:53"
/// ```
///
/// DoH with bootstrap:
/// ```yaml
/// addr: "https://dns.google.com/dns-query"
/// bootstrap: "8.8.8.8:53"
/// timeout: 5s
/// ```
#[derive(Deserialize, Debug, Clone)]
pub struct UpstreamConfig {
    /// Optional tag for identifying this upstream in logs
    pub tag: Option<String>,

    /// DNS server address in URL format
    ///
    /// Supported formats:
    /// - `udp://8.8.8.8:53` or `8.8.8.8` - DNS over UDP
    /// - `tcp://8.8.8.8:53` - DNS over TCP
    /// - `tls://dns.google.com:853` - DNS over TLS (DoT)
    /// - `quic://dns.adguard.com:853` - DNS over QUIC (DoQ)
    /// - `https://dns.google.com/dns-query` - DNS over HTTPS (DoH)
    pub addr: String,

    /// Direct IP address to use for connection (bypasses DNS resolution)
    ///
    /// Useful when you want to connect to a specific IP but use SNI for TLS.
    /// If provided, this IP is used instead of resolving the hostname from `addr`.
    pub dial_addr: Option<IpAddr>,

    /// Override the server port (if not specified in `addr`)
    ///
    /// Defaults to protocol-specific standard ports if not provided:
    /// - UDP/TCP: 53
    /// - DoT/DoQ: 853
    /// - DoH: 443
    pub port: Option<u16>,

    /// Bootstrap DNS server for resolving the upstream hostname
    ///
    /// Required when `addr` contains a hostname instead of an IP address.
    /// The bootstrap server must be specified as IP:port (e.g., "8.8.8.8:53").
    /// This prevents circular dependencies in DNS resolution.
    ///
    /// # Example
    /// ```yaml
    /// addr: "https://dns.google.com/dns-query"
    /// bootstrap: "8.8.8.8:53"  # Use Google's IP to resolve dns.google.com
    /// ```
    pub bootstrap: Option<String>,

    /// IP version preference for bootstrap DNS resolution
    ///
    /// - `Some(4)` or `None`: Resolve to IPv4 (A records)
    /// - `Some(6)`: Resolve to IPv6 (AAAA records)
    pub bootstrap_version: Option<u8>,

    /// SOCKS5 proxy server for upstream connections
    ///
    /// When specified, all DNS connections to the upstream server will be
    /// routed through this SOCKS5 proxy. The proxy address can be either an
    /// IP address or a hostname (which will be resolved using system DNS).
    ///
    /// Supports two formats:
    /// - **Without authentication**: `"host:port"`
    ///   - Example: `"127.0.0.1:1080"`
    ///   - Example: `"proxy.example.com:1080"`
    ///
    /// - **With authentication**: `"username:password@host:port"`
    ///   - Example: `"user:pass@127.0.0.1:1080"`
    ///   - Example: `"myuser:mypass@proxy.example.com:1080"`
    ///
    /// **Note**: If the proxy hostname fails to resolve, the upstream will
    /// not be created and an error will be logged during initialization.
    ///
    /// # IPv6 Support
    /// IPv6 addresses must be enclosed in brackets:
    /// - `"[::1]:1080"` - IPv6 without auth
    /// - `"user:pass@[2001:db8::1]:1080"` - IPv6 with auth
    pub socks5: Option<String>,

    /// Connection idle timeout in seconds
    ///
    /// Currently not implemented. Reserved for future connection pool optimization
    /// to automatically close idle connections.
    pub idle_timeout: Option<u64>,

    /// Maximum number of connections in the pool
    ///
    /// Currently not implemented. Reserved for future connection pool scaling
    /// to limit resource usage per upstream.
    pub max_conns: Option<usize>,

    /// Skip TLS certificate verification (**INSECURE**, testing only!)
    ///
    /// When `true`, disables certificate validation for TLS/QUIC/DoH connections.
    /// **Security Warning**: This makes connections vulnerable to MITM attacks.
    /// Only use for testing or with self-signed certificates you trust.
    pub insecure_skip_verify: Option<bool>,

    /// DNS query timeout duration
    ///
    /// Maximum time to wait for a DNS response before considering the query failed.
    /// Defaults to 5 seconds if not specified.
    pub timeout: Option<Duration>,

    /// Enable request pipelining for TCP/DoT connections
    ///
    /// When `true`, allows multiple concurrent queries over a single TCP connection.
    /// When `false`, uses connection pooling with one query per connection.
    /// Only applicable to TCP and DoT protocols.
    pub enable_pipeline: Option<bool>,

    /// Enable HTTP/3 for DoH connections
    ///
    /// When `true`, uses HTTP/3 (QUIC) instead of HTTP/2 for DoH.
    /// Requires the upstream server to support HTTP/3.
    pub enable_http3: Option<bool>,

    /// Linux SO_MARK socket option for policy routing
    ///
    /// Sets the mark on outgoing packets, which can be used with
    /// iptables/nftables for advanced routing policies.
    /// **Linux only** - ignored on other platforms.
    pub so_mark: Option<u32>,

    /// Linux SO_BINDTODEVICE - bind socket to specific network interface
    ///
    /// Forces the socket to use a specific network interface (e.g., "eth0", "wlan0").
    /// Useful for multi-homed systems or VPN scenarios.
    /// **Linux only** - ignored on other platforms.
    pub bind_to_device: Option<String>,
}

#[async_trait]
#[allow(unused)]
pub trait Upstream: Send + Sync + Debug {
    /// **Internal API - Do not call directly!**
    ///
    /// Send a DNS query without timeout protection.
    /// This method is called internally by `query()` which adds timeout handling.
    ///
    /// # For Implementors
    /// Implement this method to provide the actual DNS query logic.
    ///
    /// # For Callers
    /// **Always use `query()` instead!** Calling this method directly bypasses
    /// timeout protection and is considered a bug.
    #[doc(hidden)]
    async fn inner_query(&self, request: Message) -> Result<Message>;

    /// Return the connection configuration information
    ///
    /// Provides access to all upstream connection parameters including
    /// connection type, timeout, addresses, and protocol-specific settings.
    fn connection_info(&self) -> &ConnectionInfo;

    /// Return the timeout duration for this upstream
    ///
    /// Default implementation reads from connection_info.
    /// Can be overridden if custom timeout logic is needed.
    #[inline]
    fn timeout(&self) -> Duration {
        self.connection_info().timeout
    }

    /// Return the connection type of this upstream
    ///
    /// Convenience method for accessing connection_info.connection_type.
    #[inline]
    fn connection_type(&self) -> ConnectionType {
        self.connection_info().connection_type
    }

    /// Send a DNS query with unified timeout handling
    ///
    /// This is the **recommended API** for all DNS queries.
    /// Automatically applies timeout based on `timeout()` configuration.
    ///
    /// # Performance Notes
    /// - Message is moved (not cloned) to avoid allocation overhead
    /// - Timeout error logging uses structured fields for zero-copy
    /// - Only logs on timeout, not on successful queries (hot path optimization)
    ///
    /// # Errors
    /// - Returns `DnsError::plugin` on timeout
    /// - Returns upstream-specific errors on query failures
    async fn query(&self, message: Message) -> Result<Message> {
        let timeout_duration = self.timeout();

        // Apply timeout wrapper to the inner query
        // This ensures all upstream queries have consistent timeout behavior
        match tokio::time::timeout(timeout_duration, self.inner_query(message)).await {
            // Success: query completed within timeout
            Ok(Ok(response)) => Ok(response),

            // Error: query failed (network error, invalid response, etc.)
            Ok(Err(e)) => Err(e),

            // Timeout: query took too long
            Err(_) => {
                // Log timeout event for monitoring and debugging
                // Uses structured logging (zero-copy) instead of format! for performance
                warn!(
                    timeout_secs = timeout_duration.as_secs_f64(),
                    "Upstream DNS query timeout"
                );

                // Return timeout error
                // Note: format! only happens on timeout (rare case), acceptable overhead
                Err(DnsError::plugin(format!(
                    "DNS query timeout after {:?}",
                    timeout_duration
                )))
            }
        }
    }
}

/// SOCKS5 proxy configuration with resolved socket address
///
/// This struct contains the parsed and resolved SOCKS5 proxy information,
/// ready to be used for establishing proxy connections.
///
/// # Fields
/// - `username`: Optional SOCKS5 authentication username
/// - `password`: Optional SOCKS5 authentication password
/// - `socket_addr`: Resolved proxy server socket address (IP + port)
///
/// # Note
/// The hostname in the original configuration (if any) has already been
/// resolved to an IP address when this struct is created.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Socks5Opt {
    username: Option<String>,
    password: Option<String>,
    socket_addr: SocketAddr,
}

/// Runtime connection information for upstream DNS servers
///
/// Parsed and processed configuration ready for connection establishment.
/// Created from `UpstreamConfig` via `From` trait, passed to connection builders.
///
/// Thread-safe (`Clone`) for sharing across multiple connection instances.
#[derive(Debug, Clone)]
#[allow(unused)]
pub struct ConnectionInfo {
    /// Optional tag for identifying this upstream in logs
    pub tag: Option<String>,

    /// Protocol type (auto-detected from URL scheme: udp://, tcp://, tls://, quic://, https://)
    pub connection_type: ConnectionType,

    /// Original address string from configuration (for logging)
    pub raw_addr: String,

    /// Resolved or configured IP address (`None` if it needs runtime resolution via bootstrap)
    pub remote_ip: Option<IpAddr>,

    /// Server port (protocol default or explicitly configured)
    pub port: u16,

    /// SOCKS5 proxy configuration
    pub socks5: Option<Socks5Opt>,

    /// Bootstrap resolver for dynamic hostname resolution with TTL caching
    pub bootstrap: Option<Arc<Bootstrap>>,

    /// DoH request path (e.g., `/dns-query`), empty for non-HTTP protocols
    pub path: String,

    /// Server hostname for TLS SNI and certificate validation
    pub server_name: String,

    /// Skip TLS certificate verification (**INSECURE** - testing only)
    pub insecure_skip_verify: bool,

    /// Connection idle timeout in seconds
    pub idle_timeout: Option<u64>,

    /// Maximum number of connections in the pool
    pub max_conns: Option<usize>,

    /// DNS query timeout (includes I/O, handshakes, and round-trip time)
    pub timeout: Duration,

    /// Request pipelining for TCP/DoT (`None` = protocol default)
    pub enable_pipeline: Option<bool>,

    /// Use HTTP/3 (true) instead of HTTP/2 (false) for DoH
    pub enable_http3: bool,

    /// Linux SO_MARK for packet marking (policy routing)
    pub so_mark: Option<u32>,

    /// Linux SO_BINDTODEVICE - bind to specific network interface
    pub bind_to_device: Option<String>,
}

impl ConnectionInfo {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
    const DEFAULT_MAX_CONNS_SIZE: usize = 64;
    const DEFAULT_MAX_CONNS_LOAD: u16 = 64;
    const DEFAULT_IDLE_TIME: u64 = 10;
    pub fn with_addr(addr: &str) -> Self {
        let (connection_type, host, port, path) = detect_connection_type(addr);
        let port = port.unwrap_or(connection_type.default_port());

        debug!(
            "Building ConnectionInfo: type={:?}, host={}, port={}, path={}",
            connection_type, host, port, path
        );

        let remote_ip = resolve_ip_from_host(&host, None, false);

        ConnectionInfo {
            tag: None,
            remote_ip,
            port,
            socks5: None,
            connection_type,
            bootstrap: None,
            path,
            timeout: Self::DEFAULT_TIMEOUT,
            server_name: host,
            insecure_skip_verify: false,
            idle_timeout: None,
            raw_addr: addr.to_string(),
            enable_pipeline: None,
            enable_http3: false,
            so_mark: None,
            bind_to_device: None,
            max_conns: None,
        }
    }
}

impl From<UpstreamConfig> for ConnectionInfo {
    fn from(upstream_config: UpstreamConfig) -> Self {
        let (connection_type, host, port, path) = detect_connection_type(&upstream_config.addr);

        let port = upstream_config
            .port
            .or(port)
            .unwrap_or(connection_type.default_port());

        debug!(
            "Building ConnectionInfo: type={:?}, host={}, port={}, path={}",
            connection_type, &host, port, path
        );

        let has_bootstrap = upstream_config.bootstrap.is_some();
        let remote_ip = resolve_ip_from_host(&host, upstream_config.dial_addr, has_bootstrap);

        let bootstrap = if let Some(bootstrap_server) = upstream_config.bootstrap
            && remote_ip.is_none()
        {
            Some(Arc::new(Bootstrap::new(
                &bootstrap_server,
                &host,
                upstream_config.bootstrap_version,
            )))
        } else {
            None
        };

        let socks5 = if let Some(socks5_str) = upstream_config.socks5 {
            match connection_type {
                ConnectionType::TCP | ConnectionType::DoT => parse_socks5_opt(&socks5_str),
                ConnectionType::DoH => {
                    if upstream_config.enable_http3.unwrap_or(false) {
                        warn!("Sock5 proxy only support tcp portal");
                        None
                    } else {
                        parse_socks5_opt(&socks5_str)
                    }
                }
                _ => {
                    warn!("Sock5 proxy only support tcp portal");
                    None
                }
            }
        } else {
            None
        };

        ConnectionInfo {
            tag: upstream_config.tag,
            remote_ip,
            port,
            socks5,
            connection_type,
            bootstrap,
            path,
            timeout: upstream_config.timeout.unwrap_or(Self::DEFAULT_TIMEOUT),
            server_name: host,
            insecure_skip_verify: upstream_config.insecure_skip_verify.unwrap_or(false),
            idle_timeout: upstream_config.idle_timeout,
            raw_addr: upstream_config.addr,
            enable_pipeline: upstream_config.enable_pipeline,
            enable_http3: upstream_config.enable_http3.unwrap_or(false),
            so_mark: upstream_config.so_mark,
            bind_to_device: upstream_config.bind_to_device,
            max_conns: upstream_config.max_conns,
        }
    }
}

/// Resolve IP address from hostname
///
/// # Arguments
/// - `host`: The hostname or IP address string
/// - `dial_addr`: Optional pre-configured IP address to use directly
/// - `has_bootstrap`: Whether a bootstrap server is configured (skip resolution if true)
///
/// # Returns
/// `Some(IpAddr)` if successfully resolved or provided, `None` otherwise
fn resolve_ip_from_host(
    host: &str,
    dial_addr: Option<IpAddr>,
    has_bootstrap: bool,
) -> Option<IpAddr> {
    // 1. Use dial_addr if provided
    if let Some(ip) = dial_addr {
        return Some(ip);
    }

    // 2. Try parsing as IP address
    if let Ok(ip) = IpAddr::from_str(host) {
        return Some(ip);
    }

    // 3. For domain names: resolve only if no bootstrap configured
    if !has_bootstrap {
        match try_lookup_server_name(host) {
            Ok(ip) => Some(ip),
            Err(e) => {
                warn!("Failed to resolve server name '{}': {}", host, e);
                None
            }
        }
    } else {
        // Bootstrap will handle resolution later
        None
    }
}

/// Detect the connection type from the config address
fn detect_connection_type(addr: &str) -> (ConnectionType, String, Option<u16>, String) {
    if !addr.contains("//") {
        return detect_connection_type(&("udp://".to_owned() + addr));
    }

    let url = Url::parse(addr).expect("Invalid upstream URL");
    let connection_type;

    let host = if let Some(host) = url.host_str() {
        host.to_owned()
    } else {
        panic!("Invalid upstream URL, no host specified");
    };

    match url.scheme() {
        "udp" => {
            connection_type = ConnectionType::UDP;
        }
        "tcp" => {
            connection_type = ConnectionType::TCP;
        }
        "tls" => {
            connection_type = ConnectionType::DoT;
        }
        "quic" | "doq" => {
            connection_type = ConnectionType::DoQ;
        }
        "https" | "doh" => {
            connection_type = ConnectionType::DoH;
        }
        other => {
            panic!("Invalid upstream URL scheme: {}", other);
        }
    };

    debug!(
        "Detected upstream: scheme={}, type={:?}, host={}, port={:?}, path={}",
        url.scheme(),
        connection_type,
        host,
        url.port(),
        url.path()
    );

    (connection_type, host, url.port(), url.path().to_string())
}

/// Builder for creating upstream instances
pub struct UpstreamBuilder;

impl UpstreamBuilder {
    pub fn with_connection_info(connection_info: ConnectionInfo) -> Box<dyn Upstream> {
        debug!(
            "Creating upstream: type={:?}, remote={:?}, port={}",
            connection_info.connection_type, connection_info.remote_ip, connection_info.port
        );

        if connection_info.bootstrap.is_none() {
            match connection_info.connection_type {
                ConnectionType::UDP => {
                    debug!("Creating UDP upstream for {}", connection_info.raw_addr);
                    let builder = UdpConnectionBuilder::new(&connection_info);
                    let main_pool = PipelinePool::new(
                        1,
                        connection_info
                            .max_conns
                            .unwrap_or(ConnectionInfo::DEFAULT_MAX_CONNS_SIZE),
                        ConnectionInfo::DEFAULT_MAX_CONNS_LOAD,
                        connection_info
                            .idle_timeout
                            .unwrap_or(ConnectionInfo::DEFAULT_IDLE_TIME),
                        Box::new(builder),
                    );

                    let tcp_builder = TcpConnectionBuilder::new(&connection_info);
                    let fallback_pool = ReusePool::new(
                        0,
                        connection_info
                            .max_conns
                            .unwrap_or(ConnectionInfo::DEFAULT_MAX_CONNS_SIZE),
                        connection_info
                            .idle_timeout
                            .unwrap_or(ConnectionInfo::DEFAULT_IDLE_TIME),
                        Box::new(tcp_builder),
                    );

                    Box::new(UdpTruncatedUpstream {
                        connection_info,
                        main_pool,
                        fallback_pool,
                    })
                }
                ConnectionType::TCP | ConnectionType::DoT => {
                    debug!(
                        "Creating {:?} upstream for {}",
                        connection_info.connection_type, connection_info.raw_addr
                    );
                    let builder = TcpConnectionBuilder::new(&connection_info);
                    create_pipeline_or_reuse_pool(1, connection_info, Box::new(builder))
                }
                ConnectionType::DoQ => {
                    debug!("Creating QUIC upstream for {}", connection_info.raw_addr);
                    let builder = QuicConnectionBuilder::new(&connection_info);
                    create_pipeline_pool(1, connection_info, Box::new(builder))
                }
                ConnectionType::DoH => {
                    debug!(
                        "Creating DoH upstream for {} (HTTP/{})",
                        connection_info.raw_addr,
                        if connection_info.enable_http3 {
                            "3"
                        } else {
                            "2"
                        }
                    );
                    if connection_info.enable_http3 {
                        let builder = H3ConnectionBuilder::new(&connection_info);
                        create_pipeline_pool(0, connection_info, Box::new(builder))
                    } else {
                        let builder = H2ConnectionBuilder::new(&connection_info);
                        create_pipeline_pool(0, connection_info, Box::new(builder))
                    }
                }
            }
        } else {
            // Domain-based upstream: use bootstrap or system DNS for resolution
            match &connection_info.connection_type {
                ConnectionType::UDP => {
                    let upstream: BootstrapUpstream<UdpConnection> =
                        BootstrapUpstream::new(connection_info);
                    Box::new(upstream)
                }
                ConnectionType::TCP | ConnectionType::DoT => {
                    let upstream: BootstrapUpstream<TcpConnection> =
                        BootstrapUpstream::new(connection_info);
                    Box::new(upstream)
                }
                ConnectionType::DoQ => {
                    let upstream: BootstrapUpstream<QuicConnection> =
                        BootstrapUpstream::new(connection_info);
                    Box::new(upstream)
                }
                ConnectionType::DoH => {
                    if connection_info.enable_http3 {
                        let upstream: BootstrapUpstream<H3Connection> =
                            BootstrapUpstream::new(connection_info);
                        Box::new(upstream)
                    } else {
                        let upstream: BootstrapUpstream<H2Connection> =
                            BootstrapUpstream::new(connection_info);
                        Box::new(upstream)
                    }
                }
            }
        }
    }

    /// Build an upstream instance from configuration
    pub fn with_upstream_config(upstream_config: UpstreamConfig) -> Box<dyn Upstream> {
        let connection_info = ConnectionInfo::from(upstream_config);
        Self::with_connection_info(connection_info)
    }
}

fn create_pipeline_pool<C: Connection>(
    min_size: usize,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    Box::new(PooledUpstream::<C> {
        pool: PipelinePool::new(
            min_size,
            connection_info
                .max_conns
                .unwrap_or(ConnectionInfo::DEFAULT_MAX_CONNS_SIZE),
            ConnectionInfo::DEFAULT_MAX_CONNS_LOAD,
            connection_info
                .idle_timeout
                .unwrap_or(ConnectionInfo::DEFAULT_IDLE_TIME),
            builder,
        ),
        connection_info,
    })
}

fn create_reuse_pool<C: Connection>(
    min_size: usize,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    Box::new(PooledUpstream::<C> {
        pool: ReusePool::new(
            min_size,
            connection_info
                .max_conns
                .unwrap_or(ConnectionInfo::DEFAULT_MAX_CONNS_SIZE),
            connection_info
                .idle_timeout
                .unwrap_or(ConnectionInfo::DEFAULT_IDLE_TIME),
            builder,
        ),
        connection_info,
    })
}

fn create_pipeline_or_reuse_pool<C: Connection>(
    min_size: usize,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    if connection_info.enable_pipeline.unwrap_or(false) {
        create_pipeline_pool(min_size, connection_info, builder)
    } else {
        create_reuse_pool(min_size, connection_info, builder)
    }
}

/// Pooled upstream resolver implementation
///
/// Uses connection pooling to efficiently reuse connections for multiple queries.
/// The pool type (pipeline or reuse) is determined during creation based on
/// protocol capabilities and configuration.
#[allow(unused)]
#[derive(Debug)]
struct PooledUpstream<C: Connection> {
    /// Connection metadata (remote address, port, etc.)
    connection_info: ConnectionInfo,
    /// Connection pool for load balancing and connection reuse
    pool: Arc<dyn ConnectionPool<C>>,
}

#[async_trait]
impl<C: Connection> Upstream for PooledUpstream<C> {
    /// Execute DNS query through the connection pool
    ///
    /// The pool handles connection selection, creation, and lifecycle management.
    /// No additional logging here as the pool layer already logs connection events.
    async fn inner_query(&self, request: Message) -> Result<Message> {
        self.pool.query(request).await
    }

    fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info
    }
    // Note: timeout() uses default implementation from trait
}

/// UDP upstream with automatic TCP fallback on truncation
///
/// DNS over UDP has a 512-byte size limit (or EDNS extended size).
/// When responses exceed this limit, the TC (truncated) bit is set,
/// indicating the client should retry over TCP to get the full response.
///
/// This upstream automatically handles this fallback:
/// 1. Try UDP first (fast, low overhead)
/// 2. If truncated, automatically retry over TCP
#[derive(Debug)]
struct UdpTruncatedUpstream {
    /// Connection configuration (includes timeout)
    connection_info: ConnectionInfo,
    /// Primary UDP connection pool (fast path)
    main_pool: Arc<dyn ConnectionPool<UdpConnection>>,
    /// Fallback TCP connection pool (used when UDP response is truncated)
    fallback_pool: Arc<dyn ConnectionPool<TcpConnection>>,
}

#[async_trait]
impl Upstream for UdpTruncatedUpstream {
    async fn inner_query(&self, request: Message) -> Result<Message> {
        // Try UDP first (most DNS queries fit in UDP packets)
        let response = self.main_pool.query(request.clone()).await?;

        // Check if response was truncated (TC bit set)
        if response.truncated() {
            // Log fallback event (only happens occasionally, minimal performance impact)
            debug!("UDP response truncated, falling back to TCP");

            // Retry over TCP to get the full response
            self.fallback_pool.query(request).await
        } else {
            // UDP response was complete, return it
            Ok(response)
        }
    }

    fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info
    }
    // Note: timeout() and connection_type() use default implementations from trait
}

#[derive(Debug)]
pub struct ConnectionBuilderFactory {
    connection_info: ConnectionInfo,
}

impl ConnectionBuilderFactory {
    pub fn new(connection_info: ConnectionInfo) -> Self {
        ConnectionBuilderFactory { connection_info }
    }

    /// Build a ConnectionBuilder with the resolved IP address.
    ///
    /// # Safety
    ///
    /// This method uses `unsafe transmute` to convert concrete ConnectionBuilder types
    /// to the generic type `C`. This is SAFE because:
    ///
    /// 1. The generic parameter `C` in `DomainUpstream<C>` is determined at creation time
    ///    based on `connection_info.connection_type`
    /// 2. `connection_info.connection_type` is immutable and never changes at runtime
    /// 3. The match ensures we always transmute the correct concrete type to `C`:
    ///    - ConnectionType::UDP �?always used with DomainUpstream<UdpConnection>
    ///    - ConnectionType::TCP �?always used with DomainUpstream<TcpConnection>
    ///    - etc.
    ///
    /// The type invariant is established in `UpstreamBuilder::with_upstream_config()`
    /// where `DomainUpstream<C>` is created with the matching `C` for each ConnectionType.
    pub fn build<C: Connection>(&self, ip: IpAddr) -> Box<dyn ConnectionBuilder<C>> {
        let mut info = self.connection_info.clone();
        info.remote_ip = Some(ip);
        match info.connection_type {
            ConnectionType::UDP => {
                let src: Box<dyn ConnectionBuilder<UdpConnection>> =
                    Box::new(UdpConnectionBuilder::new(&info));
                unsafe {
                    std::mem::transmute::<
                        Box<dyn ConnectionBuilder<UdpConnection>>,
                        Box<dyn ConnectionBuilder<C>>,
                    >(src)
                }
            }
            ConnectionType::TCP | ConnectionType::DoT => {
                let src: Box<dyn ConnectionBuilder<TcpConnection>> =
                    Box::new(TcpConnectionBuilder::new(&info));
                unsafe {
                    std::mem::transmute::<
                        Box<dyn ConnectionBuilder<TcpConnection>>,
                        Box<dyn ConnectionBuilder<C>>,
                    >(src)
                }
            }
            ConnectionType::DoQ => {
                let src: Box<dyn ConnectionBuilder<QuicConnection>> =
                    Box::new(QuicConnectionBuilder::new(&info));
                unsafe {
                    std::mem::transmute::<
                        Box<dyn ConnectionBuilder<QuicConnection>>,
                        Box<dyn ConnectionBuilder<C>>,
                    >(src)
                }
            }
            ConnectionType::DoH => {
                if info.enable_http3 {
                    let src: Box<dyn ConnectionBuilder<H3Connection>> =
                        Box::new(H3ConnectionBuilder::new(&info));
                    unsafe {
                        std::mem::transmute::<
                            Box<dyn ConnectionBuilder<H3Connection>>,
                            Box<dyn ConnectionBuilder<C>>,
                        >(src)
                    }
                } else {
                    let src: Box<dyn ConnectionBuilder<H2Connection>> =
                        Box::new(H2ConnectionBuilder::new(&info));
                    unsafe {
                        std::mem::transmute::<
                            Box<dyn ConnectionBuilder<H2Connection>>,
                            Box<dyn ConnectionBuilder<C>>,
                        >(src)
                    }
                }
            }
        }
    }
}

/// Domain-based upstream resolver that uses bootstrap to resolve domain names
///
/// When the upstream server is specified as a domain name (e.g., dns.google.com)
/// instead of an IP address, we need to resolve it first. This creates a
/// chicken-and-egg problem: we need DNS to resolve the DNS server's address!
///
/// This upstream solves it by using a bootstrap resolver:
/// 1. Bootstrap resolver (configured with IP) resolves the domain name
/// 2. Resolved IP is cached with TTL
/// 3. Connection pool is created/updated when IP changes
/// 4. DNS queries are forwarded through the pool
///
/// # Performance
/// - Lock-free pool swapping using ArcSwap (no blocking on IP changes)
/// - IP resolution is cached, not done on every query
/// - Automatic pool refresh when TTL expires
#[derive(Debug)]
struct BootstrapUpstream<C: Connection> {
    /// Upstream server domain name (for logging)
    server_name: String,
    /// Connection metadata (includes bootstrap config)
    connection_info: ConnectionInfo,
    /// Bootstrap resolver for domain name resolution
    bootstrap: Arc<Bootstrap>,
    /// Lock-free connection pool with current resolved IP
    /// Tuple: (current_ip, connection_pool)
    pool: ArcSwap<(Option<IpAddr>, Arc<dyn ConnectionPool<C>>)>,
    /// Factory for creating connection builders when IP changes
    builder_factory: ConnectionBuilderFactory,
}

impl<C: Connection> BootstrapUpstream<C> {
    /// Create a new domain upstream with the given connection info and optional bootstrap server
    fn new(connection_info: ConnectionInfo) -> Self {
        // 创建一个空的连接池，将在第一次查询时初始�?
        let pool: Arc<dyn ConnectionPool<C>> =
            ReusePool::<C>::new(0, 1, 10, Box::new(DummyConnectionBuilder {}));

        let conn_info = connection_info.clone();
        let builder_factory = ConnectionBuilderFactory::new(conn_info.clone());
        BootstrapUpstream {
            server_name: connection_info.server_name.clone(),
            bootstrap: connection_info.bootstrap.clone().unwrap(),
            connection_info,
            pool: ArcSwap::from_pointee((None, pool)),
            builder_factory,
        }
    }

    /// Initialize or refresh the connection pool with the resolved IP
    ///
    /// This method handles:
    /// - Initial pool creation on first query
    /// - IP change detection and pool refresh
    /// - Lock-free pool updates using ArcSwap
    ///
    /// # Performance
    /// - Fast path: single atomic load when IP hasn't changed
    /// - Pool recreation only happens on IP change (rare)
    /// - No locks or blocking operations
    async fn init_pool_if_needed(&self) -> Result<()> {
        // Fast path: atomically load current pool state (lock-free)
        let guard = &(*self.pool.load());
        let pool_ip = guard.0;

        // Resolve domain name via bootstrap (cached in Bootstrap with TTL)
        let ip = match self.bootstrap.get().await {
            Ok(value) => value,
            Err(value) => return Err(value),
        };

        // Check if IP has changed since last resolution
        if let Some(current_ip) = pool_ip {
            if current_ip == ip {
                // IP unchanged, continue using current pool (hot path)
                return Ok(());
            }

            // IP changed - log the change (rare event, acceptable overhead)
            info!(
                server = %self.server_name,
                old_ip = %current_ip,
                new_ip = %ip,
                "Upstream IP address changed, refreshing connection pool"
            );
        } else {
            // First initialization
            info!(
                server = %self.server_name,
                ip = %ip,
                "Initializing connection pool for domain-based upstream"
            );
        }

        // Create new connection builder with the resolved IP
        let builder: Box<dyn ConnectionBuilder<C>> = self.builder_factory.build(ip);

        // Create appropriate pool type based on protocol
        let new_pool: Arc<dyn ConnectionPool<C>> = match self.connection_info.connection_type {
            ConnectionType::UDP | ConnectionType::TCP | ConnectionType::DoT => {
                if self.connection_info.enable_pipeline.unwrap_or(false) {
                    PipelinePool::new(0, 1, 64, 10, builder)
                } else {
                    ReusePool::new(0, 1, 10, builder)
                }
            }
            ConnectionType::DoQ | ConnectionType::DoH => PipelinePool::new(0, 1, 64, 10, builder),
        };

        // Atomically swap to new pool (lock-free, readers see old or new pool consistently)
        self.pool.swap(Arc::from((Some(ip), new_pool)));

        Ok(())
    }
}

#[async_trait]
impl<C: Connection> Upstream for BootstrapUpstream<C> {
    /// Execute DNS query through bootstrap-resolved upstream
    ///
    /// # Process
    /// 1. Resolve domain name to IP (cached with TTL in bootstrap)
    /// 2. Initialize/refresh pool if IP changed
    /// 3. Forward query through the pool
    ///
    /// # Performance
    /// - Hot path: pool already initialized, just forward query
    /// - Cold path: bootstrap resolution + pool creation (first query only)
    /// - IP change: new pool creation (rare, based on DNS TTL)
    async fn inner_query(&self, request: Message) -> Result<Message> {
        // Ensure connection pool is initialized with current IP
        // Fast path: just checks atomic, no allocation
        // Slow path: resolves DNS + creates pool (only on first query or IP change)
        self.init_pool_if_needed().await?;

        // Get current connection pool (lock-free atomic load)
        let pool = &*self.pool.load();

        // Forward query through the pool
        pool.1.query(request).await
    }

    fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info
    }
    // Note: timeout() and connection_type() use default implementations from trait
}

/// Dummy connection builder for initial empty pool
///
/// This is used as a placeholder before the first DNS resolution completes.
/// Any attempt to create a connection will fail with an error.
#[derive(Debug)]
struct DummyConnectionBuilder {}

#[async_trait]
impl<C: Connection> ConnectionBuilder<C> for DummyConnectionBuilder {
    async fn create_connection(&self, _conn_id: u16) -> Result<Arc<C>> {
        Err(DnsError::protocol(
            "DummyConnectionBuilder cannot create connections (pool not yet initialized)",
        ))
    }
}

/// Parse SOCKS5 proxy configuration from string
///
/// Supports two formats:
/// - "host:port" - SOCKS5 without authentication
/// - "username:password@host:port" - SOCKS5 with authentication
///
/// If host is a domain name, it will be resolved using system DNS.
///
/// # Arguments
/// * `socks5_str` - SOCKS5 proxy string in one of the supported formats
///
/// # Returns
/// - `Some(Socks5Opt)` if parsing and resolution succeed
/// - `None` if parsing fails or hostname resolution fails
///
/// # Examples
/// ```
/// // Without auth
/// parse_socks5_opt("127.0.0.1:1080")
/// parse_socks5_opt("proxy.example.com:1080")
///
/// // With auth
/// parse_socks5_opt("user:pass@127.0.0.1:1080")
/// parse_socks5_opt("user:pass@proxy.example.com:1080")
/// ```
fn parse_socks5_opt(socks5_str: &str) -> Option<Socks5Opt> {
    // Split by '@' to separate auth from host:port
    let (username, password, host_port) = if let Some(at_pos) = socks5_str.rfind('@') {
        // Format: username:password@host:port
        let auth_part = &socks5_str[..at_pos];
        let host_part = &socks5_str[at_pos + 1..];

        // Split auth by ':'
        if let Some(colon_pos) = auth_part.find(':') {
            let username = auth_part[..colon_pos].to_string();
            let password = auth_part[colon_pos + 1..].to_string();
            (Some(username), Some(password), host_part)
        } else {
            warn!(
                "Invalid SOCKS5 auth format (expected username:password): {}",
                socks5_str
            );
            return None;
        }
    } else {
        // Format: host:port (no auth)
        (None, None, socks5_str)
    };

    // Parse host:port - use last colon to split
    let (mut host, port) = match host_port.rfind(':') {
        Some(colon_pos) => {
            let host = &host_port[..colon_pos];
            let port_str = &host_port[colon_pos + 1..];

            match port_str.parse::<u16>() {
                Ok(port) => (host, port),
                Err(_) => {
                    warn!("Invalid SOCKS5 port: {}", port_str);
                    return None;
                }
            }
        }
        None => {
            warn!("Invalid SOCKS5 format (expected host:port): {}", host_port);
            return None;
        }
    };

    // Remove IPv6 brackets if present: [::1] -> ::1
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }

    // Resolve host to IP address
    let ip_addr = if let Ok(ip) = IpAddr::from_str(host) {
        // Already an IP address
        ip
    } else {
        // It's a hostname, resolve it
        match try_lookup_server_name(host) {
            Ok(ip) => ip,
            Err(e) => {
                warn!("Failed to resolve SOCKS5 hostname '{}': {}", host, e);
                return None;
            }
        }
    };

    Some(Socks5Opt {
        username,
        password,
        socket_addr: SocketAddr::new(ip_addr, port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks5_opt_ip_without_auth() {
        // Test parsing IP address without authentication
        let result = parse_socks5_opt("127.0.0.1:1080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert!(opt.username.is_none());
        assert!(opt.password.is_none());
        assert_eq!(opt.socket_addr.ip(), IpAddr::from_str("127.0.0.1").unwrap());
        assert_eq!(opt.socket_addr.port(), 1080);
    }

    #[test]
    fn test_parse_socks5_opt_ip_with_auth() {
        // Test parsing IP address with authentication
        let result = parse_socks5_opt("myuser:mypass@192.168.1.100:8080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert_eq!(opt.username, Some("myuser".to_string()));
        assert_eq!(opt.password, Some("mypass".to_string()));
        assert_eq!(
            opt.socket_addr.ip(),
            IpAddr::from_str("192.168.1.100").unwrap()
        );
        assert_eq!(opt.socket_addr.port(), 8080);
    }

    #[test]
    fn test_parse_socks5_opt_ipv6_without_auth() {
        // Test parsing IPv6 address without authentication
        let result = parse_socks5_opt("[::1]:1080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert!(opt.username.is_none());
        assert!(opt.password.is_none());
        assert_eq!(opt.socket_addr.ip(), IpAddr::from_str("::1").unwrap());
        assert_eq!(opt.socket_addr.port(), 1080);
    }

    #[test]
    fn test_parse_socks5_opt_ipv6_with_auth() {
        // Test parsing IPv6 address with authentication
        let result = parse_socks5_opt("user:pass@[2001:db8::1]:8080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert_eq!(opt.username, Some("user".to_string()));
        assert_eq!(opt.password, Some("pass".to_string()));
        assert_eq!(
            opt.socket_addr.ip(),
            IpAddr::from_str("2001:db8::1").unwrap()
        );
        assert_eq!(opt.socket_addr.port(), 8080);
    }

    #[test]
    fn test_parse_socks5_opt_ipv6_full_address() {
        // Test parsing full IPv6 address
        let result = parse_socks5_opt("[fe80::1234:5678:90ab:cdef]:9050");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert_eq!(
            opt.socket_addr.ip(),
            IpAddr::from_str("fe80::1234:5678:90ab:cdef").unwrap()
        );
        assert_eq!(opt.socket_addr.port(), 9050);
    }

    #[test]
    fn test_parse_socks5_opt_ipv6_missing_bracket() {
        // Test IPv6 without brackets - this actually succeeds for simple cases like ::1
        // because rfind(':') correctly splits "::1:1080" into "::1" and "1080"
        // However, brackets are still RECOMMENDED for clarity and standards compliance
        let result = parse_socks5_opt("::1:1080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert_eq!(opt.socket_addr.ip(), IpAddr::from_str("::1").unwrap());
        assert_eq!(opt.socket_addr.port(), 1080);
    }

    #[test]
    fn test_parse_socks5_opt_ipv6_missing_port() {
        // Test IPv6 with brackets but no port
        let result = parse_socks5_opt("[::1]");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_socks5_opt_ipv6_unclosed_bracket() {
        // Test IPv6 with unclosed bracket
        let result = parse_socks5_opt("[::1:1080");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_socks5_opt_invalid_port() {
        // Test invalid port number
        let result = parse_socks5_opt("127.0.0.1:invalid");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_socks5_opt_missing_port() {
        // Test missing port
        let result = parse_socks5_opt("127.0.0.1");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_socks5_opt_invalid_auth_format() {
        // Test invalid auth format (missing password)
        let result = parse_socks5_opt("myuser@127.0.0.1:1080");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_socks5_opt_password_with_colon() {
        // Test password containing colon
        let result = parse_socks5_opt("user:pass:word@127.0.0.1:1080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert_eq!(opt.username, Some("user".to_string()));
        assert_eq!(opt.password, Some("pass:word".to_string()));
        assert_eq!(opt.socket_addr.port(), 1080);
    }

    #[test]
    fn test_parse_socks5_opt_hostname_localhost() {
        // Test hostname resolution (localhost should always work)
        let result = parse_socks5_opt("localhost:1080");
        assert!(result.is_some());

        let opt = result.unwrap();
        assert!(opt.username.is_none());
        assert!(opt.password.is_none());
        assert_eq!(opt.socket_addr.port(), 1080);
        // localhost can resolve to either 127.0.0.1 or ::1
        assert!(
            opt.socket_addr.ip() == IpAddr::from_str("127.0.0.1").unwrap()
                || opt.socket_addr.ip() == IpAddr::from_str("::1").unwrap()
        );
    }
}
