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
use crate::network::upstream::pool::pool_pipeline::PipelinePool;
use crate::network::upstream::pool::conn_quic::{QuicConnection, QuicConnectionBuilder};
use crate::network::upstream::pool::pool_reuse::ReusePool;
use crate::network::upstream::pool::conn_tcp::{TcpConnection, TcpConnectionBuilder};
use crate::network::upstream::pool::conn_udp::{UdpConnection, UdpConnectionBuilder};
use crate::network::upstream::pool::{Connection, ConnectionBuilder, ConnectionPool};
use crate::network::upstream::utils::try_lookup_server_name;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use serde::Deserialize;
use std::fmt::Debug;
use std::net::IpAddr;
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

    /// SOCKS5 proxy server for connection (format: "host:port")
    ///
    /// When specified, all connections to the upstream server will be
    /// routed through this SOCKS5 proxy.
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
    /// Send a DNS query and wait for the response
    async fn query(&self, request: Message) -> Result<DnsResponse>;

    /// Return the connection type of this upstream
    fn connection_type(&self) -> ConnectionType;
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
    tag: Option<String>,

    /// Protocol type (auto-detected from URL scheme: udp://, tcp://, tls://, quic://, https://)
    connection_type: ConnectionType,

    /// Original address string from configuration (for logging)
    raw_addr: String,

    /// Resolved or configured IP address (`None` if needs runtime resolution via bootstrap)
    remote_ip: Option<IpAddr>,

    /// Server port (protocol default or explicitly configured)
    port: u16,

    /// SOCKS5 proxy configuration
    socks5: Option<String>,

    /// Bootstrap resolver for dynamic hostname resolution with TTL caching
    bootstrap: Option<Arc<Bootstrap>>,

    /// DoH request path (e.g., `/dns-query`), empty for non-HTTP protocols
    path: String,

    /// Server hostname for TLS SNI and certificate validation
    server_name: String,

    /// Skip TLS certificate verification (**INSECURE** - testing only)
    insecure_skip_verify: bool,

    /// Connection idle timeout in seconds
    idle_timeout: Option<u64>,

    /// Maximum number of connections in the pool
    max_conns: Option<usize>,

    /// DNS query timeout (includes I/O, handshakes, and round-trip time)
    timeout: Duration,

    /// Request pipelining for TCP/DoT (`None` = protocol default)
    enable_pipeline: Option<bool>,

    /// Use HTTP/3 (true) instead of HTTP/2 (false) for DoH
    enable_http3: bool,

    /// Linux SO_MARK for packet marking (policy routing)
    so_mark: Option<u32>,

    /// Linux SO_BINDTODEVICE - bind to specific network interface
    bind_to_device: Option<String>,
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

        ConnectionInfo {
            tag: upstream_config.tag,
            remote_ip,
            port,
            socks5: upstream_config.socks5,
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
    let max_size = connection_info
        .max_conns
        .unwrap_or(ConnectionInfo::DEFAULT_MAX_CONNS_SIZE);
    let idle_time = connection_info
        .idle_timeout
        .unwrap_or(ConnectionInfo::DEFAULT_IDLE_TIME);
    Box::new(PooledUpstream::<C> {
        connection_info,
        pool: PipelinePool::new(
            min_size,
            max_size,
            ConnectionInfo::DEFAULT_MAX_CONNS_LOAD,
            idle_time,
            builder,
        ),
    })
}

fn create_reuse_pool<C: Connection>(
    min_size: usize,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    let max_size = connection_info
        .max_conns
        .unwrap_or(ConnectionInfo::DEFAULT_MAX_CONNS_SIZE);
    let idle_time = connection_info
        .idle_timeout
        .unwrap_or(ConnectionInfo::DEFAULT_IDLE_TIME);
    Box::new(PooledUpstream::<C> {
        connection_info,
        pool: ReusePool::new(min_size, max_size, idle_time, builder),
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
#[allow(unused)]
#[derive(Debug)]
pub struct PooledUpstream<C: Connection> {
    /// Connection metadata (remote address, port, etc.)
    pub connection_info: ConnectionInfo,
    /// Connection pool for load balancing
    pub pool: Arc<dyn ConnectionPool<C>>,
}

#[async_trait]
impl<C: Connection> Upstream for PooledUpstream<C> {
    async fn query(&self, request: Message) -> Result<DnsResponse> {
        match self.pool.query(request).await {
            Ok(res) => Ok(res),
            Err(e) => Err(e),
        }
    }

    fn connection_type(&self) -> ConnectionType {
        self.connection_info.connection_type
    }
}

#[derive(Debug)]
pub struct UdpTruncatedUpstream {
    pub main_pool: Arc<dyn ConnectionPool<UdpConnection>>,
    pub fallback_pool: Arc<dyn ConnectionPool<TcpConnection>>,
}

#[async_trait]
impl Upstream for UdpTruncatedUpstream {
    async fn query(&self, request: Message) -> Result<DnsResponse> {
        let response = self.main_pool.query(request.clone()).await?;

        if response.truncated() {
            self.fallback_pool.query(request).await
        } else {
            Ok(response)
        }
    }

    fn connection_type(&self) -> ConnectionType {
        ConnectionType::UDP
    }
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
#[derive(Debug)]
pub struct BootstrapUpstream<C: Connection> {
    server_name: String,
    /// Connection metadata
    connection_info: ConnectionInfo,
    /// Bootstrap resolver for domain name resolution (None = use system resolver once)
    bootstrap: Arc<Bootstrap>,
    /// Connection pool for DNS queries
    pool: ArcSwap<(Option<IpAddr>, Arc<dyn ConnectionPool<C>>)>,
    /// Builder for creating new connections
    builder_factory: ConnectionBuilderFactory,
}

impl<C: Connection> BootstrapUpstream<C> {
    /// Create a new domain upstream with the given connection info and optional bootstrap server
    fn new(connection_info: ConnectionInfo) -> Self {
        // 创建一个空的连接池，将在第一次查询时初始�?
        let pool: Arc<dyn ConnectionPool<C>> =
            ReusePool::<C>::new(0, 1, 10, Box::new(DummyConnectionBuilder {}));

        let conn_info = connection_info.clone();
        let bootstrap = connection_info.bootstrap.clone().unwrap();
        let builder_factory = ConnectionBuilderFactory::new(conn_info.clone());
        BootstrapUpstream {
            server_name: connection_info.server_name.clone(),
            connection_info,
            bootstrap,
            pool: ArcSwap::from_pointee((None, pool)),
            builder_factory,
        }
    }

    /// Initialize or refresh the connection pool with the resolved IP
    ///
    /// This method handles:
    /// - Initial pool creation on first query
    /// - IP change detection and pool refresh
    /// - Caching for non-bootstrap upstreams (permanent cache)
    async fn init_pool_if_needed(&self) -> Result<()> {
        // Check current pool state
        let guard = &(*self.pool.load());
        let pool_ip = guard.0;

        let ip = match self.bootstrap.get().await {
            Ok(value) => value,
            Err(value) => return Err(value),
        };

        // Check if IP has changed
        if let Some(current_ip) = pool_ip {
            if current_ip == ip {
                // IP unchanged, continue using current pool
                return Ok(());
            }
            info!(
                "IP address changed for {:?}: {} -> {}",
                self.server_name, current_ip, ip
            );
        }

        // IP changed or first initialization - create new connection pool
        info!(
            "Creating new connection pool for {:?} with IP {}",
            self.server_name, ip
        );

        let builder: Box<dyn ConnectionBuilder<C>> = self.builder_factory.build(ip);
        debug!("Created new connection builder {:?}", builder);

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

        // Atomically update connection pool
        self.pool.swap(Arc::from((Some(ip), new_pool)));
        Ok(())
    }
}

#[async_trait]
impl<C: Connection> Upstream for BootstrapUpstream<C> {
    async fn query(&self, request: Message) -> Result<DnsResponse> {
        // Ensure connection pool is initialized (handles IP resolution and pool creation)
        self.init_pool_if_needed().await?;

        // Get current connection pool
        let pool = &*self.pool.load();

        // Execute DNS query through the pool
        match pool.1.query(request.clone()).await {
            Ok(res) => Ok(res),
            Err(e) => Err(e),
        }
    }

    fn connection_type(&self) -> ConnectionType {
        self.connection_info.connection_type
    }
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
