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
use crate::network::upstream::pool::h2_conn::{H2Connection, H2ConnectionBuilder};
use crate::network::upstream::pool::h3_conn::{H3Connection, H3ConnectionBuilder};
use crate::network::upstream::pool::pipeline::PipelinePool;
use crate::network::upstream::pool::quic_conn::{QuicConnection, QuicConnectionBuilder};
use crate::network::upstream::pool::reuse::ReusePool;
use crate::network::upstream::pool::tcp_conn::{TcpConnection, TcpConnectionBuilder};
use crate::network::upstream::pool::udp_conn::{UdpConnection, UdpConnectionBuilder};
use crate::network::upstream::pool::{Connection, ConnectionBuilder, ConnectionPool};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use serde::Deserialize;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};
use url::Url;

mod bootstrap;
mod pool;
mod tls_client_config;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNS_SIZE: usize = 64;
const DEFAULT_MAX_CONNS_LOAD: u16 = 64;

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

/// Configuration for building an upstream
#[derive(Deserialize, Debug)]
pub struct UpstreamConfig {
    /// DNS server address (hostname or IP)
    pub addr: String,
    /// Optional server port (falls back to type default if not specified)
    pub port: Option<u16>,
    /// Optional SOCKS5 proxy to connect through
    pub socks5: Option<String>,
    /// Optional bootstrap server for resolving hostname during runtime
    pub bootstrap: Option<String>,
    /// Direct dial IP address, if provided
    pub dial_addr: Option<IpAddr>,
    /// Skip TLS certificate verification (not recommended)
    pub insecure_skip_verify: Option<bool>,
    /// DNS request timeout
    pub timeout: Option<Duration>,
    pub enable_pipeline: Option<bool>,
    pub enable_http3: Option<bool>,
}

#[async_trait]
#[allow(unused)]
pub trait Upstream: Send + Sync + Debug {
    /// Send a DNS query and wait for the response
    async fn query(&self, request: Message) -> Result<DnsResponse>;

    /// Return the connection type of this upstream
    fn connection_type(&self) -> ConnectionType;
}

/// Connection metadata used by all upstreams
#[derive(Clone, Debug)]
#[allow(unused)]
pub struct ConnectionInfo {
    /// Connection type (UDP, TCP, DoT, DoQ, DoH)
    connection_type: ConnectionType,
    raw_addr: String,
    /// Local bind address, defaults to 0.0.0.0:0
    bind_addr: String,
    /// Upstream DNS server address (hostname or IP)
    remote_addr: String,
    /// Upstream server port
    port: u16,
    /// Optional SOCKS5 proxy
    socks5: Option<String>,
    /// Bootstrap server for hostname resolution
    bootstrap: Option<String>,
    /// For DoH: request path on the server
    path: String,
    /// Raw hostname from configuration
    host: String,
    /// Whether the host is a valid IP address
    is_ip_host: bool,
    /// Whether to skip TLS certificate verification
    insecure_skip_verify: bool,
    /// DNS request timeout
    timeout: Duration,
    enable_pipeline: Option<bool>,
    enable_http3: bool,
}

impl ConnectionInfo {
    /// Build `ConnectionInfo` from `UpstreamConfig`
    pub fn with_upstream_config(upstream_config: &UpstreamConfig) -> Self {
        let (connection_type, host, port, path) =
            Self::detect_connection_type(&upstream_config.addr);

        let port = upstream_config
            .port
            .or(port)
            .unwrap_or(connection_type.default_port());

        debug!(
            "Building ConnectionInfo: type={:?}, host={}, port={}, path={}",
            connection_type, host, port, path
        );

        ConnectionInfo {
            bind_addr: "0.0.0.0:0".to_string(),
            remote_addr: if let Some(ip) = upstream_config.dial_addr {
                ip.to_string()
            } else {
                host.clone()
            },
            port,
            socks5: upstream_config.socks5.clone(),
            connection_type,
            bootstrap: upstream_config.bootstrap.clone(),
            path,
            timeout: upstream_config.timeout.unwrap_or(DEFAULT_TIMEOUT),
            host: host.clone(),
            is_ip_host: IpAddr::from_str(&host).is_ok(),
            insecure_skip_verify: upstream_config.insecure_skip_verify.unwrap_or(false),
            raw_addr: upstream_config.addr.clone(),
            enable_pipeline: upstream_config.enable_pipeline,
            enable_http3: upstream_config.enable_http3.unwrap_or(false),
        }
    }

    /// Detect the connection type from the config address
    fn detect_connection_type(addr: &str) -> (ConnectionType, String, Option<u16>, String) {
        if !addr.contains("//") {
            return Self::detect_connection_type(&("udp://".to_owned() + addr));
        }

        let url = Url::parse(addr).expect("Invalid upstream URL");
        let connection_type;
        let host;

        match url.scheme() {
            "udp" => {
                connection_type = ConnectionType::UDP;
                host = url.host_str().unwrap().to_string();
            }
            "tcp" => {
                connection_type = ConnectionType::TCP;
                host = url.host_str().unwrap().to_string();
            }
            "tls" => {
                connection_type = ConnectionType::DoT;
                host = url.host_str().unwrap().to_string();
            }
            "quic" | "doq" => {
                connection_type = ConnectionType::DoQ;
                host = url.host_str().unwrap().to_string();
            }
            "https" | "doh" => {
                connection_type = ConnectionType::DoH;
                host = url.host_str().unwrap().to_string();
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

    pub fn remote_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.remote_addr.parse().expect("Invalid remote address"),
            self.port,
        )
    }

    pub fn bind_socket_addr(&self) -> SocketAddr {
        self.bind_addr.parse().unwrap()
    }
}

/// Builder for creating upstream instances
pub struct UpstreamBuilder;

impl UpstreamBuilder {
    /// Build an upstream instance from configuration
    pub fn with_upstream_config(upstream_config: &UpstreamConfig) -> Box<dyn Upstream> {
        let connection_info = ConnectionInfo::with_upstream_config(upstream_config);

        debug!(
            "Creating upstream: type={:?}, remote={}, port={}",
            connection_info.connection_type, connection_info.remote_addr, connection_info.port
        );

        if upstream_config.dial_addr.is_some() || connection_info.is_ip_host {
            match connection_info.connection_type {
                ConnectionType::UDP => {
                    debug!("Creating UDP upstream for {}", connection_info.raw_addr);
                    let builder = UdpConnectionBuilder::new(&connection_info);
                    let main_pool = PipelinePool::new(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        Box::new(builder),
                    );

                    let tcp_builder = TcpConnectionBuilder::new(&connection_info);
                    let fallback_pool =
                        ReusePool::new(0, DEFAULT_MAX_CONNS_SIZE, Box::new(tcp_builder));

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
                    create_pipeline_or_reuse_pool(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        connection_info,
                        Box::new(builder),
                    )
                }
                ConnectionType::DoQ => {
                    debug!("Creating QUIC upstream for {}", connection_info.raw_addr);
                    let builder = QuicConnectionBuilder::new(&connection_info);
                    create_pipeline_pool(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        connection_info,
                        Box::new(builder),
                    )
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
                        create_pipeline_pool(
                            0,
                            DEFAULT_MAX_CONNS_SIZE,
                            DEFAULT_MAX_CONNS_LOAD,
                            connection_info,
                            Box::new(builder),
                        )
                    } else {
                        let builder = H2ConnectionBuilder::new(&connection_info);
                        create_pipeline_pool(
                            0,
                            DEFAULT_MAX_CONNS_SIZE,
                            DEFAULT_MAX_CONNS_LOAD,
                            connection_info,
                            Box::new(builder),
                        )
                    }
                }
            }
        } else {
            // Domain-based upstream: use bootstrap or system DNS for resolution
            let bootstrap_server = connection_info.bootstrap.clone();

            if let Some(ref server) = bootstrap_server {
                info!(
                    "Using bootstrap server {} to resolve {}",
                    server, &connection_info.host
                );
            } else {
                info!(
                    "Using system DNS to resolve {} (one-time resolution)",
                    &connection_info.host
                );
            }

            let bootstrap_opt = bootstrap_server.as_deref();
            match &connection_info.connection_type {
                ConnectionType::UDP => {
                    let upstream: DomainUpstream<UdpConnection> =
                        DomainUpstream::new(connection_info, bootstrap_opt);
                    Box::new(upstream)
                }
                ConnectionType::TCP | ConnectionType::DoT => {
                    let upstream: DomainUpstream<TcpConnection> =
                        DomainUpstream::new(connection_info, bootstrap_opt);
                    Box::new(upstream)
                }
                ConnectionType::DoQ => {
                    let upstream: DomainUpstream<QuicConnection> =
                        DomainUpstream::new(connection_info, bootstrap_opt);
                    Box::new(upstream)
                }
                ConnectionType::DoH => {
                    if connection_info.enable_http3 {
                        let upstream: DomainUpstream<H3Connection> =
                            DomainUpstream::new(connection_info, bootstrap_opt);
                        Box::new(upstream)
                    } else {
                        let upstream: DomainUpstream<H2Connection> =
                            DomainUpstream::new(connection_info, bootstrap_opt);
                        Box::new(upstream)
                    }
                }
            }
        }
    }
}

fn create_pipeline_pool<C: Connection>(
    min_size: usize,
    max_size: usize,
    max_load: u16,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    Box::new(PooledUpstream::<C> {
        connection_info,
        pool: PipelinePool::new(min_size, max_size, max_load, builder),
    })
}

fn create_reuse_pool<C: Connection>(
    min_size: usize,
    max_size: usize,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    Box::new(PooledUpstream::<C> {
        connection_info,
        pool: ReusePool::new(min_size, max_size, builder),
    })
}

fn create_pipeline_or_reuse_pool<C: Connection>(
    min_size: usize,
    max_size: usize,
    max_load: u16,
    connection_info: ConnectionInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn Upstream> {
    if connection_info.enable_pipeline.unwrap_or(false) {
        create_pipeline_pool(min_size, max_size, max_load, connection_info, builder)
    } else {
        create_reuse_pool(min_size, max_size, connection_info, builder)
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
        info.remote_addr = ip.to_string();
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
pub struct DomainUpstream<C: Connection> {
    /// Connection metadata
    connection_info: ConnectionInfo,
    /// Bootstrap resolver for domain name resolution (None = use system resolver once)
    bootstrap: Option<Arc<bootstrap::Bootstrap>>,
    /// Connection pool for DNS queries
    pool: ArcSwap<(Option<IpAddr>, Arc<dyn ConnectionPool<C>>)>,
    /// Builder for creating new connections
    builder_factory: ConnectionBuilderFactory,
}

impl<C: Connection> DomainUpstream<C> {
    /// Create a new domain upstream with the given connection info and optional bootstrap server
    fn new(connection_info: ConnectionInfo, bootstrap_server: Option<&str>) -> Self {
        let bootstrap = bootstrap_server
            .map(|server| Arc::new(bootstrap::Bootstrap::new(server, &connection_info.host)));

        // 创建一个空的连接池，将在第一次查询时初始�?
        let pool: Arc<dyn ConnectionPool<C>> =
            ReusePool::<C>::new(0, 1, Box::new(DummyConnectionBuilder {}));

        let conn_info = connection_info.clone();
        let builder_factory = ConnectionBuilderFactory::new(conn_info.clone());
        DomainUpstream {
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

        // If no bootstrap and already resolved once, use permanent cache
        if self.bootstrap.is_none() && pool_ip.is_some() {
            return Ok(());
        }

        let ip = match self.get_ip().await {
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
                "IP address changed for {}: {} -> {}",
                self.connection_info.host, current_ip, ip
            );
        }

        // IP changed or first initialization - create new connection pool
        info!(
            "Creating new connection pool for {} with IP {}",
            self.connection_info.host, ip
        );
        let builder: Box<dyn ConnectionBuilder<C>> = self.builder_factory.build(ip);
        debug!("Created new connection builder {:?}", builder);

        let new_pool: Arc<dyn ConnectionPool<C>> = match self.connection_info.connection_type {
            ConnectionType::UDP | ConnectionType::TCP | ConnectionType::DoT => {
                if self.connection_info.enable_pipeline.unwrap_or(false) {
                    PipelinePool::new(1, DEFAULT_MAX_CONNS_SIZE, DEFAULT_MAX_CONNS_LOAD, builder)
                } else {
                    ReusePool::new(1, DEFAULT_MAX_CONNS_SIZE, builder)
                }
            }
            ConnectionType::DoQ | ConnectionType::DoH => {
                PipelinePool::new(1, DEFAULT_MAX_CONNS_SIZE, DEFAULT_MAX_CONNS_LOAD, builder)
            }
        };

        // Atomically update connection pool
        self.pool.swap(Arc::from((Some(ip), new_pool)));
        Ok(())
    }

    /// Resolve domain to IP address
    ///
    /// Uses bootstrap resolver if configured, otherwise falls back to system DNS.
    /// System DNS results are cached permanently (no refresh).
    async fn get_ip(&self) -> Result<IpAddr> {
        let ip = if let Some(ref bootstrap) = self.bootstrap {
            // Use bootstrap resolver (supports periodic refresh via TTL)
            match bootstrap.get().await {
                Ok(ip) => ip,
                Err(e) => {
                    return Err(DnsError::protocol(format!(
                        "Bootstrap resolution failed for {}: {}",
                        self.connection_info.host, e
                    )));
                }
            }
        } else {
            // Use system DNS one-time resolution (permanent cache)
            match tokio::net::lookup_host(format!("{}:0", self.connection_info.host)).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => {
                        let ip = addr.ip();
                        info!(
                            "Resolved {} to {} using system DNS (one-time, permanent cache)",
                            self.connection_info.host, ip
                        );
                        ip
                    }
                    None => {
                        return Err(DnsError::protocol(format!(
                            "System DNS returned no addresses for {}",
                            self.connection_info.host
                        )));
                    }
                },
                Err(e) => {
                    return Err(DnsError::protocol(format!(
                        "System DNS resolution failed for {}: {}",
                        self.connection_info.host, e
                    )));
                }
            }
        };
        Ok(ip)
    }
}

#[async_trait]
impl<C: Connection> Upstream for DomainUpstream<C> {
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
