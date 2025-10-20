/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::context::DnsContext;
use crate::pkg::upstream::pool::h2_conn::H2ConnectionBuilder;
use crate::pkg::upstream::pool::h3_conn::H3ConnectionBuilder;
use crate::pkg::upstream::pool::pipeline::PipelinePool;
use crate::pkg::upstream::pool::quic_conn::QuicConnectionBuilder;
use crate::pkg::upstream::pool::reuse::ReusePool;
use crate::pkg::upstream::pool::tcp_conn::{TcpConnection, TcpConnectionBuilder};
use crate::pkg::upstream::pool::udp_conn::{UdpConnection, UdpConnectionBuilder};
use crate::pkg::upstream::pool::{h2_conn, h3_conn, quic_conn, Connection, ConnectionBuilder, ConnectionPool};
use async_trait::async_trait;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

mod bootstrap;
mod pool;
mod tls_client_config;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNS_SIZE: usize = 64;
const DEFAULT_MAX_CONNS_LOAD: u16 = 64;

/// Supported upstream connection types
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectType {
    UDP,
    TCP,
    DoT,
    DoQ,
    DoH,
}

#[allow(unused)]
impl ConnectType {
    /// Returns the default port for each connection type
    pub fn default_port(&self) -> u16 {
        match self {
            ConnectType::UDP => 53,
            ConnectType::TCP => 53,
            ConnectType::DoT => 853,
            ConnectType::DoQ => 853,
            ConnectType::DoH => 443,
        }
    }

    /// Returns all supported URL schemes for this connection type
    pub fn schema(&self) -> Vec<&str> {
        match self {
            ConnectType::UDP => vec!["udp", ""],
            ConnectType::TCP => vec!["tcp"],
            ConnectType::DoT => vec!["tls"],
            ConnectType::DoQ => vec!["doq", "quic"],
            ConnectType::DoH => vec!["doh", "https"],
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
pub trait UpStream: Send + Sync {
    /// Send a DNS query and wait for the response
    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError>;

    /// Return the connection type of this upstream
    fn connect_type(&self) -> ConnectType;
}

/// Connection metadata used by all upstreams
#[derive(Clone)]
#[allow(unused)]
pub struct ConnectInfo {
    /// Connection type (UDP, TCP, DoT, DoQ, DoH)
    connect_type: ConnectType,
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

impl ConnectInfo {
    /// Build `ConnectInfo` from `UpstreamConfig`
    pub fn with_upstream_config(upstream_config: &UpstreamConfig) -> Self {
        let (connect_type, host, port, path) = Self::detect_connect_type(&upstream_config.addr);

        let port = upstream_config
            .port
            .or(port)
            .unwrap_or(connect_type.default_port());

        info!(
            "Building ConnectInfo: type={:?}, host={}, port={}, path={}",
            connect_type, host, port, path
        );

        ConnectInfo {
            bind_addr: "0.0.0.0:0".to_string(),
            remote_addr: if let Some(ip) = upstream_config.dial_addr {
                ip.to_string()
            } else {
                host.clone()
            },
            port,
            socks5: upstream_config.socks5.clone(),
            connect_type,
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
    fn detect_connect_type(addr: &str) -> (ConnectType, String, Option<u16>, String) {
        if !addr.contains("//") {
            return Self::detect_connect_type(&("udp://".to_owned() + addr));
        }

        let url = Url::parse(addr).expect("Invalid upstream URL");
        let connect_type;
        let host;

        match url.scheme() {
            "udp" => {
                connect_type = ConnectType::UDP;
                host = url.host_str().unwrap().to_string();
            }
            "tcp" => {
                connect_type = ConnectType::TCP;
                host = url.host_str().unwrap().to_string();
            }
            "tls" => {
                connect_type = ConnectType::DoT;
                host = url.host_str().unwrap().to_string();
            }
            "quic" | "doq" => {
                connect_type = ConnectType::DoQ;
                host = url.host_str().unwrap().to_string();
            }
            "https" | "doh" => {
                connect_type = ConnectType::DoH;
                host = url.host_str().unwrap().to_string();
            }
            other => {
                panic!("Invalid upstream URL scheme: {}", other);
            }
        };

        debug!(
            "Detected upstream: scheme={}, type={:?}, host={}, port={:?}, path={}",
            url.scheme(),
            connect_type,
            host,
            url.port(),
            url.path()
        );

        (connect_type, host, url.port(), url.path().to_string())
    }

    pub fn get_full_remote_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.remote_addr.parse().expect("Invalid remote address"),
            self.port,
        )
    }

    pub fn get_bind_socket_addr(&self) -> SocketAddr {
        self.bind_addr.parse().unwrap()
    }
}

/// Builder for creating upstream instances
pub struct UpStreamBuilder;

impl UpStreamBuilder {
    /// Build an upstream instance from configuration
    pub fn with_upstream_config(upstream_config: &UpstreamConfig) -> Box<dyn UpStream> {
        let connect_info = ConnectInfo::with_upstream_config(upstream_config);

        info!(
            "Creating upstream: type={:?}, remote={}, port={}",
            connect_info.connect_type, connect_info.remote_addr, connect_info.port
        );

        if upstream_config.dial_addr.is_some() || connect_info.is_ip_host {
            match connect_info.connect_type {
                ConnectType::UDP => {
                    info!("Using UDP upstream");
                    let builder = UdpConnectionBuilder::new(&connect_info);
                    let main_pool = PipelinePool::new(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        Box::new(builder),
                    );

                    let tcp_builder = TcpConnectionBuilder::new(&connect_info);
                    let fallback_pool =
                        ReusePool::new(0, DEFAULT_MAX_CONNS_SIZE, Box::new(tcp_builder));

                    Box::new(UdpTruncatedUpstream {
                        main_pool,
                        fallback_pool,
                    })
                }
                ConnectType::TCP | ConnectType::DoT => {
                    info!("Using {:?} upstream", connect_info.connect_type);
                    let builder = TcpConnectionBuilder::new(&connect_info);
                    create_pipeline_or_reuse_pool(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        connect_info,
                        Box::new(builder),
                    )
                }
                ConnectType::DoQ => {
                    info!("Using Quic upstream");
                    let builder = QuicConnectionBuilder::new(&connect_info);
                    create_pipeline_pool(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        connect_info,
                        Box::new(builder),
                    )
                }
                ConnectType::DoH => {
                    info!("Using DoH upstream");
                    if connect_info.enable_http3 {
                        let builder = H3ConnectionBuilder::new(&connect_info);
                        create_pipeline_pool(
                            0,
                            DEFAULT_MAX_CONNS_SIZE,
                            DEFAULT_MAX_CONNS_LOAD,
                            connect_info,
                            Box::new(builder),
                        )
                    } else {
                        let builder = H2ConnectionBuilder::new(&connect_info);
                        create_pipeline_pool(
                            0,
                            DEFAULT_MAX_CONNS_SIZE,
                            DEFAULT_MAX_CONNS_LOAD,
                            connect_info,
                            Box::new(builder),
                        )
                    }
                }
            }
        } else {
            warn!("Upstream requires domain resolution: {}", connect_info.host);

            // 使用bootstrap服务器解析域名
            if let Some(bootstrap_server) = &connect_info.bootstrap {
                info!("Using bootstrap server {} to resolve {}", bootstrap_server, connect_info.host);
                match connect_info.connect_type {
                    ConnectType::UDP => {
                        Box::new(DomainUpstream::new_udp(connect_info, bootstrap_server))
                    }
                    ConnectType::TCP | ConnectType::DoT => {
                        Box::new(DomainUpstream::new_tcp(connect_info, bootstrap_server))
                    }
                    ConnectType::DoQ => {
                        Box::new(DomainUpstream::new_quic(connect_info, bootstrap_server))
                    }
                    ConnectType::DoH => {
                        if connect_info.enable_http3 {
                            Box::new(DomainUpstream::new_h3(connect_info, bootstrap_server))
                        } else {
                            Box::new(DomainUpstream::new_h2(connect_info, bootstrap_server))
                        }
                    }
                }
            } else {
                panic!("Domain upstream requires bootstrap server: {}", connect_info.host);
            }
        }
    }
}

fn create_pipeline_pool<C: Connection>(
    min_size: usize,
    max_size: usize,
    max_load: u16,
    connect_info: ConnectInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn UpStream> {
    Box::new(PooledUpstream::<C> {
        connect_info,
        pool: PipelinePool::new(min_size, max_size, max_load, builder),
    })
}

fn create_reuse_pool<C: Connection>(
    min_size: usize,
    max_size: usize,
    connect_info: ConnectInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn UpStream> {
    Box::new(PooledUpstream::<C> {
        connect_info,
        pool: ReusePool::new(min_size, max_size, builder),
    })
}

fn create_pipeline_or_reuse_pool<C: Connection>(
    min_size: usize,
    max_size: usize,
    max_load: u16,
    connect_info: ConnectInfo,
    builder: Box<dyn ConnectionBuilder<C>>,
) -> Box<dyn UpStream> {
    if connect_info.enable_pipeline.unwrap_or(false) {
        create_pipeline_pool(min_size, max_size, max_load, connect_info, builder)
    } else {
        create_reuse_pool(min_size, max_size, connect_info, builder)
    }
}

/// UDP-based upstream resolver implementation
#[allow(unused)]
pub struct PooledUpstream<C: Connection> {
    /// Connection metadata (remote address, port, etc.)
    pub connect_info: ConnectInfo,
    /// Lazy-initialized UDP connection pool
    pub pool: Arc<dyn ConnectionPool<C>>,
}

#[async_trait]
impl<C: Connection> UpStream for PooledUpstream<C> {
    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError> {
        match self.pool.query(context.request.clone()).await {
            Ok(res) => Ok(res),
            Err(e) => Err(e),
        }
    }

    fn connect_type(&self) -> ConnectType {
        self.connect_info.connect_type
    }
}

pub struct UdpTruncatedUpstream {
    pub main_pool: Arc<dyn ConnectionPool<UdpConnection>>,
    pub fallback_pool: Arc<dyn ConnectionPool<TcpConnection>>,
}

#[async_trait]
impl UpStream for UdpTruncatedUpstream {
    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError> {
        let response = self.main_pool.query(context.request.clone()).await?;

        if response.truncated() {
            self.fallback_pool.query(context.request.clone()).await
        } else {
            Ok(response)
        }
    }

    fn connect_type(&self) -> ConnectType {
        ConnectType::UDP
    }
}

/// Domain-based upstream resolver that uses bootstrap to resolve domain names
pub struct DomainUpstream<C: Connection> {
    /// Connection metadata
    connect_info: ConnectInfo,
    /// Bootstrap resolver for domain name resolution
    bootstrap: Arc<bootstrap::Bootstrap>,
    /// Connection pool for DNS queries
    pool: RwLock<Arc<dyn ConnectionPool<C>>>,
    /// Connection type
    connect_type: ConnectType,
    /// Builder for creating new connections
    builder_factory: Box<dyn Fn(IpAddr) -> Box<dyn ConnectionBuilder<C>> + Send + Sync>,
}

impl<C: Connection> DomainUpstream<C> {
    /// Create a new domain upstream with the given connection info and bootstrap server
    fn new(
        connect_info: ConnectInfo,
        bootstrap_server: &str,
        connect_type: ConnectType,
        builder_factory: Box<dyn Fn(IpAddr) -> Box<dyn ConnectionBuilder<C>> + Send + Sync>,
    ) -> Self {
        let bootstrap = Arc::new(bootstrap::Bootstrap::new(bootstrap_server, &connect_info.host));

        // 创建一个空的连接池，将在第一次查询时初始化
        let pool = RwLock::new(Arc::new(ReusePool::new(0, 0, Box::new(DummyConnectionBuilder {}))) as Arc<dyn ConnectionPool<C>>);

        DomainUpstream {
            connect_info,
            bootstrap,
            pool,
            connect_type,
            builder_factory,
        }
    }

    /// Create a new UDP domain upstream
    pub fn new_udp(connect_info: ConnectInfo, bootstrap_server: &str) -> DomainUpstream<UdpConnection> {
        let builder_factory = Box::new(move |ip: IpAddr| {
            let mut new_info = connect_info.clone();
            new_info.remote_addr = ip.to_string();
            Box::new(UdpConnectionBuilder::new(&new_info))
        });

        DomainUpstream::new(
            connect_info,
            bootstrap_server,
            ConnectType::UDP,
            builder_factory,
        )
    }

    /// Create a new TCP domain upstream
    pub fn new_tcp(connect_info: ConnectInfo, bootstrap_server: &str) -> DomainUpstream<TcpConnection> {
        let builder_factory = Box::new(move |ip: IpAddr| {
            let mut new_info = connect_info.clone();
            new_info.remote_addr = ip.to_string();
            Box::new(TcpConnectionBuilder::new(&new_info))
        });

        DomainUpstream::new(
            connect_info,
            bootstrap_server,
            connect_info.connect_type,
            builder_factory,
        )
    }

    /// Create a new QUIC domain upstream
    pub fn new_quic(connect_info: ConnectInfo, bootstrap_server: &str) -> DomainUpstream<quic_conn::QuicConnection> {
        let builder_factory = Box::new(move |ip: IpAddr| {
            let mut new_info = connect_info.clone();
            new_info.remote_addr = ip.to_string();
            Box::new(QuicConnectionBuilder::new(&new_info))
        });

        DomainUpstream::new(
            connect_info,
            bootstrap_server,
            ConnectType::DoQ,
            builder_factory,
        )
    }

    /// Create a new HTTP/2 domain upstream
    pub fn new_h2(connect_info: ConnectInfo, bootstrap_server: &str) -> DomainUpstream<h2_conn::H2Connection> {
        let builder_factory = Box::new(move |ip: IpAddr| {
            let mut new_info = connect_info.clone();
            new_info.remote_addr = ip.to_string();
            Box::new(H2ConnectionBuilder::new(&new_info))
        });

        DomainUpstream::new(
            connect_info,
            bootstrap_server,
            ConnectType::DoH,
            builder_factory,
        )
    }

    /// Create a new HTTP/3 domain upstream
    pub fn new_h3(connect_info: ConnectInfo, bootstrap_server: &str) -> DomainUpstream<h3_conn::H3Connection> {
        let builder_factory = Box::new(move |ip: IpAddr| {
            let mut new_info = connect_info.clone();
            new_info.remote_addr = ip.to_string();
            Box::new(H3ConnectionBuilder::new(&new_info))
        });

        DomainUpstream::new(
            connect_info,
            bootstrap_server,
            ConnectType::DoH,
            builder_factory,
        )
    }

    /// Initialize or refresh the connection pool with the resolved IP
    async fn ensure_pool_initialized(&self) -> Result<(), ProtoError> {
        // 解析域名
        let ip = match self.bootstrap.get().await {
            Ok(ip) => ip,
            Err(e) => return Err(ProtoError::from(format!("Failed to resolve domain: {}", e))),
        };

        // 检查当前池是否已经使用了这个IP
        let current_pool = self.pool.read().await.clone();
        if let Some(current_ip) = self.get_pool_ip(&current_pool).await {
            if current_ip == ip {
                // IP没有变化，继续使用当前池
                return Ok(());
            }
        }

        // IP已变化或首次初始化，创建新的连接池
        info!("Creating new connection pool for {} with IP {}", self.connect_info.host, ip);
        let builder = (self.builder_factory)(ip);

        let new_pool: Arc<dyn ConnectionPool<C>> = match self.connect_info.connect_type {
            ConnectType::UDP | ConnectType::TCP | ConnectType::DoT => {
                if self.connect_info.enable_pipeline.unwrap_or(false) {
                    Arc::new(PipelinePool::new(
                        1,
                        DEFAULT_MAX_CONNS_SIZE,
                        DEFAULT_MAX_CONNS_LOAD,
                        builder,
                    ))
                } else {
                    Arc::new(ReusePool::new(1, DEFAULT_MAX_CONNS_SIZE, builder))
                }
            }
            ConnectType::DoQ | ConnectType::DoH => {
                Arc::new(PipelinePool::new(
                    1,
                    DEFAULT_MAX_CONNS_SIZE,
                    DEFAULT_MAX_CONNS_LOAD,
                    builder,
                ))
            }
        };

        // 更新连接池
        let mut pool_write = self.pool.write().await;
        *pool_write = new_pool;

        Ok(())
    }

    /// 获取当前池使用的IP地址
    async fn get_pool_ip(&self, _pool: &Arc<dyn ConnectionPool<C>>) -> Option<IpAddr> {
        // 这里可以实现一个机制来跟踪连接池使用的IP
        // 简化实现，总是返回None，强制刷新连接池
        None
    }
}

#[async_trait]
impl<C: Connection> UpStream for DomainUpstream<C> {
    async fn query(&self, context: &mut DnsContext) -> Result<DnsResponse, ProtoError> {
        // 确保连接池已初始化
        self.ensure_pool_initialized().await?;

        // 获取当前连接池
        let pool = self.pool.read().await.clone();

        // 执行查询
        match pool.query(context.request.clone()).await {
            Ok(res) => Ok(res),
            Err(e) => {
                // 如果查询失败，尝试刷新连接池并重试一次
                if let Err(refresh_err) = self.ensure_pool_initialized().await {
                    warn!("Failed to refresh connection pool: {}", refresh_err);
                    return Err(e);
                }

                let new_pool = self.pool.read().await.clone();
                new_pool.query(context.request.clone()).await
            }
        }
    }

    fn connect_type(&self) -> ConnectType {
        self.connect_type
    }
}

/// 用于创建初始空连接池的虚拟ConnectionBuilder
#[derive(Debug)]
struct DummyConnectionBuilder {}

#[async_trait]
impl<C: Connection> ConnectionBuilder<C> for DummyConnectionBuilder {
    async fn new_conn(&self, _conn_id: u16) -> Result<Arc<C>, ProtoError> {
        Err(ProtoError::from("DummyConnectionBuilder cannot create connections"))
    }
}
