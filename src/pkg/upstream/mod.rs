/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::context::DnsContext;
use crate::pkg::upstream::pool::doh_cnn::{DoHConnection, DoHConnectionBuilder};
use crate::pkg::upstream::pool::pipeline::PipelinePool;
use crate::pkg::upstream::pool::reuse::ReusePool;
use crate::pkg::upstream::pool::tcp_conn::{TcpConnection, TcpConnectionBuilder};
use crate::pkg::upstream::pool::udp_conn::{UdpConnection, UdpConnectionBuilder};
use crate::pkg::upstream::pool::{Connection, ConnectionPool};
use async_trait::async_trait;
use hickory_proto::ProtoError;
use hickory_proto::xfer::DnsResponse;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
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
            ConnectType::DoQ => 784,
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
                    if connect_info.enable_pipeline.unwrap_or(false) {
                        Box::new(PooledUpstream::<TcpConnection> {
                            connect_info,
                            pool: PipelinePool::new(
                                1,
                                DEFAULT_MAX_CONNS_SIZE,
                                DEFAULT_MAX_CONNS_LOAD,
                                Box::new(builder),
                            ),
                        })
                    } else {
                        Box::new(PooledUpstream::<TcpConnection> {
                            connect_info,
                            pool: ReusePool::new(1, DEFAULT_MAX_CONNS_SIZE, Box::new(builder)),
                        })
                    }
                }

                ConnectType::DoQ => {
                    warn!("DoQ upstream not yet implemented");
                    todo!()
                }
                ConnectType::DoH => {
                    info!("Using DoH upstream");
                    let builder = DoHConnectionBuilder::new(&connect_info);
                    if connect_info.enable_pipeline.unwrap_or(true) {
                        Box::new(PooledUpstream::<DoHConnection> {
                            connect_info,
                            pool: PipelinePool::new(
                                1,
                                DEFAULT_MAX_CONNS_SIZE,
                                DEFAULT_MAX_CONNS_LOAD,
                                Box::new(builder),
                            ),
                        })
                    } else {
                        Box::new(PooledUpstream::<DoHConnection> {
                            connect_info,
                            pool: ReusePool::new(1, DEFAULT_MAX_CONNS_SIZE, Box::new(builder)),
                        })
                    }
                }
            }
        } else {
            warn!("Upstream requires domain resolution: {}", connect_info.host);
            todo!("new domain upstream")
        }
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
