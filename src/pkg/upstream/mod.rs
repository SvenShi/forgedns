/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::core::context::DnsContext;
use crate::pkg::upstream::pool::pipeline::PipelinePool;
use crate::pkg::upstream::pool::reuse::ReusePool;
use crate::pkg::upstream::pool::tcp::{TcpConnection, TcpConnectionBuilder};
use crate::pkg::upstream::pool::udp::{UdpConnection, UdpConnectionBuilder};
use crate::pkg::upstream::pool::{Connection, ConnectionPool};
use async_trait::async_trait;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use url::Url;

mod bootstrap;
mod pool;
mod tls_client_config;

/// Supported upstream connection types
#[derive(Clone, Copy, Debug)]
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
            host: host.clone(),
            is_ip_host: IpAddr::from_str(&host).is_ok(),
            insecure_skip_verify: upstream_config.insecure_skip_verify.unwrap_or(false),
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
}

/// Builder for creating upstream instances
pub struct UpStreamBuilder;

const TIMEOUT_SECS: u64 = 1;

impl UpStreamBuilder {
    /// Build an upstream instance from configuration
    pub fn with_upstream_config(up_stream_config: &UpstreamConfig) -> Box<dyn UpStream> {
        let connect_info = ConnectInfo::with_upstream_config(up_stream_config);

        info!(
            "Creating upstream: type={:?}, remote={}, port={}",
            connect_info.connect_type, connect_info.remote_addr, connect_info.port
        );

        if up_stream_config.dial_addr.is_some() || connect_info.is_ip_host {
            match connect_info.connect_type {
                ConnectType::UDP => {
                    info!("Using UDP upstream");
                    let builder = UdpConnectionBuilder::new(
                        connect_info
                            .bind_addr
                            .parse()
                            .expect("Invalid bind address"),
                        SocketAddr::new(
                            connect_info
                                .remote_addr
                                .parse()
                                .expect("Invalid remote address"),
                            connect_info.port,
                        ),
                        TIMEOUT_SECS,
                    );
                    Box::new(PooledUpstream::<UdpConnection> {
                        connect_info,
                        pool: PipelinePool::new(1, 64, 64, Box::new(builder)),
                    })
                }
                ConnectType::TCP => {
                    info!("Using TCP upstream");
                    let builder = TcpConnectionBuilder::new(
                        SocketAddr::new(
                            connect_info
                                .remote_addr
                                .parse()
                                .expect("Invalid remote address"),
                            connect_info.port,
                        ),
                        TIMEOUT_SECS,
                    );
                    Box::new(PooledUpstream::<TcpConnection> {
                        connect_info,
                        pool: ReusePool::new(1, 64, Box::new(builder)),
                    })
                }
                ConnectType::DoT => {
                    warn!("DoT upstream not yet implemented");
                    todo!()
                }
                ConnectType::DoQ => {
                    warn!("DoQ upstream not yet implemented");
                    todo!()
                }
                ConnectType::DoH => {
                    warn!("DoH upstream not yet implemented");
                    todo!()
                }
            }
        } else {
            warn!("Upstream requires domain resolution: {}", connect_info.host);
            todo!("new domain upstream")
        }
    }
}

/// UDP-based upstream resolver implementation
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
            Ok(mut res) => {
                let mut header = res.header().clone();
                header.set_id(context.request.id());
                res.set_header(header);
                Ok(res)
            }
            Err(e) => Err(e),
        }
    }

    fn connect_type(&self) -> ConnectType {
        self.connect_info.connect_type
    }
}
