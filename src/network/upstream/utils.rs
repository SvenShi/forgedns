/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Utility functions for connection pooling
//!
//! Provides helper functions for:
//! - TLS connection establishment
//! - QUIC connection setup
//! - DoH request construction
//! - Connection cleanup

use crate::core::error::{DnsError, Result};
use crate::network::upstream::pool::Connection;
use crate::network::upstream::tls_client_config::{insecure_client_config, secure_client_config};
use crate::network::upstream::{ConnectionInfo, ConnectionType, Socks5Opt};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bytes::BytesMut;
use fast_socks5::client::Socks5Stream;
use http::header::CONTENT_LENGTH;
use http::{HeaderValue, Method, Request, Response, Version, header};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TokioRuntime};
use rustls::pki_types::ServerName;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::info;

/// Establish TLS connection over an existing TCP stream
///
/// Performs TLS 1.2/1.3 handshake with configurable certificate verification.
///
/// # Arguments
/// * `tcp_stream` - Established TCP connection to upgrade to TLS
/// * `skip_cert` - If true, skip certificate validation (**INSECURE** - testing/debug only!)
/// * `server_name` - SNI (Server Name Indication) hostname for TLS handshake
/// * `conn_timeout` - Maximum time to wait for TLS handshake to complete
///
/// # Returns
/// - `Ok(TlsStream)` if TLS handshake succeeds
/// - `Err(DnsError)` if handshake fails or times out
///
/// # Security Warning
/// Setting `skip_cert` to true disables certificate validation and makes the connection
/// vulnerable to man-in-the-middle attacks. Only use this for testing!
#[inline]
pub(crate) async fn connect_tls(
    tcp_stream: TcpStream,
    skip_cert: bool,
    server_name: String,
    conn_timeout: Duration,
) -> Result<TlsStream<TcpStream>> {
    let config = if skip_cert {
        insecure_client_config()
    } else {
        secure_client_config()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let dns_name = ServerName::try_from(server_name)
        .map_err(|_| DnsError::protocol("Invalid DNS server name"))?;

    match timeout(conn_timeout, connector.connect(dns_name, tcp_stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(DnsError::protocol(format!("TLS connection error: {}", e))),
        Err(_) => Err(DnsError::protocol("TLS handshake timeout")),
    }
}

/// Establish QUIC connection for DoQ (DNS over QUIC, RFC 9250)
///
/// Creates a QUIC endpoint from the provided UDP socket and performs the
/// QUIC+TLS 1.3 handshake with the remote DNS server.
///
/// # Arguments
/// * `udp_socket` - Pre-configured UDP socket (already connected to remote)
/// * `skip_cert` - If true, skip certificate validation (**INSECURE** - testing only!)
/// * `server_name` - SNI (Server Name Indication) hostname for TLS 1.3 handshake
/// * `conn_timeout` - Maximum time to wait for QUIC handshake to complete
///
/// # Returns
/// - `Ok(quinn::Connection)` if QUIC handshake succeeds
/// - `Err(DnsError)` if handshake fails, times out, or configuration is invalid
///
/// # Protocol
/// - Uses QUIC with mandatory TLS 1.3 (per RFC 9250)
/// - Supports 0-RTT for resumed connections
/// - Includes ALPN negotiation for "doq" protocol
///
/// # Security Warning
/// Setting `skip_cert` to true disables certificate validation. Only use for testing!
pub(crate) async fn connect_quic(
    udp_socket: UdpSocket,
    skip_cert: bool,
    server_name: String,
    conn_timeout: Duration,
) -> Result<quinn::Connection> {
    let remote_addr = udp_socket.peer_addr()?;
    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        udp_socket,
        Arc::new(TokioRuntime),
    )?;

    let client_config = if skip_cert {
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            insecure_client_config(),
        )?))
    } else {
        ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(secure_client_config())?,
        ))
    };

    endpoint.set_default_client_config(client_config);

    match timeout(conn_timeout, endpoint.connect(remote_addr, &server_name)?).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(DnsError::protocol(format!("QUIC connection error: {}", e))),
        Err(_) => Err(DnsError::protocol("QUIC handshake timeout")),
    }
}

/// Close multiple connections synchronously
///
/// Iterates through the connection vector and calls `close()` on each.
/// This is a convenience function for bulk connection cleanup.
///
/// # Arguments
/// * `conns` - Vector of Arc-wrapped connections to close
///
/// # Notes
/// - close() is idempotent, so calling this multiple times is safe
/// - close() is synchronous, so this function doesn't need to be async
/// - Connections are not removed from the vector, just marked as closed
#[inline]
pub fn close_conns<C: Connection>(conns: &Vec<Arc<C>>) {
    for conn in conns {
        conn.close();
    }
}

/// Content type header for DNS-over-HTTPS (RFC 8484 Section 6)
const DNS_HEADER_VALUE: HeaderValue = HeaderValue::from_static("application/dns-message");

/// Build a DoH GET request with base64url-encoded DNS query
///
/// Constructs an HTTP GET request following RFC 8484 Section 4.1 (GET method).
/// The DNS message is base64url-encoded (without padding) and appended to the URI.
///
/// # Arguments
/// * `uri` - Base URI with "?dns=" already appended (will add base64 query)
/// * `buf` - Raw DNS message bytes (wire format)
/// * `version` - HTTP version (HTTP/2 for h2, HTTP/3 for h3)
///
/// # Returns
/// HTTP Request with empty body (query is in URI parameter)
///
/// # Example URI
/// `https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB`
#[inline]
pub fn build_dns_get_request(mut uri: String, buf: Vec<u8>, version: Version) -> Request<()> {
    // Encode DNS message using base64url without padding (RFC 4648 Section 5)
    uri.push_str(&BASE64_URL_SAFE_NO_PAD.encode(buf));

    http::Request::builder()
        .version(version)
        .header(header::CONTENT_TYPE, DNS_HEADER_VALUE)
        .method(Method::GET)
        .uri(uri)
        .body(())
        .expect("Failed to build HTTP request (should never fail with static headers)")
}

/// Extract and pre-allocate response buffer from HTTP response
///
/// Reads the Content-Length header to optimize buffer allocation.
/// This avoids repeated reallocations when receiving the response body.
///
/// # Arguments
/// * `response` - HTTP response with headers
///
/// # Returns
/// BytesMut buffer pre-allocated to Content-Length size (or 4KB default)
///
/// # Performance
/// Pre-allocating based on Content-Length avoids:
/// - Multiple buffer reallocations during body reception
/// - Memory copies when buffer grows
/// - Potential performance hiccups from allocator
#[inline]
pub fn get_buf_from_res<T>(response: &mut Response<T>) -> BytesMut {
    let capacity = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4096); // Default 4KB for typical DNS responses

    BytesMut::with_capacity(capacity)
}

/// Build DoH request URI template from connection info
///
/// Constructs the full HTTPS URI for DoH requests, handling non-standard ports.
/// The returned URI ends with "?dns=" ready for base64url-encoded query to be appended.
///
/// # Arguments
/// * `connection_info` - Connection configuration with server name, port, and path
///
/// # Returns
/// String containing "https://server:port/path?dns=" (port omitted if 443)
///
/// # Examples
/// - Standard port: `https://dns.example.com/dns-query?dns=`
/// - Custom port: `https://dns.example.com:8443/dns-query?dns=`
///
/// # Performance
/// Pre-reserves 512 bytes to accommodate the base64-encoded DNS query without reallocation
pub fn build_doh_request_uri(connection_info: &ConnectionInfo) -> String {
    let mut uri = if connection_info.port != ConnectionType::DoH.default_port() {
        // Include port in URI for non-standard ports
        format!(
            "https://{}:{}{}?dns=",
            connection_info.server_name, connection_info.port, connection_info.path
        )
    } else {
        // Omit port 443 (standard HTTPS port) from URI
        format!(
            "https://{}{}?dns=",
            connection_info.server_name, connection_info.path
        )
    };

    // Pre-allocate space for base64url-encoded DNS query (~600 bytes for typical query)
    uri.reserve(512);
    uri
}

/// Resolve hostname to IP address using system DNS
///
/// Uses the operating system's DNS resolver (e.g., getaddrinfo on Unix/Linux).
/// This is a blocking operation that uses the system's configured DNS servers.
///
/// # Arguments
/// * `server_name` - Hostname to resolve (e.g., "dns.example.com")
///
/// # Returns
/// - `Ok(IpAddr)` with the first resolved IP address
/// - `Err(DnsError)` if resolution fails or returns no results
///
/// # Notes
/// - This is typically used once during initialization for static upstream servers
/// - For dynamic resolution with TTL support, use Bootstrap instead
/// - Blocks the current task - consider using bootstrap for async resolution
/// - Returns the first address from the system resolver (maybe IPv4 or IPv6)
///
/// # Platform Behavior
/// - Unix/Linux: Uses getaddrinfo() respecting /etc/resolv.conf and /etc/hosts
/// - macOS: May use mDNSResponder
/// - Windows: Uses the Windows DNS Client service
pub fn try_lookup_server_name(server_name: &str) -> Result<IpAddr> {
    match format!("{}:0", server_name).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => {
                let ip = addr.ip();
                info!(
                    server_name = %server_name,
                    resolved_ip = %ip,
                    ip_version = if ip.is_ipv4() { "IPv4" } else { "IPv6" },
                    "Resolved hostname using system DNS (one-time, permanent cache)"
                );
                Ok(ip)
            }
            None => Err(DnsError::protocol(format!(
                "System DNS returned no addresses for '{}'",
                server_name
            ))),
        },
        Err(e) => Err(DnsError::protocol(format!(
            "System DNS resolution failed for '{}': {}",
            server_name, e
        ))),
    }
}

/// Create and configure a UDP socket for DNS communication
///
/// Creates a non-blocking UDP socket with optional Linux-specific socket options
/// (SO_MARK, SO_BINDTODEVICE) and connects it to the remote DNS server.
///
/// # Arguments
/// * `remote_ip` - Remote server IP address (if None, resolves server_name)
/// * `server_name` - Hostname to resolve if remote_ip is None
/// * `port` - Remote server port
/// * `so_mark` - Linux SO_MARK socket option (for policy routing)
/// * `bind_to_device` - Linux SO_BINDTODEVICE option (bind to specific interface)
///
/// # Returns
/// - `Ok(UdpSocket)` connected UDP socket in non-blocking mode
/// - `Err(DnsError)` if socket creation, configuration, or connection fails
///
/// # Platform-Specific Features
/// - **Linux**: Supports SO_MARK (for netfilter/policy routing) and SO_BINDTODEVICE
/// - **Other platforms**: SO_MARK and bind_to_device options are ignored
///
/// # Notes
/// - Socket is set to non-blocking mode for async I/O
/// - SO_REUSEADDR is enabled to allow rapid reconnection
/// - connect() is called to set the default destination (allows using send vs send_to)
#[allow(unused)]
pub fn connect_socket(
    remote_ip: Option<IpAddr>,
    server_name: String,
    port: u16,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
) -> Result<UdpSocket> {
    // Resolve remote address if not provided
    let socket_addr = if let Some(remote_ip) = remote_ip {
        SocketAddr::new(remote_ip, port)
    } else {
        let addr = try_lookup_server_name(&server_name)?;
        SocketAddr::new(addr, port)
    };

    // Create UDP socket with appropriate address family
    let socket = Socket::new(
        Domain::for_address(socket_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    // Configure socket for async I/O
    let _ = socket.set_nonblocking(true);
    let _ = socket.set_reuse_address(true);

    // Linux-specific socket options for advanced routing
    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(device) = bind_to_device {
        socket.bind_device(Some(device.as_bytes()))?;
    }

    // Connect socket to set default destination (allows using send() instead of send_to())
    socket.connect(&socket_addr.into())?;

    Ok(socket.into())
}

/// Create and configure a TCP stream for DNS communication
///
/// Creates a non-blocking TCP socket with TCP_NODELAY enabled and optional
/// Linux-specific socket options, then connects to the remote DNS server.
/// Supports SOCKS5 proxy with bind_device applied to the proxy connection.
///
/// # Arguments
/// * `remote_ip` - Remote server IP address (if None, resolves server_name)
/// * `server_name` - Hostname to resolve if remote_ip is None
/// * `port` - Remote server port
/// * `so_mark` - Linux SO_MARK socket option (for policy routing)
/// * `bind_to_device` - Linux SO_BINDTODEVICE option (bind to specific interface)
/// * `socks5_opt` - Optional SOCKS5 proxy configuration
///
/// # Returns
/// - `Ok(TcpStream)` connected TCP stream (async, non-blocking mode)
/// - `Err(DnsError)` if socket creation, configuration, or connection fails
///
/// # Socket Configuration
/// - **TCP_NODELAY**: Enabled to disable Nagle's algorithm for low-latency DNS queries
/// - **SO_REUSEADDR**: Enabled to allow rapid reconnection
/// - **Non-blocking**: Set for async I/O compatibility
///
/// # Platform-Specific Features
/// - **Linux**: Supports SO_MARK and SO_BINDTODEVICE for advanced routing
/// - **Other platforms**: These options are silently ignored
///
/// # SOCKS5 Support
/// When `socks5_opt` is provided:
/// - Creates connection to SOCKS5 proxy server
/// - Applies bind_device to the proxy connection (Linux only)
/// - Establishes SOCKS5 tunnel to the target server
/// - Supports username/password authentication
///
/// # Performance
/// TCP_NODELAY is critical for DNS-over-TCP performance, as it ensures
/// small DNS queries are sent immediately without waiting for more data
#[allow(unused)]
pub async fn connect_stream(
    remote_ip: Option<IpAddr>,
    server_name: String,
    port: u16,
    so_mark: Option<u32>,
    bind_to_device: Option<String>,
    socks5_opt: Option<Socks5Opt>,
) -> Result<TcpStream> {
    // If SOCKS5 proxy is configured, use it
    if let Some(socks5) = socks5_opt {
        // Create socket to SOCKS5 proxy server
        let socket = Socket::new(
            Domain::for_address(socks5.socket_addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;

        // Configure socket for low-latency async I/O
        let _ = socket.set_nonblocking(true);
        let _ = socket.set_tcp_nodelay(true);
        let _ = socket.set_reuse_address(true);

        // Apply Linux-specific socket options to proxy connection
        #[cfg(target_os = "linux")]
        if let Some(so_mark) = so_mark {
            socket.set_mark(so_mark)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ref device) = bind_to_device {
            socket.bind_device(Some(device.as_bytes()))?;
        }

        // Connect to SOCKS5 proxy (non-blocking)
        socket.connect(&socks5.socket_addr.into());

        // Convert to tokio TcpStream
        let std_stream: std::net::TcpStream = socket.into();
        let proxy_stream = TcpStream::from_std(std_stream)?;

        // Establish SOCKS5 connection through proxy
        use fast_socks5::util::target_addr::TargetAddr;
        use fast_socks5::{AuthenticationMethod, Socks5Command};

        // Create authentication method
        let auth = if let (Some(username), Some(password)) =
            (socks5.username.as_ref(), socks5.password.as_ref())
        {
            Some(AuthenticationMethod::Password {
                username: username.clone(),
                password: password.clone(),
            })
        } else {
            None
        };

        let config = if auth.is_some() {
            fast_socks5::client::Config::default()
        } else {
            let mut config = fast_socks5::client::Config::default();
            config.set_skip_auth(true);
            config
        };

        // Create SOCKS5 stream
        let mut socks5_stream = Socks5Stream::use_stream(proxy_stream, auth, config).await?;

        // Prepare target address
        let target_addr = if let Some(remote_ip) = remote_ip {
            TargetAddr::Ip(SocketAddr::new(remote_ip, port))
        } else {
            TargetAddr::Domain(server_name, port)
        };

        // Connect to target through SOCKS5
        socks5_stream
            .request(Socks5Command::TCPConnect, target_addr)
            .await?;

        // Get the underlying TcpStream
        let stream = socks5_stream.get_socket();

        // Enable TCP_NODELAY on the established SOCKS5 tunnel
        let _ = stream.set_nodelay(true);

        Ok(stream)
    } else {
        // Direct connection (no SOCKS5 proxy)
        let socket_addr = if let Some(remote_ip) = remote_ip {
            SocketAddr::new(remote_ip, port)
        } else {
            let addr = try_lookup_server_name(&server_name)?;
            SocketAddr::new(addr, port)
        };

        // Create TCP socket with appropriate address family
        let socket = Socket::new(
            Domain::for_address(socket_addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;

        // Configure socket for low-latency async I/O
        let _ = socket.set_nonblocking(true);
        let _ = socket.set_reuse_address(true);

        // Linux-specific socket options for advanced routing
        #[cfg(target_os = "linux")]
        if let Some(so_mark) = so_mark {
            socket.set_mark(so_mark)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ref device) = bind_to_device {
            socket.bind_device(Some(device.as_bytes()))?;
        }

        // Initiate TCP connection (non-blocking, will complete asynchronously)
        socket.connect(&socket_addr.into());

        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;

        Ok(stream)
    }
}
