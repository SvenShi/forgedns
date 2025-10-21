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

use crate::pkg::upstream::pool::Connection;
use crate::pkg::upstream::tls_client_config::{insecure_client_config, secure_client_config};
use crate::pkg::upstream::{ConnectInfo, ConnectType};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bytes::BytesMut;
use hickory_proto::ProtoError;
use http::header::CONTENT_LENGTH;
use http::{HeaderValue, Method, Request, Response, Version, header};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TokioRuntime};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Establish TLS connection over an existing TCP stream
///
/// Performs TLS handshake with optional certificate verification.
///
/// # Arguments
/// * `tcp_stream` - Established TCP connection
/// * `skip_cert` - If true, skip certificate validation (INSECURE - testing only!)
/// * `server_name` - SNI hostname for TLS
/// * `conn_timeout` - Handshake timeout
#[inline]
pub(crate) async fn connect_tls(
    tcp_stream: TcpStream,
    skip_cert: bool,
    server_name: String,
    conn_timeout: Duration,
) -> Result<TlsStream<TcpStream>, ProtoError> {
    let config = if skip_cert {
        insecure_client_config()
    } else {
        secure_client_config()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let dns_name = ServerName::try_from(server_name)
        .map_err(|_| ProtoError::from("Invalid DNS server name"))?;
    
    match timeout(conn_timeout, connector.connect(dns_name, tcp_stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(ProtoError::from(format!("TLS connection error: {}", e))),
        Err(_) => Err(ProtoError::from("TLS handshake timeout")),
    }
}

/// Establish QUIC connection for DoQ
///
/// Creates a QUIC endpoint and connects to the remote server.
///
/// # Arguments
/// * `bind_addr` - Local address to bind to
/// * `remote_addr` - Remote server address
/// * `skip_cert` - If true, skip certificate validation (INSECURE!)
/// * `server_name` - SNI hostname
/// * `conn_timeout` - Connection timeout
pub(crate) async fn connect_quic(
    bind_addr: SocketAddr,
    remote_addr: SocketAddr,
    skip_cert: bool,
    server_name: String,
    conn_timeout: Duration,
) -> Result<quinn::Connection, ProtoError> {
    let udp_socket = UdpSocket::bind(bind_addr).await?;

    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        udp_socket.into_std()?,
        Arc::new(TokioRuntime),
    )?;
    
    let client_config = if skip_cert {
        ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(insecure_client_config()).unwrap(),
        ))
    } else {
        ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(secure_client_config()).unwrap(),
        ))
    };

    endpoint.set_default_client_config(client_config);
    
    match timeout(
        conn_timeout,
        endpoint.connect(remote_addr, server_name.as_ref()).unwrap(),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(ProtoError::from(format!("QUIC connection error: {}", e))),
        Err(_) => Err(ProtoError::from("QUIC handshake timeout")),
    }
}

/// Close multiple connections synchronously
///
/// Calls the `close()` method on each connection.
/// Since close() is synchronous, this doesn't require async.
#[inline]
pub fn close_conns<C: Connection>(conns: &Vec<Arc<C>>) {
    for conn in conns {
        conn.close();
    }
}

/// Content type header for DNS-over-HTTPS
const DNS_HEADER_VALUE: HeaderValue = HeaderValue::from_static("application/dns-message");

/// Build a DoH GET request with base64-encoded DNS query
///
/// Constructs an HTTP GET request with the DNS message in the query string.
///
/// # Arguments
/// * `uri` - Base URI (will append "?dns=<base64>")
/// * `buf` - Raw DNS message bytes
/// * `version` - HTTP version (HTTP/2 or HTTP/3)
#[inline]
pub fn build_dns_get_request(mut uri: String, buf: Vec<u8>, version: Version) -> Request<()> {
    uri.push_str(&BASE64_URL_SAFE_NO_PAD.encode(buf));

    http::Request::builder()
        .version(version)
        .header(header::CONTENT_TYPE, DNS_HEADER_VALUE)
        .method(Method::GET)
        .uri(uri)
        .body(())
        .unwrap()
}

/// Extract response buffer from HTTP response
///
/// Pre-allocates buffer based on Content-Length header if present.
#[inline]
pub fn get_buf_from_res<T>(response: &mut Response<T>) -> BytesMut {
    let response_bytes = BytesMut::with_capacity(
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(4096), // Default 4KB
    );
    response_bytes
}

/// Build DoH request URI from connection info
///
/// Constructs the full HTTPS URI for DoH requests, handling non-standard ports.
pub fn build_doh_request_uri(connect_info: &ConnectInfo) -> String {
    if connect_info.port != ConnectType::DoH.default_port() {
        let mut uri = format!(
            "https://{}:{}{}?dns=",
            connect_info.host, connect_info.port, connect_info.path
        );
        uri.reserve(512); // Pre-allocate for base64 query
        uri
    } else {
        let mut uri = format!("https://{}{}?dns=", connect_info.host, connect_info.path);
        uri.reserve(512);
        uri
    }
}
