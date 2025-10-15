/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::pkg::upstream::pool::Connection;
use crate::pkg::upstream::tls_client_config::{insecure_client_config, secure_client_config};
use hickory_proto::ProtoError;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TokioRuntime};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

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
        .map_err(|_| ProtoError::from("invalid dns server name"))?;
    match timeout(conn_timeout, connector.connect(dns_name, tcp_stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(ProtoError::from(format!("tls connect error: {e}"))),
        Err(_) => Err(ProtoError::from("TLS handshake timeout")),
    }
}

pub(crate) async fn connect_quic(
    bind_addr: SocketAddr,
    remote_addr: SocketAddr,
    skip_cert: bool,
    server_name: String,
    conn_timeout: Duration,
) -> Result<quinn::Connection, ProtoError> {
    let udp_socket = UdpSocket::bind(bind_addr).await?;
    udp_socket.connect(remote_addr).await?;

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
        Ok(Err(e)) => Err(ProtoError::from(format!("quic connect error: {e}"))),
        Err(_) => Err(ProtoError::from("QUIC handshake timeout")),
    }
}

/// Synchronous close helper (close() is sync)
#[inline]
pub fn close_conns<C: Connection>(conns: &Vec<Arc<C>>) {
    for conn in conns {
        // it's fine if close() is sync: call directly
        conn.close();
    }
}
