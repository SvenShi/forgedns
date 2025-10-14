/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::pkg::upstream::tls_client_config;
use hickory_proto::ProtoError;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use crate::pkg::upstream::pool::Connection;

#[inline]
pub async fn connect_tls(
    tcp_stream: TcpStream,
    skip_cert: bool,
    server_name: String,
    conn_timeout: Duration,
) -> Result<TlsStream<TcpStream>, ProtoError> {
    let config = if skip_cert {
        tls_client_config::insecure_client_config()
    } else {
        tls_client_config::secure_client_config()
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

/// Synchronous close helper (close() is sync)
#[inline]
pub fn close_conns<C: Connection>(conns: &Vec<Arc<C>>) {
    for conn in conns {
        // it's fine if close() is sync: call directly
        conn.close();
    }
}
