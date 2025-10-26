/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::DnsContext;
use crate::core::error::DnsError;
use crate::plugin::executor::Executor;
use crate::plugin::{Plugin, PluginRegistry};
use hickory_proto::op::{Message, MessageType, OpCode};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{Level, debug, event_enabled};

pub mod tcp;
pub mod udp;
pub mod http;

pub trait Server: Plugin {
    fn run(&self);
}

#[derive(Debug)]
pub struct RequestHandle {
    pub entry_executor: Arc<dyn Executor>,
    pub registry: Arc<PluginRegistry>,
}

impl RequestHandle {
    pub async fn handle_request(&self, msg: Message, src_addr: SocketAddr) -> Message {
        // Parse DNS message
        let mut context = DnsContext {
            src_addr,
            request: msg,
            response: None,
            mark: Vec::new(),
            attributes: HashMap::new(),
            registry: self.registry.clone(),
        };

        // Log request details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "DNS request from {}, queries: {:?}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.queries(),
                context.request.extensions(),
                context.request.name_servers()
            );
        }

        // Execute entry plugin to process the request
        self.entry_executor.execute(&mut context).await;

        // Construct response message
        let mut response;
        match context.response {
            None => {
                debug!("No response received from entry plugin");
                response = Message::new();
                response.set_id(context.request.id());
                response.set_op_code(OpCode::Query);
                response.set_message_type(MessageType::Query);
            }
            Some(res) => {
                response = Message::from(res);
            }
        }

        // Log response details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "Sending response to {}, queries: {:?}, id: {}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.queries(),
                context.request.id(),
                response.extensions(),
                response.name_servers()
            );
        }

        response
    }
}

/// Load TLS certificates and private key from files
///
/// Reads PEM-encoded certificate chain and private key from the specified files.
///
/// # Arguments
/// * `cert_path` - Path to the certificate file (PEM format)
/// * `key_path` - Path to the private key file (PEM format)
///
/// # Returns
/// * `Ok(TlsAcceptor)` - Configured TLS acceptor
/// * `Err(DnsError)` - Error if files cannot be read or parsed
pub fn load_tls_config(cert_path: &str, key_path: &str) -> crate::core::error::Result<TlsAcceptor> {
    // Load certificates
    let cert_file = File::open(cert_path).map_err(|e| {
        DnsError::plugin(format!(
            "Failed to open certificate file {}: {}",
            cert_path, e
        ))
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            DnsError::plugin(format!(
                "Failed to parse certificate file {}: {}",
                cert_path, e
            ))
        })?;

    if certs.is_empty() {
        return Err(DnsError::plugin(format!(
            "No certificates found in {}",
            cert_path
        )));
    }

    // Load private key
    let key_file = File::open(key_path).map_err(|e| {
        DnsError::plugin(format!(
            "Failed to open private key file {}: {}",
            key_path, e
        ))
    })?;
    let mut key_reader = BufReader::new(key_file);

    // Try to read private key (supports PKCS8, RSA, EC formats)
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            DnsError::plugin(format!(
                "Failed to parse private key file {}: {}",
                key_path, e
            ))
        })?
        .ok_or_else(|| DnsError::plugin(format!("No private key found in {}", key_path)))?;

    // Build TLS server configuration
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| DnsError::plugin(format!("Failed to build TLS configuration: {}", e)))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
