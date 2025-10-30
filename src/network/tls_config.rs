/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! TLS client configuration for secure DNS protocols
//!
//! Provides pre-built TLS configurations for:
//! - Secure mode: validates certificates against system roots
//! - Insecure mode: skips certificate validation (for testing only)
//!
//! Configurations are lazily initialized and cached for reuse.

use crate::core::error::DnsError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, ServerConfig, SignatureScheme,
};
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Once};
use tracing::info;

lazy_static::lazy_static! {
    /// Secure TLS configuration with certificate validation
    static ref SECURE_CONFIG: ClientConfig = build_secure_config();

    /// Insecure TLS configuration (no certificate validation)
    static ref INSECURE_CONFIG: ClientConfig = build_insecure_config();

}

static DEFAULT_PROVIDER: Once = Once::new();

pub fn install_default_provider() {
    DEFAULT_PROVIDER.call_once(|| {
        ring::default_provider()
            .install_default()
            .expect("default provider already set elsewhere");
    })
}

/// Build secure TLS client configuration
///
/// Uses system root certificates for validation.
/// Enables early data (0-RTT) for performance.
fn build_secure_config() -> ClientConfig {
    install_default_provider();
    let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap();

    let builder = builder.with_root_certificates({
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    });

    let mut config = builder.with_no_client_auth();
    config.enable_early_data = true;
    config
}

/// Build insecure TLS client configuration
///
/// **WARNING**: Skips all certificate validation. Use only for testing!
fn build_insecure_config() -> ClientConfig {
    install_default_provider();
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();

    config.enable_early_data = true;
    config
}

/// Get secure TLS configuration (with certificate validation)
pub(crate) fn secure_client_config() -> ClientConfig {
    SECURE_CONFIG.clone()
}

/// Get insecure TLS configuration (no certificate validation)
///
/// **WARNING**: Only use for testing/development!
pub(crate) fn insecure_client_config() -> ClientConfig {
    INSECURE_CONFIG.clone()
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
pub fn load_tls_config(
    cert: &Option<String>,
    key: &Option<String>,
) -> Option<crate::core::error::Result<ServerConfig>> {
    match (cert, key) {
        (Some(cert), Some(key)) => {
            info!("Loading TLS configuration: cert={}, key={}", cert, key);
            Some(load_tls_config_from_path(&cert, &key))
        }
        (Some(_), None) => Some(Err(DnsError::plugin(" cert specified but key is missing"))),
        (None, Some(_)) => Some(Err(DnsError::plugin("key specified but cert is missing"))),
        (None, None) => None,
    }
}

fn load_tls_config_from_path(
    cert_path: &str,
    key_path: &str,
) -> crate::core::error::Result<ServerConfig> {
    install_default_provider();
    // Load certificates
    let cert_file = File::open(cert_path).map_err(|e| {
        DnsError::plugin(format!(
            "Failed to open certificate file {}: {}",
            cert_path, e
        ))
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
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
    Ok(config)
}

/// Certificate verifier that accepts any certificate (INSECURE!)
///
/// This is used for testing environments where certificate validation
/// would be problematic. **Never use in production!**
struct NoCertVerification;

impl Debug for NoCertVerification {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoCertVerification")
    }
}

impl ServerCertVerifier for NoCertVerification {
    /// Accept any server certificate without validation
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Accept any TLS 1.2 signature
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Accept any TLS 1.3 signature
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Support all signature schemes
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}
