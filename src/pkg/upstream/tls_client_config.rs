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

use lazy_static::lazy_static;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

lazy_static::lazy_static! {
    /// Secure TLS configuration with certificate validation
    static ref SECURE_CONFIG: ClientConfig = build_secure_config();
    
    /// Insecure TLS configuration (no certificate validation)
    static ref INSECURE_CONFIG: ClientConfig = build_insecure_config();
}

/// Build secure TLS client configuration
///
/// Uses system root certificates for validation.
/// Enables early data (0-RTT) for performance.
fn build_secure_config() -> ClientConfig {
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
    set_alpn(config)
}

/// Build insecure TLS client configuration
///
/// **WARNING**: Skips all certificate validation. Use only for testing!
fn build_insecure_config() -> ClientConfig {
    ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");
    
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    
    config.enable_early_data = true;
    set_alpn(config)
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

/// Supported ALPN protocols for DNS over TLS/QUIC/HTTPS
static ALPN_PROTOCOLS: &[&[u8]] = &[b"h3", b"h2", b"dot", b"doq"];

lazy_static! {
    /// Pre-allocated ALPN protocol list
    static ref alpn: Vec<Vec<u8>> = ALPN_PROTOCOLS.iter().map(|&p| p.to_vec()).collect();
}

/// Configure ALPN protocols for the TLS config
fn set_alpn(mut config: ClientConfig) -> ClientConfig {
    config.alpn_protocols = alpn.clone();
    config
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
