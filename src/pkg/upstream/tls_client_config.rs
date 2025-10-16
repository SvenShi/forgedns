/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use lazy_static::lazy_static;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref SECURE_CONFIG: ClientConfig = build_secure_config();
    static ref INSECURE_CONFIG: ClientConfig = build_insecure_config();
}

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
fn build_insecure_config() -> ClientConfig {
    ring::default_provider()
        .install_default()
        .expect("failed to install default CryptoProvider");
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    config.enable_early_data = true;
    set_alpn(config)
}

pub(crate) fn secure_client_config() -> ClientConfig {
    SECURE_CONFIG.clone()
}
pub(crate) fn insecure_client_config() -> ClientConfig {
    INSECURE_CONFIG.clone()
}

static ALPN_PROTOCOLS: &[&[u8]] = &[b"h3", b"h2", b"dot", b"doq"];

lazy_static! {
    static ref alpn: Vec<Vec<u8>> = ALPN_PROTOCOLS.iter().map(|&p| p.to_vec()).collect();
}

fn set_alpn(mut config: ClientConfig) -> ClientConfig {
    config.alpn_protocols = alpn.clone();
    config
}

struct NoCertVerification;

impl Debug for NoCertVerification {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoCertVerification")
    }
}

impl ServerCertVerifier for NoCertVerification {
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

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

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
