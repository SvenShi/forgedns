/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Unified error handling module for RustDNS
//!
//! Provides a centralized error type that can represent various error conditions
//! throughout the application, making error handling more consistent and easier
//! to maintain.

use crate::config::types::ConfigError;
use fast_socks5::SocksError;
use quinn::crypto::rustls::NoInitialCipherSuite;
use quinn::{ConnectError, VarIntBoundsExceeded};
use thiserror::Error;

/// Main error type for RustDNS
///
/// This enum represents all possible errors that can occur in the application.
/// It can be constructed from various error types using the `From` trait implementations.
#[derive(Debug, Error)]
pub enum DnsError {
    /// I/O operation failed
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML parsing or serialization failed
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yml::Error),

    /// Configuration validation error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Plugin initialization or operation error
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// Network address parsing error
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// Tokio runtime error
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// Dependency resolution error
    #[error("Dependency error: {0}")]
    Dependency(String),

    /// DNS protocol error
    #[error("DNS protocol error: {0}")]
    Protocol(String),

    /// DNS protocol error
    #[error("DNS Hickory protocol error: {0}")]
    HickoryProtocol(#[from] hickory_proto::ProtoError),

    /// Quic connect error
    #[error("quic connect error: {0}")]
    QuicConnectError(#[from] ConnectError),

    /// No initial cipher error
    #[error("No initial cipher error: {0}")]
    NoInitialCipherSuiteError(#[from] NoInitialCipherSuite),

    #[error("integer bounds exceeded error: {0}")]
    VarIntBoundsExceeded(#[from] VarIntBoundsExceeded),

    /// socks5 connect error
    #[error("Socks5 error: {0}")]
    SocksError(#[from] SocksError),

    /// Generic error with custom message
    #[error("{0}")]
    Generic(String),
}

#[allow(unused)]
impl DnsError {
    /// Create a configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        DnsError::Config(msg.into())
    }

    /// Create a plugin error
    pub fn plugin<S: Into<String>>(msg: S) -> Self {
        DnsError::Plugin(msg.into())
    }

    /// Create a runtime error
    pub fn runtime<S: Into<String>>(msg: S) -> Self {
        DnsError::Runtime(msg.into())
    }

    /// Create a dependency error
    pub fn dependency<S: Into<String>>(msg: S) -> Self {
        DnsError::Dependency(msg.into())
    }

    /// Create a protocol error
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        DnsError::Protocol(msg.into())
    }
}

/// Allow conversion from String to DnsError
impl From<String> for DnsError {
    fn from(s: String) -> Self {
        DnsError::Generic(s)
    }
}

/// Allow conversion from &str to DnsError
impl From<&str> for DnsError {
    fn from(s: &str) -> Self {
        DnsError::Generic(s.to_string())
    }
}

/// Allow conversion from ConfigError to DnsError
impl From<ConfigError> for DnsError {
    fn from(e: ConfigError) -> Self {
        DnsError::Config(e.to_string())
    }
}

/// Convenient type alias for Results using DnsError
pub type Result<T> = std::result::Result<T, DnsError>;
