/*
 * SPDX-FileCopyrightText: 2026 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    Protocol(String),

    #[error("dns class string unknown: {0}")]
    UnknownDnsClassStr(String),

    #[error("record type string unknown: {0}")]
    UnknownRecordTypeStr(String),
}

impl ProtoError {
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Self::Protocol(msg.into())
    }

    pub fn new<S: Into<String>>(msg: S) -> Self {
        Self::Protocol(msg.into())
    }
}

impl From<String> for ProtoError {
    fn from(value: String) -> Self {
        Self::Protocol(value)
    }
}

impl From<&str> for ProtoError {
    fn from(value: &str) -> Self {
        Self::Protocol(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ProtoError>;
