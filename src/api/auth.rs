// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Authentication helpers for the management API.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::HeaderMap;

use crate::config::types::ApiAuthConfig;

pub(crate) fn is_authorized(headers: &HeaderMap, auth: Option<&ApiAuthConfig>) -> bool {
    let Some(auth) = auth else {
        return true;
    };
    match auth {
        ApiAuthConfig::Basic { username, password } => {
            let Some(value) = headers.get(http::header::AUTHORIZATION) else {
                return false;
            };
            let Ok(value) = value.to_str() else {
                return false;
            };
            let Some(encoded) = value.strip_prefix("Basic ") else {
                return false;
            };
            let Ok(decoded) = STANDARD.decode(encoded) else {
                return false;
            };
            let Ok(decoded) = String::from_utf8(decoded) else {
                return false;
            };
            decoded == format!("{username}:{password}")
        }
    }
}
