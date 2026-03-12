/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared DNS-level helpers used across plugins and executors.

use crate::message::ResponseCode;

/// Parse symbolic DNS response code name.
///
/// # Examples
/// ```
/// use forgedns::core::dns_utils::parse_named_response_code;
/// use forgedns::message::ResponseCode;
///
/// assert_eq!(parse_named_response_code("SERVFAIL"), Some(ResponseCode::ServFail));
/// assert_eq!(parse_named_response_code("3"), Some(ResponseCode::NXDomain));
/// assert_eq!(parse_named_response_code("UNKNOWN"), None);
/// ```
pub fn parse_named_response_code(raw: &str) -> Option<ResponseCode> {
    if let Ok(code) = raw.parse::<u16>() {
        return Some(code.into());
    }

    match raw.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(ResponseCode::NoError),
        "FORMERR" => Some(ResponseCode::FormErr),
        "SERVFAIL" => Some(ResponseCode::ServFail),
        "NXDOMAIN" => Some(ResponseCode::NXDomain),
        "NOTIMP" => Some(ResponseCode::NotImp),
        "REFUSED" => Some(ResponseCode::Refused),
        "YXDOMAIN" => Some(ResponseCode::YXDomain),
        "YXRRSET" => Some(ResponseCode::YXRRSet),
        "NXRRSET" => Some(ResponseCode::NXRRSet),
        "NOTAUTH" => Some(ResponseCode::NotAuth),
        "NOTZONE" => Some(ResponseCode::NotZone),
        "BADVERS" => Some(ResponseCode::BADVERS),
        "BADSIG" => Some(ResponseCode::BADSIG),
        "BADKEY" => Some(ResponseCode::BADKEY),
        "BADTIME" => Some(ResponseCode::BADTIME),
        "BADMODE" => Some(ResponseCode::BADMODE),
        "BADNAME" => Some(ResponseCode::BADNAME),
        "BADALG" => Some(ResponseCode::BADALG),
        "BADTRUNC" => Some(ResponseCode::BADTRUNC),
        "BADCOOKIE" => Some(ResponseCode::BADCOOKIE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Verify named and numeric response-code parsing share the same lookup table.
    fn test_parse_named_response_code_supports_name_and_numeric() {
        assert_eq!(
            parse_named_response_code("NOERROR"),
            Some(ResponseCode::NoError)
        );
        assert_eq!(parse_named_response_code("2"), Some(ResponseCode::ServFail));
        assert_eq!(parse_named_response_code("UNKNOWN_CODE"), None);
    }
}
