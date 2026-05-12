use std::net::SocketAddr;

use http::{HeaderMap, HeaderValue};

use crate::config::types::ApiCorsConfig;

/// Add CORS headers to the management API response based on the configured
/// allowed origins.
///
/// This is only applied to the control-plane API, never to the DNS data path.
pub(super) fn add_cors_headers(
    headers: &mut HeaderMap,
    request_headers: Option<&HeaderMap>,
    cors: &ApiCorsConfig,
) {
    let wildcard = cors.allow_any_origin || cors.allowed_origins.iter().any(|o| o == "*");

    let origin_value = request_headers
        .and_then(|h| h.get(http::header::ORIGIN))
        .and_then(|v| v.to_str().ok());

    let allowed_origin = if wildcard {
        HeaderValue::from_static("*")
    } else if let Some(origin) = origin_value {
        if cors.allowed_origins.iter().any(|o| o == origin)
            || origin_host_allowed(origin, &cors.allowed_origin_hosts)
        {
            HeaderValue::from_str(origin).unwrap_or_else(|_| HeaderValue::from_static("*"))
        } else {
            return;
        }
    } else {
        match cors.allowed_origins.first() {
            Some(origin) => {
                HeaderValue::from_str(origin).unwrap_or_else(|_| HeaderValue::from_static("*"))
            }
            None => return,
        }
    };

    headers.insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin);
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );

    if !wildcard {
        headers.insert(
            http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
}

pub(super) fn infer_cors_config_from_listen(listen: SocketAddr) -> ApiCorsConfig {
    let ip = listen.ip();
    if ip.is_unspecified() {
        return ApiCorsConfig {
            allowed_origins: Vec::new(),
            allow_any_origin: true,
            allowed_origin_hosts: Vec::new(),
        };
    }

    let mut allowed_origin_hosts = vec![normalize_origin_host(&ip.to_string())];
    if ip.is_loopback() {
        allowed_origin_hosts.push("localhost".to_string());
    }

    allowed_origin_hosts.sort();
    allowed_origin_hosts.dedup();

    ApiCorsConfig {
        allowed_origins: Vec::new(),
        allow_any_origin: false,
        allowed_origin_hosts,
    }
}

pub(super) fn resolve_cors_config(
    configured: Option<ApiCorsConfig>,
    listen: SocketAddr,
) -> ApiCorsConfig {
    match configured {
        Some(cors)
            if cors.allow_any_origin
                || !cors.allowed_origins.is_empty()
                || !cors.allowed_origin_hosts.is_empty() =>
        {
            cors
        }
        _ => infer_cors_config_from_listen(listen),
    }
}

fn origin_host_allowed(origin: &str, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        return false;
    }

    let Ok(uri) = origin.parse::<http::Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };

    let host = normalize_origin_host(host);
    allowed_hosts.iter().any(|allowed| allowed == &host)
}

fn normalize_origin_host(host: &str) -> String {
    host.trim_matches(['[', ']']).to_ascii_lowercase()
}
