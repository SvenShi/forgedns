use std::path::{Component, Path, PathBuf};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use tokio::fs;
use tracing::warn;

use crate::api::{ApiResponse, simple_response};
use crate::config::types::ApiWebUiConfig;
use crate::core::error::{DnsError, Result};

#[derive(Debug)]
pub(super) struct StaticFileServer {
    root: PathBuf,
    index: String,
}

impl StaticFileServer {
    pub(super) fn from_config(config: &ApiWebUiConfig) -> Result<Self> {
        let root = config.root.trim();
        if root.is_empty() {
            return Err(DnsError::config("api.http.webui.root cannot be empty"));
        }

        let index = config
            .index
            .as_deref()
            .map(str::trim)
            .filter(|index| !index.is_empty())
            .unwrap_or("index.html")
            .to_string();
        if Path::new(&index)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(DnsError::config(
                "api.http.webui.index must be a file name relative to api.http.webui.root",
            ));
        }

        Ok(Self {
            root: PathBuf::from(root),
            index,
        })
    }

    pub(super) async fn handle(&self, request: Request<Bytes>) -> ApiResponse {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return simple_response(StatusCode::METHOD_NOT_ALLOWED, Bytes::new());
        }

        let head_only = request.method() == Method::HEAD;
        let request_path = request.uri().path();
        let Some(relative_path) = match_static_path(request_path) else {
            return simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"));
        };

        let candidate = if relative_path.as_os_str().is_empty() {
            self.root.join(&self.index)
        } else {
            self.root.join(&relative_path)
        };

        let response_path = match fs::metadata(&candidate).await {
            Ok(metadata) if metadata.is_file() => candidate,
            Ok(metadata) if metadata.is_dir() => candidate.join(&self.index),
            _ => self.root.join(&self.index),
        };

        self.file_response(&response_path, head_only).await
    }

    async fn file_response(&self, path: &Path, head_only: bool) -> ApiResponse {
        let Ok(metadata) = fs::metadata(path).await else {
            return simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"));
        };
        if !metadata.is_file() {
            return simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"));
        }

        let body = if head_only {
            Bytes::new()
        } else {
            match fs::read(path).await {
                Ok(body) => Bytes::from(body),
                Err(err) => {
                    warn!(path = %path.display(), error = %err, "failed to read WebUI static file");
                    return simple_response(StatusCode::INTERNAL_SERVER_ERROR, Bytes::new());
                }
            }
        };

        let mut response = simple_response(StatusCode::OK, body);
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type_for_path(path)),
        );
        if let Ok(value) = HeaderValue::from_str(&metadata.len().to_string()) {
            response
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, value);
        }
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control_for_path(path)),
        );
        response
    }
}

pub(super) fn match_static_path(path: &str) -> Option<PathBuf> {
    let decoded = percent_decode_path(path)?;
    let relative = decoded.trim_start_matches('/');
    if relative.is_empty() {
        return Some(PathBuf::new());
    }

    let path = Path::new(relative);
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(clean)
}

fn percent_decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return None;
            }
            let high = hex_value(bytes[idx + 1])?;
            let low = hex_value(bytes[idx + 2])?;
            decoded.push(high << 4 | low);
            idx += 3;
        } else {
            decoded.push(bytes[idx]);
            idx += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") | Some("map") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn cache_control_for_path(path: &Path) -> &'static str {
    if path.file_name().and_then(|name| name.to_str()) == Some("index.html") {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    }
}
