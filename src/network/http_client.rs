// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared HTTP client helpers.
//!
//! The client is intentionally dependency-light and shared by HTTP side-effect
//! executors, rule downloads, and release upgrades. It centralizes TLS policy,
//! SOCKS5 dialing, redirects, response draining, and atomic file downloads.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::future::BoxFuture;
use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue, LOCATION};
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tower_service::Service;
use url::Url;

use crate::core::error::{DnsError, Result};
use crate::network::tls_config::{insecure_client_config, secure_client_config};
use crate::network::upstream::{Socks5Opt, connect_tcp_stream};

pub const DEFAULT_MAX_REDIRECTS: usize = 5;

type InnerClient = HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Clone, Debug, Default)]
pub struct HttpClientOptions {
    pub insecure_skip_verify: bool,
    pub socks5: Option<Socks5Opt>,
}

#[derive(Clone, Debug)]
pub struct HttpRequestOptions {
    pub url: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    pub max_redirects: usize,
}

impl HttpRequestOptions {
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Vec::new(),
            body: Bytes::new(),
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }

    pub fn with_headers(mut self, headers: Vec<(HeaderName, HeaderValue)>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }

    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    pub downloaded: u64,
    pub total: Option<u64>,
}

#[derive(Clone)]
pub struct HttpClient {
    client: InnerClient,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new(options: HttpClientOptions) -> Self {
        let tls_config = if options.insecure_skip_verify {
            insecure_client_config()
        } else {
            secure_client_config()
        };

        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(HttpConnector {
                socks5: options.socks5,
            });

        Self {
            client: HyperClient::builder(TokioExecutor::new()).build(connector),
        }
    }

    pub async fn get_request(&self, options: HttpRequestOptions) -> Result<HttpResponse> {
        let options = HttpRequestOptions {
            body: Bytes::new(),
            ..options
        };
        self.request(Method::GET, options).await
    }

    pub async fn post_request(&self, options: HttpRequestOptions) -> Result<HttpResponse> {
        self.request(Method::POST, options).await
    }

    pub async fn request(
        &self,
        method: Method,
        options: HttpRequestOptions,
    ) -> Result<HttpResponse> {
        let response = self.request_following_redirects(method, options).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|err| DnsError::plugin(format!("failed to read response body: {err}")))?
            .to_bytes();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    pub async fn download(&self, options: HttpRequestOptions, path: &Path) -> Result<()> {
        self.download_with_progress(options, path, |_| {}).await
    }

    pub async fn download_with_progress<F>(
        &self,
        options: HttpRequestOptions,
        path: &Path,
        progress: F,
    ) -> Result<()>
    where
        F: FnMut(DownloadProgress),
    {
        let options = HttpRequestOptions {
            body: Bytes::new(),
            ..options
        };
        let response = self
            .request_following_redirects(Method::GET, options)
            .await?;
        let total = content_length(response.headers());
        write_target_file(path, response.into_body(), total, progress).await
    }

    async fn request_following_redirects(
        &self,
        method: Method,
        mut options: HttpRequestOptions,
    ) -> Result<hyper::Response<Incoming>> {
        let label = request_label(&method, options.url.as_str());

        for redirect_count in 0..=options.max_redirects {
            let request = build_hyper_request(&method, &options)?;
            let response =
                self.client.request(request).await.map_err(|err| {
                    DnsError::plugin(format!("request failed for '{label}': {err}"))
                })?;

            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }

            if status.is_redirection() {
                if redirect_count == options.max_redirects {
                    drain_response_body(response.into_body()).await?;
                    return Err(DnsError::plugin(format!(
                        "request failed for '{}': too many redirects",
                        request_label(&method, options.url.as_str())
                    )));
                }

                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| {
                        DnsError::plugin(format!(
                            "request failed for '{}': redirect {} missing Location header",
                            request_label(&method, options.url.as_str()),
                            format_status(status)
                        ))
                    })?
                    .to_str()
                    .map_err(|err| {
                        DnsError::plugin(format!(
                            "request failed for '{}': invalid redirect Location header: {}",
                            request_label(&method, options.url.as_str()),
                            err
                        ))
                    })?
                    .to_string();
                drain_response_body(response.into_body()).await?;
                options.url = resolve_redirect_url(options.url.as_str(), location.as_str())?;
                continue;
            }

            drain_response_body(response.into_body()).await?;
            return Err(DnsError::plugin(format!(
                "request failed for '{}': unexpected status {}",
                request_label(&method, options.url.as_str()),
                format_status(status)
            )));
        }

        Err(DnsError::plugin(format!(
            "request failed for '{}': too many redirects",
            request_label(&method, options.url.as_str())
        )))
    }
}

fn build_hyper_request(
    method: &Method,
    options: &HttpRequestOptions,
) -> Result<Request<Full<Bytes>>> {
    let uri = options.url.parse::<Uri>().map_err(|err| {
        DnsError::plugin(format!(
            "failed to build http request for '{}': invalid uri: {}",
            request_label(method, options.url.as_str()),
            err
        ))
    })?;
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    let headers = builder.headers_mut().ok_or_else(|| {
        DnsError::plugin(format!(
            "failed to build http request for '{}': headers unavailable",
            request_label(method, options.url.as_str())
        ))
    })?;
    for (name, value) in &options.headers {
        headers.append(name.clone(), value.clone());
    }
    builder
        .body(Full::new(options.body.clone()))
        .map_err(|err| {
            DnsError::plugin(format!(
                "failed to build http request for '{}': {}",
                request_label(method, options.url.as_str()),
                err
            ))
        })
}

#[derive(Debug, Clone)]
struct HttpConnector {
    socks5: Option<Socks5Opt>,
}

impl Service<Uri> for HttpConnector {
    type Error = DnsError;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;
    type Response = TokioIo<TcpStream>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let socks5 = self.socks5.clone();
        Box::pin(async move {
            let host = dst.host().ok_or_else(|| {
                DnsError::plugin(format!("http request uri '{}' is missing host", dst))
            })?;
            let port = dst
                .port_u16()
                .or_else(|| match dst.scheme_str() {
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                })
                .ok_or_else(|| {
                    DnsError::plugin(format!(
                        "http request uri '{}' uses unsupported or missing scheme",
                        dst
                    ))
                })?;
            let remote_ip = host.parse::<IpAddr>().ok();
            let stream = connect_tcp_stream(remote_ip, host.to_string(), port, socks5).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

pub async fn drain_response_body(mut body: Incoming) -> Result<()> {
    while let Some(frame) = body.frame().await {
        frame.map_err(|err| {
            DnsError::plugin(format!("failed to read http response body: {}", err))
        })?;
    }
    Ok(())
}

async fn write_target_file<F>(
    path: &Path,
    mut body: Incoming,
    total: Option<u64>,
    mut progress: F,
) -> Result<()>
where
    F: FnMut(DownloadProgress),
{
    let dir = path.parent().ok_or_else(|| {
        DnsError::plugin(format!(
            "target path '{}' has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(dir).await.map_err(|err| {
        DnsError::plugin(format!(
            "failed to create target directory '{}': {}",
            dir.display(),
            err
        ))
    })?;

    let tmp_path = temp_path_for(path);
    let mut file = File::create(&tmp_path).await.map_err(|err| {
        DnsError::plugin(format!(
            "failed to create temp file '{}': {}",
            tmp_path.display(),
            err
        ))
    })?;
    let mut downloaded = 0u64;
    progress(DownloadProgress { downloaded, total });
    while let Some(frame_result) = body.frame().await {
        let frame = match frame_result {
            Ok(frame) => frame,
            Err(err) => {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(DnsError::plugin(format!(
                    "failed to read response body: {err}"
                )));
            }
        };
        if let Ok(data) = frame.into_data() {
            if let Err(err) = file.write_all(&data).await {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(DnsError::plugin(format!(
                    "failed to write temp file '{}': {}",
                    tmp_path.display(),
                    err
                )));
            }
            downloaded = downloaded.saturating_add(data.len() as u64);
            progress(DownloadProgress { downloaded, total });
        }
    }
    file.sync_all().await.map_err(|err| {
        DnsError::plugin(format!(
            "failed to sync temp file '{}': {}",
            tmp_path.display(),
            err
        ))
    })?;
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, path).await {
        let rename_fallback = matches!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
        );
        if !rename_fallback {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(DnsError::plugin(format!(
                "failed to replace target file '{}': {}",
                path.display(),
                err
            )));
        }

        if fs::try_exists(path).await.unwrap_or(false)
            && let Err(err) = fs::remove_file(path).await
        {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(DnsError::plugin(format!(
                "failed to remove existing target file '{}': {}",
                path.display(),
                err
            )));
        }
        fs::rename(&tmp_path, path).await.map_err(|err| {
            DnsError::plugin(format!(
                "failed to replace target file '{}' after fallback: {}",
                path.display(),
                err
            ))
        })?;
    }

    Ok(())
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    tmp.set_file_name(format!(".{file_name}.{nanos}.tmp"));
    tmp
}

fn request_label(method: &Method, url: &str) -> String {
    format!("{method} {url}")
}

pub fn resolve_redirect_url(current_url: &str, location: &str) -> Result<String> {
    let base = Url::parse(current_url).map_err(|err| {
        DnsError::plugin(format!(
            "failed to parse redirect base url '{}': {}",
            current_url, err
        ))
    })?;
    base.join(location)
        .map(|url| url.to_string())
        .map_err(|err| {
            DnsError::plugin(format!(
                "failed to resolve redirect location '{}' against '{}': {}",
                location, current_url, err
            ))
        })
}

pub fn format_status(status: StatusCode) -> String {
    status
        .canonical_reason()
        .map(|reason| format!("{} {}", status.as_u16(), reason))
        .unwrap_or_else(|| status.as_u16().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_redirect_url_supports_relative_location() {
        let resolved = resolve_redirect_url(
            "https://example.com/releases/latest/download/file.dat",
            "/assets/file.dat",
        )
        .expect("relative redirect should resolve");
        assert_eq!(resolved, "https://example.com/assets/file.dat");
    }

    #[test]
    fn test_request_options_builders_set_expected_fields() {
        let options = HttpRequestOptions::from_url("https://example.com")
            .with_headers(vec![(
                HeaderName::from_static("x-test"),
                HeaderValue::from_static("1"),
            )])
            .with_body(Bytes::from_static(b"body"))
            .with_max_redirects(2);
        assert_eq!(options.url, "https://example.com");
        assert_eq!(options.headers.len(), 1);
        assert_eq!(options.body, Bytes::from_static(b"body"));
        assert_eq!(options.max_redirects, 2);
    }

    #[test]
    fn test_build_hyper_request_uses_method_headers_and_body() {
        let options = HttpRequestOptions::from_url("https://example.com/api")
            .with_headers(vec![(
                HeaderName::from_static("x-test"),
                HeaderValue::from_static("1"),
            )])
            .with_body(Bytes::from_static(b"payload"));
        let request = build_hyper_request(&Method::PATCH, &options).unwrap();
        assert_eq!(request.method(), Method::PATCH);
        assert_eq!(request.uri(), "https://example.com/api");
        assert_eq!(request.headers()["x-test"], "1");
    }
}
