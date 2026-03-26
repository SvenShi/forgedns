/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Management HTTP API hub and plugin route registration.

pub mod control;
pub mod health;

use crate::api::health::HealthState;
use crate::config::types::{ApiAuthConfig, ApiConfig, ResolvedApiHttpConfig};
use crate::core::error::{DnsError, Result};
use crate::network::tls_config::load_server_tls_config;
use crate::plugin::server::parse_listen_addr;
use ahash::AHashMap;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use serde::Serialize;
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

#[async_trait]
pub trait ApiHandler: Send + Sync + 'static {
    async fn handle(&self, request: Request<Bytes>) -> Response<Bytes>;
}

#[derive(Clone)]
pub struct ApiRegister {
    hub: Arc<ApiHub>,
}

impl ApiRegister {
    pub(crate) fn new(hub: Arc<ApiHub>) -> Self {
        Self { hub }
    }

    /// Register one handler under an absolute API path.
    pub fn register_route(
        &self,
        method: Method,
        path: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub.register_route(method, path, handler)
    }

    /// Register one GET handler under an absolute API path.
    pub fn register_get(&self, path: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.register_route(Method::GET, path, handler)
    }

    /// Register one POST handler under an absolute API path.
    pub fn register_post(&self, path: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.register_route(Method::POST, path, handler)
    }

    /// Register one GET handler under `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_get(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_route(plugin_tag, Method::GET, subpath, handler)
    }

    /// Register one POST handler under `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_post(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_route(plugin_tag, Method::POST, subpath, handler)
    }
}

impl Debug for ApiRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiRegister").finish_non_exhaustive()
    }
}

pub struct ApiHub {
    config: ResolvedApiHttpConfig,
    routes: Mutex<AHashMap<RouteKey, Arc<dyn ApiHandler>>>,
    health: Arc<HealthState>,
    shutdown_tx: watch::Sender<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Debug for ApiHub {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let route_count = self.routes.lock().map(|routes| routes.len()).unwrap_or(0);
        f.debug_struct("ApiHub")
            .field("listen", &self.config.listen)
            .field("has_tls", &self.config.ssl.is_some())
            .field("has_auth", &self.config.auth.is_some())
            .field("route_count", &route_count)
            .finish()
    }
}

impl ApiHub {
    pub fn from_config(config: &ApiConfig) -> Result<Option<Arc<Self>>> {
        let Some(http) = &config.http else {
            return Ok(None);
        };

        let resolved = http.resolve();
        let listen = resolved.listen.trim();
        if listen.is_empty() {
            return Err(DnsError::config("api.http.listen cannot be empty"));
        }
        let normalized_listen = parse_listen_addr(listen)?.to_string();

        let (shutdown_tx, _) = watch::channel(false);
        Ok(Some(Arc::new(Self {
            config: ResolvedApiHttpConfig {
                listen: normalized_listen,
                ssl: resolved.ssl,
                auth: resolved.auth,
            },
            routes: Mutex::new(AHashMap::new()),
            health: Arc::new(HealthState::new()),
            shutdown_tx,
            task_handle: Mutex::new(None),
        }))
        .map(|hub| {
            health::register_builtin_routes(&ApiRegister::new(hub.clone()), hub.health.clone())
                .expect("builtin API routes should register");
            hub
        }))
    }

    pub fn register_plugin_route(
        &self,
        plugin_tag: &str,
        method: Method,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        let plugin_tag = plugin_tag.trim();
        if plugin_tag.is_empty() {
            return Err(DnsError::plugin("api route plugin tag cannot be empty"));
        }

        let route_path = build_plugin_route_path(plugin_tag, subpath)?;
        self.register_route(method, &route_path, handler)
    }

    pub fn register_route(
        &self,
        method: Method,
        path: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        let route_path = normalize_route_path(path)?;
        let key = RouteKey::new(method, route_path);
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?;

        if routes.insert(key.clone(), handler).is_some() {
            return Err(DnsError::plugin(format!(
                "duplicate API route registered: {} {}",
                key.method, key.path
            )));
        }
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        let mut task_slot = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("API server task lock poisoned"))?;
        if task_slot.is_some() {
            return Ok(());
        }

        let listen = self.config.listen.clone();
        let routes = self
            .routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?
            .clone();
        let tls_acceptor = build_tls_acceptor(&self.config)?;
        let auth = self.config.auth.clone();
        let health = self.health.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let (startup_tx, startup_rx) = oneshot::channel();
        *task_slot = Some(tokio::spawn(async move {
            run_api_server(
                listen,
                routes,
                tls_acceptor,
                auth,
                health,
                &mut shutdown_rx,
                startup_tx,
            )
            .await;
        }));
        drop(task_slot);

        match startup_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(DnsError::runtime(err)),
            Err(_) => Err(DnsError::runtime(
                "API server startup channel closed unexpectedly",
            )),
        }
    }

    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let handle = match self.task_handle.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => None,
        };
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    pub fn mark_plugins_initialized(&self, total_plugins: usize, server_plugins: usize) {
        self.health
            .mark_plugins_initialized(total_plugins, server_plugins);
    }
}

#[derive(Clone, Debug)]
struct RouteKey {
    method: Method,
    path: String,
}

impl RouteKey {
    fn new(method: Method, path: String) -> Self {
        Self { method, path }
    }
}

impl PartialEq for RouteKey {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method && self.path == other.path
    }
}

impl Eq for RouteKey {}

impl std::hash::Hash for RouteKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.method.hash(state);
        self.path.hash(state);
    }
}

fn build_plugin_route_path(plugin_tag: &str, subpath: &str) -> Result<String> {
    if plugin_tag.bytes().any(|b| matches!(b, b'/' | b'?' | b'#')) {
        return Err(DnsError::plugin(format!(
            "plugin tag '{}' is not valid for API route paths",
            plugin_tag
        )));
    }

    let subpath = if subpath.is_empty() {
        ""
    } else if subpath.starts_with('/') {
        subpath
    } else {
        return Err(DnsError::plugin(format!(
            "API subpath '{}' must start with '/'",
            subpath
        )));
    };

    normalize_route_path(&format!("/plugins/{plugin_tag}{subpath}"))
}

fn normalize_route_path(path: &str) -> Result<String> {
    let path = path.trim();
    if path.is_empty() || !path.starts_with('/') {
        return Err(DnsError::plugin(format!(
            "API route path '{}' must start with '/'",
            path
        )));
    }
    if path.bytes().any(|b| matches!(b, b'?' | b'#')) {
        return Err(DnsError::plugin(format!(
            "API route path '{}' cannot contain query or fragment",
            path
        )));
    }
    Ok(path.to_string())
}

fn build_tls_acceptor(config: &ResolvedApiHttpConfig) -> Result<Option<Arc<TlsAcceptor>>> {
    let Some(ssl) = &config.ssl else {
        return Ok(None);
    };
    let server_config = load_server_tls_config(
        ssl.cert.as_deref(),
        ssl.key.as_deref(),
        ssl.client_ca.as_deref(),
        ssl.require_client_cert.unwrap_or(false),
    )?;
    Ok(server_config.map(|mut cfg| {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(TlsAcceptor::from(Arc::new(cfg)))
    }))
}

async fn run_api_server(
    listen: String,
    routes: AHashMap<RouteKey, Arc<dyn ApiHandler>>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    auth: Option<ApiAuthConfig>,
    health: Arc<HealthState>,
    shutdown_rx: &mut watch::Receiver<bool>,
    startup_tx: oneshot::Sender<std::result::Result<(), String>>,
) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(listener) => listener,
        Err(err) => {
            let _ = startup_tx.send(Err(format!(
                "failed to bind API listener on {}: {}",
                listen, err
            )));
            return;
        }
    };
    health.mark_api_listening();
    let _ = startup_tx.send(Ok(()));
    info!(
        listen = %listen,
        tls = %tls_acceptor.is_some(),
        auth = %auth.is_some(),
        routes = routes.len(),
        "Management API listening"
    );

    let routes = Arc::new(routes);
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, remote_addr) = match accepted {
                    Ok(item) => item,
                    Err(err) => {
                        warn!(error = %err, "API accept failed");
                        continue;
                    }
                };
                let routes = routes.clone();
                let tls_acceptor = tls_acceptor.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, remote_addr, routes, tls_acceptor, auth).await {
                        warn!(remote = %remote_addr, error = %err, "API connection failed");
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    routes: Arc<AHashMap<RouteKey, Arc<dyn ApiHandler>>>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    auth: Option<ApiAuthConfig>,
) -> Result<()> {
    match tls_acceptor {
        Some(acceptor) => {
            let stream = acceptor
                .accept(stream)
                .await
                .map_err(|err| DnsError::runtime(format!("API TLS handshake failed: {err}")))?;
            handle_hyper_stream(stream, remote_addr, routes, auth).await
        }
        None => handle_hyper_stream(stream, remote_addr, routes, auth).await,
    }
}

async fn handle_hyper_stream<S>(
    stream: S,
    remote_addr: SocketAddr,
    routes: Arc<AHashMap<RouteKey, Arc<dyn ApiHandler>>>,
    auth: Option<ApiAuthConfig>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let routes = routes.clone();
        let auth = auth.clone();
        async move { handle_hyper_request(request, remote_addr, routes, auth).await }
    });

    let io = TokioIo::new(stream);
    AutoBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|err| DnsError::runtime(format!("API hyper connection failed: {err}")))
}

async fn handle_hyper_request(
    request: Request<Incoming>,
    remote_addr: SocketAddr,
    routes: Arc<AHashMap<RouteKey, Arc<dyn ApiHandler>>>,
    auth: Option<ApiAuthConfig>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let request = match read_hyper_request(request).await {
        Ok(request) => request,
        Err(status) => return Ok(response_to_hyper(simple_response(status, Bytes::new()))),
    };

    debug!(
        remote = %remote_addr,
        method = %request.method(),
        path = %request.uri().path(),
        body_len = request.body().len(),
        "API request received"
    );

    let response = if !is_authorized(request.headers(), auth.as_ref()) {
        let mut response =
            simple_response(StatusCode::UNAUTHORIZED, Bytes::from("401 Unauthorized"));
        response.headers_mut().insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Basic realm=\"forgedns\""),
        );
        response
    } else {
        let key = RouteKey::new(request.method().clone(), request.uri().path().to_string());
        if let Some(handler) = routes.get(&key) {
            handler.handle(request).await
        } else {
            simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"))
        }
    };

    Ok(response_to_hyper(response))
}

fn is_authorized(headers: &HeaderMap, auth: Option<&ApiAuthConfig>) -> bool {
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

async fn read_hyper_request(
    request: Request<Incoming>,
) -> std::result::Result<Request<Bytes>, StatusCode> {
    let (parts, mut body) = request.into_parts();
    let mut collected = Vec::with_capacity(2048);

    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            collected.extend_from_slice(&data);
        }
    }

    Ok(Request::from_parts(parts, Bytes::from(collected)))
}

fn response_to_hyper(response: Response<Bytes>) -> Response<Full<Bytes>> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Full::new(body))
}

pub fn simple_response(status: StatusCode, body: Bytes) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .body(body)
        .expect("failed to build simple API response")
}

pub fn json_response<T>(status: StatusCode, value: &T) -> Response<Bytes>
where
    T: Serialize + ?Sized,
{
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = simple_response(status, Bytes::from(body));
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(err) => simple_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from(format!("failed to serialize json response: {err}")),
        ),
    }
}

pub fn json_ok<T>(status: StatusCode, value: &T) -> Response<Bytes>
where
    T: Serialize + ?Sized,
{
    json_response(status, value)
}

pub fn json_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response<Bytes> {
    #[derive(Serialize)]
    struct ErrorBody {
        ok: bool,
        code: &'static str,
        message: String,
    }

    json_response(
        status,
        &ErrorBody {
            ok: false,
            code,
            message: message.into(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{ApiAuthConfig, ApiConfig, ApiHttpConfig, ApiHttpDetailedConfig};
    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use http::Uri;
    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use http_body_util::Empty;
    use hyper::Request as HyperRequest;
    use hyper::Version;
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use serde::Serialize;
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use tokio::time::{Duration, sleep};

    #[derive(Debug)]
    struct TestEchoHandler;

    #[async_trait]
    impl ApiHandler for TestEchoHandler {
        async fn handle(&self, request: Request<Bytes>) -> Response<Bytes> {
            let payload = serde_json::json!({
                "method": request.method().as_str(),
                "path": request.uri().path(),
                "body_len": request.body().len(),
            });
            json_ok(StatusCode::OK, &payload)
        }
    }

    fn reserve_local_addr() -> SocketAddr {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        addr
    }

    fn test_api_hub(addr: SocketAddr, auth: Option<ApiAuthConfig>) -> Arc<ApiHub> {
        let config = ApiConfig {
            http: Some(ApiHttpConfig::Detailed(ApiHttpDetailedConfig {
                listen: addr.to_string(),
                ssl: None,
                auth,
            })),
        };
        ApiHub::from_config(&config)
            .expect("api hub config should be valid")
            .expect("api hub should be enabled")
    }

    async fn start_test_api_hub(hub: &Arc<ApiHub>) {
        hub.start().await.expect("api hub should start");
        sleep(Duration::from_millis(50)).await;
    }

    fn http1_client() -> Client<HttpConnector, Empty<Bytes>> {
        Client::builder(TokioExecutor::new()).build_http()
    }

    fn http2_client() -> Client<HttpConnector, Empty<Bytes>> {
        Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http()
    }

    #[test]
    fn test_build_plugin_route_path() {
        let route = build_plugin_route_path("cache_main", "/flush").expect("route should be built");
        assert_eq!(route, "/plugins/cache_main/flush");
    }

    #[test]
    fn test_build_plugin_route_path_without_subpath() {
        let route = build_plugin_route_path("reverse_lookup", "").expect("route should be built");
        assert_eq!(route, "/plugins/reverse_lookup");
    }

    #[test]
    fn test_basic_auth_matches_expected_credentials() {
        let auth = ApiAuthConfig::Basic {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            http::HeaderValue::from_static("Basic YWRtaW46c2VjcmV0"),
        );
        assert!(is_authorized(&headers, Some(&auth)));
    }

    #[test]
    fn test_json_response_sets_content_type_and_body() {
        #[derive(Serialize)]
        struct Payload {
            ok: bool,
            count: u32,
        }

        let response = json_response(StatusCode::OK, &Payload { ok: true, count: 2 });

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.body(),
            &Bytes::from_static(br#"{"ok":true,"count":2}"#)
        );
    }

    #[test]
    fn test_json_error_sets_content_type_and_body() {
        let response = json_error(StatusCode::BAD_REQUEST, "bad_request", "missing field");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.body(),
            &Bytes::from_static(br#"{"ok":false,"code":"bad_request","message":"missing field"}"#)
        );
    }

    #[test]
    fn test_register_helper_methods_register_without_error() {
        let addr = reserve_local_addr();
        let hub = test_api_hub(addr, None);
        let register = ApiRegister::new(hub);

        register
            .register_get("/helper", Arc::new(TestEchoHandler))
            .expect("register GET");
        register
            .register_post("/helper-post", Arc::new(TestEchoHandler))
            .expect("register POST");
        register
            .register_plugin_get("cache_main", "/stats", Arc::new(TestEchoHandler))
            .expect("register plugin GET");
        register
            .register_plugin_post("cache_main", "/reload", Arc::new(TestEchoHandler))
            .expect("register plugin POST");
    }

    #[tokio::test]
    async fn test_hyper_http1_serves_auth_and_plugin_route() {
        let addr = reserve_local_addr();
        let hub = test_api_hub(
            addr,
            Some(ApiAuthConfig::Basic {
                username: "admin".to_string(),
                password: "secret".to_string(),
            }),
        );
        let register = ApiRegister::new(hub.clone());
        register
            .register_plugin_post("test_plugin", "/echo", Arc::new(TestEchoHandler))
            .expect("register plugin route");

        start_test_api_hub(&hub).await;

        let client = http1_client();
        let uri: Uri = format!("http://{addr}/plugins/test_plugin/echo")
            .parse()
            .expect("request uri");

        let unauthorized = client
            .request(
                HyperRequest::builder()
                    .method(Method::POST)
                    .uri(uri.clone())
                    .body(Empty::new())
                    .expect("request"),
            )
            .await
            .expect("unauthorized response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let auth_header = format!("Basic {}", STANDARD.encode("admin:secret"));
        let authorized = client
            .request(
                HyperRequest::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header(AUTHORIZATION, auth_header)
                    .body(Empty::new())
                    .expect("authorized request"),
            )
            .await
            .expect("authorized response");

        assert_eq!(authorized.version(), Version::HTTP_11);
        assert_eq!(authorized.status(), StatusCode::OK);
        assert_eq!(
            authorized.headers().get(CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/json"))
        );
        let body = authorized
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("utf8 body");
        assert!(body.contains("\"method\":\"POST\""));
        assert!(body.contains("\"path\":\"/plugins/test_plugin/echo\""));

        hub.stop().await;
    }

    #[tokio::test]
    async fn test_hyper_http2_serves_builtin_health_route() {
        let addr = reserve_local_addr();
        let hub = test_api_hub(addr, None);

        start_test_api_hub(&hub).await;

        let client = http2_client();
        let uri: Uri = format!("http://{addr}/healthz")
            .parse()
            .expect("request uri");
        let response = client
            .request(
                HyperRequest::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Empty::new())
                    .expect("request"),
            )
            .await
            .expect("health response");

        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(body, Bytes::from_static(b"ok"));

        hub.stop().await;
    }
}
