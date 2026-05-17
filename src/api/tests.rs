use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::{Request as HyperRequest, Version};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use tokio::time::{Duration, sleep};

use super::cors::{add_cors_headers, infer_cors_config_from_listen, resolve_cors_config};
use super::static_files::match_static_path;
use super::*;
use crate::config::types::{
    ApiAuthConfig, ApiConfig, ApiCorsConfig, ApiHttpConfig, ApiHttpDetailedConfig, ApiWebUiConfig,
};
use crate::core::app_clock::AppClock;
use crate::{register_api_route, register_plugin_api};

#[derive(Debug)]
struct TestEchoHandler;

#[async_trait]
impl ApiHandler for TestEchoHandler {
    async fn handle(&self, request: Request<Bytes>) -> ApiResponse {
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
    test_api_hub_with_cors(addr, auth, None)
}

fn test_api_hub_with_cors(
    addr: SocketAddr,
    auth: Option<ApiAuthConfig>,
    cors: Option<ApiCorsConfig>,
) -> Arc<ApiHub> {
    test_api_hub_with_options(addr, auth, cors, None)
}

fn test_api_hub_with_webui(
    addr: SocketAddr,
    auth: Option<ApiAuthConfig>,
    webui: ApiWebUiConfig,
) -> Arc<ApiHub> {
    test_api_hub_with_options(addr, auth, None, Some(webui))
}

fn test_api_hub_with_options(
    addr: SocketAddr,
    auth: Option<ApiAuthConfig>,
    cors: Option<ApiCorsConfig>,
    webui: Option<ApiWebUiConfig>,
) -> Arc<ApiHub> {
    let config = ApiConfig {
        http: Some(ApiHttpConfig::Detailed(Box::new(ApiHttpDetailedConfig {
            listen: addr.to_string(),
            ssl: None,
            auth,
            cors,
            webui,
        }))),
    };
    let hub = ApiHub::from_config(&config)
        .expect("api hub config should be valid")
        .expect("api hub should be enabled");
    let register = ApiRegister::new(hub.clone());
    health::register_builtin_routes(&register, hub.health_state())
        .expect("health routes should register");
    metrics::register_builtin_routes(&register).expect("metrics routes should register");
    hub
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
fn test_cors_headers_echo_allowed_request_origin_and_delete_method() {
    let cors = ApiCorsConfig {
        allowed_origins: vec![
            "http://localhost:3000".to_string(),
            "http://192.168.1.100:3000".to_string(),
        ],
        ..Default::default()
    };
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://192.168.1.100:3000"),
    );
    let mut response_headers = HeaderMap::new();

    add_cors_headers(&mut response_headers, Some(&request_headers), &cors);

    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("http://192.168.1.100:3000"))
    );
    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_METHODS),
        Some(&http::HeaderValue::from_static(
            "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        ))
    );
    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        Some(&http::HeaderValue::from_static("true"))
    );
}

#[test]
fn test_inferred_cors_for_unspecified_listen_allows_any_origin() {
    let cors = infer_cors_config_from_listen("0.0.0.0:8080".parse().expect("listen addr"));
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://example.test:5173"),
    );
    let mut response_headers = HeaderMap::new();

    add_cors_headers(&mut response_headers, Some(&request_headers), &cors);

    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("*"))
    );
    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        None
    );

    let ipv6_cors = infer_cors_config_from_listen("[::]:8080".parse().expect("listen addr"));
    let mut ipv6_response_headers = HeaderMap::new();
    add_cors_headers(
        &mut ipv6_response_headers,
        Some(&request_headers),
        &ipv6_cors,
    );
    assert_eq!(
        ipv6_response_headers.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("*"))
    );
}

#[test]
fn test_inferred_cors_for_specific_listen_matches_host_without_port_limit() {
    let cors = infer_cors_config_from_listen("192.168.1.10:8080".parse().expect("listen addr"));
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://192.168.1.10:5173"),
    );
    let mut response_headers = HeaderMap::new();

    add_cors_headers(&mut response_headers, Some(&request_headers), &cors);

    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("http://192.168.1.10:5173"))
    );
}

#[test]
fn test_inferred_cors_for_specific_listen_rejects_other_hosts() {
    let cors = infer_cors_config_from_listen("192.168.1.10:8080".parse().expect("listen addr"));
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://192.168.1.11:5173"),
    );
    let mut response_headers = HeaderMap::new();

    add_cors_headers(&mut response_headers, Some(&request_headers), &cors);

    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        None
    );
}

#[test]
fn test_empty_configured_cors_falls_back_to_listen_inference() {
    let cors = resolve_cors_config(
        Some(ApiCorsConfig::default()),
        "0.0.0.0:8080".parse().expect("listen addr"),
    );
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        http::header::ORIGIN,
        http::HeaderValue::from_static("http://localhost:3000"),
    );
    let mut response_headers = HeaderMap::new();

    add_cors_headers(&mut response_headers, Some(&request_headers), &cors);

    assert_eq!(
        response_headers.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("*"))
    );
}

#[tokio::test]
async fn test_json_response_sets_content_type_and_body() {
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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(br#"{"ok":true,"count":2}"#));
}

#[tokio::test]
async fn test_json_error_sets_content_type_and_body() {
    let response = json_error(StatusCode::BAD_REQUEST, "bad_request", "missing field");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/json"))
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        body,
        Bytes::from_static(br#"{"ok":false,"code":"bad_request","message":"missing field"}"#)
    );
}

#[test]
fn test_api_prefix_helpers_strip_and_rewrite_path() {
    assert_eq!(strip_api_prefix("/api").as_deref(), Some("/"));
    assert_eq!(strip_api_prefix("/api/health").as_deref(), Some("/health"));
    assert_eq!(strip_api_prefix("/health"), None);

    let request = Request::builder()
        .uri("/api/plugins/cache/entries?limit=10")
        .body(Bytes::new())
        .expect("request");
    let request = rewrite_request_path(request, "/plugins/cache/entries").expect("rewrite uri");
    assert_eq!(request.uri().path(), "/plugins/cache/entries");
    assert_eq!(request.uri().query(), Some("limit=10"));
}

#[test]
fn test_static_path_rejects_traversal() {
    assert!(match_static_path("/assets/app.js").is_some());
    assert!(match_static_path("/../secret").is_none());
    assert!(match_static_path("/%2e%2e/secret").is_none());
    assert!(match_static_path("/%zz").is_none());
}

#[test]
fn test_register_helper_methods_register_without_error() {
    AppClock::start();
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
    register
        .register_plugin_delete("cache_main", "/entries/abc", Arc::new(TestEchoHandler))
        .expect("register plugin DELETE");

    let plugin_api = register.plugin("query_recorder").expect("plugin registrar");
    assert_eq!(
        plugin_api.path("/records/").expect("plugin path"),
        "/plugins/query_recorder/records/"
    );
    plugin_api
        .get("/records", Arc::new(TestEchoHandler))
        .expect("register scoped GET");
    plugin_api
        .delete_prefix("/records/", Arc::new(TestEchoHandler))
        .expect("register scoped DELETE prefix");
}

#[tokio::test]
async fn test_global_api_route_macros_noop_when_api_is_disabled() {
    let _guard = global_api_test_guard().await;
    clear_global_api();

    register_api_route!(GET "/macro-noop" => TestEchoHandler).expect("global route no-op");
    register_plugin_api!(
        "macro_plugin",
        GET "/noop" => TestEchoHandler,
        DELETE_PREFIX "/noop/" => TestEchoHandler,
    )
    .expect("plugin route no-op");
}

#[tokio::test]
async fn test_global_api_route_macros_register_routes_and_clear() {
    let _guard = global_api_test_guard().await;
    clear_global_api();
    AppClock::start();
    let addr = reserve_local_addr();
    let hub = test_api_hub(addr, None);
    install_global_api(hub.clone());

    register_api_route!(GET "/macro-global" => TestEchoHandler).expect("register global route");
    register_plugin_api!(
        "macro_plugin",
        |plugin_api|
        GET "/records" => TestEchoHandler,
        DELETE_PREFIX "/records/" => TestEchoHandler,
        POST "/uses-path" => TestEchoHandler,
    )
    .expect("register plugin routes");
    assert_eq!(
        global_api_register()
            .expect("global register should be set")
            .plugin("macro_plugin")
            .and_then(|api| api.path("/records/"))
            .expect("plugin path"),
        "/plugins/macro_plugin/records/"
    );

    start_test_api_hub(&hub).await;
    let client = http1_client();
    let delete_uri: Uri = format!("http://{addr}/api/plugins/macro_plugin/records/abc")
        .parse()
        .expect("delete uri");
    let response = client
        .request(
            HyperRequest::builder()
                .method(Method::DELETE)
                .uri(delete_uri)
                .body(Empty::new())
                .expect("delete request"),
        )
        .await
        .expect("delete response");
    assert_eq!(response.status(), StatusCode::OK);

    clear_global_api();
    assert!(global_api_register().is_none());
    hub.stop().await;
}

#[tokio::test]
async fn test_hyper_http1_serves_auth_and_plugin_route() {
    AppClock::start();
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
    let uri: Uri = format!("http://{addr}/api/plugins/test_plugin/echo")
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
async fn test_hyper_response_uses_request_origin_for_cors() {
    AppClock::start();
    let addr = reserve_local_addr();
    let hub = test_api_hub_with_cors(
        addr,
        None,
        Some(ApiCorsConfig {
            allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://192.168.1.100:3000".to_string(),
            ],
            ..Default::default()
        }),
    );

    start_test_api_hub(&hub).await;

    let client = http1_client();
    let uri: Uri = format!("http://{addr}/api/healthz")
        .parse()
        .expect("request uri");
    let response = client
        .request(
            HyperRequest::builder()
                .method(Method::GET)
                .uri(uri)
                .header(http::header::ORIGIN, "http://192.168.1.100:3000")
                .body(Empty::new())
                .expect("request"),
        )
        .await
        .expect("health response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("http://192.168.1.100:3000"))
    );

    let preflight_uri: Uri = format!("http://{addr}/api/health")
        .parse()
        .expect("request uri");
    let preflight = client
        .request(
            HyperRequest::builder()
                .method(Method::OPTIONS)
                .uri(preflight_uri)
                .header(http::header::ORIGIN, "http://192.168.1.100:3000")
                .body(Empty::new())
                .expect("request"),
        )
        .await
        .expect("preflight response");
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        preflight
            .headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&http::HeaderValue::from_static("http://192.168.1.100:3000"))
    );

    hub.stop().await;
}

#[tokio::test]
async fn test_hyper_old_unprefixed_api_route_is_not_registered() {
    AppClock::start();
    let addr = reserve_local_addr();
    let hub = test_api_hub(addr, None);

    start_test_api_hub(&hub).await;

    let client = http1_client();
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    hub.stop().await;
}

#[tokio::test]
async fn test_hyper_serves_webui_static_files_and_spa_fallback() {
    AppClock::start();
    let temp = tempfile::tempdir().expect("temp webui dir");
    fs::write(temp.path().join("index.html"), "<html>oxidns</html>").expect("write index");
    fs::create_dir_all(temp.path().join("assets")).expect("create assets");
    fs::write(temp.path().join("assets/app.js"), "console.log('ok');").expect("write asset");

    let addr = reserve_local_addr();
    let hub = test_api_hub_with_webui(
        addr,
        Some(ApiAuthConfig::Basic {
            username: "admin".to_string(),
            password: "secret".to_string(),
        }),
        ApiWebUiConfig {
            root: temp.path().display().to_string(),
            index: None,
        },
    );

    start_test_api_hub(&hub).await;

    let client = http1_client();
    let index_uri: Uri = format!("http://{addr}/").parse().expect("index uri");
    let index = client
        .request(
            HyperRequest::builder()
                .method(Method::GET)
                .uri(index_uri)
                .body(Empty::new())
                .expect("request"),
        )
        .await
        .expect("index response");
    assert_eq!(index.status(), StatusCode::OK);
    assert_eq!(
        index.headers().get(http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/html; charset=utf-8"))
    );
    assert_eq!(
        index.headers().get(http::header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-cache"))
    );
    let body = index
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"<html>oxidns</html>"));

    let asset_uri: Uri = format!("http://{addr}/assets/app.js")
        .parse()
        .expect("asset uri");
    let asset = client
        .request(
            HyperRequest::builder()
                .method(Method::GET)
                .uri(asset_uri)
                .body(Empty::new())
                .expect("request"),
        )
        .await
        .expect("asset response");
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        asset.headers().get(http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/javascript; charset=utf-8"))
    );

    let fallback_uri: Uri = format!("http://{addr}/settings")
        .parse()
        .expect("fallback uri");
    let fallback = client
        .request(
            HyperRequest::builder()
                .method(Method::GET)
                .uri(fallback_uri)
                .body(Empty::new())
                .expect("request"),
        )
        .await
        .expect("fallback response");
    assert_eq!(fallback.status(), StatusCode::OK);

    let api_unknown_uri: Uri = format!("http://{addr}/api/unknown")
        .parse()
        .expect("api unknown uri");
    let api_unknown = client
        .request(
            HyperRequest::builder()
                .method(Method::GET)
                .uri(api_unknown_uri)
                .header(
                    AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode("admin:secret")),
                )
                .body(Empty::new())
                .expect("request"),
        )
        .await
        .expect("api unknown response");
    assert_eq!(api_unknown.status(), StatusCode::NOT_FOUND);

    hub.stop().await;
}

#[tokio::test]
async fn test_hyper_http2_serves_builtin_health_route() {
    AppClock::start();
    let addr = reserve_local_addr();
    let hub = test_api_hub(addr, None);

    start_test_api_hub(&hub).await;

    let client = http2_client();
    let uri: Uri = format!("http://{addr}/api/healthz")
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

#[tokio::test]
async fn test_hyper_serves_builtin_metrics_route() {
    AppClock::start();
    let addr = reserve_local_addr();
    let hub = test_api_hub(addr, None);

    start_test_api_hub(&hub).await;

    let client = http1_client();
    let uri: Uri = format!("http://{addr}/api/metrics")
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
        .expect("metrics response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&http::HeaderValue::from_static(
            "text/plain; version=0.0.4; charset=utf-8"
        ))
    );

    hub.stop().await;
}
