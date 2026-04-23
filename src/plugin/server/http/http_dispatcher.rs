/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! HTTP Dispatcher - Routes requests based on method and path
//!
//! Supports DNS over HTTPS (DoH) RFC 8484 standard:
//! - GET method: DNS query passed via URL parameter (base64url encoded)
//! - POST method: DNS query passed in request body (binary format)

use crate::plugin::server::{RequestHandle, RequestMeta};
use crate::proto::{Message, Rcode};
use ahash::AHashMap;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Method, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, warn};

/// HTTP Dispatcher - Manages routes and handlers
///
/// The dispatcher maintains a map of (Method, Path) -> Handler and routes
/// incoming HTTP requests to the appropriate handler based on the request
/// method and path.
pub struct HttpDispatcher {
    routes: AHashMap<(Method, Arc<str>), Box<dyn HttpHandler>>,
}

impl HttpDispatcher {
    /// Create a new HTTP dispatcher
    pub fn new() -> Self {
        Self {
            routes: AHashMap::new(),
        }
    }

    /// Register a route handler
    ///
    /// Associates a specific HTTP method and path with a handler that will
    /// process requests matching that route.
    pub fn register_route(
        &mut self,
        method: Method,
        path: Arc<str>,
        handler: Box<dyn HttpHandler>,
    ) {
        self.routes.insert((method, path), handler);
    }

    /// Handle an HTTP request
    ///
    /// Dispatches the request to the appropriate handler based on method and path.
    /// Returns a 404 response if no matching route is found.
    #[hotpath::measure]
    pub async fn handle_request(
        &self,
        method: Method,
        path: Arc<str>,
        query: Option<Arc<str>>,
        body: Bytes,
        src_addr: SocketAddr,
        server_name: Option<Arc<str>>,
    ) -> Response<Bytes> {
        debug!("Received request: {} {} from {}", method, path, src_addr);

        // Look up the matching route
        if let Some(handler) = self.routes.get(&(method.clone(), path.clone())) {
            handler
                .handle(method, path, query, body, src_addr, server_name)
                .await
        } else {
            // Return 404 Not Found for unmatched routes
            warn!("Route not found: {} {}", method, path);
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "text/plain")
                .body(Bytes::from("404 Not Found"))
                .expect("Failed to build 404 response")
        }
    }
}

impl Default for HttpDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP Handler trait
///
/// Defines the interface for handling HTTP requests. Implementations should
/// process the request and return an appropriate HTTP response.
#[async_trait]
pub trait HttpHandler: Send + Sync + 'static {
    /// Handle an HTTP request and return a response
    ///
    /// # Parameters
    /// - `method`: HTTP method (GET, POST, etc.)
    /// - `path`: Request path
    /// - `query`: Optional query string
    /// - `body`: Request body as bytes
    /// - `src_addr`: Source address of the client (maybe real client IP from headers)
    async fn handle(
        &self,
        method: Method,
        path: Arc<str>,
        query: Option<Arc<str>>,
        body: Bytes,
        src_addr: SocketAddr,
        server_name: Option<Arc<str>>,
    ) -> Response<Bytes>;
}

/// DNS over HTTPS GET request handler
///
/// RFC 8484: DNS query is passed via URL parameter ?dns=<base64url>
/// Example: /dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
pub struct DnsGetHandler {
    request_handle: Arc<RequestHandle>,
}

impl DnsGetHandler {
    pub fn new(request_handle: Arc<RequestHandle>) -> Self {
        Self { request_handle }
    }

    /// Parse DNS message from URL query parameters
    ///
    /// Looks for the "dns" parameter containing a base64url-encoded DNS query.
    /// Returns None if the parameter is missing or cannot be decoded.
    fn parse_dns_query(&self, query: Option<&str>) -> Option<Message> {
        let query = query?;

        // Parse query parameters: ?dns=<base64url>
        for param in query.split('&') {
            if let Some(value) = param.strip_prefix("dns=") {
                // Decode base64url
                return match URL_SAFE_NO_PAD.decode(value) {
                    Ok(dns_bytes) => match Message::from_bytes(&dns_bytes) {
                        Ok(msg) => {
                            debug!("Successfully parsed GET DNS query, ID: {}", msg.id());
                            Some(msg)
                        }
                        Err(e) => {
                            warn!("Failed to parse DNS message: {}", e);
                            None
                        }
                    },
                    Err(e) => {
                        warn!("Failed to decode base64: {}", e);
                        None
                    }
                };
            }
        }

        warn!("DNS parameter not found in query string");
        None
    }
}

#[async_trait]
impl HttpHandler for DnsGetHandler {
    async fn handle(
        &self,
        _method: Method,
        path: Arc<str>,
        query: Option<Arc<str>>,
        _body: Bytes,
        src_addr: SocketAddr,
        server_name: Option<Arc<str>>,
    ) -> Response<Bytes> {
        // Parse DNS query from URL parameters
        let dns_query = match self.parse_dns_query(query.as_deref()) {
            Some(parsed) => parsed,
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "text/plain")
                    .body(Bytes::from("400 Bad Request: Invalid DNS query"))
                    .expect("Failed to build error response");
            }
        };

        // Process DNS query through the executor
        let dns_result = self
            .request_handle
            .handle_request(
                dns_query,
                src_addr,
                RequestMeta {
                    server_name,
                    url_path: Some(path),
                },
            )
            .await;
        msg_response(dns_result.response)
    }
}

/// DNS over HTTPS POST request handler
///
/// RFC 8484: DNS query is passed in request body as binary format
/// The request body should be the raw DNS message bytes.
pub struct DnsPostHandler {
    request_handle: Arc<RequestHandle>,
}

impl DnsPostHandler {
    pub fn new(request_handle: Arc<RequestHandle>) -> Self {
        Self { request_handle }
    }
}

#[async_trait]
impl HttpHandler for DnsPostHandler {
    async fn handle(
        &self,
        _method: Method,
        path: Arc<str>,
        _query: Option<Arc<str>>,
        body: Bytes,
        src_addr: SocketAddr,
        server_name: Option<Arc<str>>,
    ) -> Response<Bytes> {
        // Limit request size (RFC 8484 recommends maximum 65535 bytes)
        // This prevents memory exhaustion attacks
        const MAX_DNS_MESSAGE_SIZE: usize = 65535;
        if body.len() > MAX_DNS_MESSAGE_SIZE {
            warn!(
                "DNS message too large: {} bytes from {}",
                body.len(),
                src_addr
            );
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("Content-Type", "text/plain")
                .body(Bytes::from("413 Payload Too Large"))
                .expect("Failed to build error response");
        }

        // Parse DNS query from binary body
        let dns_query = match Message::from_bytes(&body) {
            Ok(msg) => {
                debug!(
                    "Successfully parsed POST DNS query, ID: {}, size: {} bytes",
                    msg.id(),
                    body.len()
                );
                msg
            }
            Err(e) => {
                warn!("Failed to parse DNS message: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "text/plain")
                    .body(Bytes::from("400 Bad Request: Invalid DNS message"))
                    .expect("Failed to build error response");
            }
        };

        // Process DNS query through the executor
        let dns_result = self
            .request_handle
            .handle_request(
                dns_query,
                src_addr,
                RequestMeta {
                    server_name,
                    url_path: Some(path),
                },
            )
            .await;
        msg_response(dns_result.response)
    }
}

#[inline]
fn msg_response(dns_response: Message) -> Response<Bytes> {
    // Serialize DNS response to binary format
    match dns_response.to_bytes() {
        Ok(response_bytes) => {
            let size = response_bytes.len();
            debug!("DNS response size: {} bytes", size);
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/dns-message")
                .header("Content-Length", size.to_string());

            if let Some(ttl) = http_cache_ttl(&dns_response) {
                builder = builder.header("Cache-Control", format!("max-age={ttl}"));
            }

            builder
                .body(Bytes::from(response_bytes))
                .expect("Failed to build DNS response")
        }
        Err(e) => {
            warn!("Failed to serialize DNS response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "text/plain")
                .body(Bytes::from("500 Internal Server Error"))
                .expect("Failed to build error response")
        }
    }
}

#[inline]
fn http_cache_ttl(response: &Message) -> Option<u32> {
    match response.rcode() {
        Rcode::NoError => response
            .min_answer_ttl()
            .filter(|ttl| *ttl > 0)
            .or_else(|| {
                if response.answers().is_empty() {
                    response.negative_ttl_from_soa().filter(|ttl| *ttl > 0)
                } else {
                    None
                }
            }),
        Rcode::NXDomain => response.negative_ttl_from_soa().filter(|ttl| *ttl > 0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::core::error::Result;
    use crate::plugin::Plugin;
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{Name, RecordType};
    use crate::proto::{Question, Rcode};
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedRequest {
        query_name: String,
        query_id: u16,
        server_name: Option<String>,
        url_path: Option<String>,
    }

    #[derive(Debug)]
    struct RecordingExecutor {
        observed: Arc<Mutex<Option<ObservedRequest>>>,
        response_code: Rcode,
    }

    #[async_trait]
    impl Plugin for RecordingExecutor {
        fn tag(&self) -> &str {
            "recording_executor"
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for RecordingExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            let query_name = context
                .request
                .first_question()
                .expect("request should contain one query")
                .name()
                .normalized()
                .to_string();
            let observed = ObservedRequest {
                query_name,
                query_id: context.request.id(),
                server_name: context.server_name().map(str::to_string),
                url_path: context.url_path().map(str::to_string),
            };
            self.observed
                .lock()
                .expect("request observation lock should not be poisoned")
                .replace(observed);
            context.set_response(context.request.response(self.response_code));
            Ok(ExecStep::Next)
        }
    }

    fn make_request_handle(
        response_code: Rcode,
    ) -> (Arc<RequestHandle>, Arc<Mutex<Option<ObservedRequest>>>) {
        let observed = Arc::new(Mutex::new(None));
        let executor = Arc::new(RecordingExecutor {
            observed: observed.clone(),
            response_code,
        });
        (
            Arc::new(RequestHandle {
                entry_executor: executor,
                registry: test_registry(),
            }),
            observed,
        )
    }

    fn make_dns_query(id: u16, qname: &str) -> Message {
        let mut request = Message::new();
        request.set_id(id);
        request.add_question(Question::new(
            Name::from_ascii(qname).expect("query name should be valid"),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));
        request
    }

    fn encode_query(message: &Message) -> String {
        URL_SAFE_NO_PAD.encode(
            message
                .to_bytes()
                .expect("DNS query should serialize successfully"),
        )
    }

    fn decode_response(response: &Response<Bytes>) -> Message {
        Message::from_bytes(response.body()).expect("HTTP body should contain DNS wire format")
    }

    #[tokio::test]
    async fn test_handle_request_returns_not_found_for_unregistered_route() {
        let dispatcher = HttpDispatcher::new();

        let response = dispatcher
            .handle_request(
                Method::GET,
                Arc::from("/missing"),
                None,
                Bytes::new(),
                SocketAddr::from(([127, 0, 0, 1], 5400)),
                None,
            )
            .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.body().as_ref(), b"404 Not Found");
    }

    #[tokio::test]
    async fn test_dns_get_handler_returns_bad_request_when_dns_param_is_missing() {
        let (request_handle, observed) = make_request_handle(Rcode::NoError);
        let mut dispatcher = HttpDispatcher::new();
        dispatcher.register_route(
            Method::GET,
            Arc::from("/dns-query"),
            Box::new(DnsGetHandler::new(request_handle)),
        );

        let response = dispatcher
            .handle_request(
                Method::GET,
                Arc::from("/dns-query"),
                Some(Arc::from("foo=bar")),
                Bytes::new(),
                SocketAddr::from(([127, 0, 0, 1], 5401)),
                Some(Arc::from("dns.example.test")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.body().as_ref(),
            b"400 Bad Request: Invalid DNS query"
        );
        assert!(
            observed
                .lock()
                .expect("request observation lock should not be poisoned")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_dns_get_handler_processes_valid_query_and_forwards_meta() {
        let (request_handle, observed) = make_request_handle(Rcode::Refused);
        let mut dispatcher = HttpDispatcher::new();
        dispatcher.register_route(
            Method::GET,
            Arc::from("/dns-query"),
            Box::new(DnsGetHandler::new(request_handle)),
        );
        let query = make_dns_query(31, "www.example.test.");
        let encoded_query = encode_query(&query);

        let response = dispatcher
            .handle_request(
                Method::GET,
                Arc::from("/dns-query"),
                Some(Arc::from(format!("foo=bar&dns={encoded_query}"))),
                Bytes::new(),
                SocketAddr::from(([127, 0, 0, 1], 5402)),
                Some(Arc::from("dns.example.test")),
            )
            .await;

        let dns_response = decode_response(&response);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["Content-Type"],
            "application/dns-message"
        );
        assert_eq!(
            response.headers()["Content-Length"],
            dns_response
                .to_bytes()
                .expect("DNS response should serialize")
                .len()
                .to_string()
        );
        assert!(!response.headers().contains_key("Cache-Control"));
        assert_eq!(dns_response.id(), 31);
        assert_eq!(dns_response.rcode(), Rcode::Refused);
        assert_eq!(
            observed
                .lock()
                .expect("request observation lock should not be poisoned")
                .clone(),
            Some(ObservedRequest {
                query_name: "www.example.test".to_string(),
                query_id: 31,
                server_name: Some("dns.example.test".to_string()),
                url_path: Some("/dns-query".to_string()),
            })
        );
    }

    #[tokio::test]
    async fn test_dns_post_handler_returns_payload_too_large_for_oversized_body() {
        let (request_handle, observed) = make_request_handle(Rcode::NoError);
        let mut dispatcher = HttpDispatcher::new();
        dispatcher.register_route(
            Method::POST,
            Arc::from("/dns-query"),
            Box::new(DnsPostHandler::new(request_handle)),
        );

        let response = dispatcher
            .handle_request(
                Method::POST,
                Arc::from("/dns-query"),
                None,
                Bytes::from(vec![0u8; 65536]),
                SocketAddr::from(([127, 0, 0, 1], 5403)),
                Some(Arc::from("dns.example.test")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.body().as_ref(), b"413 Payload Too Large");
        assert!(
            observed
                .lock()
                .expect("request observation lock should not be poisoned")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_dns_post_handler_returns_bad_request_for_invalid_dns_body() {
        let (request_handle, observed) = make_request_handle(Rcode::NoError);
        let mut dispatcher = HttpDispatcher::new();
        dispatcher.register_route(
            Method::POST,
            Arc::from("/dns-query"),
            Box::new(DnsPostHandler::new(request_handle)),
        );

        let response = dispatcher
            .handle_request(
                Method::POST,
                Arc::from("/dns-query"),
                None,
                Bytes::from_static(b"not-a-dns-message"),
                SocketAddr::from(([127, 0, 0, 1], 5404)),
                Some(Arc::from("dns.example.test")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.body().as_ref(),
            b"400 Bad Request: Invalid DNS message"
        );
        assert!(
            observed
                .lock()
                .expect("request observation lock should not be poisoned")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_dns_post_handler_processes_valid_body_and_forwards_meta() {
        let (request_handle, observed) = make_request_handle(Rcode::NXDomain);
        let mut dispatcher = HttpDispatcher::new();
        dispatcher.register_route(
            Method::POST,
            Arc::from("/dns-query"),
            Box::new(DnsPostHandler::new(request_handle)),
        );
        let query = make_dns_query(41, "api.example.test.");
        let query_bytes = query
            .to_bytes()
            .expect("DNS query should serialize successfully");

        let response = dispatcher
            .handle_request(
                Method::POST,
                Arc::from("/dns-query"),
                None,
                Bytes::from(query_bytes),
                SocketAddr::from(([127, 0, 0, 1], 5405)),
                Some(Arc::from("dns.example.test")),
            )
            .await;

        let dns_response = decode_response(&response);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["Content-Length"],
            dns_response
                .to_bytes()
                .expect("DNS response should serialize")
                .len()
                .to_string()
        );
        assert!(!response.headers().contains_key("Cache-Control"));
        assert_eq!(dns_response.id(), 41);
        assert_eq!(dns_response.rcode(), Rcode::NXDomain);
        assert_eq!(
            observed
                .lock()
                .expect("request observation lock should not be poisoned")
                .clone(),
            Some(ObservedRequest {
                query_name: "api.example.test".to_string(),
                query_id: 41,
                server_name: Some("dns.example.test".to_string()),
                url_path: Some("/dns-query".to_string()),
            })
        );
    }

    #[test]
    fn test_http_cache_ttl_prefers_min_answer_ttl_for_positive_response() {
        let mut response = Message::new();
        response.set_message_type(crate::proto::MessageType::Response);
        response.set_rcode(Rcode::NoError);
        response.add_answer(crate::proto::Record::from_rdata(
            Name::from_ascii("example.com.").expect("name should parse"),
            120,
            crate::proto::RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(1, 1, 1, 1))),
        ));
        response.add_answer(crate::proto::Record::from_rdata(
            Name::from_ascii("example.com.").expect("name should parse"),
            30,
            crate::proto::RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(1, 0, 0, 1))),
        ));

        assert_eq!(http_cache_ttl(&response), Some(30));
    }

    #[test]
    fn test_http_cache_ttl_uses_soa_for_nxdomain() {
        let mut response = Message::new();
        response.set_message_type(crate::proto::MessageType::Response);
        response.set_rcode(Rcode::NXDomain);
        response.add_authority(crate::proto::Record::from_rdata(
            Name::from_ascii("example.com.").expect("name should parse"),
            180,
            crate::proto::RData::SOA(crate::proto::rdata::SOA::new(
                Name::from_ascii("ns1.example.com.").expect("mname should parse"),
                Name::from_ascii("hostmaster.example.com.").expect("rname should parse"),
                1,
                7200,
                1800,
                86400,
                60,
            )),
        ));

        assert_eq!(http_cache_ttl(&response), Some(60));
    }

    #[test]
    fn test_http_cache_ttl_uses_soa_for_nodata() {
        let mut response = Message::new();
        response.set_message_type(crate::proto::MessageType::Response);
        response.set_rcode(Rcode::NoError);
        response.add_authority(crate::proto::Record::from_rdata(
            Name::from_ascii("example.com.").expect("name should parse"),
            90,
            crate::proto::RData::SOA(crate::proto::rdata::SOA::new(
                Name::from_ascii("ns1.example.com.").expect("mname should parse"),
                Name::from_ascii("hostmaster.example.com.").expect("rname should parse"),
                1,
                7200,
                1800,
                86400,
                120,
            )),
        ));

        assert_eq!(http_cache_ttl(&response), Some(90));
    }

    #[test]
    fn test_http_cache_ttl_omits_header_when_no_safe_ttl_exists() {
        let mut response = Message::new();
        response.set_message_type(crate::proto::MessageType::Response);
        response.set_rcode(Rcode::NXDomain);

        assert_eq!(http_cache_ttl(&response), None);
    }
}
