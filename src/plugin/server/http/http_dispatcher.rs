/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! HTTP Dispatcher - Routes requests based on method and path
//!
//! Supports DNS over HTTPS (DoH) RFC 8484 standard:
//! - GET method: DNS query passed via URL parameter (base64url encoded)
//! - POST method: DNS query passed in request body (binary format)

use crate::plugin::server::RequestHandle;
use ahash::AHashMap;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
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
    routes: AHashMap<(Method, String), Box<dyn HttpHandler>>,
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
    pub fn register_route(&mut self, method: Method, path: String, handler: Box<dyn HttpHandler>) {
        debug!("Registering route: {} {}", method, path);
        self.routes.insert((method, path), handler);
    }

    /// Handle an HTTP request
    ///
    /// Dispatches the request to the appropriate handler based on method and path.
    /// Returns a 404 response if no matching route is found.
    pub async fn handle_request(
        &self,
        method: Method,
        path: String,
        query: Option<String>,
        body: Bytes,
        src_addr: SocketAddr,
    ) -> Response<Bytes> {
        debug!("Received request: {} {} from {}", method, path, src_addr);

        // Look up the matching route
        if let Some(handler) = self.routes.get(&(method.clone(), path.clone())) {
            handler.handle(method, path, query, body, src_addr).await
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
        path: String,
        query: Option<String>,
        body: Bytes,
        src_addr: SocketAddr,
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
                    Ok(dns_bytes) => {
                        // Parse DNS message
                        match Message::from_bytes(&dns_bytes) {
                            Ok(msg) => {
                                debug!("Successfully parsed GET DNS query, ID: {}", msg.id());
                                Some(msg)
                            }
                            Err(e) => {
                                warn!("Failed to parse DNS message: {}", e);
                                None
                            }
                        }
                    }
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
        _path: String,
        query: Option<String>,
        _body: Bytes,
        src_addr: SocketAddr,
    ) -> Response<Bytes> {
        // Parse DNS query from URL parameters
        let dns_query = match self.parse_dns_query(query.as_deref()) {
            Some(msg) => msg,
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
            .handle_request(dns_query, src_addr)
            .await;
        msg_to_response(dns_result.response)
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
        _path: String,
        _query: Option<String>,
        body: Bytes,
        src_addr: SocketAddr,
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
            .handle_request(dns_query, src_addr)
            .await;
        msg_to_response(dns_result.response)
    }
}

#[inline]
fn msg_to_response(dns_response: Message) -> Response<Bytes> {
    // Serialize DNS response to binary format
    match dns_response.to_bytes() {
        Ok(response_bytes) => {
            debug!("DNS response size: {} bytes", response_bytes.len());
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/dns-message")
                .header("Cache-Control", "max-age=300")
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
