// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Global Prometheus metrics API route.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode};

use crate::api::{ApiHandler, ApiRegister, simple_response};
use crate::core::error::Result;
use crate::core::metrics::render_prometheus_metrics;

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Debug)]
struct MetricsHandler;

#[async_trait]
impl ApiHandler for MetricsHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        let body = render_prometheus_metrics();
        let mut response = simple_response(StatusCode::OK, Bytes::from(body));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
        );
        response
    }
}

pub fn register_builtin_routes(register: &ApiRegister) -> Result<()> {
    register.register_get("/metrics", Arc::new(MetricsHandler))
}
