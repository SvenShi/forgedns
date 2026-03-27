/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Built-in application health endpoints for the management API.

use crate::api::{ApiHandler, ApiRegister, json_ok, simple_response};
use crate::core::VERSION;
use crate::core::app_clock::AppClock;
use crate::core::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug)]
pub struct HealthState {
    started_at_ms: u64,
    api_listening: AtomicBool,
    plugins_initialized: AtomicBool,
    server_startup_complete: AtomicBool,
    total_plugins: AtomicUsize,
    server_plugins: AtomicUsize,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            started_at_ms: AppClock::elapsed_millis(),
            api_listening: AtomicBool::new(false),
            plugins_initialized: AtomicBool::new(false),
            server_startup_complete: AtomicBool::new(false),
            total_plugins: AtomicUsize::new(0),
            server_plugins: AtomicUsize::new(0),
        }
    }

    pub fn mark_api_listening(&self) {
        self.api_listening.store(true, Ordering::Relaxed);
    }

    pub fn mark_plugins_initialized(&self, total_plugins: usize, server_plugins: usize) {
        self.total_plugins.store(total_plugins, Ordering::Relaxed);
        self.server_plugins.store(server_plugins, Ordering::Relaxed);
        self.plugins_initialized.store(true, Ordering::Relaxed);
        self.server_startup_complete
            .store(server_plugins > 0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HealthSnapshot {
        let api_listening = self.api_listening.load(Ordering::Relaxed);
        let plugins_initialized = self.plugins_initialized.load(Ordering::Relaxed);
        let server_startup_complete = self.server_startup_complete.load(Ordering::Relaxed);
        HealthSnapshot {
            status: if api_listening && plugins_initialized && server_startup_complete {
                "ok"
            } else {
                "not_ready"
            },
            version: VERSION,
            uptime_ms: AppClock::elapsed_millis().saturating_sub(self.started_at_ms),
            checks: HealthChecks {
                api: bool_status(api_listening),
                plugin_init: bool_status(plugins_initialized),
                server_startup: bool_status(server_startup_complete),
            },
            plugins: HealthPluginCounts {
                total: self.total_plugins.load(Ordering::Relaxed),
                servers: self.server_plugins.load(Ordering::Relaxed),
            },
        }
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
struct HealthSnapshot {
    status: &'static str,
    version: &'static str,
    uptime_ms: u64,
    checks: HealthChecks,
    plugins: HealthPluginCounts,
}

#[derive(Debug, Serialize)]
struct HealthChecks {
    api: &'static str,
    plugin_init: &'static str,
    server_startup: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthPluginCounts {
    total: usize,
    servers: usize,
}

#[derive(Debug)]
struct HealthzHandler {
    health: Arc<HealthState>,
}

#[async_trait]
impl ApiHandler for HealthzHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        if self.health.api_listening.load(Ordering::Relaxed) {
            simple_response(StatusCode::OK, Bytes::from("ok"))
        } else {
            simple_response(
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from("not_listening"),
            )
        }
    }
}

#[derive(Debug)]
struct ReadyzHandler {
    health: Arc<HealthState>,
}

#[async_trait]
impl ApiHandler for ReadyzHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        let snapshot = self.health.snapshot();
        if snapshot.checks.plugin_init == "ok" && snapshot.checks.server_startup == "ok" {
            simple_response(StatusCode::OK, Bytes::from("ready"))
        } else {
            simple_response(StatusCode::SERVICE_UNAVAILABLE, Bytes::from("not_ready"))
        }
    }
}

#[derive(Debug)]
struct HealthHandler {
    health: Arc<HealthState>,
}

#[async_trait]
impl ApiHandler for HealthHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        let snapshot = self.health.snapshot();
        let status =
            if snapshot.checks.plugin_init == "ok" && snapshot.checks.server_startup == "ok" {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
        json_ok(status, &snapshot)
    }
}

fn bool_status(value: bool) -> &'static str {
    if value { "ok" } else { "not_ready" }
}

pub fn register_builtin_routes(register: &ApiRegister, health: Arc<HealthState>) -> Result<()> {
    register.register_get(
        "/healthz",
        Arc::new(HealthzHandler {
            health: health.clone(),
        }),
    )?;
    register.register_get(
        "/readyz",
        Arc::new(ReadyzHandler {
            health: health.clone(),
        }),
    )?;
    register.register_get("/health", Arc::new(HealthHandler { health }))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn test_request(path: &str) -> Request<Bytes> {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Bytes::new())
            .expect("request should build");
        request.extensions_mut().insert(
            "127.0.0.1:12345"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr"),
        );
        request
    }

    #[tokio::test]
    async fn test_healthz_readyz_and_health_follow_state() {
        let health = Arc::new(HealthState::new());
        let healthz = HealthzHandler {
            health: health.clone(),
        };
        let readyz = ReadyzHandler {
            health: health.clone(),
        };
        let details = HealthHandler {
            health: health.clone(),
        };

        let response = healthz.handle(test_request("/healthz")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        health.mark_api_listening();
        let response = healthz.handle(test_request("/healthz")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &Bytes::from_static(b"ok"));

        let response = readyz.handle(test_request("/readyz")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        health.mark_plugins_initialized(4, 1);
        let response = readyz.handle(test_request("/readyz")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &Bytes::from_static(b"ready"));

        let response = details.handle(test_request("/health")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = std::str::from_utf8(response.body()).expect("utf8 json");
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains(&format!("\"version\":\"{}\"", VERSION)));
        assert!(body.contains("\"api\":\"ok\""));
        assert!(body.contains("\"plugin_init\":\"ok\""));
        assert!(body.contains("\"server_startup\":\"ok\""));
        assert!(body.contains("\"total\":4"));
        assert!(body.contains("\"servers\":1"));
    }
}
