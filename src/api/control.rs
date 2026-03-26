/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Built-in application control endpoints for the management API.

use crate::api::{ApiHandler, ApiRegister, json_error, json_ok};
use crate::config;
use crate::config::types::Config;
use crate::core::app_clock::AppClock;
use crate::core::error::Result;
use crate::plugin;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCommand {
    Shutdown,
    Reload,
}

#[derive(Debug)]
pub struct AppController {
    started_at_ms: u64,
    config_path: PathBuf,
    state: Mutex<ControlState>,
    command_tx: mpsc::UnboundedSender<ControlCommand>,
}

#[derive(Debug, Default)]
struct ControlState {
    shutdown_requested: bool,
    reload_pending: bool,
    reload_in_progress: bool,
    last_reload_started_ms: Option<u64>,
    last_reload_completed_ms: Option<u64>,
    last_reload_success_ms: Option<u64>,
    last_reload_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlSnapshot {
    status: &'static str,
    uptime_ms: u64,
    config_path: String,
    shutdown_requested: bool,
    reload: ReloadSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReloadSnapshot {
    status: &'static str,
    pending: bool,
    in_progress: bool,
    last_started_ms: Option<u64>,
    last_completed_ms: Option<u64>,
    last_success_ms: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug)]
pub enum ControlRequestError {
    ReloadBusy,
    CommandChannelClosed,
}

impl Display for ControlRequestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReloadBusy => write!(f, "reload is already pending or in progress"),
            Self::CommandChannelClosed => write!(f, "control command channel is closed"),
        }
    }
}

impl AppController {
    pub fn new(config_path: PathBuf) -> (Arc<Self>, mpsc::UnboundedReceiver<ControlCommand>) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                started_at_ms: AppClock::elapsed_millis(),
                config_path,
                state: Mutex::new(ControlState::default()),
                command_tx,
            }),
            command_rx,
        )
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn snapshot(&self) -> ControlSnapshot {
        let state = self.state.lock().expect("control state poisoned");
        ControlSnapshot {
            status: if state.shutdown_requested {
                "shutdown_requested"
            } else {
                "running"
            },
            uptime_ms: AppClock::elapsed_millis().saturating_sub(self.started_at_ms),
            config_path: self.config_path.display().to_string(),
            shutdown_requested: state.shutdown_requested,
            reload: state.reload_snapshot(),
        }
    }

    pub fn reload_snapshot(&self) -> ReloadSnapshot {
        self.state
            .lock()
            .expect("control state poisoned")
            .reload_snapshot()
    }

    pub fn request_shutdown(&self) -> std::result::Result<(), ControlRequestError> {
        {
            let mut state = self.state.lock().expect("control state poisoned");
            state.shutdown_requested = true;
        }
        self.command_tx
            .send(ControlCommand::Shutdown)
            .map_err(|_| ControlRequestError::CommandChannelClosed)
    }

    pub fn request_reload(&self) -> std::result::Result<(), ControlRequestError> {
        {
            let mut state = self.state.lock().expect("control state poisoned");
            if state.reload_pending || state.reload_in_progress {
                return Err(ControlRequestError::ReloadBusy);
            }
            state.reload_pending = true;
            state.last_reload_error = None;
        }
        self.command_tx
            .send(ControlCommand::Reload)
            .map_err(|_| ControlRequestError::CommandChannelClosed)
    }

    pub fn mark_reload_started(&self) {
        let mut state = self.state.lock().expect("control state poisoned");
        state.reload_pending = false;
        state.reload_in_progress = true;
        state.last_reload_started_ms = Some(AppClock::elapsed_millis());
        state.last_reload_error = None;
    }

    pub fn mark_reload_succeeded(&self) {
        let now = AppClock::elapsed_millis();
        let mut state = self.state.lock().expect("control state poisoned");
        state.reload_pending = false;
        state.reload_in_progress = false;
        state.last_reload_completed_ms = Some(now);
        state.last_reload_success_ms = Some(now);
        state.last_reload_error = None;
    }

    pub fn mark_reload_failed(&self, message: impl Into<String>) {
        let mut state = self.state.lock().expect("control state poisoned");
        state.reload_pending = false;
        state.reload_in_progress = false;
        state.last_reload_completed_ms = Some(AppClock::elapsed_millis());
        state.last_reload_error = Some(message.into());
    }
}

impl ControlState {
    fn reload_snapshot(&self) -> ReloadSnapshot {
        ReloadSnapshot {
            status: if self.reload_in_progress {
                "in_progress"
            } else if self.reload_pending {
                "pending"
            } else if self.last_reload_error.is_some() {
                "failed"
            } else if self.last_reload_success_ms.is_some() {
                "ok"
            } else {
                "idle"
            },
            pending: self.reload_pending,
            in_progress: self.reload_in_progress,
            last_started_ms: self.last_reload_started_ms,
            last_completed_ms: self.last_reload_completed_ms,
            last_success_ms: self.last_reload_success_ms,
            last_error: self.last_reload_error.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ActionAcceptedResponse {
    ok: bool,
    action: &'static str,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ConfigCheckResponse {
    ok: bool,
    source: &'static str,
    path: Option<String>,
    plugin_count: usize,
    message: String,
}

#[derive(Debug)]
struct ControlHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ControlHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        json_ok(StatusCode::OK, &self.controller.snapshot())
    }
}

#[derive(Debug)]
struct ShutdownHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ShutdownHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        match self.controller.request_shutdown() {
            Ok(()) => json_ok(
                StatusCode::ACCEPTED,
                &ActionAcceptedResponse {
                    ok: true,
                    action: "shutdown",
                    status: "accepted",
                },
            ),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "control_command_failed",
                err.to_string(),
            ),
        }
    }
}

#[derive(Debug)]
struct ReloadHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ReloadHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        match self.controller.request_reload() {
            Ok(()) => json_ok(
                StatusCode::ACCEPTED,
                &ActionAcceptedResponse {
                    ok: true,
                    action: "reload",
                    status: "accepted",
                },
            ),
            Err(ControlRequestError::ReloadBusy) => json_error(
                StatusCode::CONFLICT,
                "reload_busy",
                "reload is already pending or in progress",
            ),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "control_command_failed",
                err.to_string(),
            ),
        }
    }
}

#[derive(Debug)]
struct ReloadStatusHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ReloadStatusHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        json_ok(StatusCode::OK, &self.controller.reload_snapshot())
    }
}

#[derive(Debug)]
struct ConfigCheckHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ConfigCheckHandler {
    async fn handle(&self, _request: Request<Bytes>) -> Response<Bytes> {
        match validate_config_file(self.controller.config_path()) {
            Ok(response) => json_ok(StatusCode::OK, &response),
            Err(err) => json_error(StatusCode::BAD_REQUEST, "config_check_failed", err),
        }
    }
}

#[derive(Debug)]
struct ConfigValidateHandler;

#[async_trait]
impl ApiHandler for ConfigValidateHandler {
    async fn handle(&self, request: Request<Bytes>) -> Response<Bytes> {
        let body = match std::str::from_utf8(request.body()) {
            Ok(body) if !body.trim().is_empty() => body,
            Ok(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "empty_config_body",
                    "request body must contain YAML configuration",
                );
            }
            Err(err) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_utf8_body",
                    format!("request body is not valid UTF-8: {err}"),
                );
            }
        };

        match validate_config_text(body) {
            Ok(response) => json_ok(StatusCode::OK, &response),
            Err(err) => json_error(StatusCode::BAD_REQUEST, "config_validate_failed", err),
        }
    }
}

fn validate_config_file(path: &Path) -> std::result::Result<ConfigCheckResponse, String> {
    let config = config::init(&path.to_path_buf()).map_err(|err| err.to_string())?;
    plugin::validate_configuration(&config).map_err(|err| err.to_string())?;
    Ok(ConfigCheckResponse {
        ok: true,
        source: "file",
        path: Some(path.display().to_string()),
        plugin_count: config.plugins.len(),
        message: "configuration is valid".to_string(),
    })
}

fn validate_config_text(text: &str) -> std::result::Result<ConfigCheckResponse, String> {
    let config: Config = serde_yml::from_str(text).map_err(|err| err.to_string())?;
    config.validate().map_err(|err| err.to_string())?;
    plugin::validate_configuration(&config).map_err(|err| err.to_string())?;
    Ok(ConfigCheckResponse {
        ok: true,
        source: "body",
        path: None,
        plugin_count: config.plugins.len(),
        message: "configuration is valid".to_string(),
    })
}

pub fn register_builtin_routes(
    register: &ApiRegister,
    controller: Arc<AppController>,
) -> Result<()> {
    register.register_get(
        "/control",
        Arc::new(ControlHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_post(
        "/shutdown",
        Arc::new(ShutdownHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_post(
        "/reload",
        Arc::new(ReloadHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_get(
        "/reload/status",
        Arc::new(ReloadStatusHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_get(
        "/config/check",
        Arc::new(ConfigCheckHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_post("/config/validate", Arc::new(ConfigValidateHandler))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiHandler;
    use http::Method;
    use tempfile::NamedTempFile;
    use tokio::sync::mpsc::error::TryRecvError;

    fn valid_config_yaml() -> &'static str {
        r#"
plugins:
  - tag: debug_main
    type: debug_print
"#
    }

    fn test_request(method: Method, path: &str, body: Bytes) -> Request<Bytes> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(body)
            .expect("request should build")
    }

    #[tokio::test]
    async fn control_handlers_enqueue_shutdown_and_reload() {
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");
        let (controller, mut rx) = AppController::new(temp.path().to_path_buf());

        let shutdown = ShutdownHandler {
            controller: controller.clone(),
        };
        let reload = ReloadHandler {
            controller: controller.clone(),
        };

        let response = shutdown
            .handle(test_request(Method::POST, "/shutdown", Bytes::new()))
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            rx.try_recv().expect("shutdown command"),
            ControlCommand::Shutdown
        );

        let response = reload
            .handle(test_request(Method::POST, "/reload", Bytes::new()))
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            rx.try_recv().expect("reload command"),
            ControlCommand::Reload
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn reload_handler_rejects_parallel_reload_requests() {
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");
        let (controller, _rx) = AppController::new(temp.path().to_path_buf());
        controller.request_reload().expect("first reload accepted");

        let handler = ReloadHandler { controller };
        let response = handler
            .handle(test_request(Method::POST, "/reload", Bytes::new()))
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn config_handlers_validate_current_file_and_request_body() {
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");
        let (controller, _rx) = AppController::new(temp.path().to_path_buf());

        let check = ConfigCheckHandler {
            controller: controller.clone(),
        };
        let validate = ConfigValidateHandler;

        let response = check
            .handle(test_request(Method::GET, "/config/check", Bytes::new()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = validate
            .handle(test_request(
                Method::POST,
                "/config/validate",
                Bytes::from(valid_config_yaml().as_bytes().to_vec()),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = validate
            .handle(test_request(
                Method::POST,
                "/config/validate",
                Bytes::from_static(b"plugins: ["),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn reload_snapshot_tracks_state_transitions() {
        let temp = NamedTempFile::new().expect("temp file");
        let (controller, _rx) = AppController::new(temp.path().to_path_buf());
        assert_eq!(controller.reload_snapshot().status, "idle");

        controller.request_reload().expect("request reload");
        assert_eq!(controller.reload_snapshot().status, "pending");

        controller.mark_reload_started();
        assert_eq!(controller.reload_snapshot().status, "in_progress");

        controller.mark_reload_failed("boom");
        let snapshot = controller.reload_snapshot();
        assert_eq!(snapshot.status, "failed");
        assert_eq!(snapshot.last_error.as_deref(), Some("boom"));

        controller.request_reload().expect("request second reload");
        controller.mark_reload_started();
        controller.mark_reload_succeeded();
        assert_eq!(controller.reload_snapshot().status, "ok");
    }
}
