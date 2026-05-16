// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Built-in application control endpoints for the management API.

use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tokio::sync::mpsc;

use crate::api::{ApiHandler, ApiRegister, json_error, json_ok, json_response};
use crate::config;
use crate::core::VERSION;
use crate::core::app_clock::AppClock;
use crate::core::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCommand {
    Shutdown,
    Reload,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessMetrics {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub system_memory_total_mb: u64,
}

#[derive(Debug)]
pub struct AppController {
    started_at_ms: u64,
    config_path: PathBuf,
    state: Mutex<ControlState>,
    command_tx: mpsc::UnboundedSender<ControlCommand>,
    sysinfo: Mutex<System>,
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
        let pid = Pid::from_u32(std::process::id());
        let refresh_kind = ProcessRefreshKind::nothing().with_cpu().with_memory();
        let mut sys =
            System::new_with_specifics(RefreshKind::nothing().with_processes(refresh_kind));
        // Prime the CPU baseline so the first real sample isn't always 0%.
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), false, refresh_kind);
        (
            Arc::new(Self {
                started_at_ms: AppClock::elapsed_millis(),
                config_path,
                state: Mutex::new(ControlState::default()),
                command_tx,
                sysinfo: Mutex::new(sys),
            }),
            command_rx,
        )
    }

    pub fn sample_process_metrics(&self) -> ProcessMetrics {
        let pid = Pid::from_u32(std::process::id());
        let mut sys = self.sysinfo.lock().expect("sysinfo poisoned");
        sys.refresh_memory();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        let cpu_count = sys.cpus().len().max(1) as f32;
        let (cpu_percent, memory_mb) = sys
            .process(pid)
            .map(|p| (p.cpu_usage() / cpu_count, p.memory() / 1_048_576))
            .unwrap_or((0.0, 0));
        ProcessMetrics {
            cpu_percent,
            memory_mb,
            system_memory_total_mb: sys.total_memory() / 1_048_576,
        }
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
    dependency_graph: crate::plugin::DependencyGraphReport,
    message: String,
}

#[derive(Debug, Serialize)]
struct ConfigFileResponse {
    ok: bool,
    path: String,
    format: &'static str,
    content: String,
    version: String,
    updated_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ConfigSaveRequest {
    format: Option<String>,
    content: String,
    base_version: Option<String>,
    validate: Option<bool>,
    reload: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ConfigSaveResponse {
    ok: bool,
    path: String,
    format: &'static str,
    version: String,
    updated_at_ms: Option<u64>,
    plugin_count: usize,
    init_order: Vec<String>,
    reload: Option<ReloadSnapshot>,
    message: String,
}

#[derive(Debug, Serialize)]
struct SystemResponse {
    ok: bool,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    uptime_ms: u64,
    config_path: String,
    api_enabled: bool,
    reload: ReloadSnapshot,
    process_cpu_percent: f32,
    process_memory_mb: u64,
    system_memory_total_mb: u64,
}

#[derive(Debug, Serialize)]
struct ConfigValidationErrorResponse {
    ok: bool,
    code: &'static str,
    message: String,
    diagnostics: Vec<String>,
    diagnostic_details: Vec<ConfigDiagnostic>,
}

#[derive(Debug, Serialize)]
struct ConfigDiagnostic {
    message: String,
    severity: &'static str,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Debug)]
struct ControlHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ControlHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        json_ok(StatusCode::OK, &self.controller.snapshot())
    }
}

#[derive(Debug)]
struct ShutdownHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ShutdownHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
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
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
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

#[derive(Debug)]
struct SystemHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ReloadStatusHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        json_ok(StatusCode::OK, &self.controller.reload_snapshot())
    }
}

#[async_trait]
impl ApiHandler for SystemHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        let snapshot = self.controller.snapshot();
        let metrics = self.controller.sample_process_metrics();
        json_ok(
            StatusCode::OK,
            &SystemResponse {
                ok: true,
                version: VERSION,
                os: std::env::consts::OS,
                arch: std::env::consts::ARCH,
                uptime_ms: snapshot.uptime_ms,
                config_path: snapshot.config_path,
                api_enabled: true,
                reload: snapshot.reload,
                process_cpu_percent: metrics.cpu_percent,
                process_memory_mb: metrics.memory_mb,
                system_memory_total_mb: metrics.system_memory_total_mb,
            },
        )
    }
}

#[derive(Debug)]
struct ConfigCheckHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ConfigCheckHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        match validate_config_file(self.controller.config_path()) {
            Ok(response) => json_ok(StatusCode::OK, &response),
            Err(err) => config_validation_error("config_check_failed", err, None),
        }
    }
}

#[derive(Debug)]
struct ConfigGetHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ConfigGetHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        match read_config_file_response(self.controller.config_path()) {
            Ok(response) => json_ok(StatusCode::OK, &response),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "config_read_failed", err),
        }
    }
}

#[derive(Debug)]
struct ConfigSaveHandler {
    controller: Arc<AppController>,
}

#[async_trait]
impl ApiHandler for ConfigSaveHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let save_request = match serde_json::from_slice::<ConfigSaveRequest>(request.body()) {
            Ok(request) => request,
            Err(err) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_config_save_request",
                    format!("request body must be JSON: {err}"),
                );
            }
        };

        match save_config_file(self.controller.clone(), save_request) {
            Ok(response) => json_ok(StatusCode::OK, &response),
            Err(ConfigSaveError::InvalidFormat(format)) => json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_config_format",
                format!("unsupported config format: {format}"),
            ),
            Err(ConfigSaveError::VersionConflict) => json_error(
                StatusCode::CONFLICT,
                "config_conflict",
                "configuration file changed since it was loaded",
            ),
            Err(ConfigSaveError::Validation(message)) => {
                json_error(StatusCode::BAD_REQUEST, "config_validate_failed", message)
            }
            Err(ConfigSaveError::ReloadBusy) => json_error(
                StatusCode::CONFLICT,
                "reload_busy",
                "configuration was saved, but reload is already pending or in progress",
            ),
            Err(ConfigSaveError::Io(message) | ConfigSaveError::Reload(message)) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "config_save_failed",
                message,
            ),
        }
    }
}

#[derive(Debug)]
struct ConfigValidateHandler;

#[async_trait]
impl ApiHandler for ConfigValidateHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let body = match config_text_from_validate_request(request.body()) {
            Ok(body) => body,
            Err(err) => return err.into_response(),
        };

        match validate_config_text(&body) {
            Ok(response) => json_ok(StatusCode::OK, &response),
            Err(err) => config_validation_error("config_validate_failed", err, Some(&body)),
        }
    }
}

fn config_validation_error(
    code: &'static str,
    message: String,
    config_text: Option<&str>,
) -> crate::api::ApiResponse {
    let diagnostic = config_text
        .map(|text| locate_config_diagnostic(text, &message))
        .unwrap_or_else(|| default_config_diagnostic(&message));
    json_response(
        StatusCode::BAD_REQUEST,
        &ConfigValidationErrorResponse {
            ok: false,
            diagnostics: vec![message.clone()],
            diagnostic_details: vec![diagnostic],
            code,
            message,
        },
    )
}

fn default_config_diagnostic(message: &str) -> ConfigDiagnostic {
    ConfigDiagnostic {
        message: message.to_string(),
        severity: "error",
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 2,
    }
}

fn locate_config_diagnostic(config_text: &str, message: &str) -> ConfigDiagnostic {
    if let Some(loc) = config::diagnostic::locate_in_config(config_text, message) {
        return ConfigDiagnostic {
            message: message.to_string(),
            severity: "error",
            line: loc.line,
            column: loc.column,
            end_line: loc.line,
            end_column: loc.end_column,
        };
    }
    default_config_diagnostic(message)
}

fn config_text_from_validate_request(
    body: &Bytes,
) -> std::result::Result<String, ConfigValidateRequestError> {
    if let Ok(request) = serde_json::from_slice::<ConfigSaveRequest>(body) {
        if request.format.as_deref().unwrap_or("yaml") != "yaml" {
            return Err(ConfigValidateRequestError::UnsupportedFormat);
        }
        return Ok(request.content);
    }

    let body = match std::str::from_utf8(body) {
        Ok(body) if !body.trim().is_empty() => body,
        Ok(_) => {
            return Err(ConfigValidateRequestError::EmptyBody);
        }
        Err(err) => {
            return Err(ConfigValidateRequestError::InvalidUtf8(err.to_string()));
        }
    };

    Ok(body.to_string())
}

#[derive(Debug)]
enum ConfigValidateRequestError {
    UnsupportedFormat,
    EmptyBody,
    InvalidUtf8(String),
}

impl ConfigValidateRequestError {
    fn into_response(self) -> crate::api::ApiResponse {
        match self {
            Self::UnsupportedFormat => json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_config_format",
                "request format must be yaml",
            ),
            Self::EmptyBody => json_error(
                StatusCode::BAD_REQUEST,
                "empty_config_body",
                "request body must contain YAML configuration",
            ),
            Self::InvalidUtf8(message) => json_error(
                StatusCode::BAD_REQUEST,
                "invalid_utf8_body",
                format!("request body is not valid UTF-8: {message}"),
            ),
        }
    }
}

#[derive(Debug)]
enum ConfigSaveError {
    InvalidFormat(String),
    VersionConflict,
    Validation(String),
    Io(String),
    ReloadBusy,
    Reload(String),
}

fn validate_config_file(path: &Path) -> std::result::Result<ConfigCheckResponse, String> {
    let summary = config::validate_file(path).map_err(|err| err.to_string())?;
    Ok(ConfigCheckResponse {
        ok: true,
        source: "file",
        path: Some(path.display().to_string()),
        plugin_count: summary.plugin_count,
        dependency_graph: summary.dependency_graph,
        message: "configuration is valid".to_string(),
    })
}

fn validate_config_text(text: &str) -> std::result::Result<ConfigCheckResponse, String> {
    let summary = config::validate_text(text).map_err(|err| err.to_string())?;
    Ok(ConfigCheckResponse {
        ok: true,
        source: "body",
        path: None,
        plugin_count: summary.plugin_count,
        dependency_graph: summary.dependency_graph,
        message: "configuration is valid".to_string(),
    })
}

fn read_config_file_response(path: &Path) -> std::result::Result<ConfigFileResponse, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read config {}: {err}", path.display()))?;
    let updated_at_ms = config_updated_at_ms(path);
    Ok(ConfigFileResponse {
        ok: true,
        path: path.display().to_string(),
        format: "yaml",
        version: config_version(&content),
        updated_at_ms,
        content,
    })
}

fn save_config_file(
    controller: Arc<AppController>,
    request: ConfigSaveRequest,
) -> std::result::Result<ConfigSaveResponse, ConfigSaveError> {
    let format = request.format.as_deref().unwrap_or("yaml");
    if format != "yaml" {
        return Err(ConfigSaveError::InvalidFormat(format.to_string()));
    }

    let path = controller.config_path();
    let current = fs::read_to_string(path).map_err(|err| {
        ConfigSaveError::Io(format!("failed to read config {}: {err}", path.display()))
    })?;
    if let Some(base_version) = request.base_version.as_deref()
        && base_version != config_version(&current)
    {
        return Err(ConfigSaveError::VersionConflict);
    }

    let summary = if request.validate.unwrap_or(true) {
        config::validate_text(&request.content)
            .map_err(|err| ConfigSaveError::Validation(err.to_string()))?
    } else {
        let parsed: crate::config::types::Config = serde_yaml_ng::from_str(&request.content)
            .map_err(|err| ConfigSaveError::Validation(err.to_string()))?;
        crate::config::ConfigValidationSummary {
            plugin_count: parsed.plugins.len(),
            dependency_graph: crate::plugin::analyze_configuration(&parsed)
                .map_err(|err| ConfigSaveError::Validation(err.to_string()))?,
        }
    };

    fs::write(path, request.content.as_bytes()).map_err(|err| {
        ConfigSaveError::Io(format!("failed to write config {}: {err}", path.display()))
    })?;

    let saved = fs::read_to_string(path).map_err(|err| {
        ConfigSaveError::Io(format!(
            "failed to read saved config {}: {err}",
            path.display()
        ))
    })?;

    let reload = if request.reload.unwrap_or(false) {
        match controller.request_reload() {
            Ok(()) => Some(controller.reload_snapshot()),
            Err(ControlRequestError::ReloadBusy) => return Err(ConfigSaveError::ReloadBusy),
            Err(err) => return Err(ConfigSaveError::Reload(err.to_string())),
        }
    } else {
        None
    };

    Ok(ConfigSaveResponse {
        ok: true,
        path: path.display().to_string(),
        format: "yaml",
        version: config_version(&saved),
        updated_at_ms: config_updated_at_ms(path),
        plugin_count: summary.plugin_count,
        init_order: summary.dependency_graph.init_order,
        reload,
        message: "configuration saved".to_string(),
    })
}

fn config_version(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

fn config_updated_at_ms(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
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
        "/system",
        Arc::new(SystemHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_get(
        "/config/check",
        Arc::new(ConfigCheckHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_get(
        "/config",
        Arc::new(ConfigGetHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_route(
        Method::PUT,
        "/config",
        Arc::new(ConfigSaveHandler {
            controller: controller.clone(),
        }),
    )?;
    register.register_post("/config/validate", Arc::new(ConfigValidateHandler))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::Method;
    use http_body_util::BodyExt;
    use tempfile::NamedTempFile;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;
    use crate::api::ApiHandler;

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
        AppClock::start();
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
        AppClock::start();
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
        AppClock::start();
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
                Bytes::from(
                    serde_json::json!({
                        "format": "yaml",
                        "content": valid_config_yaml()
                    })
                    .to_string(),
                ),
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

    #[tokio::test]
    async fn config_validate_error_includes_diagnostic_location() {
        let validate = ConfigValidateHandler;
        let response = validate
            .handle(test_request(
                Method::POST,
                "/config/validate",
                Bytes::from_static(
                    b"
plugins:
  - tag: bad
    type: missing_plugin
",
                ),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("body should collect")
            .to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(
            value["diagnostic_details"][0]["message"],
            "Plugin error: Unknown plugin type: missing_plugin"
        );
        assert_eq!(value["diagnostic_details"][0]["line"], 4);
        assert_eq!(value["diagnostic_details"][0]["column"], 11);
    }

    #[tokio::test]
    async fn config_get_and_save_handlers_round_trip_file_content() {
        AppClock::start();
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");
        let (controller, mut rx) = AppController::new(temp.path().to_path_buf());

        let get = ConfigGetHandler {
            controller: controller.clone(),
        };
        let save = ConfigSaveHandler {
            controller: controller.clone(),
        };

        let response = get
            .handle(test_request(Method::GET, "/config", Bytes::new()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let loaded: serde_json::Value = serde_json::from_slice(&body).expect("json response");
        let version = loaded["version"].as_str().expect("version");
        assert_eq!(loaded["content"], valid_config_yaml());

        let next_config = r#"
plugins:
  - tag: saved_debug
    type: debug_print
"#;
        let response = save
            .handle(test_request(
                Method::PUT,
                "/config",
                Bytes::from(
                    serde_json::json!({
                        "format": "yaml",
                        "content": next_config,
                        "base_version": version,
                        "validate": true,
                        "reload": true
                    })
                    .to_string(),
                ),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(std::fs::read_to_string(temp.path()).unwrap(), next_config);
        assert_eq!(
            rx.try_recv().expect("reload command"),
            ControlCommand::Reload
        );
    }

    #[tokio::test]
    async fn config_save_rejects_invalid_yaml_and_version_conflicts() {
        AppClock::start();
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");
        let (controller, _rx) = AppController::new(temp.path().to_path_buf());
        let save = ConfigSaveHandler { controller };

        let response = save
            .handle(test_request(
                Method::PUT,
                "/config",
                Bytes::from(
                    serde_json::json!({
                        "format": "yaml",
                        "content": "plugins: [",
                        "validate": true
                    })
                    .to_string(),
                ),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = save
            .handle(test_request(
                Method::PUT,
                "/config",
                Bytes::from(
                    serde_json::json!({
                        "format": "yaml",
                        "content": valid_config_yaml(),
                        "base_version": "stale"
                    })
                    .to_string(),
                ),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn config_save_reports_reload_busy_after_successful_write() {
        AppClock::start();
        let temp = NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), valid_config_yaml()).expect("write config");
        let (controller, _rx) = AppController::new(temp.path().to_path_buf());
        controller.request_reload().expect("seed pending reload");
        let save = ConfigSaveHandler { controller };

        let next_config = r#"
plugins:
  - tag: saved_before_busy_reload
    type: debug_print
"#;
        let response = save
            .handle(test_request(
                Method::PUT,
                "/config",
                Bytes::from(
                    serde_json::json!({
                        "format": "yaml",
                        "content": next_config,
                        "reload": true
                    })
                    .to_string(),
                ),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(std::fs::read_to_string(temp.path()).unwrap(), next_config);
    }

    #[test]
    fn reload_snapshot_tracks_state_transitions() {
        AppClock::start();
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
