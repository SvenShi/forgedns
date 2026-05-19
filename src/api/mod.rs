// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Management HTTP API hub and route registration.
//!
//! This module provides the optional control-plane HTTP server used for health
//! endpoints, lifecycle control, and plugin-specific API surfaces.
//!
//! Core responsibilities:
//!
//! - normalize and validate the configured API listen address;
//! - host a small in-process route registry keyed by method and path;
//! - provide [`ApiRegister`] so built-in components and plugins can expose
//!   endpoints without coupling to the HTTP server implementation;
//! - enforce optional basic authentication and TLS; and
//! - publish shared health state about startup, plugin initialization, and
//!   shutdown.
//!
//! The API layer is intentionally separate from the DNS request path. It shares
//! runtime state with the application, but it does not participate in query
//! matching or response generation.

mod auth;
pub mod control;
mod cors;
mod global;
mod handler;
pub mod health;
mod hub;
pub mod logs;
mod metrics;
mod request;
mod response;
mod route;
mod server;
mod static_files;

use std::sync::Arc;

#[cfg(test)]
pub(super) use auth::is_authorized;
#[cfg(test)]
pub(crate) use global::global_api_test_guard;
#[cfg(test)]
pub(crate) use global::set_global_api_register_for_test;
pub use global::{clear_global_api, global_api_register, install_global_api};
pub use handler::{ApiBody, ApiHandler, ApiResponse};
pub use hub::{ApiHub, ApiRegister, PluginApiRegister};
#[cfg(test)]
pub(super) use request::{rewrite_request_path, strip_api_prefix};
pub use response::{json_error, json_ok, json_response, simple_response, streaming_response};
#[cfg(test)]
pub(super) use route::build_plugin_route_path;

use crate::core::error::Result;

/// Register process-wide API routes that do not depend on application control
/// state.
///
/// Plugin-scoped routes are still registered by each plugin under
/// `/plugins/<tag>/...`; this function is only for global API surfaces such as
/// health and metrics.
pub fn register_builtin_routes() -> Result<()> {
    if let Some(register) = global_api_register() {
        health::register_builtin_routes(&register, register.health_state())?;
        metrics::register_builtin_routes(&register)?;
        logs::register_log_routes(&register)?;
    }
    Ok(())
}

/// Register process-wide control routes that need the application controller.
pub fn register_control_routes(controller: Arc<control::AppController>) -> Result<()> {
    if let Some(register) = global_api_register() {
        control::register_builtin_routes(&register, controller)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[macro_export]
macro_rules! register_plugin_api {
    ($tag:expr, |$plugin_api:ident| $($method:ident $path:expr => $handler:expr),+ $(,)?) => {{
        (|| -> $crate::core::error::Result<()> {
            if let Some(api_register) = $crate::api::global_api_register() {
                let $plugin_api = api_register.plugin($tag)?;
                $(
                    $crate::register_plugin_api!(@register $plugin_api, $method, $path, $handler)?;
                )+
            }
            Ok(())
        })()
    }};
    ($tag:expr, $($method:ident $path:expr => $handler:expr),+ $(,)?) => {{
        (|| -> $crate::core::error::Result<()> {
            if let Some(api_register) = $crate::api::global_api_register() {
                let plugin_api = api_register.plugin($tag)?;
                $(
                    $crate::register_plugin_api!(@register plugin_api, $method, $path, $handler)?;
                )+
            }
            Ok(())
        })()
    }};
    (@register $plugin_api:ident, GET, $path:expr, $handler:expr) => {
        $plugin_api.get($path, std::sync::Arc::new($handler))
    };
    (@register $plugin_api:ident, POST, $path:expr, $handler:expr) => {
        $plugin_api.post($path, std::sync::Arc::new($handler))
    };
    (@register $plugin_api:ident, DELETE, $path:expr, $handler:expr) => {
        $plugin_api.delete($path, std::sync::Arc::new($handler))
    };
    (@register $plugin_api:ident, GET_PREFIX, $path:expr, $handler:expr) => {
        $plugin_api.get_prefix($path, std::sync::Arc::new($handler))
    };
    (@register $plugin_api:ident, POST_PREFIX, $path:expr, $handler:expr) => {
        $plugin_api.post_prefix($path, std::sync::Arc::new($handler))
    };
    (@register $plugin_api:ident, DELETE_PREFIX, $path:expr, $handler:expr) => {
        $plugin_api.delete_prefix($path, std::sync::Arc::new($handler))
    };
}

#[macro_export]
macro_rules! register_api_route {
    ($method:ident $path:expr => $handler:expr $(,)?) => {{
        (|| -> $crate::core::error::Result<()> {
            if let Some(api_register) = $crate::api::global_api_register() {
                $crate::register_api_route!(@register api_register, $method, $path, $handler)?;
            }
            Ok(())
        })()
    }};
    (@register $api_register:ident, GET, $path:expr, $handler:expr) => {
        $api_register.register_get($path, std::sync::Arc::new($handler))
    };
    (@register $api_register:ident, POST, $path:expr, $handler:expr) => {
        $api_register.register_post($path, std::sync::Arc::new($handler))
    };
    (@register $api_register:ident, DELETE, $path:expr, $handler:expr) => {
        $api_register.register_delete($path, std::sync::Arc::new($handler))
    };
    (@register $api_register:ident, GET_PREFIX, $path:expr, $handler:expr) => {
        $api_register.register_get_prefix($path, std::sync::Arc::new($handler))
    };
    (@register $api_register:ident, POST_PREFIX, $path:expr, $handler:expr) => {
        $api_register.register_post_prefix($path, std::sync::Arc::new($handler))
    };
    (@register $api_register:ident, DELETE_PREFIX, $path:expr, $handler:expr) => {
        $api_register.register_delete_prefix($path, std::sync::Arc::new($handler))
    };
}
