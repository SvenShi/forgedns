// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Route registration keys and path matching helpers.

use std::sync::Arc;

use ahash::AHashMap;
use http::Method;

use crate::api::ApiHandler;
use crate::core::error::{DnsError, Result};

#[derive(Clone, Debug)]
pub(super) struct RouteKey {
    pub(super) method: Method,
    pub(super) path: String,
}

impl RouteKey {
    pub(super) fn new(method: Method, path: String) -> Self {
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

#[derive(Clone)]
pub(super) struct PrefixRoute {
    pub(super) method: Method,
    pub(super) path_prefix: String,
    pub(super) handler: Arc<dyn ApiHandler>,
}

impl PrefixRoute {
    pub(super) fn new(method: Method, path_prefix: String, handler: Arc<dyn ApiHandler>) -> Self {
        Self {
            method,
            path_prefix,
            handler,
        }
    }
}

pub(crate) fn build_plugin_route_path(plugin_tag: &str, subpath: &str) -> Result<String> {
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

pub(super) fn normalize_route_path(path: &str) -> Result<String> {
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

pub(super) fn lookup_handler(
    method: &Method,
    path: &str,
    routes: &AHashMap<RouteKey, Arc<dyn ApiHandler>>,
    prefix_routes: &[PrefixRoute],
) -> Option<Arc<dyn ApiHandler>> {
    let key = RouteKey::new(method.clone(), path.to_string());
    if let Some(handler) = routes.get(&key) {
        return Some(handler.clone());
    }

    prefix_routes
        .iter()
        .filter(|route| route.method == *method && path.starts_with(route.path_prefix.as_str()))
        .max_by_key(|route| route.path_prefix.len())
        .map(|route| route.handler.clone())
}
