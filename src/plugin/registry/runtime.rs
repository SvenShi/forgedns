// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Global plugin runtime lifecycle and application-control integration.

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use tokio::sync::Mutex as AsyncMutex;

use super::{
    PluginRegistry, PluginRuntime, lock_mutex, read_rwlock, try_global_catalog, write_rwlock,
};
use crate::api::control::{AppController, ControlRequestError};
use crate::config::types::Config;
use crate::core::error::{DnsError, Result};

#[cfg(debug_assertions)]
#[derive(Debug)]
pub(super) struct TestRuntimeGuard {
    pub(super) _guard: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(debug_assertions)]
fn test_runtime_lock() -> Arc<AsyncMutex<()>> {
    static TEST_RUNTIME_LOCK: OnceLock<Arc<AsyncMutex<()>>> = OnceLock::new();
    TEST_RUNTIME_LOCK
        .get_or_init(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

#[cfg(debug_assertions)]
static SERIALIZE_RUNTIME_FOR_TESTS: AtomicBool = AtomicBool::new(false);

#[cfg(debug_assertions)]
pub fn enable_runtime_test_serialization() {
    SERIALIZE_RUNTIME_FOR_TESTS.store(true, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct PluginRuntimeManager {
    pub(super) current: RwLock<Option<Arc<PluginRuntime>>>,
    controller: Mutex<Option<Arc<AppController>>>,
    lifecycle: AsyncMutex<()>,
}

impl PluginRuntimeManager {
    pub(super) fn new() -> Self {
        Self {
            current: RwLock::new(None),
            controller: Mutex::new(None),
            lifecycle: AsyncMutex::new(()),
        }
    }

    pub fn current_runtime(&self) -> Option<Arc<PluginRuntime>> {
        read_rwlock(&self.current).clone()
    }

    pub async fn init_runtime(&self, config: Config) -> Result<Arc<PluginRuntime>> {
        let _guard = self.lifecycle.lock().await;
        #[cfg(debug_assertions)]
        let test_guard = if SERIALIZE_RUNTIME_FOR_TESTS.load(Ordering::Relaxed) {
            Some(test_runtime_lock().lock_owned().await)
        } else {
            None
        };
        let mut candidate = PluginRegistry::new();
        #[cfg(debug_assertions)]
        candidate.set_test_runtime_guard(test_guard);
        candidate.load_catalog(try_global_catalog()?);
        let candidate = Arc::new(candidate);
        if let Err(err) = candidate.clone().init_plugins(config.plugins).await {
            candidate.destroy().await;
            return Err(err);
        }

        // Poison-tolerant swap: the install must always succeed once the
        // candidate is built, otherwise a failed swap would masquerade as a
        // successful reload while readers keep seeing the old/empty runtime.
        let previous = write_rwlock(&self.current).replace(candidate.clone());
        if let Some(previous) = previous {
            previous.destroy().await;
        }
        Ok(candidate)
    }

    pub async fn destroy_runtime(&self) {
        let _guard = self.lifecycle.lock().await;
        let previous = write_rwlock(&self.current).take();
        if let Some(previous) = previous {
            previous.destroy().await;
        }
    }

    /// The manager is the single authoritative owner of the application
    /// controller. Runtimes never carry their own copy, so swapping a runtime
    /// can neither lose nor race the controller.
    pub fn set_controller(&self, controller: Arc<AppController>) {
        *lock_mutex(&self.controller) = Some(controller);
    }

    pub fn clear_controller(&self) {
        *lock_mutex(&self.controller) = None;
    }

    fn controller(&self) -> Option<Arc<AppController>> {
        lock_mutex(&self.controller).clone()
    }

    pub fn request_app_reload(&self) -> Result<()> {
        let controller = self.controller().ok_or_else(|| {
            DnsError::plugin("reload executor requires application control context")
        })?;
        controller.request_reload().map_err(|err| match err {
            ControlRequestError::ReloadBusy => {
                DnsError::plugin("reload is already pending or in progress")
            }
            ControlRequestError::CommandChannelClosed => {
                DnsError::plugin("application reload command channel is closed")
            }
        })
    }

    pub async fn reload_provider(&self, tag: &str) -> Result<()> {
        let runtime = self
            .current_runtime()
            .ok_or_else(|| DnsError::plugin("provider reload requires an initialized runtime"))?;
        runtime.reload_provider(tag).await
    }

    pub fn plugin_count(&self) -> usize {
        self.current_runtime()
            .map_or(0, |runtime| runtime.plugin_count())
    }

    pub fn server_plugin_count(&self) -> usize {
        self.current_runtime()
            .map_or(0, |runtime| runtime.server_plugin_count())
    }

    #[cfg(test)]
    async fn set_current_runtime_for_test(&self, runtime: Arc<PluginRuntime>) {
        let _guard = self.lifecycle.lock().await;
        let previous = write_rwlock(&self.current).replace(runtime);
        if let Some(previous) = previous {
            previous.destroy().await;
        }
    }
}

static GLOBAL_MANAGER: OnceLock<Arc<PluginRuntimeManager>> = OnceLock::new();

pub fn global_manager() -> Arc<PluginRuntimeManager> {
    GLOBAL_MANAGER
        .get_or_init(|| Arc::new(PluginRuntimeManager::new()))
        .clone()
}

pub fn current_runtime() -> Option<Arc<PluginRuntime>> {
    global_manager().current_runtime()
}

pub async fn init(config: Config) -> Result<Arc<PluginRuntime>> {
    global_manager().init_runtime(config).await
}

pub async fn destroy_runtime() {
    global_manager().destroy_runtime().await;
}

pub fn set_app_controller(controller: Arc<AppController>) {
    global_manager().set_controller(controller);
}

pub fn clear_app_controller() {
    global_manager().clear_controller();
}

pub fn request_app_reload() -> Result<()> {
    global_manager().request_app_reload()
}

pub async fn reload_provider(tag: &str) -> Result<()> {
    global_manager().reload_provider(tag).await
}

pub fn plugin_count() -> usize {
    global_manager().plugin_count()
}

pub fn server_plugin_count() -> usize {
    global_manager().server_plugin_count()
}

#[cfg(test)]
pub async fn reset_runtime_for_test() {
    destroy_runtime().await;
    clear_app_controller();
}

#[cfg(test)]
pub async fn set_current_runtime_for_test(runtime: Arc<PluginRuntime>) {
    global_manager().set_current_runtime_for_test(runtime).await;
}
