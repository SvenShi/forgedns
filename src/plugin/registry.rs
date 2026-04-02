/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin registry for managing plugin factories and instances
//!
//! Provides a centralized registry for managing plugin lifecycle,
//! enabling better testability and support for multiple server instances.

use crate::api::ApiRegister;
use crate::api::control::{AppController, ControlRequestError};
use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::plugin::dependency::DependencyKind;
use crate::plugin::executor::Executor;
use crate::plugin::matcher::Matcher;
use crate::plugin::provider::Provider;
use crate::plugin::{PluginFactory, PluginInfo, PluginType};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{debug, error, info};

/// Plugin registry that manages plugin factories and instances
///
/// This replaces the global static FACTORIES and PLUGINS, allowing:
/// - Multiple DNS server instances in the same process
/// - Better testability (no shared state between tests)
/// - Proper dependency injection
#[derive(Debug)]
pub struct PluginRegistry {
    api_register: Option<ApiRegister>,

    /// Optional application controller used by plugins that need to trigger
    /// process-level control actions such as a full configuration reload.
    controller: OnceLock<Arc<AppController>>,

    /// Map of plugin type names to their factory implementations
    factories: HashMap<String, Box<dyn PluginFactory>>,

    /// Map of plugin type names to their category kind
    factory_kinds: HashMap<String, DependencyKind>,

    /// Map of plugin tags to their runtime instances
    ///
    /// Uses DashMap for interior mutability, allowing plugins to be registered
    /// even when the registry is behind an Arc.
    plugins: DashMap<String, Arc<PluginInfo>>,

    /// Initialization order of plugins (for deterministic shutdown)
    init_order: Mutex<Vec<String>>,
}

#[allow(unused)]
impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self {
            api_register: None,
            controller: OnceLock::new(),
            factories: HashMap::new(),
            factory_kinds: HashMap::new(),
            plugins: DashMap::new(),
            init_order: Mutex::new(Vec::new()),
        }
    }

    pub fn with_api(api_register: Option<ApiRegister>) -> Self {
        let mut registry = Self::new();
        registry.api_register = api_register;
        registry
    }

    /// Register a plugin factory
    ///
    /// # Arguments
    /// * `plugin_type` - The type name for this plugin (e.g., "forward", "udp_server")
    /// * `factory` - The factory implementation for creating plugin instances
    pub fn register_factory(
        &mut self,
        plugin_type: &str,
        kind: DependencyKind,
        factory: Box<dyn PluginFactory>,
    ) {
        self.factories.insert(plugin_type.to_string(), factory);
        self.factory_kinds.insert(plugin_type.to_string(), kind);
    }

    /// Build an uninitialized plugin from quick setup `type [param...]`.
    pub fn quick_setup(
        &self,
        plugin_type: &str,
        tag: &str,
        param: Option<String>,
        registry: Arc<Self>,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let factory = self.factories.get(plugin_type).ok_or_else(|| {
            DnsError::plugin(format!("quick setup type '{}' not found", plugin_type))
        })?;
        info!(
            "plugin: {}, quick setup tag {}, param {}",
            plugin_type,
            tag,
            param.as_deref().unwrap_or("none")
        );
        factory.quick_setup(tag, param, registry)
    }

    /// Initialize all plugins from configuration
    ///
    /// Automatically resolves dependencies and initializes plugins in the correct order.
    ///
    /// # Arguments
    /// * `self` - Arc-wrapped registry to allow sharing with plugins
    /// * `configs` - Vector of plugin configurations
    ///
    /// # Returns
    /// * `Ok(())` - All plugins initialized successfully
    /// * `Err(DnsError)` - Error message if initialization fails
    pub(crate) async fn init_plugins(self: Arc<Self>, configs: Vec<PluginConfig>) -> Result<()> {
        use crate::plugin::dependency;

        let mut seen_tags = HashMap::new();
        for (idx, config) in configs.iter().enumerate() {
            if let Some(prev_idx) = seen_tags.insert(config.tag.as_str(), idx) {
                return Err(DnsError::plugin(format!(
                    "Duplicate plugin tag '{}' in configuration: plugins[{}] and plugins[{}]",
                    config.tag, prev_idx, idx
                )));
            }
        }

        // Step 0: Run startup-only preparation hooks before dependency sorting.
        //
        // This is used by plugins such as `download` that may need to create
        // prerequisite files before providers or servers are initialized.
        for plugin_config in &configs {
            let Some(factory) = self.factories.get(&plugin_config.plugin_type) else {
                return Err(DnsError::plugin(format!(
                    "Unknown plugin type: {}",
                    plugin_config.plugin_type
                )));
            };
            factory.prepare_startup(plugin_config, self.clone()).await?;
        }

        // Step 1: Resolve dependencies from structured factory descriptors.
        //
        // Dependency collection should stay lightweight. Full schema parsing
        // and validation are performed exactly once in each factory `create()`.
        // We rely on:
        // - dependency graph checks (missing/type/cycle/self reference), and
        // - `create()` parse/validation during actual plugin construction.
        //
        // This keeps diagnostics intact while avoiding duplicated parse passes.
        info!("Resolving plugin dependencies...");
        let get_deps = |config: &PluginConfig| {
            self.factories
                .get(&config.plugin_type)
                .map(|f| f.get_dependency_specs(config))
                .unwrap_or_default()
        };
        let get_kind = |config: &PluginConfig| {
            self.factory_kinds
                .get(&config.plugin_type)
                .copied()
                .unwrap_or(DependencyKind::Unknown)
        };
        let sorted_plugins = dependency::resolve_dependencies(configs, &get_deps, &get_kind)?;

        // Step 2: Initialize plugins in dependency order.
        info!(
            "Initializing {} plugins in dependency order",
            sorted_plugins.len()
        );

        for (idx, plugin_config) in sorted_plugins.iter().enumerate() {
            info!(
                "  [{}/{}] Initializing plugin: {} (type: {})",
                idx + 1,
                sorted_plugins.len(),
                plugin_config.tag,
                plugin_config.plugin_type
            );
            debug!("Plugin config: {:?}", plugin_config);

            let factory = self
                .factories
                .get(&plugin_config.plugin_type)
                .ok_or_else(|| {
                    DnsError::plugin(format!(
                        "Unknown plugin type: {}",
                        plugin_config.plugin_type
                    ))
                })?;

            // Create plugin using the factory and registry
            let plugin_info = self
                .create_plugin_info_and_init(plugin_config, factory.as_ref())
                .await?;

            // DashMap allows insertion even with Arc<Self>
            if self
                .plugins
                .insert(plugin_config.tag.clone(), Arc::new(plugin_info))
                .is_some()
            {
                return Err(DnsError::plugin(format!(
                    "Duplicate runtime plugin tag '{}'",
                    plugin_config.tag
                )));
            }
            if let Ok(mut order) = self.init_order.lock() {
                order.push(plugin_config.tag.clone());
            }
        }

        info!("All plugins initialized successfully");
        Ok(())
    }

    /// Create a PluginInfo with access to the registry for dependency resolution
    ///
    /// Uses the factory's create method which receives the registry directly.
    async fn create_plugin_info_and_init(
        self: &Arc<Self>,
        config: &PluginConfig,
        factory: &dyn PluginFactory,
    ) -> Result<PluginInfo> {
        // Factory creates uninitialized plugin
        let uninitialized = factory.create(config, self.clone())?;

        // Initialize and wrap into PluginType (with Arc)
        let plugin_holder = uninitialized.init_and_wrap().await?;

        // Initialize and wrap into PluginHolder (with Arc)
        Ok(PluginInfo {
            tag: config.tag.clone(),
            plugin_name: config.plugin_type.clone(),
            plugin_type: plugin_holder.plugin_type(),
            plugin_holder,
            args: config.args.clone(),
        })
    }

    /// Get a plugin instance by tag
    pub fn get_plugin(&self, tag: &str) -> Option<Arc<PluginInfo>> {
        self.plugins.get(tag).map(|entry| entry.clone())
    }

    pub fn api_register(&self) -> Option<ApiRegister> {
        self.api_register.clone()
    }

    /// Attach the application controller after the registry has been assembled.
    pub fn set_controller(&self, controller: Arc<AppController>) {
        let _ = self.controller.set(controller);
    }

    /// Get the application controller if the registry was assembled with one.
    pub fn controller(&self) -> Option<Arc<AppController>> {
        self.controller.get().cloned()
    }

    /// Request the same full reload flow used by the management control API.
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

    fn plugin_kind_name(plugin_type: PluginType) -> &'static str {
        match plugin_type {
            PluginType::Server => "server",
            PluginType::Executor => "executor",
            PluginType::Matcher => "matcher",
            PluginType::Provider => "provider",
        }
    }

    fn get_required_plugin(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<PluginInfo>> {
        self.get_plugin(target_tag).ok_or_else(|| {
            DnsError::plugin(format!(
                "plugin '{}' field '{}' references missing plugin '{}'",
                source_tag, field, target_tag
            ))
        })
    }

    pub fn get_executor_dependency(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Executor>> {
        let plugin = self.get_required_plugin(source_tag, field, target_tag)?;
        if plugin.plugin_type != PluginType::Executor {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects executor plugin, but '{}' is {} (type '{}')",
                source_tag,
                field,
                target_tag,
                Self::plugin_kind_name(plugin.plugin_type),
                plugin.plugin_name
            )));
        }
        Ok(plugin.to_executor())
    }

    pub fn get_executor_dependency_of_type(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Executor>> {
        let plugin = self.get_required_plugin(source_tag, field, target_tag)?;
        if plugin.plugin_type != PluginType::Executor {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects executor plugin type '{}', but '{}' is {} (type '{}')",
                source_tag,
                field,
                expected_plugin_type,
                target_tag,
                Self::plugin_kind_name(plugin.plugin_type),
                plugin.plugin_name
            )));
        }
        if plugin.plugin_name != expected_plugin_type {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects executor plugin type '{}', but '{}' has type '{}'",
                source_tag, field, expected_plugin_type, target_tag, plugin.plugin_name
            )));
        }
        Ok(plugin.to_executor())
    }

    pub fn get_matcher_dependency(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Matcher>> {
        let plugin = self.get_required_plugin(source_tag, field, target_tag)?;
        if plugin.plugin_type != PluginType::Matcher {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects matcher plugin, but '{}' is {} (type '{}')",
                source_tag,
                field,
                target_tag,
                Self::plugin_kind_name(plugin.plugin_type),
                plugin.plugin_name
            )));
        }
        Ok(plugin.to_matcher())
    }

    pub fn get_provider_dependency(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Provider>> {
        let plugin = self.get_required_plugin(source_tag, field, target_tag)?;
        if plugin.plugin_type != PluginType::Provider {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects provider plugin, but '{}' is {} (type '{}')",
                source_tag,
                field,
                target_tag,
                Self::plugin_kind_name(plugin.plugin_type),
                plugin.plugin_name
            )));
        }
        Ok(plugin.to_provider())
    }

    pub fn get_provider_dependency_of_type(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Provider>> {
        let plugin = self.get_required_plugin(source_tag, field, target_tag)?;
        if plugin.plugin_type != PluginType::Provider {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects provider plugin type '{}', but '{}' is {} (type '{}')",
                source_tag,
                field,
                expected_plugin_type,
                target_tag,
                Self::plugin_kind_name(plugin.plugin_type),
                plugin.plugin_name
            )));
        }
        if plugin.plugin_name != expected_plugin_type {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' expects provider plugin type '{}', but '{}' has type '{}'",
                source_tag, field, expected_plugin_type, target_tag, plugin.plugin_name
            )));
        }
        Ok(plugin.to_provider())
    }

    /// Get all registered plugin tags
    pub fn plugin_tags(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get the number of registered plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    pub fn server_plugin_count(&self) -> usize {
        self.plugins
            .iter()
            .filter(|entry| entry.plugin_type == PluginType::Server)
            .count()
    }

    /// Destroy all initialized plugins in reverse init order
    pub async fn destory(&self) {
        let order = self
            .init_order
            .lock()
            .map(|order| order.clone())
            .unwrap_or_default();

        if order.is_empty() {
            return;
        }

        info!("Destroying {} plugins in reverse order", order.len());

        for tag in order.into_iter().rev() {
            if let Some(entry) = self.plugins.remove(&tag) {
                if let Err(err) = entry.1.as_plugin().destroy().await {
                    error!(
                        plugin = %tag,
                        error = %err,
                        "Plugin destroy failed"
                    );
                }
                drop(entry);
            }
        }

        info!("All plugins destroyed");
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.plugin_count(), 0);
        assert_eq!(registry.plugin_tags().len(), 0);
    }

    #[test]
    fn test_get_nonexistent_plugin() {
        let registry = PluginRegistry::new();
        assert!(registry.get_plugin("nonexistent").is_none());
    }
}
