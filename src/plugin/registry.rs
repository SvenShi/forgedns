// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Plugin registry for managing plugin factories and instances
//!
//! Provides a centralized registry for managing plugin lifecycle,
//! enabling better testability and support for multiple server instances.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use dashmap::DashMap;
use tracing::{debug, error, info, warn};

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::plugin::dependency::DependencyKind;
use crate::plugin::executor::Executor;
use crate::plugin::matcher::Matcher;
use crate::plugin::provider::{Provider, register_reload_api_route};
use crate::plugin::{PluginCreateContext, PluginFactory, PluginInfo, PluginType};

mod catalog;
mod context;
mod init_plan;
mod runtime;

pub use catalog::{PluginCatalog, global_catalog, try_global_catalog};
pub use context::{PluginInitContext, PluginResolver};
use init_plan::{build_create_contexts, build_runtime_init_plan};
#[cfg(debug_assertions)]
use runtime::TestRuntimeGuard;
#[cfg(debug_assertions)]
pub use runtime::enable_runtime_test_serialization;
pub use runtime::{
    PluginRuntimeManager, clear_app_controller, current_runtime, destroy_runtime, global_manager,
    init, plugin_count, reload_provider, request_app_reload, server_plugin_count,
    set_app_controller,
};
#[cfg(test)]
pub use runtime::{reset_runtime_for_test, set_current_runtime_for_test};

// The lock helpers below recover the guarded value on poison instead of
// propagating the poison. Every critical section in this module is a tiny,
// panic-free state swap (replace/take/clone/clear); a thread panicking while
// holding one of these locks must not permanently brick runtime swapping or
// silently turn a failed `init_runtime` install into a success.
fn lock_mutex<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        error!("plugin registry mutex was poisoned; recovering guarded state");
        poisoned.into_inner()
    })
}

fn read_rwlock<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|poisoned| {
        error!("plugin registry RwLock was poisoned during read; recovering guarded state");
        poisoned.into_inner()
    })
}

fn write_rwlock<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|poisoned| {
        error!("plugin registry RwLock was poisoned during write; recovering guarded state");
        poisoned.into_inner()
    })
}

/// Build-time and runtime currently share the same concrete registry
/// implementation; the aliases document intent while the registry split is
/// still represented structurally by lifecycle ownership.
pub type PluginBuildSession = PluginRegistry;
pub type PluginRuntime = PluginRegistry;

/// Plugin registry that manages plugin factories and instances
///
/// This replaces the global static FACTORIES and PLUGINS, allowing:
/// - Multiple DNS server instances in the same process
/// - Better testability (no shared state between tests)
/// - Proper dependency injection
#[derive(Debug)]
pub struct PluginRegistry {
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

    #[cfg(debug_assertions)]
    test_runtime_guard: Mutex<Option<TestRuntimeGuard>>,
}

#[allow(unused)]
impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
            factory_kinds: HashMap::new(),
            plugins: DashMap::new(),
            init_order: Mutex::new(Vec::new()),
            #[cfg(debug_assertions)]
            test_runtime_guard: Mutex::new(None),
        }
    }

    #[cfg(debug_assertions)]
    fn set_test_runtime_guard(&mut self, guard: Option<tokio::sync::OwnedMutexGuard<()>>) {
        if let Some(guard) = guard
            && let Ok(slot) = self.test_runtime_guard.get_mut()
        {
            *slot = Some(TestRuntimeGuard { _guard: guard });
        }
    }

    /// Register a plugin factory
    ///
    /// # Arguments
    /// * `plugin_type` - The type name for this plugin (e.g., "forward",
    ///   "udp_server")
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

    fn load_catalog(&mut self, catalog: &PluginCatalog) {
        for (plugin_type, kind, factory) in catalog.iter_factories() {
            self.factories.insert(plugin_type.to_string(), factory);
            self.factory_kinds.insert(plugin_type.to_string(), kind);
        }
    }

    /// Build an uninitialized plugin from quick setup `type [param...]`.
    pub fn quick_setup(
        self: Arc<Self>,
        plugin_type: &str,
        tag: &str,
        param: Option<String>,
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
        factory.quick_setup(tag, param)
    }

    /// Initialize all plugins from configuration
    ///
    /// Automatically resolves dependencies and initializes plugins in the
    /// correct order.
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

        // Step 0: Validate plugin types before dependency analysis.
        for plugin_config in &configs {
            if !self.factories.contains_key(&plugin_config.plugin_type) {
                return Err(DnsError::plugin(format!(
                    "Unknown plugin type: {}",
                    plugin_config.plugin_type
                )));
            }
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
        let dependency_report = dependency::analyze_dependencies(&configs, &get_deps, &get_kind)?;
        let runtime_init_plan = build_runtime_init_plan(&dependency_report);
        for skipped_provider in &runtime_init_plan.skipped_providers {
            warn!(
                plugin = %skipped_provider.tag,
                plugin_type = %skipped_provider.plugin_type,
                reason = "no live dependents",
                "skipped provider initialization"
            );
        }

        let live_tags = runtime_init_plan
            .report
            .init_order
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        // Step 2: Run startup-only preparation hooks for live plugins.
        //
        // This is used by plugins such as `download` that may need to create
        // prerequisite files before providers or servers are initialized.
        // Keep source config order here so startup-only side effects remain
        // predictable even when no explicit dependency edge exists.
        for plugin_config in configs
            .iter()
            .filter(|config| live_tags.contains(&config.tag))
        {
            let factory = self
                .factories
                .get(&plugin_config.plugin_type)
                .ok_or_else(|| {
                    DnsError::plugin(format!(
                        "Unknown plugin type: {}",
                        plugin_config.plugin_type
                    ))
                })?;
            factory
                .prepare_startup(plugin_config, self.as_ref())
                .await?;
        }

        let create_contexts = build_create_contexts(&runtime_init_plan.report);
        let mut owned_configs: HashMap<_, _> = configs
            .into_iter()
            .map(|config| (config.tag.clone(), config))
            .collect();
        let mut sorted_plugins = Vec::with_capacity(runtime_init_plan.report.init_order.len());
        for tag in &runtime_init_plan.report.init_order {
            if let Some(config) = owned_configs.remove(tag) {
                sorted_plugins.push(config);
            }
        }

        // Step 3: Initialize live plugins in dependency order.
        info!(
            live_plugins = sorted_plugins.len(),
            skipped_providers = runtime_init_plan.skipped_providers.len(),
            "Initializing live plugins in dependency order"
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
            let create_context = create_contexts
                .get(&plugin_config.tag)
                .cloned()
                .unwrap_or_default();
            let plugin_info = self
                .create_plugin_info_and_init(plugin_config, factory.as_ref(), &create_context)
                .await?;
            let plugin_type = plugin_info.plugin_type;

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
            if plugin_type == PluginType::Provider {
                register_reload_api_route(self.clone(), &plugin_config.tag)?;
            }
            lock_mutex(&self.init_order).push(plugin_config.tag.clone());
        }

        info!("All plugins initialized successfully");
        Ok(())
    }

    /// Create a PluginInfo with access to the registry for dependency
    /// resolution
    ///
    /// Uses the factory's create method which receives the registry directly.
    async fn create_plugin_info_and_init(
        self: &Arc<Self>,
        config: &PluginConfig,
        factory: &dyn PluginFactory,
        context: &PluginCreateContext,
    ) -> Result<PluginInfo> {
        // Factory creates uninitialized plugin
        let init_context = PluginInitContext::new(self.clone(), config.tag.clone(), context);
        let uninitialized = factory.create(config, &init_context)?;

        // Initialize and wrap into PluginType (with Arc)
        let plugin_holder = uninitialized.init_and_wrap(&init_context).await?;

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

    #[hotpath::measure]
    pub async fn reload_provider(&self, tag: &str) -> Result<()> {
        let plugin = self
            .get_plugin(tag)
            .ok_or_else(|| DnsError::plugin(format!("provider '{}' is not loaded", tag)))?;
        if plugin.plugin_type != PluginType::Provider {
            return Err(DnsError::plugin(format!(
                "plugin '{}' is not a provider (type '{}')",
                tag, plugin.plugin_name
            )));
        }
        plugin.to_provider().reload().await
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
    pub async fn destroy(&self) {
        let order = lock_mutex(&self.init_order).clone();

        if order.is_empty() {
            #[cfg(debug_assertions)]
            self.release_test_runtime_guard();
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

        lock_mutex(&self.init_order).clear();
        #[cfg(debug_assertions)]
        self.release_test_runtime_guard();
        info!("All plugins destroyed");
    }

    #[cfg(debug_assertions)]
    fn release_test_runtime_guard(&self) {
        *lock_mutex(&self.test_runtime_guard) = None;
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
