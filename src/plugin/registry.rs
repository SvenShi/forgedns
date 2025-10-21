/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin registry for managing plugin factories and instances
//!
//! Provides a centralized registry for managing plugin lifecycle,
//! enabling better testability and support for multiple server instances.

use crate::config::config::PluginConfig;
use crate::plugin::{PluginFactory, PluginInfo};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

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

    /// Map of plugin tags to their runtime instances
    ///
    /// Uses DashMap for interior mutability, allowing plugins to be registered
    /// even when the registry is behind an Arc.
    plugins: DashMap<String, Arc<PluginInfo>>,
}

#[allow(unused)]
impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
            plugins: DashMap::new(),
        }
    }

    /// Register a plugin factory
    ///
    /// # Arguments
    /// * `plugin_type` - The type name for this plugin (e.g., "forward", "udp_server")
    /// * `factory` - The factory implementation for creating plugin instances
    pub fn register_factory(&mut self, plugin_type: &str, factory: Box<dyn PluginFactory>) {
        self.factories.insert(plugin_type.to_string(), factory);
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
    /// * `Err(String)` - Error message if initialization fails
    pub async fn init_plugins(self: Arc<Self>, configs: Vec<PluginConfig>) -> Result<(), String> {
        use crate::plugin::dependency;

        // Step 1: Validate all plugin configurations
        info!("Validating plugin configurations...");
        for config in &configs {
            let factory = self
                .factories
                .get(&config.plugin_type)
                .ok_or_else(|| format!("Unknown plugin type: {}", config.plugin_type))?;

            factory.validate_config(config)?;
        }

        // Step 2: Resolve dependencies using factory's get_dependencies
        info!("Resolving plugin dependencies...");
        let get_deps = |config: &PluginConfig| {
            self.factories
                .get(&config.plugin_type)
                .map(|f| f.get_dependencies(config))
                .unwrap_or_default()
        };
        let sorted_plugins = dependency::resolve_dependencies(configs, &get_deps)?;

        // Step 3: Initialize plugins in dependency order
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

            let factory = self
                .factories
                .get(&plugin_config.plugin_type)
                .ok_or_else(|| format!("Unknown plugin type: {}", plugin_config.plugin_type))?;

            // Create plugin using the factory and registry
            let mut plugin_info = self
                .create_plugin_info_and_init(plugin_config, factory)
                .await?;

            // DashMap allows insertion even with Arc<Self>
            self.plugins
                .insert(plugin_config.tag.clone(), Arc::new(plugin_info));
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
        factory: &Box<dyn PluginFactory>,
    ) -> Result<PluginInfo, String> {
        // Factory creates uninitialized plugin
        let uninitialized = factory.create(config, self.clone())?;

        // Initialize and wrap into PluginType (with Arc)
        let plugin_type = uninitialized.init_and_wrap().await;

        Ok(PluginInfo {
            tag: config.tag.clone(),
            plugin_type,
            args: config.args.clone(),
        })
    }

    /// Get a plugin instance by tag
    pub fn get_plugin(&self, tag: &str) -> Option<Arc<PluginInfo>> {
        self.plugins.get(tag).map(|entry| entry.clone())
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
