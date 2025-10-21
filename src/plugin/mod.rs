/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin system for RustDNS
//!
//! Provides a flexible plugin architecture supporting:
//! - Server plugins (UDP/TCP listeners)
//! - Executor plugins (DNS forwarding, filtering, etc.)
//! - Matcher plugins (query matching rules)
//! - DataProvider plugins (IP sets, domain lists, etc.)
//!
//! All plugins are registered via factories and instantiated from config.

use crate::config::config::{Config, PluginConfig};
use crate::core::context::DnsContext;
use crate::plugin::executable::forward::ForwardFactory;
use crate::plugin::server::udp::UdpServerFactory;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yml::Value;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

mod dependency;
pub mod executable;
mod registry;
mod server;

pub use registry::PluginRegistry;

/// Initialize all configured plugins
///
/// Creates a registry, registers all built-in factories, and initializes plugins
/// in dependency order. Returns the initialized registry.
///
/// # Arguments
/// * `config` - Server configuration containing plugin definitions
///
/// # Returns
/// * `Ok(Arc<PluginRegistry>)` - Initialized plugin registry
/// * `Err(String)` - Error message if initialization fails
pub async fn init(config: Config) -> Result<Arc<PluginRegistry>, String> {
    // Create and configure the registry
    let mut registry = PluginRegistry::new();
    
    // Register all built-in plugin factories
    registry.register_factory("forward", Box::new(ForwardFactory {}));
    registry.register_factory("udp_server", Box::new(UdpServerFactory {}));
    
    // Wrap in Arc for sharing
    let registry = Arc::new(registry);
    
    // Initialize all plugins (clone Arc to keep a reference)
    registry.clone().init_plugins(config.plugins).await?;
    
    Ok(registry)
}

/// Plugin category classification
#[derive(Clone, Debug, Deserialize)]
pub enum PluginMainType {
    /// Server plugins run continuously (e.g., UDP/TCP listeners)
    Server { tag: String, type_name: String },

    /// Executor plugins process DNS queries (e.g., forwarders, filters)
    Executor { tag: String, type_name: String },

    /// Matcher plugins test queries against rules (e.g., domain lists)
    Matcher { tag: String, type_name: String },

    /// DataProvider plugins provide data sources (e.g., IP sets, GeoIP)
    DataProvider { tag: String, type_name: String },
}

impl PluginMainType {
    /// Get the plugin instance tag
    pub fn tag(&self) -> &str {
        match self {
            PluginMainType::Server { tag, .. }
            | PluginMainType::Executor { tag, .. }
            | PluginMainType::Matcher { tag, .. }
            | PluginMainType::DataProvider { tag, .. } => tag,
        }
    }

    /// Get the plugin type name
    pub fn type_name(&self) -> &str {
        match self {
            PluginMainType::Server { type_name, .. }
            | PluginMainType::Executor { type_name, .. }
            | PluginMainType::Matcher { type_name, .. }
            | PluginMainType::DataProvider { type_name, .. } => type_name,
        }
    }

    /// Get the plugin category kind
    pub fn kind(&self) -> &'static str {
        match self {
            PluginMainType::Server { .. } => "Server",
            PluginMainType::Executor { .. } => "Executor",
            PluginMainType::Matcher { .. } => "Matcher",
            PluginMainType::DataProvider { .. } => "DataProvider",
        }
    }
}

impl Display for PluginMainType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.kind(), self.type_name(), self.tag())
    }
}

/// Core plugin trait that all plugins must implement
#[async_trait]
#[allow(unused)]
pub trait Plugin: Send + Sync + 'static {
    /// Get the plugin's unique tag
    fn tag(&self) -> &str;

    /// Initialize the plugin (called once during server startup)
    async fn init(&mut self);

    /// Execute the plugin's logic on a DNS request context
    async fn execute(&self, context: &mut DnsContext);

    /// Get the plugin's type information
    fn main_type(&self) -> PluginMainType;

    /// Clean up plugin resources (called during shutdown)
    async fn destroy(&mut self);
}

/// Plugin factory trait for creating plugin instances from configuration
#[async_trait]
pub trait PluginFactory: Send + Sync + 'static {
    /// Create a new plugin instance from configuration with registry access
    /// 
    /// # Arguments
    /// * `plugin_info` - Plugin configuration from the config file
    /// * `registry` - Shared reference to the plugin registry for accessing other plugins
    /// 
    /// This method receives a reference-counted pointer to the plugin registry,
    /// allowing plugins to store and use it during their lifecycle.
    fn create(
        &self,
        plugin_info: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<Box<dyn Plugin>, String>;

    /// Get the plugin type for a given tag
    fn plugin_type(&self, tag: &str) -> PluginMainType;

    /// Validate plugin-specific configuration
    ///
    /// Each plugin factory can validate its own configuration format.
    /// Default implementation does nothing (assumes valid).
    fn validate_config(&self, _plugin_info: &PluginConfig) -> Result<(), String> {
        Ok(())
    }

    /// Get plugin dependencies from configuration
    ///
    /// Returns a list of plugin tags that this plugin depends on.
    /// Default implementation returns empty (no dependencies).
    fn get_dependencies(&self, _plugin_info: &PluginConfig) -> Vec<String> {
        vec![]
    }
}

/// Plugin metadata and instance container
#[allow(unused)]
pub struct PluginInfo {
    /// Plugin instance tag (unique identifier)
    pub tag: String,

    /// Plugin type information
    pub plugin_type: PluginMainType,

    /// Plugin-specific configuration arguments
    pub args: Option<Value>,

    /// The actual plugin implementation
    pub plugin: Box<dyn Plugin>,
}
