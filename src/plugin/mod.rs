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

use crate::config::types::{Config, PluginConfig};
use crate::plugin::executor::forward::ForwardFactory;
use crate::plugin::executor::Executor;
use crate::plugin::server::udp::UdpServerFactory;
use async_trait::async_trait;
use serde_yml::Value;
use std::fmt::Debug;
use std::sync::Arc;

mod dependency;
pub mod executor;
pub mod registry;
pub mod server;

pub use registry::PluginRegistry;

use crate::plugin::server::Server;

/// Uninitialized plugin returned by factories
pub enum UninitializedPlugin {
    /// Server plugin (not yet initialized)
    Server(Box<dyn Server>),
    
    /// Executor plugin (not yet initialized)
    Executor(Box<dyn Executor>),
    
    /// Matcher plugin (not yet initialized)
    Matcher(Box<dyn Plugin>),
    
    /// DataProvider plugin (not yet initialized)
    DataProvider(Box<dyn Plugin>),
}

impl UninitializedPlugin {
    /// Initialize the plugin and convert to PluginType (Arc-wrapped)
    pub async fn init_and_wrap(self) -> PluginType {
        match self {
            UninitializedPlugin::Server(mut server) => {
                server.as_mut().init().await;
                PluginType::Server(server.into())
            }
            UninitializedPlugin::Executor(mut executor) => {
                executor.as_mut().init().await;
                PluginType::Executor(executor.into())
            }
            UninitializedPlugin::Matcher(mut matcher) => {
                matcher.as_mut().init().await;
                PluginType::Matcher(matcher.into())
            }
            UninitializedPlugin::DataProvider(mut provider) => {
                provider.as_mut().init().await;
                PluginType::DataProvider(provider.into())
            }
        }
    }
}

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

/// Initialized plugin categorized by type
#[derive(Debug)]
pub enum PluginType {
    /// Server plugins run continuously (e.g., UDP/TCP listeners)
    Server(Arc<dyn Server>),

    /// Executor plugins process DNS queries (e.g., forwarders, filters)
    Executor(Arc<dyn Executor>),

    /// Matcher plugins test queries against rules (e.g., domain lists)
    Matcher(Arc<dyn Plugin>),

    /// DataProvider plugins provide data sources (e.g., IP sets, GeoIP)
    DataProvider(Arc<dyn Plugin>),
}

impl PluginType {
    /// Get the plugin category kind
    pub fn kind(&self) -> &'static str {
        match self {
            PluginType::Server(..) => "Server",
            PluginType::Executor(..) => "Executor",
            PluginType::Matcher(..) => "Matcher",
            PluginType::DataProvider(..) => "DataProvider",
        }
    }

    /// Get a reference to the underlying Plugin trait object
    pub fn as_plugin(&self) -> &dyn Plugin {
        match self {
            PluginType::Server(s) => s.as_ref(),
            PluginType::Executor(e) => e.as_ref(),
            PluginType::Matcher(m) => m.as_ref(),
            PluginType::DataProvider(d) => d.as_ref(),
        }
    }
}

/// Core plugin trait that all plugins must implement
#[async_trait]
#[allow(unused)]
pub trait Plugin: Debug + Send + Sync + 'static {
    /// Get the plugin's unique tag
    fn tag(&self) -> &str;

    /// Initialize the plugin (called once during server startup)
    async fn init(&mut self);

    /// Clean up plugin resources (called during shutdown)
    async fn destroy(&mut self);
}

/// Plugin factory trait for creating plugin instances from configuration
pub trait PluginFactory: Debug + Send + Sync + 'static {
    /// Create a new uninitialized plugin instance from configuration
    ///
    /// # Arguments
    /// * `plugin_info` - Plugin configuration from the config file
    /// * `registry` - Shared reference to the plugin registry for accessing other plugins
    ///
    /// Returns an uninitialized plugin that will be initialized by the registry.
    fn create(
        &self,
        plugin_info: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin, String>;

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
#[derive(Debug)]
pub struct PluginInfo {
    /// Plugin instance tag (unique identifier)
    pub tag: String,

    /// Plugin type information
    pub plugin_type: PluginType,

    /// Plugin-specific configuration arguments
    pub args: Option<Value>,
}

impl PluginInfo {
    /// Get Arc clone of the executor (panics if not an Executor plugin)
    pub fn to_executor(&self) -> Arc<dyn Executor> {
        match &self.plugin_type {
            PluginType::Executor(executor) => executor.clone(),
            _ => panic!("Plugin '{}' is not an Executor", self.tag),
        }
    }

    /// Get reference to the executor (panics if not an Executor plugin)
    pub fn executor(&self) -> &dyn Executor {
        match &self.plugin_type {
            PluginType::Executor(executor) => executor.as_ref(),
            _ => panic!("Plugin '{}' is not an Executor", self.tag),
        }
    }

    /// Get Arc clone of the server (panics if not a Server plugin)
    pub fn to_server(&self) -> Arc<dyn Server> {
        match &self.plugin_type {
            PluginType::Server(server) => server.clone(),
            _ => panic!("Plugin '{}' is not a Server", self.tag),
        }
    }

    /// Get reference to the server (panics if not a Server plugin)
    pub fn server(&self) -> &dyn Server {
        match &self.plugin_type {
            PluginType::Server(server) => server.as_ref(),
            _ => panic!("Plugin '{}' is not a Server", self.tag),
        }
    }

    /// Get reference to underlying Plugin trait object
    pub fn as_plugin(&self) -> &dyn Plugin {
        self.plugin_type.as_plugin()
    }
}
