/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin system for ForgeDNS
//!
//! Provides a flexible plugin architecture supporting:
//! - Server plugins (UDP/TCP listeners)
//! - Executor plugins (DNS forwarding, filtering, etc.)
//! - Matcher plugins (query matching rules)
//! - DataProvider plugins (IP sets, domain lists, etc.)
//!
//! All plugins are registered via factories and instantiated from config.

mod dependency;
pub mod executor;
pub mod matcher;
pub mod provider;
pub mod registry;
pub mod server;

use crate::config::types::{Config, PluginConfig};
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::Executor;
use crate::plugin::matcher::Matcher;
use crate::plugin::provider::Provider;
use crate::plugin::server::Server;
use async_trait::async_trait;
pub use registry::PluginRegistry;
use serde_yml::Value;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;

/// Uninitialized plugin returned by factories
#[allow(unused)]
pub enum UninitializedPlugin {
    /// Server plugin (not yet initialized)
    Server(Box<dyn Server>),

    /// Executor plugin (not yet initialized)
    Executor(Box<dyn Executor>),

    /// Matcher plugin (not yet initialized)
    Matcher(Box<dyn Matcher>),

    /// DataProvider plugin (not yet initialized)
    Provider(Box<dyn Provider>),
}

impl UninitializedPlugin {
    /// Initialize the plugin and convert to PluginType (Arc-wrapped)
    pub async fn init_and_wrap(self) -> PluginHolder {
        match self {
            UninitializedPlugin::Server(mut server) => {
                server.as_mut().init().await;
                PluginHolder::Server(server.into())
            }
            UninitializedPlugin::Executor(mut executor) => {
                executor.as_mut().init().await;
                PluginHolder::Executor(executor.into())
            }
            UninitializedPlugin::Matcher(mut matcher) => {
                matcher.as_mut().init().await;
                PluginHolder::Matcher(matcher.into())
            }
            UninitializedPlugin::Provider(mut provider) => {
                provider.as_mut().init().await;
                PluginHolder::Provider(provider.into())
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
/// * `Err(DnsError)` - Error message if initialization fails
pub async fn init(config: Config) -> Result<Arc<PluginRegistry>> {
    // Create and configure the registry
    let mut registry = PluginRegistry::new();

    // Register all built-in plugin factories from inventory
    register_factories_from_inventory(&mut registry)?;

    // Wrap in Arc for sharing
    let registry = Arc::new(registry);

    // Initialize all plugins (clone Arc to keep a reference)
    registry.clone().init_plugins(config.plugins).await?;

    Ok(registry)
}

pub struct FactoryRegistration {
    pub plugin_type: &'static str,
    pub constructor: fn() -> Box<dyn PluginFactory>,
}

inventory::collect!(FactoryRegistration);

#[macro_export]
macro_rules! register_plugin_factory {
    ($plugin_type:expr, $factory_ctor:expr) => {
        inventory::submit! {
            $crate::plugin::FactoryRegistration {
                plugin_type: $plugin_type,
                constructor: || -> Box<dyn $crate::plugin::PluginFactory> {
                    Box::new($factory_ctor)
                },
            }
        }
    };
}

fn register_factories_from_inventory(registry: &mut PluginRegistry) -> Result<()> {
    let mut seen_plugin_types = HashSet::new();

    for registration in inventory::iter::<FactoryRegistration> {
        if !seen_plugin_types.insert(registration.plugin_type) {
            return Err(DnsError::plugin(format!(
                "Duplicate plugin type '{}' registered in inventory",
                registration.plugin_type
            )));
        }

        registry.register_factory(registration.plugin_type, (registration.constructor)());
    }

    Ok(())
}

#[derive(Debug)]
pub enum PluginType {
    Server,
    Executor,
    Matcher,
    Provider,
}

/// Initialized plugin categorized by type
/// Initialize the plugin and wrap into PluginHolder (Arc-wrapped)
#[derive(Debug)]
#[allow(unused)]
pub enum PluginHolder {
    /// Server plugins run continuously (e.g., UDP/TCP listeners)
    Server(Arc<dyn Server>),

    /// Executor plugins process DNS queries (e.g., forwarders, filters)
    Executor(Arc<dyn Executor>),

    /// Matcher plugins test queries against rules (e.g., domain lists)
    Matcher(Arc<dyn Matcher>),

    /// DataProvider plugins provide data sources (e.g., IP sets, GeoIP)
    Provider(Arc<dyn Provider>),
}

#[allow(unused)]
impl PluginHolder {
    /// Get the plugin category kind
    pub fn kind(&self) -> &'static str {
        match self {
            PluginHolder::Server(..) => "Server",
            PluginHolder::Executor(..) => "Executor",
            PluginHolder::Matcher(..) => "Matcher",
            PluginHolder::Provider(..) => "Provider",
        }
    }

    /// Get the plugin category enum
    pub fn plugin_type(&self) -> PluginType {
        match self {
            PluginHolder::Server(..) => PluginType::Server,
            PluginHolder::Executor(..) => PluginType::Executor,
            PluginHolder::Matcher(..) => PluginType::Matcher,
            PluginHolder::Provider(..) => PluginType::Provider,
        }
    }

    /// Get a reference to the underlying Plugin trait object
    pub fn as_plugin(&self) -> &dyn Plugin {
        match self {
            PluginHolder::Server(s) => s.as_ref(),
            PluginHolder::Executor(e) => e.as_ref(),
            PluginHolder::Matcher(m) => m.as_ref(),
            PluginHolder::Provider(d) => d.as_ref(),
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
    async fn destroy(&self);
}

/// Plugin factory trait for creating plugin instances from configuration
pub trait PluginFactory: Debug + Send + Sync + 'static {
    /// # Step 1
    /// Validate plugin-specific configuration
    ///
    /// Each plugin factory can validate its own configuration format.
    /// Default implementation does nothing (assumes valid).
    fn validate_config(&self, _plugin_config: &PluginConfig) -> Result<()> {
        Ok(())
    }

    /// # Step 2
    /// Get plugin dependencies from configuration
    ///
    /// Returns a list of plugin tags that this plugin depends on.
    /// Default implementation returns empty (no dependencies).
    fn get_dependencies(&self, _plugin_config: &PluginConfig) -> Vec<String> {
        vec![]
    }

    /// # Step 3
    /// Create a new uninitialized plugin instance from configuration
    ///
    /// # Arguments
    /// * `plugin_info` - Plugin configuration from the config file
    /// * `registry` - Shared reference to the plugin registry for accessing other plugins
    ///
    /// Returns an uninitialized plugin that will be initialized by the registry.
    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin>;

    /// Create a plugin from sequence quick setup syntax: `type [param...]`.
    ///
    /// `tag` is a synthetic runtime-only identifier generated by sequence.
    fn quick_setup(
        &self,
        _tag: &str,
        _param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        Err(DnsError::plugin("quick setup is not supported"))
    }
}

/// Plugin metadata and instance container
#[allow(unused)]
#[derive(Debug)]
pub struct PluginInfo {
    /// Plugin instance tag (unique identifier)
    pub tag: String,

    pub plugin_type: PluginType,

    /// Plugin type information
    plugin_holder: PluginHolder,

    /// Plugin-specific configuration arguments
    pub args: Option<Value>,
}

#[allow(unused)]
impl PluginInfo {
    /// Get Arc clone of the executor (panics if not an Executor plugin)
    pub fn to_executor(&self) -> Arc<dyn Executor> {
        match &self.plugin_holder {
            PluginHolder::Executor(executor) => executor.clone(),
            _ => panic!("Plugin '{}' is not an Executor", self.tag),
        }
    }

    /// Get reference to the executor (panics if not an Executor plugin)
    pub fn executor(&self) -> &dyn Executor {
        match &self.plugin_holder {
            PluginHolder::Executor(executor) => executor.as_ref(),
            _ => panic!("Plugin '{}' is not an Executor", self.tag),
        }
    }

    /// Get Arc clone of the server (panics if not a Server plugin)
    pub fn to_server(&self) -> Arc<dyn Server> {
        match &self.plugin_holder {
            PluginHolder::Server(server) => server.clone(),
            _ => panic!("Plugin '{}' is not a Server", self.tag),
        }
    }

    /// Get Arc clone of the matcher (panics if not a Matcher plugin)
    pub fn to_matcher(&self) -> Arc<dyn Matcher> {
        match &self.plugin_holder {
            PluginHolder::Matcher(matcher) => matcher.clone(),
            _ => panic!("Plugin '{}' is not a Matcher", self.tag),
        }
    }

    /// Get Arc clone of the provider (panics if not a Provider plugin)
    pub fn to_provider(&self) -> Arc<dyn Provider> {
        match &self.plugin_holder {
            PluginHolder::Provider(provider) => provider.clone(),
            _ => panic!("Plugin '{}' is not a Provider", self.tag),
        }
    }

    /// Get reference to the server (panics if not a Server plugin)
    pub fn server(&self) -> &dyn Server {
        match &self.plugin_holder {
            PluginHolder::Server(server) => server.as_ref(),
            _ => panic!("Plugin '{}' is not a Server", self.tag),
        }
    }

    /// Get reference to the matcher (panics if not a Matcher plugin)
    pub fn matcher(&self) -> &dyn Matcher {
        match &self.plugin_holder {
            PluginHolder::Matcher(matcher) => matcher.as_ref(),
            _ => panic!("Plugin '{}' is not a Matcher", self.tag),
        }
    }

    /// Get reference to the provider (panics if not a Provider plugin)
    pub fn provider(&self) -> &dyn Provider {
        match &self.plugin_holder {
            PluginHolder::Provider(provider) => provider.as_ref(),
            _ => panic!("Plugin '{}' is not a Provider", self.tag),
        }
    }

    /// Get reference to underlying Plugin trait object
    pub fn as_plugin(&self) -> &dyn Plugin {
        self.plugin_holder.as_plugin()
    }
}
