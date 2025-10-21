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
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::Deserialize;
use serde_yml::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tracing::info;

pub mod executable;
mod server;

lazy_static! {
    /// Global registry of plugin factories
    /// Maps plugin type names to their factory implementations
    static ref FACTORIES: HashMap<&'static str, Box<dyn PluginFactory>> = {
        let mut m: HashMap<&str, Box<dyn PluginFactory>> = HashMap::new();
        m.insert("forward", Box::new(ForwardFactory {}));
        m.insert("udp_server", Box::new(UdpServerFactory {}));
        m
    };
    
    /// Global registry of initialized plugin instances
    /// Maps plugin tags to their runtime instances
    static ref PLUGINS: DashMap<String, Arc<PluginInfo>> = DashMap::new();
}

/// Initialize all configured plugins
///
/// Iterates through the config, creating each plugin via its factory,
/// calling its init() method, and registering it in the global plugin map.
pub async fn init(config: Config) {
    info!("Starting plugin initialization ({} plugins)", config.plugins.len());
    
    // Each plugin type has a factory that creates plugin instances
    for plugin_config in config.plugins {
        let key = plugin_config.plugin_type.as_str();
        let factory = FACTORIES
            .get(key)
            .unwrap_or_else(|| panic!("Plugin type '{}' not found in registry", key));
        let mut plugin_info = PluginInfo::from(&plugin_config, &factory);

        info!("Initializing plugin: {} (tag: {})", plugin_info.plugin_type, plugin_info.tag);
        plugin_info.plugin.as_mut().init().await;

        PLUGINS.insert(plugin_config.tag.to_owned(), Arc::new(plugin_info));
    }
    
    info!("All plugins initialized successfully");
}

/// Get a plugin instance by tag
///
/// Returns None if no plugin with the given tag exists
pub fn get_plugin(tag: &str) -> Option<Arc<PluginInfo>> {
    Some(PLUGINS.get(tag)?.clone())
}

/// Register or update a plugin instance
#[allow(unused)]
pub fn set_plugin(plugin_info: Arc<PluginInfo>) {
    PLUGINS.insert(plugin_info.tag.to_owned(), plugin_info);
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
    /// Create a new plugin instance from configuration
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin>;

    /// Get the plugin type for a given tag
    fn plugin_type(&self, tag: &str) -> PluginMainType;
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

impl PluginInfo {
    pub fn from(config: &PluginConfig, factory: &Box<dyn PluginFactory>) -> PluginInfo {
        let plugin = factory.create(config);

        PluginInfo {
            tag: config.tag.clone(),
            plugin_type: factory.plugin_type(&config.tag),
            args: config.args.clone(),
            plugin,
        }
    }
}
