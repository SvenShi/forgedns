/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin system and registry for ForgeDNS.
//!
//! ForgeDNS is assembled around plugins instead of hard-coded protocol or
//! policy branches. This module provides the common lifecycle and registration
//! machinery for four plugin categories:
//!
//! - [`server`]: inbound protocol listeners that translate network traffic into
//!   request handling.
//! - [`executor`]: active processing stages that forward, cache, rewrite, or
//!   produce side effects.
//! - [`matcher`]: predicates used by sequence logic to branch on request or
//!   response state.
//! - [`provider`]: reusable datasets such as domain and IP membership sources.
//!
//! Initialization flow:
//!
//! - factories are registered through [`crate::register_plugin_factory!`];
//! - runtime configuration is validated against the registered plugin types;
//! - plugin dependencies are resolved in category-aware order; and
//! - concrete plugin instances are initialized and stored in [`PluginRegistry`].
//!
//! This keeps protocol handling, policy logic, and reusable datasets composable
//! while preserving a single request pipeline centered on
//! [`crate::core::context::DnsContext`].

pub(crate) mod dependency;
pub mod executor;
pub mod matcher;
pub mod provider;
pub mod registry;
pub mod server;

pub(crate) mod test_utils;

use crate::api::ApiRegister;
use crate::config::types::{Config, PluginConfig};
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::Executor;
use crate::plugin::matcher::Matcher;
use crate::plugin::provider::Provider;
use crate::plugin::server::Server;
use async_trait::async_trait;
pub use dependency::DependencyGraphReport;
use futures::future::BoxFuture;
pub use registry::PluginRegistry;
use serde_yaml_ng::Value;
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
    pub async fn init_and_wrap(self) -> Result<PluginHolder> {
        match self {
            UninitializedPlugin::Server(mut server) => {
                server.as_mut().init().await?;
                Ok(PluginHolder::Server(server.into()))
            }
            UninitializedPlugin::Executor(mut executor) => {
                executor.as_mut().init().await?;
                Ok(PluginHolder::Executor(executor.into()))
            }
            UninitializedPlugin::Matcher(mut matcher) => {
                matcher.as_mut().init().await?;
                Ok(PluginHolder::Matcher(matcher.into()))
            }
            UninitializedPlugin::Provider(mut provider) => {
                provider.as_mut().init().await?;
                Ok(PluginHolder::Provider(provider.into()))
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
pub async fn init(
    config: Config,
    api_register: Option<ApiRegister>,
) -> Result<Arc<PluginRegistry>> {
    let mut registry = PluginRegistry::with_api(api_register);

    // Register all built-in plugin factories from inventory
    register_factories_from_inventory(&mut registry)?;

    // Wrap in Arc for sharing
    let registry = Arc::new(registry);

    // Initialize all plugins (clone Arc to keep a reference)
    if let Err(err) = registry.clone().init_plugins(config.plugins).await {
        registry.destory().await;
        return Err(err);
    }

    Ok(registry)
}

pub fn validate_configuration(config: &Config) -> Result<()> {
    analyze_configuration(config).map(|_| ())
}

pub fn analyze_configuration(config: &Config) -> Result<DependencyGraphReport> {
    use crate::plugin::dependency;
    use std::collections::{HashMap, HashSet};

    let mut factories = HashMap::new();
    let mut factory_kinds = HashMap::new();
    let mut seen_plugin_types = HashSet::new();

    for registration in inventory::iter::<FactoryRegistration> {
        if !seen_plugin_types.insert(registration.plugin_type) {
            return Err(DnsError::plugin(format!(
                "Duplicate plugin type '{}' registered in inventory",
                registration.plugin_type
            )));
        }
        factories.insert(
            registration.plugin_type.to_string(),
            (registration.constructor)(),
        );
        factory_kinds.insert(
            registration.plugin_type.to_string(),
            dependency_kind_from_module_path(registration.module_path),
        );
    }

    for plugin in &config.plugins {
        if !factories.contains_key(&plugin.plugin_type) {
            return Err(DnsError::plugin(format!(
                "Unknown plugin type: {}",
                plugin.plugin_type
            )));
        }
    }

    let get_deps = |config: &PluginConfig| {
        factories
            .get(&config.plugin_type)
            .map(|factory| factory.get_dependency_specs(config))
            .unwrap_or_default()
    };
    let get_kind = |config: &PluginConfig| {
        factory_kinds
            .get(&config.plugin_type)
            .copied()
            .unwrap_or(dependency::DependencyKind::Unknown)
    };

    dependency::analyze_dependencies(&config.plugins, &get_deps, &get_kind)
}

pub struct FactoryRegistration {
    pub plugin_type: &'static str,
    pub module_path: &'static str,
    pub constructor: fn() -> Box<dyn PluginFactory>,
}

inventory::collect!(FactoryRegistration);

#[macro_export]
macro_rules! register_plugin_factory {
    ($plugin_type:expr, $factory_ctor:expr) => {
        inventory::submit! {
            $crate::plugin::FactoryRegistration {
                plugin_type: $plugin_type,
                module_path: module_path!(),
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

        registry.register_factory(
            registration.plugin_type,
            dependency_kind_from_module_path(registration.module_path),
            (registration.constructor)(),
        );
    }

    Ok(())
}

fn dependency_kind_from_module_path(module_path: &str) -> dependency::DependencyKind {
    if module_path.contains("::plugin::server::") {
        return dependency::DependencyKind::Server;
    }
    if module_path.contains("::plugin::executor::") {
        return dependency::DependencyKind::Executor;
    }
    if module_path.contains("::plugin::matcher::") {
        return dependency::DependencyKind::Matcher;
    }
    if module_path.contains("::plugin::provider::") {
        return dependency::DependencyKind::Provider;
    }
    dependency::DependencyKind::Unknown
}

pub(crate) fn registered_plugin_kind(plugin_type: &str) -> Option<dependency::DependencyKind> {
    inventory::iter::<FactoryRegistration>
        .into_iter()
        .find(|registration| registration.plugin_type == plugin_type)
        .map(|registration| dependency_kind_from_module_path(registration.module_path))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginCreateContext {
    pub dependents: Vec<PluginDependent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDependent {
    pub tag: String,
    pub plugin_type: String,
    pub kind: dependency::DependencyKind,
    pub field: String,
}

fn factory_from_inventory(plugin_type: &str) -> Option<Box<dyn PluginFactory>> {
    inventory::iter::<FactoryRegistration>
        .into_iter()
        .find(|registration| registration.plugin_type == plugin_type)
        .map(|registration| (registration.constructor)())
}

pub(crate) fn quick_setup_dependency_specs(
    plugin_type: &str,
    param: Option<&str>,
) -> Vec<dependency::DependencySpec> {
    factory_from_inventory(plugin_type)
        .map(|factory| factory.get_quick_setup_dependency_specs(param))
        .unwrap_or_default()
}

pub(crate) fn format_quick_setup_dependency_field(
    owner_field: &str,
    plugin_type: &str,
    nested_field: &str,
) -> String {
    let owner_field = owner_field.trim();
    let owner_field = if owner_field.is_empty() {
        "<unknown>"
    } else {
        owner_field
    };
    let nested_field = nested_field.trim();
    let nested_field = if nested_field.is_empty() {
        "<unknown>"
    } else {
        nested_field
    };
    format!("{owner_field} -> quick_setup({plugin_type}).{nested_field}")
}

pub(crate) fn expand_quick_setup_dependency_specs(
    owner_field: &str,
    plugin_type: &str,
    param: Option<&str>,
) -> Vec<dependency::DependencySpec> {
    quick_setup_dependency_specs(plugin_type, param)
        .into_iter()
        .map(|mut spec| {
            spec.field = format_quick_setup_dependency_field(owner_field, plugin_type, &spec.field);
            spec
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    async fn init(&mut self) -> Result<()>;

    /// Clean up plugin resources (called during shutdown)
    async fn destroy(&self) -> Result<()>;
}

/// Plugin factory trait for creating plugin instances from configuration
pub trait PluginFactory: Debug + Send + Sync + 'static {
    /// # Step 1
    /// Get structured dependency specs used by startup graph validation.
    fn get_dependency_specs(
        &self,
        _plugin_config: &PluginConfig,
    ) -> Vec<dependency::DependencySpec> {
        vec![]
    }

    /// Optional dependency extraction for runtime-only quick setup forms.
    ///
    /// Returned dependency fields should be relative to the quick-setup plugin
    /// itself, for example `domain_set_tags[0]`.
    fn get_quick_setup_dependency_specs(
        &self,
        _param: Option<&str>,
    ) -> Vec<dependency::DependencySpec> {
        vec![]
    }

    /// Optional startup-only preparation hook.
    ///
    /// Factories can use this to perform startup prerequisites before
    /// dependency sorting and normal plugin construction begin.
    fn prepare_startup<'a>(
        &'a self,
        _plugin_config: &'a PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// # Step 2
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
        _context: &PluginCreateContext,
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

    /// Concrete plugin type string from configuration (e.g. "forward")
    pub plugin_name: String,

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_kind_from_module_path_for_all_registered_plugins() {
        let mut server_count = 0usize;
        let mut executor_count = 0usize;
        let mut matcher_count = 0usize;
        let mut provider_count = 0usize;

        for registration in inventory::iter::<FactoryRegistration> {
            match dependency_kind_from_module_path(registration.module_path) {
                dependency::DependencyKind::Server => server_count += 1,
                dependency::DependencyKind::Executor => executor_count += 1,
                dependency::DependencyKind::Matcher => matcher_count += 1,
                dependency::DependencyKind::Provider => provider_count += 1,
                dependency::DependencyKind::Any | dependency::DependencyKind::Unknown => {
                    panic!(
                        "plugin type '{}' from '{}' resolved to unsupported kind",
                        registration.plugin_type, registration.module_path
                    )
                }
            }
        }

        assert!(server_count > 0, "server plugins should be registered");
        assert!(executor_count > 0, "executor plugins should be registered");
        assert!(matcher_count > 0, "matcher plugins should be registered");
        assert!(provider_count > 0, "provider plugins should be registered");
    }
}
