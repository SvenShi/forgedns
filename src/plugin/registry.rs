// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Plugin registry for managing plugin factories and instances
//!
//! Provides a centralized registry for managing plugin lifecycle,
//! enabling better testability and support for multiple server instances.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use tracing::{debug, error, info, warn};

use crate::api::ApiRegister;
use crate::api::control::{AppController, ControlRequestError};
use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use crate::plugin::dependency::DependencyKind;
use crate::plugin::executor::Executor;
use crate::plugin::matcher::Matcher;
use crate::plugin::provider::{Provider, register_reload_api_route};
use crate::plugin::{PluginCreateContext, PluginDependent, PluginFactory, PluginInfo, PluginType};

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
        factory.quick_setup(tag, param, self.clone())
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
            factory.prepare_startup(plugin_config, self.clone()).await?;
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
                register_reload_api_route(
                    self.api_register.as_ref(),
                    self.clone(),
                    &plugin_config.tag,
                )?;
            }
            if let Ok(mut order) = self.init_order.lock() {
                order.push(plugin_config.tag.clone());
            }
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
        let uninitialized = factory.create(config, self.clone(), context)?;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeInitPlan {
    report: crate::plugin::dependency::DependencyGraphReport,
    skipped_providers: Vec<SkippedProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkippedProvider {
    tag: String,
    plugin_type: String,
}

fn build_runtime_init_plan(
    report: &crate::plugin::dependency::DependencyGraphReport,
) -> RuntimeInitPlan {
    let mut edges_by_source: HashMap<&str, Vec<&crate::plugin::dependency::DependencyGraphEdge>> =
        HashMap::new();
    for edge in &report.edges {
        edges_by_source
            .entry(edge.source_tag.as_str())
            .or_default()
            .push(edge);
    }

    let mut live_tags = HashSet::new();
    let mut stack = Vec::new();

    for node in &report.nodes {
        if node.kind != DependencyKind::Provider && live_tags.insert(node.tag.clone()) {
            stack.push(node.tag.clone());
        }
    }

    while let Some(tag) = stack.pop() {
        if let Some(edges) = edges_by_source.get(tag.as_str()) {
            for edge in edges {
                if live_tags.insert(edge.target_tag.clone()) {
                    stack.push(edge.target_tag.clone());
                }
            }
        }
    }

    let mut skipped_providers = report
        .nodes
        .iter()
        .filter(|node| node.kind == DependencyKind::Provider && !live_tags.contains(&node.tag))
        .map(|node| SkippedProvider {
            tag: node.tag.clone(),
            plugin_type: node.plugin_type.clone(),
        })
        .collect::<Vec<_>>();
    skipped_providers.sort_by(|a, b| {
        a.tag
            .cmp(&b.tag)
            .then_with(|| a.plugin_type.cmp(&b.plugin_type))
    });

    RuntimeInitPlan {
        report: crate::plugin::dependency::DependencyGraphReport {
            nodes: report
                .nodes
                .iter()
                .filter(|node| live_tags.contains(&node.tag))
                .cloned()
                .collect(),
            edges: report
                .edges
                .iter()
                .filter(|edge| {
                    live_tags.contains(&edge.source_tag) && live_tags.contains(&edge.target_tag)
                })
                .cloned()
                .collect(),
            init_order: report
                .init_order
                .iter()
                .filter(|tag| live_tags.contains(*tag))
                .cloned()
                .collect(),
        },
        skipped_providers,
    }
}

fn build_create_contexts(
    report: &crate::plugin::dependency::DependencyGraphReport,
) -> HashMap<String, PluginCreateContext> {
    let node_map = report
        .nodes
        .iter()
        .map(|node| (node.tag.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut dependents_by_target: HashMap<String, Vec<PluginDependent>> = HashMap::new();

    for edge in &report.edges {
        let Some(source_node) = node_map.get(edge.source_tag.as_str()) else {
            continue;
        };
        dependents_by_target
            .entry(edge.target_tag.clone())
            .or_default()
            .push(PluginDependent {
                tag: edge.source_tag.clone(),
                plugin_type: source_node.plugin_type.clone(),
                kind: source_node.kind,
                field: edge.field.clone(),
            });
    }

    dependents_by_target
        .into_iter()
        .map(|(tag, mut dependents)| {
            dependents.sort_by(|a, b| {
                a.tag
                    .cmp(&b.tag)
                    .then_with(|| a.field.cmp(&b.field))
                    .then_with(|| a.plugin_type.cmp(&b.plugin_type))
            });
            (tag, PluginCreateContext { dependents })
        })
        .collect()
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::collections::HashMap as StdHashMap;
    use std::io::{self, Write};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::config::types::PluginConfig;
    use crate::plugin::dependency::{
        DependencyGraphEdge, DependencyGraphNode, DependencyGraphReport, DependencySpec,
    };
    use crate::plugin::executor::sequence::SequenceFactory;
    use crate::plugin::matcher::qname::QnameFactory;
    use crate::plugin::provider::Provider;
    use crate::plugin::{Plugin, UninitializedPlugin};
    use crate::proto::Name;

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

    #[derive(Debug)]
    struct CaptureProvider {
        tag: String,
        rules: Vec<String>,
    }

    #[async_trait]
    impl Plugin for CaptureProvider {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for CaptureProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn contains_name(&self, _name: &Name) -> bool {
            false
        }

        fn supports_domain_matching(&self) -> bool {
            !self.rules.is_empty()
        }
    }

    #[derive(Debug)]
    struct CaptureProviderFactory {
        captured: Arc<StdMutex<StdHashMap<String, PluginCreateContext>>>,
        created_tags: Arc<StdMutex<Vec<String>>>,
    }

    impl PluginFactory for CaptureProviderFactory {
        fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
            plugin_config
                .args
                .as_ref()
                .and_then(|value| value.as_str())
                .map(|target| vec![DependencySpec::provider("args", target)])
                .unwrap_or_default()
        }

        fn create(
            &self,
            plugin_config: &PluginConfig,
            _registry: Arc<PluginRegistry>,
            context: &PluginCreateContext,
        ) -> Result<UninitializedPlugin> {
            self.captured
                .lock()
                .expect("context mutex poisoned")
                .insert(plugin_config.tag.clone(), context.clone());
            self.created_tags
                .lock()
                .expect("created tags mutex poisoned")
                .push(plugin_config.tag.clone());
            Ok(UninitializedPlugin::Provider(Box::new(CaptureProvider {
                tag: plugin_config.tag.clone(),
                rules: vec!["example.com".to_string()],
            })))
        }
    }

    #[tokio::test]
    async fn test_init_plugins_passes_quick_setup_dependents_to_create_context() {
        let captured = Arc::new(StdMutex::new(StdHashMap::new()));
        let created_tags = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry.register_factory(
            "sequence",
            DependencyKind::Executor,
            Box::new(SequenceFactory {}),
        );
        registry.register_factory("qname", DependencyKind::Matcher, Box::new(QnameFactory {}));
        registry.register_factory(
            "capture_provider",
            DependencyKind::Provider,
            Box::new(CaptureProviderFactory {
                captured: captured.clone(),
                created_tags,
            }),
        );
        let registry = Arc::new(registry);

        let sequence_args = serde_yaml_ng::from_str(
            r#"
- matches:
    - qname $zzz_provider
  exec: accept
"#,
        )
        .expect("sequence args should parse");
        let configs = vec![
            PluginConfig {
                tag: "seq".to_string(),
                plugin_type: "sequence".to_string(),
                args: Some(sequence_args),
            },
            PluginConfig {
                tag: "zzz_provider".to_string(),
                plugin_type: "capture_provider".to_string(),
                args: None,
            },
        ];

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugin init should succeed");

        let context = captured
            .lock()
            .expect("context mutex poisoned")
            .get("zzz_provider")
            .cloned()
            .expect("create context should be captured");
        assert_eq!(
            context.dependents,
            vec![PluginDependent {
                tag: "seq".to_string(),
                plugin_type: "sequence".to_string(),
                kind: DependencyKind::Executor,
                field: "args[0].matches[0] -> quick_setup(qname).domain_set_tags[0]".to_string(),
            }]
        );

        registry.destory().await;
    }

    #[test]
    fn test_build_runtime_init_plan_skips_unreachable_provider_chain() {
        let report = DependencyGraphReport {
            nodes: vec![
                DependencyGraphNode {
                    tag: "entry".to_string(),
                    plugin_type: "sequence".to_string(),
                    kind: DependencyKind::Executor,
                },
                DependencyGraphNode {
                    tag: "live_provider".to_string(),
                    plugin_type: "capture_provider".to_string(),
                    kind: DependencyKind::Provider,
                },
                DependencyGraphNode {
                    tag: "live_leaf".to_string(),
                    plugin_type: "capture_provider".to_string(),
                    kind: DependencyKind::Provider,
                },
                DependencyGraphNode {
                    tag: "dead_provider".to_string(),
                    plugin_type: "capture_provider".to_string(),
                    kind: DependencyKind::Provider,
                },
                DependencyGraphNode {
                    tag: "dead_leaf".to_string(),
                    plugin_type: "capture_provider".to_string(),
                    kind: DependencyKind::Provider,
                },
            ],
            edges: vec![
                DependencyGraphEdge {
                    source_tag: "entry".to_string(),
                    field: "args[0].matches[0]".to_string(),
                    target_tag: "live_provider".to_string(),
                    expected_kind: DependencyKind::Provider,
                    expected_plugin_type: None,
                },
                DependencyGraphEdge {
                    source_tag: "live_provider".to_string(),
                    field: "args".to_string(),
                    target_tag: "live_leaf".to_string(),
                    expected_kind: DependencyKind::Provider,
                    expected_plugin_type: None,
                },
                DependencyGraphEdge {
                    source_tag: "dead_provider".to_string(),
                    field: "args".to_string(),
                    target_tag: "dead_leaf".to_string(),
                    expected_kind: DependencyKind::Provider,
                    expected_plugin_type: None,
                },
            ],
            init_order: vec![
                "dead_leaf".to_string(),
                "live_leaf".to_string(),
                "dead_provider".to_string(),
                "live_provider".to_string(),
                "entry".to_string(),
            ],
        };

        let runtime_plan = build_runtime_init_plan(&report);

        assert_eq!(
            runtime_plan.report.init_order,
            vec![
                "live_leaf".to_string(),
                "live_provider".to_string(),
                "entry".to_string(),
            ]
        );
        assert_eq!(
            runtime_plan.skipped_providers,
            vec![
                SkippedProvider {
                    tag: "dead_leaf".to_string(),
                    plugin_type: "capture_provider".to_string(),
                },
                SkippedProvider {
                    tag: "dead_provider".to_string(),
                    plugin_type: "capture_provider".to_string(),
                },
            ]
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_init_plugins_filters_create_contexts_to_live_dependents() {
        let captured = Arc::new(StdMutex::new(StdHashMap::new()));
        let created_tags = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry.register_factory("qname", DependencyKind::Matcher, Box::new(QnameFactory {}));
        registry.register_factory(
            "capture_provider",
            DependencyKind::Provider,
            Box::new(CaptureProviderFactory {
                captured: captured.clone(),
                created_tags: created_tags.clone(),
            }),
        );
        let registry = Arc::new(registry);

        let configs = vec![
            PluginConfig {
                tag: "orphan_provider".to_string(),
                plugin_type: "capture_provider".to_string(),
                args: Some(serde_yaml_ng::Value::String("shared_provider".to_string())),
            },
            PluginConfig {
                tag: "shared_provider".to_string(),
                plugin_type: "capture_provider".to_string(),
                args: None,
            },
            PluginConfig {
                tag: "entry_provider".to_string(),
                plugin_type: "capture_provider".to_string(),
                args: Some(serde_yaml_ng::Value::String("shared_provider".to_string())),
            },
            PluginConfig {
                tag: "match_qname".to_string(),
                plugin_type: "qname".to_string(),
                args: Some(
                    serde_yaml_ng::from_str(
                        r#"
- "$entry_provider"
"#,
                    )
                    .expect("qname args should parse"),
                ),
            },
        ];

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugin init should succeed");

        let contexts = captured.lock().expect("context mutex poisoned");
        assert!(!contexts.contains_key("orphan_provider"));
        assert_eq!(
            contexts
                .get("shared_provider")
                .expect("shared provider should be created")
                .dependents,
            vec![PluginDependent {
                tag: "entry_provider".to_string(),
                plugin_type: "capture_provider".to_string(),
                kind: DependencyKind::Provider,
                field: "args".to_string(),
            }]
        );

        let created_tags = created_tags.lock().expect("created tags mutex poisoned");
        assert_eq!(
            created_tags.as_slice(),
            ["shared_provider", "entry_provider"]
        );

        registry.destory().await;
    }

    #[derive(Clone, Default)]
    struct SharedLogBuffer {
        bytes: Arc<StdMutex<Vec<u8>>>,
    }

    impl SharedLogBuffer {
        fn contents(&self) -> String {
            String::from_utf8(
                self.bytes
                    .lock()
                    .expect("log buffer mutex poisoned")
                    .clone(),
            )
            .expect("log output should be utf-8")
        }
    }

    struct SharedLogWriter {
        bytes: Arc<StdMutex<Vec<u8>>>,
    }

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("log buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter {
                bytes: self.bytes.clone(),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_init_plugins_warns_when_skipping_unused_provider() {
        let captured = Arc::new(StdMutex::new(StdHashMap::new()));
        let created_tags = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry.register_factory(
            "capture_provider",
            DependencyKind::Provider,
            Box::new(CaptureProviderFactory {
                captured,
                created_tags: created_tags.clone(),
            }),
        );
        let registry = Arc::new(registry);
        let configs = vec![PluginConfig {
            tag: "orphan_provider".to_string(),
            plugin_type: "capture_provider".to_string(),
            args: None,
        }];

        let logs = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugin init should succeed");

        assert!(
            created_tags
                .lock()
                .expect("created tags mutex poisoned")
                .is_empty(),
            "unused provider should not be created"
        );
        let output = logs.contents();
        assert!(output.contains("WARN"));
        assert!(output.contains("orphan_provider"));
        assert!(output.contains("capture_provider"));
        assert!(output.contains("no live dependents"));
        assert!(output.contains("skipped provider initialization"));

        registry.destory().await;
    }

    #[derive(Debug)]
    struct ReloadableProvider {
        tag: String,
        reload_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for ReloadableProvider {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for ReloadableProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn contains_name(&self, _name: &Name) -> bool {
            false
        }

        async fn reload(&self) -> Result<()> {
            self.reload_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn supports_domain_matching(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct ReloadableProviderFactory {
        reload_count: Arc<AtomicUsize>,
    }

    impl PluginFactory for ReloadableProviderFactory {
        fn create(
            &self,
            plugin_config: &PluginConfig,
            _registry: Arc<PluginRegistry>,
            _context: &PluginCreateContext,
        ) -> Result<UninitializedPlugin> {
            Ok(UninitializedPlugin::Provider(Box::new(
                ReloadableProvider {
                    tag: plugin_config.tag.clone(),
                    reload_count: self.reload_count.clone(),
                },
            )))
        }
    }

    #[tokio::test]
    async fn test_reload_provider_calls_runtime_provider_reload() {
        let reload_count = Arc::new(AtomicUsize::new(0));
        let mut registry = PluginRegistry::new();
        registry.register_factory("qname", DependencyKind::Matcher, Box::new(QnameFactory {}));
        registry.register_factory(
            "reloadable_provider",
            DependencyKind::Provider,
            Box::new(ReloadableProviderFactory {
                reload_count: reload_count.clone(),
            }),
        );
        let registry = Arc::new(registry);

        let configs = vec![
            PluginConfig {
                tag: "reloadable".to_string(),
                plugin_type: "reloadable_provider".to_string(),
                args: None,
            },
            PluginConfig {
                tag: "match_qname".to_string(),
                plugin_type: "qname".to_string(),
                args: Some(serde_yaml_ng::from_str("- \"$reloadable\"").unwrap()),
            },
        ];

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugin init should succeed");

        registry
            .reload_provider("reloadable")
            .await
            .expect("provider reload should succeed");
        assert_eq!(reload_count.load(Ordering::Relaxed), 1);

        registry.destory().await;
    }

    #[tokio::test]
    async fn test_reload_provider_rejects_non_provider_and_missing_tags() {
        let reload_count = Arc::new(AtomicUsize::new(0));
        let mut registry = PluginRegistry::new();
        registry.register_factory("qname", DependencyKind::Matcher, Box::new(QnameFactory {}));
        registry.register_factory(
            "reloadable_provider",
            DependencyKind::Provider,
            Box::new(ReloadableProviderFactory { reload_count }),
        );
        let registry = Arc::new(registry);

        let configs = vec![
            PluginConfig {
                tag: "reloadable".to_string(),
                plugin_type: "reloadable_provider".to_string(),
                args: None,
            },
            PluginConfig {
                tag: "match_qname".to_string(),
                plugin_type: "qname".to_string(),
                args: Some(serde_yaml_ng::from_str("- \"$reloadable\"").unwrap()),
            },
        ];

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugin init should succeed");

        let err = registry
            .reload_provider("match_qname")
            .await
            .expect_err("matcher tag should be rejected");
        assert!(err.to_string().contains("not a provider"));

        let err = registry
            .reload_provider("missing")
            .await
            .expect_err("missing tag should be rejected");
        assert!(err.to_string().contains("is not loaded"));

        registry.destory().await;
    }
}
