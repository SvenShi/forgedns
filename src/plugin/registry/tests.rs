use std::any::Any;
use std::collections::HashMap as StdHashMap;
use std::io::{self, Write};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tracing_subscriber::fmt::MakeWriter;

use super::init_plan::SkippedProvider;
use super::*;
use crate::api::{clear_global_api, global_api_test_guard};
use crate::config::types::{Config, PluginConfig};
use crate::plugin::dependency::{
    DependencyGraphEdge, DependencyGraphNode, DependencyGraphReport, DependencySpec,
};
use crate::plugin::executor::sequence::SequenceFactory;
use crate::plugin::matcher::qname::QnameFactory;
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginDependent, UninitializedPlugin};
use crate::proto::Name;

fn test_config(plugins: Vec<PluginConfig>) -> Config {
    Config {
        include: Vec::new(),
        runtime: Default::default(),
        api: Default::default(),
        log: Default::default(),
        plugins,
    }
}

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

#[tokio::test]
async fn test_init_runtime_failure_preserves_current_runtime() {
    let manager = PluginRuntimeManager::new();
    let first = manager
        .init_runtime(test_config(Vec::new()))
        .await
        .expect("empty runtime should initialize");

    let err = manager
        .init_runtime(test_config(vec![PluginConfig {
            tag: "bad".to_string(),
            plugin_type: "missing_factory".to_string(),
            args: None,
        }]))
        .await
        .expect_err("unknown plugin type should fail initialization");
    assert!(err.to_string().contains("Unknown plugin type"));

    let current = manager
        .current_runtime()
        .expect("previous runtime should remain installed");
    assert!(Arc::ptr_eq(&first, &current));

    manager.destroy_runtime().await;
}

#[tokio::test]
async fn test_runtime_manager_recovers_poisoned_current_lock() {
    let manager = PluginRuntimeManager::new();
    let _ = std::panic::catch_unwind(|| {
        let _guard = manager
            .current
            .write()
            .expect("current lock should not be poisoned yet");
        panic!("poison current runtime lock");
    });

    let runtime = manager
        .init_runtime(test_config(Vec::new()))
        .await
        .expect("runtime install should recover poisoned current lock");
    let current = manager
        .current_runtime()
        .expect("runtime should be readable after poison recovery");
    assert!(Arc::ptr_eq(&runtime, &current));

    manager.destroy_runtime().await;
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

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
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
        init_context: &PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        self.captured
            .lock()
            .expect("context mutex poisoned")
            .insert(
                plugin_config.tag.clone(),
                PluginCreateContext {
                    dependents: init_context.dependents().to_vec(),
                },
            );
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

    registry.destroy().await;
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
        sequence_flows: Vec::new(),
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

    registry.destroy().await;
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
        .with_max_level(tracing::Level::WARN)
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
    assert!(output.contains("WARN"), "captured logs: {output}");
    assert!(
        output.contains("orphan_provider"),
        "captured logs: {output}"
    );
    assert!(
        output.contains("capture_provider"),
        "captured logs: {output}"
    );
    assert!(
        output.contains("no live dependents"),
        "captured logs: {output}"
    );
    assert!(
        output.contains("skipped provider initialization"),
        "captured logs: {output}"
    );

    registry.destroy().await;
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

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
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
        _init_context: &crate::plugin::PluginInitContext<'_>,
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
    let _guard = global_api_test_guard().await;
    clear_global_api();
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

    registry.destroy().await;
    clear_global_api();
}

#[tokio::test]
async fn test_reload_provider_rejects_non_provider_and_missing_tags() {
    let _guard = global_api_test_guard().await;
    clear_global_api();
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

    registry.destroy().await;
    clear_global_api();
}
