use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::Executor;
use crate::plugin::executor::sequence::chain::ChainNode;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use chrono::Utc;
use lazy_static::lazy_static;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone)]
enum Segment {
    Text(String),
    Var(String),
}

#[derive(Debug, Clone)]
struct CompiledTemplate {
    segments: Vec<Segment>,
}

impl CompiledTemplate {
    fn compile(template: &str) -> Self {
        let mut segments = Vec::new();
        let mut buf = String::new();
        let mut var_buf = String::new();
        let mut in_brace = false;

        for ch in template.chars() {
            match ch {
                '{' if !in_brace => {
                    if !buf.is_empty() {
                        segments.push(Segment::Text(std::mem::take(&mut buf)));
                    }
                    in_brace = true;
                    var_buf.clear();
                }
                '}' if in_brace => {
                    in_brace = false;
                    segments.push(Segment::Var(std::mem::take(&mut var_buf)));
                }
                _ if in_brace => var_buf.push(ch),
                _ => buf.push(ch),
            }
        }

        if !buf.is_empty() {
            segments.push(Segment::Text(buf));
        }

        Self { segments }
    }

    fn render(&self, ctx: &DnsContext) -> String {
        let mut out = String::new();
        for seg in &self.segments {
            match seg {
                Segment::Text(t) => out.push_str(t),
                Segment::Var(v) => {
                    if let Some(value) = get_var(v, ctx) {
                        out.push_str(&value);
                    } else {
                        out.push_str(&format!("{{{}}}", v));
                    }
                }
            }
        }
        out
    }
}

type ValueFn = dyn Fn(&DnsContext) -> String + Send + Sync + 'static;
lazy_static! {
    static ref TEMPLATE_FN_REGISTRY: HashMap<String, Box<ValueFn>> = {
        let mut map: HashMap<String, Box<ValueFn>> = HashMap::new();
        map.insert("timestamp".into(), Box::new(|_| Utc::now().to_rfc3339()));
        map.insert("src_addr".into(), Box::new(|ctx| ctx.src_addr.to_string()));
        map.insert("id".into(), Box::new(|ctx| ctx.request.id().to_string()));
        map.insert(
            "queries".into(),
            Box::new(|ctx| format!("{:?}", ctx.request.queries())),
        );
        map.insert(
            "response_set".into(),
            Box::new(|ctx| ctx.response.is_some().to_string()),
        );
        map
    };
}

fn get_var(name: &str, ctx: &DnsContext) -> Option<String> {
    TEMPLATE_FN_REGISTRY.get(name).map(|f| f(ctx))
}

#[derive(Deserialize)]
pub struct PrintConfig {
    pub before: Option<Vec<String>>,
    pub after: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct Print {
    tag: String,
    before: Option<Vec<String>>,
    after: Option<Vec<String>>,
    before_tel: Option<Vec<CompiledTemplate>>,
    after_tel: Option<Vec<CompiledTemplate>>,
}

#[async_trait]
impl Plugin for Print {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        self.before_tel = self.before.as_ref().map(|v| {
            let x1: Vec<CompiledTemplate> =
                v.iter().map(|s| CompiledTemplate::compile(s)).collect();
            x1
        });
        self.after_tel = self.after.as_ref().map(|v| {
            let x1: Vec<CompiledTemplate> =
                v.iter().map(|s| CompiledTemplate::compile(s)).collect();
            x1
        });

        info!("print plugin initialized: {}", self.tag);
    }

    async fn destroy(&mut self) {}
}

#[async_trait]
impl Executor for Print {
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<ChainNode>>) {
        if let Some(before) = self.before_tel.as_ref() {
            for tmpl in before {
                let msg = tmpl.render(context);
                info!("{}", msg);
            }
        }
        continue_next!(next, context);
        if let Some(after) = self.after_tel.as_ref() {
            for tmpl in after {
                let msg = tmpl.render(context);
                info!("{}", msg);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrintFactory {}

register_plugin_factory!("print", PrintFactory {});

impl PluginFactory for PrintFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        match plugin_config.args.clone() {
            Some(_) => Ok(()),
            None => Err(DnsError::plugin(
                "print must configure 'line' or list of strings in config file",
            )),
        }
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let print_config: PrintConfig = serde_yml::from_value(plugin_config.args.clone().unwrap())?;

        Ok(UninitializedPlugin::Executor(Box::new(Print {
            tag: plugin_config.tag.clone(),
            after: print_config.after,
            before: print_config.before,
            after_tel: None,
            before_tel: None,
        })))
    }
}
