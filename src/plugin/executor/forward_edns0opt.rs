/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `forward_edns0opt` executor plugin.
//!
//! Forwards selected EDNS0 option codes from downstream request to query and
//! then to response.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::OPT;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct ForwardEdns0OptConfig {
    #[serde(default)]
    codes: Vec<u16>,
}

#[derive(Debug)]
struct ForwardEdns0Opt {
    tag: String,
    code_set: AHashSet<u16>,
}

#[async_trait]
impl Plugin for ForwardEdns0Opt {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for ForwardEdns0Opt {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if self.code_set.is_empty() {
            return Ok(ExecStep::Next);
        }

        let selected = collect_selected_options(&context.request, &self.code_set);
        if selected.is_empty() {
            return Ok(ExecStep::Next);
        }

        Ok(ExecStep::NextWithPost(
            Some(Box::new(selected) as ExecState),
        ))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let selected = state
            .and_then(|boxed| boxed.downcast::<Vec<EdnsOption>>().ok())
            .map(|boxed| *boxed)
            .unwrap_or_default();

        if selected.is_empty() {
            return Ok(());
        }

        if let Some(response) = context.response.as_mut() {
            let mut existing_codes = collect_selected_codes(response, &self.code_set);
            let opt = ensure_opt_record(response);
            for option in selected {
                let code = u16::from(EdnsCode::from(&option));
                if existing_codes.insert(code) {
                    opt.insert(option);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ForwardEdns0OptFactory;

register_plugin_factory!("forward_edns0opt", ForwardEdns0OptFactory {});

impl PluginFactory for ForwardEdns0OptFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let _ = parse_codes_from_value(plugin_config.args.clone())?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let code_set = parse_codes_from_value(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(ForwardEdns0Opt {
            tag: plugin_config.tag.clone(),
            code_set,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let mut code_set = AHashSet::new();
        let raw = param.unwrap_or_default();
        for token in split_tokens(&raw) {
            let code = token.parse::<u16>().map_err(|e| {
                DnsError::plugin(format!("invalid EDNS0 option code '{}': {}", token, e))
            })?;
            code_set.insert(code);
        }

        Ok(UninitializedPlugin::Executor(Box::new(ForwardEdns0Opt {
            tag: tag.to_string(),
            code_set,
        })))
    }
}

fn parse_codes_from_value(args: Option<serde_yml::Value>) -> Result<AHashSet<u16>> {
    let Some(args) = args else {
        return Ok(AHashSet::new());
    };

    if let Some(raw) = args.as_str() {
        let mut out = AHashSet::new();
        for token in split_tokens(raw) {
            let code = token.parse::<u16>().map_err(|e| {
                DnsError::plugin(format!("invalid EDNS0 option code '{}': {}", token, e))
            })?;
            out.insert(code);
        }
        return Ok(out);
    }

    let cfg: ForwardEdns0OptConfig = serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse forward_edns0opt config: {}", e)))?;

    Ok(cfg.codes.into_iter().collect())
}

fn collect_selected_options(
    message: &hickory_proto::op::Message,
    code_set: &AHashSet<u16>,
) -> Vec<EdnsOption> {
    let mut selected = Vec::new();
    for record in message.additionals() {
        let RData::OPT(opt) = record.data() else {
            continue;
        };
        for (_, option) in opt.as_ref() {
            let code = u16::from(EdnsCode::from(option));
            if code_set.contains(&code) {
                selected.push(option.clone());
            }
        }
    }
    selected
}

fn collect_selected_codes(
    message: &hickory_proto::op::Message,
    code_set: &AHashSet<u16>,
) -> AHashSet<u16> {
    let mut out = AHashSet::new();
    for record in message.additionals() {
        let RData::OPT(opt) = record.data() else {
            continue;
        };
        for (_, option) in opt.as_ref() {
            let code = u16::from(EdnsCode::from(option));
            if code_set.contains(&code) {
                out.insert(code);
            }
        }
    }
    out
}

fn ensure_opt_record(message: &mut hickory_proto::op::Message) -> &mut OPT {
    let mut opt_idx = None;
    for (idx, record) in message.additionals().iter().enumerate() {
        if matches!(record.data(), RData::OPT(_)) {
            opt_idx = Some(idx);
            break;
        }
    }

    let idx = match opt_idx {
        Some(idx) => idx,
        None => {
            message.add_additional(hickory_proto::rr::Record::from_rdata(
                hickory_proto::rr::Name::root(),
                0,
                RData::OPT(OPT::default()),
            ));
            message.additionals().len() - 1
        }
    };

    match message.additionals_mut()[idx].data_mut() {
        RData::OPT(opt) => opt,
        _ => unreachable!("OPT record must contain OPT rdata"),
    }
}

fn split_tokens(raw: &str) -> Vec<&str> {
    raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}
