/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `forward_edns0opt` executor plugin.
//!
//! Forwards selected EDNS0 option codes from downstream request to final
//! response.
//!
//! Runtime behavior:
//! - `execute`: extracts configured option codes from request OPT records and
//!   prepares them for continuation-local post processing.
//! - continuation post-stage: re-inserts those options into response OPT records after
//!   downstream executors complete.
//!
//! Safety/perf notes:
//! - options are filtered by code allow-list (`codes`) and deduplicated.
//! - response OPT record is created only when needed.
//! - when no codes are configured, plugin becomes near no-op.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{EdnsCode, EdnsOption};
use crate::{continue_next, register_plugin_factory};
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct ForwardEdns0OptConfig {
    /// EDNS option codes to preserve and forward.
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

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for ForwardEdns0Opt {
    fn with_next(&self) -> bool {
        true
    }

    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.execute_with_next(context, None).await
    }

    async fn execute_with_next(
        &self,
        context: &mut DnsContext,
        next: Option<ExecutorNext>,
    ) -> Result<ExecStep> {
        if self.code_set.is_empty() {
            return continue_next!(next, context);
        }

        let selected = collect_selected_options(&context.request, &self.code_set);
        let step = continue_next!(next, context)?;
        if selected.is_empty() {
            return Ok(step);
        }

        if let Some(response) = context.response_mut() {
            let mut existing_codes = collect_selected_codes(response, &self.code_set);
            let opt = ensure_opt_record(response);
            for option in selected {
                let code = u16::from(EdnsCode::from(&option));
                if existing_codes.insert(code) {
                    opt.insert(option);
                }
            }
        }

        Ok(step)
    }
}

#[derive(Debug, Clone)]
pub struct ForwardEdns0OptFactory;

register_plugin_factory!("forward_edns0opt", ForwardEdns0OptFactory {});

impl PluginFactory for ForwardEdns0OptFactory {
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

fn parse_codes_from_value(args: Option<Value>) -> Result<AHashSet<u16>> {
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

    let cfg: ForwardEdns0OptConfig = serde_yaml_ng::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse forward_edns0opt config: {}", e)))?;

    Ok(cfg.codes.into_iter().collect())
}

fn collect_selected_options(
    message: &crate::proto::Message,
    code_set: &AHashSet<u16>,
) -> Vec<EdnsOption> {
    let Some(edns) = message.edns() else {
        return Vec::new();
    };

    let mut selected = Vec::new();
    for option in edns.options() {
        let code = u16::from(EdnsCode::from(option));
        if code_set.contains(&code) {
            selected.push(option.clone());
        }
    }
    selected
}

fn collect_selected_codes(
    message: &crate::proto::Message,
    code_set: &AHashSet<u16>,
) -> AHashSet<u16> {
    let Some(edns) = message.edns() else {
        return AHashSet::new();
    };

    let mut out = AHashSet::new();
    for option in edns.options() {
        let code = u16::from(EdnsCode::from(option));
        if code_set.contains(&code) {
            out.insert(code);
        }
    }
    out
}

fn ensure_opt_record(message: &mut crate::proto::Message) -> &mut crate::proto::Edns {
    message.ensure_edns_mut()
}

fn split_tokens(raw: &str) -> Vec<&str> {
    raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{ClientSubnet, DNSClass, Message, Question};
    use crate::proto::{Name, RecordType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_codes_from_value_validation() {
        assert!(parse_codes_from_value(Some(Value::String("x".into()))).is_err());
        assert!(
            parse_codes_from_value(Some(serde_yaml_ng::from_str("codes: [8, 15]").unwrap()))
                .is_ok()
        );
    }

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    fn add_ecs(message: &mut Message, ip: Ipv4Addr, mask: u8) {
        let opt = ensure_opt_record(message);
        opt.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(ip),
            mask,
            0,
        )));
    }

    fn count_code(message: &Message, code: u16) -> usize {
        message
            .edns()
            .as_ref()
            .map(|edns| {
                edns.options()
                    .iter()
                    .filter(|option| u16::from(EdnsCode::from(*option)) == code)
                    .count()
            })
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn test_forward_edns0opt_moves_selected_request_options_response() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        ctx.set_response(Message::new());
        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            count_code(ctx.response().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_with_next_deduplicates_existing_code() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let mut response = Message::new();
        add_ecs(&mut response, Ipv4Addr::new(2, 2, 2, 2), 24);
        ctx.set_response(response);

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            count_code(ctx.response().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_reads_selected_options_from_request() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        ctx.set_response(Message::new());
        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            count_code(ctx.response().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_keeps_single_existing_rcode() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let mut response = Message::new();
        add_ecs(&mut response, Ipv4Addr::new(2, 2, 2, 2), 24);
        ctx.set_response(response);

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            count_code(ctx.response().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_appends_to_existing_response_opt() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let mut response = Message::new();
        let _ = ensure_opt_record(&mut response);
        ctx.set_response(response);

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
        assert_eq!(
            count_code(ctx.response().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_creates_response_opt_when_missing() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        ctx.set_response(Message::new());

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");

        let updated = ctx.response().expect("response should exist");
        assert!(updated.edns().is_some());
        assert_eq!(
            count_code(ctx.response().expect("response should exist"), 8),
            1
        );
    }
}
