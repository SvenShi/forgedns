/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `rcode` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches DNS response code from the generated upstream response.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_quick_setup_rules, parse_rcode, parse_rules_from_value, parse_u16_rules,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RcodeFactory {}

register_plugin_factory!("rcode", RcodeFactory {});

impl PluginFactory for RcodeFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        validate_non_empty_rules("rcode", &rules)?;
        let _ = parse_u16_rules("rcode", &rules, parse_rcode)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_rcode_matcher(plugin_config.tag.clone(), rules)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_rcode_matcher(tag.to_string(), rules)
    }
}

fn build_rcode_matcher(tag: String, rules: Vec<String>) -> DnsResult<UninitializedPlugin> {
    validate_non_empty_rules("rcode", &rules)?;
    let rcodes = parse_u16_rules("rcode", &rules, parse_rcode)?;
    Ok(UninitializedPlugin::Matcher(Box::new(RcodeMatcher {
        tag,
        rcodes,
    })))
}

#[derive(Debug)]
struct RcodeMatcher {
    tag: String,
    rcodes: AHashSet<u16>,
}

#[async_trait]
impl Plugin for RcodeMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for RcodeMatcher {
    async fn is_match(&self, context: &mut DnsContext) -> bool {
        let Some(response) = context.response.as_ref() else {
            return false;
        };
        self.rcodes.contains(&u16::from(response.response_code()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        DnsContext {
            src_addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: HashMap::new(),
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    #[tokio::test]
    async fn test_rcode_matcher_only_checks_rcode() {
        let matcher = RcodeMatcher {
            tag: "rcode".into(),
            rcodes: [u16::from(ResponseCode::ServFail)].into_iter().collect(),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.set_response_code(ResponseCode::NoError);
        ctx.response = Some(response);

        assert!(!matcher.is_match(&mut ctx).await);
    }
}
