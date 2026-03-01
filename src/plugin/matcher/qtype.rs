/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `qtype` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches DNS question types in request queries.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_quick_setup_rules, parse_record_type, parse_rules_from_value, parse_u16_rules,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QtypeFactory {}

register_plugin_factory!("qtype", QtypeFactory {});

impl PluginFactory for QtypeFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        validate_non_empty_rules("qtype", &rules)?;
        let _ = parse_u16_rules("qtype", &rules, parse_record_type)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_qtype_matcher(plugin_config.tag.clone(), rules)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_qtype_matcher(tag.to_string(), rules)
    }
}

fn build_qtype_matcher(tag: String, rules: Vec<String>) -> DnsResult<UninitializedPlugin> {
    validate_non_empty_rules("qtype", &rules)?;
    let qtypes = parse_u16_rules("qtype", &rules, parse_record_type)?;
    Ok(UninitializedPlugin::Matcher(Box::new(QtypeMatcher {
        tag,
        qtypes,
    })))
}

#[derive(Debug)]
struct QtypeMatcher {
    tag: String,
    qtypes: AHashSet<u16>,
}

#[async_trait]
impl Plugin for QtypeMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

impl Matcher for QtypeMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context
            .request
            .queries()
            .iter()
            .any(|q| self.qtypes.contains(&u16::from(q.query_type())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::net::SocketAddr;

    fn make_context(qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        let mut query = Query::query(Name::from_ascii("example.com.").unwrap(), qtype);
        query.set_query_class(DNSClass::IN);
        request.add_query(query);

        DnsContext {
            src_addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            query_view: None,
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    #[tokio::test]
    async fn test_qtype_matcher_only_checks_qtype() {
        let matcher = QtypeMatcher {
            tag: "qtype".into(),
            qtypes: [u16::from(RecordType::AAAA)].into_iter().collect(),
        };
        let mut ctx = make_context(RecordType::A);
        assert!(!matcher.is_match(&mut ctx));
    }
}
