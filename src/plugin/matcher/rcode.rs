// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `rcode` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches DNS response code from the generated upstream response.
//!
//! Config accepts decimal numeric rcodes and text names, for example `["0"]`,
//! `["NOERROR"]`, or quick-setup syntax like `rcode SERVFAIL`.

use std::fmt::Debug;

use ahash::AHashSet;
use async_trait::async_trait;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_enum_rules_from_value, parse_quick_setup_rules, parse_rcode, parse_u16_rules,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;

#[derive(Debug, Clone)]
#[plugin_factory("rcode")]
pub struct RcodeFactory {}

impl PluginFactory for RcodeFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_enum_rules_from_value("rcode", plugin_config.args.clone())?;
        build_rcode_matcher(plugin_config.tag.clone(), rules)
    }

    fn quick_setup(&self, tag: &str, param: Option<String>) -> DnsResult<UninitializedPlugin> {
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

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> DnsResult<()> {
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for RcodeMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let Some(rcode) = context.response().map(|response| response.rcode()) else {
            return false;
        };
        self.rcodes.contains(&rcode.value())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::{Message, Name, Question, Rcode, RecordType};

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));

        DnsContext::new(SocketAddr::new("127.0.0.1".parse().unwrap(), 5353), request)
    }

    #[tokio::test]
    async fn test_rcode_matcher_only_checks_rcode() {
        let matcher = RcodeMatcher {
            tag: "rcode".into(),
            rcodes: [u16::from(Rcode::ServFail)].into_iter().collect(),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        ctx.set_response(response);

        assert!(!matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_build_rcode_matcher_accepts_text_rules() {
        let matcher = match build_rcode_matcher(
            "rcode".to_string(),
            vec![
                "SERVFAIL".to_string(),
                "ServFail".to_string(),
                "NXDOMAIN".to_string(),
                "2".to_string(),
            ],
        )
        .expect("text rcode rules should build")
        {
            UninitializedPlugin::Matcher(matcher) => matcher,
            _ => unreachable!("rcode factory should create a matcher"),
        };

        let mut servfail_ctx = make_context();
        servfail_ctx.set_response(servfail_ctx.request().response(Rcode::ServFail));
        assert!(matcher.is_match(&mut servfail_ctx));

        let mut nxdomain_ctx = make_context();
        nxdomain_ctx.set_response(nxdomain_ctx.request().response(Rcode::NXDomain));
        assert!(matcher.is_match(&mut nxdomain_ctx));
    }

    #[tokio::test]
    async fn test_rcode_matcher_matches_expected_code_and_requires_response() {
        let matcher = RcodeMatcher {
            tag: "rcode".into(),
            rcodes: [u16::from(Rcode::ServFail)].into_iter().collect(),
        };

        let mut no_response_ctx = make_context();
        assert!(!matcher.is_match(&mut no_response_ctx));

        let mut match_ctx = make_context();
        let mut response = Message::new();
        response.set_rcode(Rcode::ServFail);
        match_ctx.set_response(response);
        assert!(matcher.is_match(&mut match_ctx));
    }
}
