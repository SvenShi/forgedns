/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `has_wanted_ans` matcher plugin.
//!
//! Returns true when answer section contains at least one RR whose type
//! matches any request question type.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct HasWantedAnsFactory {}

register_plugin_factory!("has_wanted_ans", HasWantedAnsFactory {});

impl PluginFactory for HasWantedAnsFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        Ok(UninitializedPlugin::Matcher(Box::new(
            HasWantedAnsMatcher {
                tag: plugin_config.tag.clone(),
            },
        )))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        if let Some(param) = param {
            if !param.trim().is_empty() {
                return Err(DnsError::plugin(
                    "has_wanted_ans does not accept parameters",
                ));
            }
        }
        Ok(UninitializedPlugin::Matcher(Box::new(
            HasWantedAnsMatcher {
                tag: tag.to_string(),
            },
        )))
    }
}

#[derive(Debug)]
struct HasWantedAnsMatcher {
    tag: String,
}

#[async_trait]
impl Plugin for HasWantedAnsMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for HasWantedAnsMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let Some(response) = context.response.as_ref() else {
            return false;
        };

        let queries = context.request.queries();
        if queries.is_empty() {
            return false;
        }

        if queries.len() == 1 {
            let qtype = queries[0].query_type();
            return response
                .answers()
                .iter()
                .any(|rr| rr.record_type() == qtype);
        }

        let mut wanted = AHashSet::with_capacity(queries.len());
        for query in queries {
            wanted.insert(u16::from(query.query_type()));
        }
        response
            .answers()
            .iter()
            .any(|rr| wanted.contains(&u16::from(rr.record_type())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::{test_context, test_registry};
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    #[test]
    fn test_has_wanted_ans_quick_setup_rejects_param() {
        let factory = HasWantedAnsFactory {};
        assert!(
            factory
                .quick_setup(
                    "has_wanted_ans",
                    Some("unexpected".to_string()),
                    test_registry(),
                )
                .is_err()
        );
    }

    #[test]
    fn test_has_wanted_ans_matches_answer_type_against_query() {
        let matcher = HasWantedAnsMatcher {
            tag: "wanted".to_string(),
        };
        let mut ctx = test_context();
        ctx.request.queries_mut().clear();
        ctx.request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        let mut response = hickory_proto::op::Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A::new(1, 1, 1, 1)),
        ));
        ctx.response = Some(response);

        assert!(matcher.is_match(&mut ctx));

        ctx.response = Some(hickory_proto::op::Message::new());
        assert!(!matcher.is_match(&mut ctx));
    }
}
