/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `arbitrary` executor plugin.
//!
//! This executor is intentionally aligned with mosdns `arbitrary` semantics:
//! - zone-style records are parsed at startup;
//! - matching is exact on `(qname, qtype, qclass)`;
//! - all matched questions in the request contribute answers;
//! - the executor sets the response and, by default, keeps the chain running.
//!
//! ForgeDNS keeps a `short_circuit` switch as an explicit extension so callers
//! can stop the executor chain after a synthetic response when needed.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{DNSClass, Name, Rcode, Record, RecordType};
use crate::register_plugin_factory;
use ahash::AHashMap;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::sync::Arc;
use zoneparser::{ParseOptions, parse_file as parse_zone_file, parse_str as parse_zone_str};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ArbitraryConfig {
    /// Inline zone snippets.
    ///
    /// Each item is parsed independently, matching mosdns `rules` semantics.
    #[serde(default)]
    rules: Vec<String>,
    /// Paths to zone files parsed at startup.
    #[serde(default)]
    files: Vec<String>,
    /// Whether to stop the executor chain after producing a local answer.
    #[serde(default)]
    short_circuit: bool,
}

#[derive(Debug)]
struct Arbitrary {
    tag: String,
    answers: AnswerIndex,
    short_circuit: bool,
}

type AnswerIndex = AHashMap<(Name, RecordType, DNSClass), SharedRecords>;
type BuildAnswerIndex = AHashMap<(Name, RecordType, DNSClass), Vec<Record>>;

#[derive(Debug, Clone, Default)]
struct SharedRecords {
    records: Arc<[Record]>,
}

impl SharedRecords {
    fn extend_answers_into(&self, answers: &mut Vec<Record>) {
        answers.reserve(self.records.len());
        answers.extend(self.records.iter().cloned());
    }
}

#[async_trait]
impl Plugin for Arbitrary {
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
impl Executor for Arbitrary {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let response = {
            let request = context.request();
            let mut response = None;

            for question in request.questions() {
                let key = (question.name().clone(), question.qtype(), question.qclass());
                let Some(records) = self.answers.get(&key) else {
                    continue;
                };

                let message = response.get_or_insert_with(|| request.response(Rcode::NoError));
                records.extend_answers_into(message.answers_mut());
            }

            response
        };

        if let Some(response) = response {
            context.set_response(response);
            if self.short_circuit {
                return Ok(ExecStep::Stop);
            }
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct ArbitraryFactory;

register_plugin_factory!("arbitrary", ArbitraryFactory {});

impl PluginFactory for ArbitraryFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let answers = build_records(&cfg)?;

        Ok(UninitializedPlugin::Executor(Box::new(Arbitrary {
            tag: plugin_config.tag.clone(),
            answers,
            short_circuit: cfg.short_circuit,
        })))
    }
}

fn parse_config(args: Option<Value>) -> Result<ArbitraryConfig> {
    let Some(args) = args else {
        return Ok(ArbitraryConfig::default());
    };

    serde_yaml_ng::from_value::<ArbitraryConfig>(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse arbitrary config: {}", e)))
}

fn build_records(cfg: &ArbitraryConfig) -> Result<AnswerIndex> {
    let mut index = BuildAnswerIndex::new();

    for (idx, raw) in cfg.rules.iter().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        load_inline_zone_source(&mut index, raw, idx + 1)?;
    }

    for path in &cfg.files {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        load_zone_file(&mut index, path)?;
    }

    Ok(finalize_index(index))
}

fn load_inline_zone_source(index: &mut BuildAnswerIndex, raw: &str, rule_no: usize) -> Result<()> {
    let records = parse_zone_str(raw, &ParseOptions::default()).map_err(|e| {
        DnsError::plugin(format!(
            "failed to parse arbitrary rule #{}: {}",
            rule_no, e
        ))
    })?;

    for record in records {
        insert_record(index, record);
    }

    Ok(())
}

fn load_zone_file(index: &mut BuildAnswerIndex, path: &str) -> Result<()> {
    let records = parse_zone_file(path, &ParseOptions::default()).map_err(|e| {
        DnsError::plugin(format!("failed to parse arbitrary file '{}': {}", path, e))
    })?;

    for record in records {
        insert_record(index, record);
    }

    Ok(())
}

fn insert_record(index: &mut BuildAnswerIndex, record: Record) {
    index
        .entry((record.name().clone(), record.rr_type(), record.class()))
        .or_default()
        .push(record);
}

fn finalize_index(index: BuildAnswerIndex) -> AnswerIndex {
    index
        .into_iter()
        .map(|(key, records)| {
            (
                key,
                SharedRecords {
                    records: Arc::<[Record]>::from(records),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
    use crate::proto::rdata::A;
    use crate::proto::{Message, Question, RData};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tempfile::NamedTempFile;

    fn make_context(question_specs: &[(&str, RecordType, DNSClass)]) -> DnsContext {
        let mut request = Message::new();
        for (name, qtype, qclass) in question_specs {
            request.add_question(Question::new(
                Name::from_ascii(name).unwrap(),
                *qtype,
                *qclass,
            ));
        }
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    fn build_plugin(cfg: &ArbitraryConfig) -> Arbitrary {
        Arbitrary {
            tag: "arbitrary".to_string(),
            answers: build_records(cfg).expect("records should parse"),
            short_circuit: cfg.short_circuit,
        }
    }

    #[test]
    fn test_parse_config_accepts_short_circuit() {
        let value: Value = serde_yaml_ng::from_str(
            r#"
rules:
  - "example.com. 60 IN A 1.1.1.1"
short_circuit: true
"#,
        )
        .expect("yaml should parse");

        let cfg = parse_config(Some(value)).expect("short_circuit should be accepted");
        assert!(cfg.short_circuit);
    }

    #[test]
    fn test_build_records_supports_zone_directives_in_inline_rules() {
        let cfg = ArbitraryConfig {
            rules: vec![
                "$ORIGIN example.com.\n$TTL 60\nwww IN A 1.1.1.1\n".to_string(),
                "example.com. 120 IN TXT \"hello world\"\n".to_string(),
            ],
            files: vec![],
            short_circuit: false,
        };

        let answers = build_records(&cfg).expect("records should parse");
        let a_key = (
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );
        let txt_key = (
            Name::from_ascii("example.com.").unwrap(),
            RecordType::TXT,
            DNSClass::IN,
        );
        let a_records = answers.get(&a_key).expect("A record should exist");
        assert_eq!(a_records.records.len(), 1);
        assert_eq!(a_records.records[0].ttl(), 60);

        let txt_records = answers.get(&txt_key).expect("TXT record should exist");
        let RData::TXT(txt) = txt_records.records[0].data() else {
            panic!("expected TXT record");
        };
        let chunks: Vec<&str> = txt
            .txt_data_utf8()
            .map(|part| part.expect("utf8 chunk expected"))
            .collect();
        assert_eq!(chunks, vec!["hello world"]);
    }

    #[test]
    fn test_build_records_defaults_ttl_to_3600_when_omitted_without_ttl_directive() {
        let cfg = ArbitraryConfig {
            rules: vec!["example.com. IN A 1.1.1.1\n".to_string()],
            files: vec![],
            short_circuit: false,
        };

        let answers = build_records(&cfg).expect("records should parse");
        let key = (
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );

        let records = answers.get(&key).expect("A record should exist");
        assert_eq!(records.records[0].ttl(), 3600);
    }

    #[test]
    fn test_build_records_preserves_explicit_zero_ttl() {
        let cfg = ArbitraryConfig {
            rules: vec!["$TTL 60\nexample.com. 0 IN A 1.1.1.1\n".to_string()],
            files: vec![],
            short_circuit: false,
        };

        let answers = build_records(&cfg).expect("records should parse");
        let key = (
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );

        let records = answers.get(&key).expect("A record should exist");
        assert_eq!(records.records[0].ttl(), 0);
    }

    #[test]
    fn test_build_records_supports_zone_files() {
        let mut file = NamedTempFile::new().expect("temp file should exist");
        write!(
            file,
            "$ORIGIN example.com.\n\
             $TTL 300\n\
             @ IN SOA ns1 hostmaster 1 7200 1800 86400 60\n\
             www IN AAAA ::1\n"
        )
        .expect("zone file should be written");
        file.flush().expect("zone file should flush");

        let cfg = ArbitraryConfig {
            rules: vec![],
            files: vec![file.path().display().to_string()],
            short_circuit: false,
        };
        let answers = build_records(&cfg).expect("records should parse");

        let soa_key = (
            Name::from_ascii("example.com.").unwrap(),
            RecordType::SOA,
            DNSClass::IN,
        );
        let aaaa_key = (
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::AAAA,
            DNSClass::IN,
        );

        assert!(answers.contains_key(&soa_key));
        assert!(answers.contains_key(&aaaa_key));
    }

    #[tokio::test]
    async fn test_arbitrary_execute_matches_exact_question_tuple() {
        let cfg = ArbitraryConfig {
            rules: vec!["example.com. 60 IN A 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: false,
        };
        let plugin = build_plugin(&cfg);

        let mut any_ctx = make_context(&[("example.com.", RecordType::ANY, DNSClass::IN)]);
        let step = plugin
            .execute(&mut any_ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        assert!(any_ctx.response().is_none());

        let mut class_ctx = make_context(&[("example.com.", RecordType::A, DNSClass::CH)]);
        plugin
            .execute(&mut class_ctx)
            .await
            .expect("execute should succeed");
        assert!(class_ctx.response().is_none());
    }

    #[tokio::test]
    async fn test_arbitrary_execute_accumulates_matches_for_multiple_questions() {
        let cfg = ArbitraryConfig {
            rules: vec![
                "example.com. 60 IN A 1.1.1.1".to_string(),
                "example.com. 60 IN AAAA ::1".to_string(),
            ],
            files: vec![],
            short_circuit: false,
        };
        let plugin = build_plugin(&cfg);

        let mut ctx = make_context(&[
            ("example.com.", RecordType::A, DNSClass::IN),
            ("example.com.", RecordType::AAAA, DNSClass::IN),
        ]);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));

        let response = ctx.response().expect("response should exist");
        assert_eq!(response.answers().len(), 2);
        assert!(response.has_answer_ip(|ip| ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(response.has_answer_ip(|ip| ip == IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn test_arbitrary_execute_replaces_response_and_continues_chain() {
        let cfg = ArbitraryConfig {
            rules: vec!["example.com. 60 IN A 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: false,
        };
        let plugin = build_plugin(&cfg);

        let mut ctx = make_context(&[("example.com.", RecordType::A, DNSClass::IN)]);
        let mut existing = ctx.request().response(Rcode::NoError);
        existing.add_answer(Record::from_rdata(
            Name::from_ascii("old.example.com.").unwrap(),
            30,
            RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
        ));
        ctx.set_response(existing);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));

        let response = ctx.response().expect("response should exist");
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].name().to_string(), "example.com");
    }

    #[tokio::test]
    async fn test_arbitrary_execute_stops_when_short_circuit_enabled() {
        let cfg = ArbitraryConfig {
            rules: vec!["example.com. 60 IN A 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: true,
        };
        let plugin = build_plugin(&cfg);

        let mut ctx = make_context(&[("example.com.", RecordType::A, DNSClass::IN)]);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");

        assert!(matches!(step, ExecStep::Stop));
        assert!(ctx.response().is_some());
    }

    #[test]
    fn test_arbitrary_quick_setup_is_not_supported() {
        let err = match ArbitraryFactory.quick_setup(
            "arbitrary_qs",
            Some("example.com. 60 IN A 1.1.1.1".to_string()),
            Arc::new(PluginRegistry::new()),
        ) {
            Ok(_) => panic!("quick setup should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("quick setup is not supported"));
    }
}
