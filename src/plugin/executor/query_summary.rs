/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `query_summary` executor plugin.
//!
//! Logs compact query summary after downstream execution.
//!
//! This plugin is an observer-only stage:
//! - continuation pre-stage stores request start timestamp.
//! - continuation post-stage logs source, qname/qtype, final rcode and elapsed time.
//!
//! It does not change request routing or response content, so it can be placed
//! anywhere in a sequence for tracing and latency attribution.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::{continue_next, register_plugin_factory};
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::sync::Arc;
use tracing::info;

const DEFAULT_MSG: &str = "query summary";

#[derive(Debug, Clone, Deserialize, Default)]
struct QuerySummaryConfig {
    /// Optional summary title shown in logs.
    msg: Option<String>,
}

#[derive(Debug)]
struct QuerySummary {
    tag: String,
    msg: String,
}

#[async_trait]
impl Plugin for QuerySummary {
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
impl Executor for QuerySummary {
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
        let start_ms = AppClock::elapsed_millis();
        let result = continue_next!(next, context);
        self.finish_with_log(context, start_ms, result)
    }
}

impl QuerySummary {
    fn finish_with_log(
        &self,
        context: &DnsContext,
        start_ms: u64,
        result: Result<ExecStep>,
    ) -> Result<ExecStep> {
        let elapsed = AppClock::elapsed_millis().saturating_sub(start_ms);
        let (qname, qtype) = match context.request.first_question() {
            Some(question) => (
                question.name().normalized().to_string(),
                format!("{:?}", question.qtype()),
            ),
            None => ("<none>".to_string(), "<none>".to_string()),
        };
        let rcode = context
            .response()
            .map(|response| format!("{:?}", response.rcode()))
            .unwrap_or_else(|| "<none>".to_string());

        info!(
            plugin = %self.tag,
            title = %self.msg,
            qname = %qname,
            qtype = %qtype,
            src = %context.peer_addr(),
            rcode = %rcode,
            elapsed_ms = elapsed,
            "query_summary"
        );

        result
    }
}

#[derive(Debug, Clone)]
pub struct QuerySummaryFactory;

register_plugin_factory!("query_summary", QuerySummaryFactory {});

impl PluginFactory for QuerySummaryFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let msg = parse_msg(plugin_config.args.clone()).unwrap_or_else(|| DEFAULT_MSG.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(QuerySummary {
            tag: plugin_config.tag.clone(),
            msg,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let msg = param
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_MSG.to_string());

        Ok(UninitializedPlugin::Executor(Box::new(QuerySummary {
            tag: tag.to_string(),
            msg,
        })))
    }
}

fn parse_msg(args: Option<Value>) -> Option<String> {
    let args = args?;

    if let Some(s) = args.as_str() {
        let s = s.trim();
        return if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
    }

    serde_yaml_ng::from_value::<QuerySummaryConfig>(args)
        .ok()
        .and_then(|cfg| cfg.msg)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::DnsError;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::test_context;
    use crate::proto::Message;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing::dispatcher::Dispatch;
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn test_parse_msg_trims_and_filters_empty() {
        assert_eq!(parse_msg(None), None);
        assert_eq!(
            parse_msg(Some(Value::String(" hi ".into()))),
            Some("hi".into())
        );
        assert_eq!(parse_msg(Some(Value::String("   ".into()))), None);
    }

    #[tokio::test]
    async fn test_query_summary_execute_returns_next() {
        let plugin = QuerySummary {
            tag: "summary".to_string(),
            msg: "m".to_string(),
        };
        let mut ctx = test_context();
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
    }

    #[tokio::test]
    async fn test_query_summary_continuation_runs_with_terminal_next() {
        let plugin = QuerySummary {
            tag: "summary".to_string(),
            msg: "m".to_string(),
        };
        let mut ctx = test_context();
        ctx.set_response(Message::new());

        plugin
            .execute_with_next(&mut ctx, None)
            .await
            .expect("continuation execute should succeed");
    }

    #[derive(Clone, Default)]
    struct SharedWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    struct SharedWriterGuard {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriterGuard;

        fn make_writer(&'a self) -> Self::Writer {
            SharedWriterGuard {
                buffer: self.buffer.clone(),
            }
        }
    }

    impl io::Write for SharedWriterGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_query_summary_logs_when_result_is_error() {
        let plugin = QuerySummary {
            tag: "summary".to_string(),
            msg: "m".to_string(),
        };
        let ctx = test_context();
        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(writer.clone())
            .finish();

        let err = tracing::dispatcher::with_default(&Dispatch::new(subscriber), || {
            plugin.finish_with_log(
                &ctx,
                AppClock::elapsed_millis(),
                Err(DnsError::plugin("downstream failed")),
            )
        })
        .expect_err("error result should be preserved");

        assert!(err.to_string().contains("downstream failed"));

        let output = String::from_utf8(writer.buffer.lock().unwrap().clone())
            .expect("captured logs should be valid utf-8");
        assert!(output.contains("query_summary"));
    }
}
