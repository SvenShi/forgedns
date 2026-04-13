/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `script` executor plugin.
//!
//! Runs an external command with context-derived arguments and environment
//! variables.
//!
//! Design constraints:
//! - the command path itself is explicit and never templated;
//! - argument/env interpolation is limited to a stable built-in key set;
//! - execution is bounded by timeout and output capture limits; and
//! - v1 is side-effect only: scripts do not mutate DNS responses or attrs.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::parse_simple_duration;
use crate::plugin::executor::template::Template;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{info, warn};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_OUTPUT_BYTES: usize = 4096;
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptConfig {
    command: String,
    args: Option<Vec<String>>,
    env: Option<HashMap<String, String>>,
    cwd: Option<String>,
    timeout: Option<String>,
    error_mode: Option<ScriptErrorMode>,
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ScriptErrorMode {
    #[default]
    Continue,
    Stop,
    Fail,
}

#[derive(Debug)]
struct ScriptExecutor {
    tag: String,
    command: String,
    args: Vec<Template>,
    env: Vec<(String, Template)>,
    cwd: Option<PathBuf>,
    timeout: Duration,
    error_mode: ScriptErrorMode,
    max_output_bytes: usize,
}

#[derive(Debug, Default)]
struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
struct ProcessOutput {
    stdout: CapturedOutput,
    stderr: CapturedOutput,
}

#[derive(Debug)]
enum ExecutionFailure {
    Exit {
        status: String,
        output: ProcessOutput,
    },
    Timeout {
        output: ProcessOutput,
    },
    Runtime {
        detail: String,
    },
}

#[async_trait]
impl Plugin for ScriptExecutor {
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
impl Executor for ScriptExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let rendered_args = self
            .args
            .iter()
            .map(|template| template.render(context))
            .collect::<Vec<_>>();
        let rendered_env = self
            .env
            .iter()
            .map(|(key, template)| (key.clone(), template.render(context)))
            .collect::<Vec<_>>();

        match self
            .run_process(rendered_args.as_slice(), rendered_env.as_slice())
            .await
        {
            Ok(output) => {
                info!(
                    plugin = %self.tag,
                    command = %self.command,
                    args = ?rendered_args,
                    cwd = ?self.cwd,
                    stdout = %display_output(&output.stdout),
                    stderr = %display_output(&output.stderr),
                    "script completed successfully"
                );
                Ok(ExecStep::Next)
            }
            Err(failure) => self.handle_failure(failure, rendered_args.as_slice()),
        }
    }
}

impl ScriptExecutor {
    async fn run_process(
        &self,
        rendered_args: &[String],
        rendered_env: &[(String, String)],
    ) -> std::result::Result<ProcessOutput, ExecutionFailure> {
        let mut command = Command::new(&self.command);
        command.args(rendered_args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in rendered_env {
            command.env(key, value);
        }

        let mut child = command.spawn().map_err(|err| ExecutionFailure::Runtime {
            detail: format!("failed to spawn '{}': {}", self.command, err),
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecutionFailure::Runtime {
                detail: "failed to capture child stdout".to_string(),
            })?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecutionFailure::Runtime {
                detail: "failed to capture child stderr".to_string(),
            })?;

        let stdout_task = tokio::spawn(read_limited(stdout, self.max_output_bytes));
        let stderr_task = tokio::spawn(read_limited(stderr, self.max_output_bytes));

        let status = match timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) => Some(status),
            Ok(Err(err)) => {
                return Err(ExecutionFailure::Runtime {
                    detail: format!("failed while waiting for child process: {}", err),
                });
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                None
            }
        };

        let output = ProcessOutput {
            stdout: join_output(stdout_task).await?,
            stderr: join_output(stderr_task).await?,
        };

        if let Some(status) = status {
            if status.success() {
                Ok(output)
            } else {
                Err(ExecutionFailure::Exit {
                    status: format_exit_status(status.code()),
                    output,
                })
            }
        } else {
            Err(ExecutionFailure::Timeout { output })
        }
    }

    fn handle_failure(
        &self,
        failure: ExecutionFailure,
        rendered_args: &[String],
    ) -> Result<ExecStep> {
        let (summary, stdout, stderr) = match &failure {
            ExecutionFailure::Exit { status, output } => (
                format!("script exited with {}", status),
                display_output(&output.stdout),
                display_output(&output.stderr),
            ),
            ExecutionFailure::Timeout { output } => (
                format!("script timed out after {:?}", self.timeout),
                display_output(&output.stdout),
                display_output(&output.stderr),
            ),
            ExecutionFailure::Runtime { detail } => (detail.clone(), String::new(), String::new()),
        };

        match self.error_mode {
            ScriptErrorMode::Continue => {
                warn!(
                    plugin = %self.tag,
                    command = %self.command,
                    args = ?rendered_args,
                    cwd = ?self.cwd,
                    stdout = %stdout,
                    stderr = %stderr,
                    error = %summary,
                    "script execution failed; continuing"
                );
                Ok(ExecStep::Next)
            }
            ScriptErrorMode::Stop => {
                warn!(
                    plugin = %self.tag,
                    command = %self.command,
                    args = ?rendered_args,
                    cwd = ?self.cwd,
                    stdout = %stdout,
                    stderr = %stderr,
                    error = %summary,
                    "script execution failed; stopping"
                );
                Ok(ExecStep::Stop)
            }
            ScriptErrorMode::Fail => Err(DnsError::plugin(format!(
                "script plugin '{}' failed: {}",
                self.tag, summary
            ))),
        }
    }
}

fn format_exit_status(code: Option<i32>) -> String {
    match code {
        Some(code) => format!("exit code {}", code),
        None => "termination by signal".to_string(),
    }
}

fn display_output(output: &CapturedOutput) -> String {
    let mut rendered = String::from_utf8_lossy(output.bytes.as_slice()).into_owned();
    if output.truncated {
        rendered.push_str(" [truncated]");
    }
    rendered
}

async fn join_output(
    handle: tokio::task::JoinHandle<std::io::Result<CapturedOutput>>,
) -> std::result::Result<CapturedOutput, ExecutionFailure> {
    match handle.await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(ExecutionFailure::Runtime {
            detail: format!("failed to read child output: {}", err),
        }),
        Err(err) => Err(ExecutionFailure::Runtime {
            detail: format!("output reader task failed: {}", err),
        }),
    }
}

async fn read_limited<R>(mut reader: R, limit: usize) -> std::io::Result<CapturedOutput>
where
    R: AsyncRead + Unpin,
{
    let mut output = CapturedOutput::default();
    let mut buf = [0u8; 1024];

    loop {
        let count = reader.read(&mut buf).await?;
        if count == 0 {
            break;
        }

        if output.bytes.len() < limit {
            let remaining = limit - output.bytes.len();
            let copy_len = remaining.min(count);
            output.bytes.extend_from_slice(&buf[..copy_len]);
            if copy_len < count {
                output.truncated = true;
            }
        } else {
            output.truncated = true;
        }
    }

    Ok(output)
}

#[derive(Debug, Clone)]
pub struct ScriptFactory;

register_plugin_factory!("script", ScriptFactory {});

impl PluginFactory for ScriptFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let args = plugin_config
            .args
            .clone()
            .ok_or_else(|| DnsError::plugin("script requires configuration arguments"))?;
        let config = serde_yaml_ng::from_value::<ScriptConfig>(args)
            .map_err(|err| DnsError::plugin(format!("failed to parse script config: {}", err)))?;
        build_executor(plugin_config.tag.as_str(), config)
            .map(|executor| UninitializedPlugin::Executor(Box::new(executor)))
    }
}

fn build_executor(tag: &str, config: ScriptConfig) -> Result<ScriptExecutor> {
    let command = config.command.trim().to_string();
    if command.is_empty() {
        return Err(DnsError::plugin("script command cannot be empty"));
    }

    let timeout = match config.timeout.as_deref() {
        Some(raw) => parse_simple_duration(raw).map_err(|err| {
            DnsError::plugin(format!("invalid script timeout '{}': {}", raw, err))
        })?,
        None => DEFAULT_TIMEOUT,
    };

    let max_output_bytes = config.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES);
    if max_output_bytes == 0 {
        return Err(DnsError::plugin(
            "script max_output_bytes must be greater than 0",
        ));
    }

    let args = config
        .args
        .unwrap_or_default()
        .into_iter()
        .map(|raw| Template::parse(raw.as_str()))
        .collect::<Result<Vec<_>>>()?;

    let mut env = Vec::new();
    for (key, value) in config.env.unwrap_or_default() {
        let key = key.trim().to_string();
        if key.is_empty() {
            return Err(DnsError::plugin("script env key cannot be empty"));
        }
        env.push((key, Template::parse(value.as_str())?));
    }

    Ok(ScriptExecutor {
        tag: tag.to_string(),
        command,
        args,
        env,
        cwd: config
            .cwd
            .filter(|cwd| !cwd.trim().is_empty())
            .map(PathBuf::from),
        timeout,
        error_mode: config.error_mode.unwrap_or_default(),
        max_output_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::executor::template::resolve_builtin;
    use crate::plugin::test_utils::{plugin_config, test_context, test_registry};
    use crate::proto::rdata::A;
    use crate::proto::{DNSClass, Message, Name, Question, RData, Rcode, Record, RecordType};
    use serde_yaml_ng::Value;
    use std::net::Ipv4Addr;

    fn context_with_question() -> DnsContext {
        let mut ctx = test_context();
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        ctx.replace_request(request);
        ctx
    }

    #[test]
    fn test_template_parse_rejects_unknown_placeholder() {
        let err = Template::parse("${unknown}").expect_err("unknown placeholder should fail");
        assert!(err.to_string().contains("unsupported placeholder"));
    }

    #[test]
    fn test_template_render_supports_builtin_and_escape() {
        let template = Template::parse("q=${qname} $$ ${client_ip}").unwrap();
        let ctx = context_with_question();
        assert_eq!(template.render(&ctx), "q=www.example.com $ 127.0.0.1");
    }

    #[test]
    fn test_resolve_builtin_formats_collections_stably() {
        let mut ctx = context_with_question();
        ctx.marks_mut().insert(2);
        ctx.marks_mut().insert(1);

        let mut response = ctx.request().response(Rcode::NoError);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 2))),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        ctx.set_response(response);

        assert_eq!(resolve_builtin(&ctx, "marks"), "1,2");
        assert_eq!(resolve_builtin(&ctx, "resp_ip"), "192.0.2.1,198.51.100.2");
        assert_eq!(resolve_builtin(&ctx, "rcode"), "0");
        assert_eq!(resolve_builtin(&ctx, "rcode_name"), "NoError");
    }

    #[test]
    fn test_resolve_builtin_reads_cron_attrs() {
        let mut ctx = test_context();
        ctx.set_attr("cron.plugin_tag", "cron_main".to_string());
        ctx.set_attr("cron.job_name", "job1".to_string());
        ctx.set_attr("cron.trigger_kind", "interval".to_string());
        ctx.set_attr("cron.scheduled_at_unix_ms", 123_i64);

        assert_eq!(resolve_builtin(&ctx, "cron_plugin_tag"), "cron_main");
        assert_eq!(resolve_builtin(&ctx, "cron_job_name"), "job1");
        assert_eq!(resolve_builtin(&ctx, "cron_trigger_kind"), "interval");
        assert_eq!(resolve_builtin(&ctx, "cron_scheduled_at_unix_ms"), "123");
    }

    #[test]
    fn test_factory_create_rejects_invalid_placeholder() {
        let cfg = plugin_config(
            "script",
            "script",
            Some(
                serde_yaml_ng::from_str::<Value>(
                    r#"
command: "echo"
args:
  - "${bad}"
"#,
                )
                .unwrap(),
            ),
        );
        let err = match ScriptFactory.create(&cfg, test_registry()) {
            Ok(_) => panic!("invalid placeholder should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unsupported placeholder"));
    }

    #[test]
    fn test_factory_create_rejects_zero_output_limit() {
        let cfg = plugin_config(
            "script",
            "script",
            Some(
                serde_yaml_ng::from_str::<Value>(
                    r#"
command: "echo"
max_output_bytes: 0
"#,
                )
                .unwrap(),
            ),
        );
        let err = match ScriptFactory.create(&cfg, test_registry()) {
            Ok(_) => panic!("zero output limit should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("max_output_bytes"));
    }

    #[tokio::test]
    async fn test_script_continue_failure_maps_to_next() {
        let executor = build_executor(
            "script",
            ScriptConfig {
                command: platform_failure_command().0,
                args: Some(platform_failure_command().1),
                env: None,
                cwd: None,
                timeout: None,
                error_mode: Some(ScriptErrorMode::Continue),
                max_output_bytes: None,
            },
        )
        .unwrap();
        let mut ctx = test_context();
        let step = executor.execute(&mut ctx).await.unwrap();
        assert!(matches!(step, ExecStep::Next));
    }

    #[cfg(unix)]
    fn platform_failure_command() -> (String, Vec<String>) {
        (
            "sh".to_string(),
            vec!["-c".to_string(), "exit 7".to_string()],
        )
    }

    #[cfg(windows)]
    fn platform_failure_command() -> (String, Vec<String>) {
        (
            "cmd.exe".to_string(),
            vec!["/C".to_string(), "exit /b 7".to_string()],
        )
    }
}
