/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::dns_utils::{build_response_from_request, parse_named_response_code};
use crate::core::error::{DnsError, Result};
use crate::plugin::UninitializedPlugin;
use crate::plugin::executor::recursive::{NextChainRunner, RecursiveHandle};
use crate::plugin::executor::sequence::Rule;
use crate::plugin::executor::sequence::{SequenceRef, parse_sequence_ref};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::matcher::Matcher;
use crate::plugin::{PluginHolder, PluginRegistry};
use ahash::AHashSet;
use hickory_proto::op::ResponseCode;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug)]
struct MatcherRef {
    /// Concrete matcher instance used by this instruction.
    matcher: Arc<dyn Matcher>,
    /// Whether matcher result should be logically negated (`!matcher`).
    reverse: bool,
}

#[derive(Debug)]
enum BuiltinOp {
    /// Mark chain as accepted and stop current sequence execution.
    Accept,
    /// Stop current sequence execution and return to caller.
    Return,
    /// Build and set a DNS response with the specified rcode, then stop.
    Reject(ResponseCode),
    /// Execute another sequence executor, then continue current program.
    Jump(Arc<dyn Executor>),
    /// Execute another sequence executor and stop current program immediately.
    Goto(Arc<dyn Executor>),
    /// Insert marks into context and continue execution.
    Mark(AHashSet<String>),
}

#[derive(Debug)]
enum OpCode {
    /// Normal executor plugin dispatch.
    Executor(Arc<dyn Executor>),
    /// Builtin control-flow operation.
    Builtin(BuiltinOp),
}

#[derive(Debug)]
struct Instruction {
    /// All matchers that must pass before the op is executed.
    matchers: Vec<MatcherRef>,
    /// The operation to run once matchers pass.
    op: OpCode,
}

#[derive(Debug)]
pub struct ChainProgram {
    /// Flattened instruction stream executed by a program counter.
    instructions: Vec<Instruction>,
}

impl ChainProgram {
    /// Run sequence program with explicit program-counter control flow.
    ///
    /// Execution model:
    /// - Evaluate matchers for current instruction.
    /// - Execute either executor opcode or builtin opcode.
    /// - Advance `pc` according to returned [`ExecStep`] / builtin semantics.
    /// - Execute deferred `post_execute` callbacks in LIFO order.
    pub async fn run(self: &Arc<Self>, context: &mut DnsContext) -> Result<()> {
        self.run_from_inner(context, 0).await
    }

    async fn run_from_inner(
        self: &Arc<Self>,
        context: &mut DnsContext,
        mut pc: usize,
    ) -> Result<()> {
        // Deferred post callbacks for `ExecStep::NextWithPost`.
        let mut post_stack: Vec<(Arc<dyn Executor>, Option<ExecState>)> = Vec::new();
        let mut run_error: Option<crate::core::error::DnsError> = None;

        while pc < self.instructions.len() {
            let instruction = &self.instructions[pc];
            if !instruction.matches(context) {
                pc += 1;
                continue;
            }

            match &instruction.op {
                OpCode::Executor(executor) => {
                    let next = RecursiveHandle::new(self.clone(), pc + 1);
                    match executor.execute_with_handle(context, Some(next)).await {
                        Ok(step) => match step {
                            ExecStep::Next => pc += 1,
                            ExecStep::NextWithPost(state) => {
                                post_stack.push((executor.clone(), state));
                                pc += 1;
                            }
                            ExecStep::Stop => break,
                        },
                        Err(e) => {
                            run_error = Some(e);
                            break;
                        }
                    }
                }
                OpCode::Builtin(op) => match op {
                    BuiltinOp::Accept => {
                        context.exec_flow_state = ExecFlowState::Broken;
                        break;
                    }
                    BuiltinOp::Return => break,
                    BuiltinOp::Reject(rcode) => {
                        context.response =
                            Some(build_response_from_request(&context.request, *rcode));
                        context.exec_flow_state = ExecFlowState::Broken;
                        break;
                    }
                    BuiltinOp::Jump(executor) => {
                        if let Err(e) = executor.execute_with_handle(context, None).await {
                            run_error = Some(e);
                            break;
                        }
                        if context.exec_flow_state == ExecFlowState::Broken {
                            break;
                        }
                        if context.exec_flow_state == ExecFlowState::ReachedTail {
                            context.exec_flow_state = ExecFlowState::Running;
                        }
                        pc += 1;
                    }
                    BuiltinOp::Goto(executor) => {
                        if let Err(e) = executor.execute_with_handle(context, None).await {
                            run_error = Some(e);
                        }
                        break;
                    }
                    BuiltinOp::Mark(marks) => {
                        context.marks.extend(marks.iter().cloned());
                        pc += 1;
                    }
                },
            }
        }

        while let Some((executor, state)) = post_stack.pop() {
            if let Err(e) = executor.post_execute(context, state).await {
                if run_error.is_none() {
                    run_error = Some(e);
                }
            }
        }

        if let Some(e) = run_error {
            Err(e)
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl NextChainRunner for ChainProgram {
    async fn run_from(self: Arc<Self>, context: &mut DnsContext, start_pc: usize) -> Result<()> {
        self.run_from_inner(context, start_pc).await
    }
}

impl Instruction {
    /// Return true only when all matchers pass after applying reverse flags.
    fn matches(&self, context: &mut DnsContext) -> bool {
        for matcher_ref in &self.matchers {
            let matched = matcher_ref.matcher.is_match(context);
            let matched = if matcher_ref.reverse {
                !matched
            } else {
                matched
            };
            if !matched {
                debug!(
                    "instruction skipped, matcher: {}",
                    matcher_ref.matcher.tag()
                );
                return false;
            }
        }
        true
    }
}

/// Builder that converts sequence rules into an executable instruction program.
pub struct ChainBuilder {
    /// Program being built in rule order.
    instructions: Vec<Instruction>,
    /// Shared plugin registry for resolving executor/matcher references.
    registry: Arc<PluginRegistry>,
    /// Current sequence tag (used for generated quick-setup tags).
    sequence_tag: String,
    /// Current rule index in this sequence.
    node_index: usize,
    /// Runtime-created quick-setup executors that require lifecycle management.
    quick_setup_executors: Vec<Arc<dyn Executor>>,
    /// Runtime-created quick-setup matchers that require lifecycle management.
    quick_setup_matchers: Vec<Arc<dyn Matcher>>,
}
impl ChainBuilder {
    pub fn new(registry: Arc<PluginRegistry>, sequence_tag: impl Into<String>) -> Self {
        ChainBuilder {
            instructions: Vec::new(),
            registry,
            sequence_tag: sequence_tag.into(),
            node_index: 0,
            quick_setup_executors: Vec::new(),
            quick_setup_matchers: Vec::new(),
        }
    }

    pub async fn append_node(&mut self, rule: &Rule) -> Result<()> {
        let node_index = self.node_index;
        let instruction = self.create_instruction(rule, node_index).await?;
        self.instructions.push(instruction);
        self.node_index += 1;
        Ok(())
    }

    pub fn build(
        self,
    ) -> (
        Arc<ChainProgram>,
        Vec<Arc<dyn Executor>>,
        Vec<Arc<dyn Matcher>>,
    ) {
        (
            Arc::new(ChainProgram {
                instructions: self.instructions,
            }),
            self.quick_setup_executors,
            self.quick_setup_matchers,
        )
    }

    async fn create_instruction(&mut self, rule: &Rule, node_index: usize) -> Result<Instruction> {
        let mut matchers = Vec::new();
        if let Some(matcher_exprs) = &rule.matches {
            for (match_index, matcher_raw) in matcher_exprs.iter().enumerate() {
                let (reverse, matcher_expr) = parse_matcher_expr(matcher_raw)?;
                matchers.push(MatcherRef {
                    matcher: self
                        .resolve_matcher_ref(matcher_expr, node_index, match_index)
                        .await?,
                    reverse,
                });
            }
        }

        let exec = rule
            .exec
            .as_ref()
            .ok_or_else(|| DnsError::plugin("rule must have 'exec' field"))?;

        // Builtin syntax has priority; otherwise resolve as normal executor reference.
        let op = if let Some(op) = self.parse_builtin(exec).await? {
            OpCode::Builtin(op)
        } else {
            OpCode::Executor(self.resolve_executor_ref(exec, node_index).await?)
        };

        Ok(Instruction { matchers, op })
    }

    async fn parse_builtin(&mut self, expr: &str) -> Result<Option<BuiltinOp>> {
        let mut split = expr.trim().splitn(2, char::is_whitespace);
        let op = split.next().unwrap_or_default();
        let arg = split.next().map(str::trim).filter(|s| !s.is_empty());

        match op {
            "accept" => Ok(Some(BuiltinOp::Accept)),
            "return" => Ok(Some(BuiltinOp::Return)),
            "reject" => Ok(Some(BuiltinOp::Reject(parse_reject_rcode(arg)?))),
            "mark" => Ok(Some(BuiltinOp::Mark(parse_mark_values(arg)?))),
            "jump" => Ok(Some(BuiltinOp::Jump(
                self.resolve_jump_or_goto_executor("jump", arg).await?,
            ))),
            "goto" => Ok(Some(BuiltinOp::Goto(
                self.resolve_jump_or_goto_executor("goto", arg).await?,
            ))),
            _ => Ok(None),
        }
    }

    async fn resolve_jump_or_goto_executor(
        &mut self,
        op: &str,
        arg: Option<&str>,
    ) -> Result<Arc<dyn Executor>> {
        // `jump/goto` only accept plugin tag references (`$tag`) to avoid
        // nested quick-setup ambiguity and lifecycle complexity.
        let raw =
            arg.ok_or_else(|| DnsError::plugin(format!("{} requires sequence tag argument", op)))?;
        let tag = match parse_sequence_ref(raw)? {
            SequenceRef::PluginTag(tag) => tag,
            SequenceRef::QuickSetup { .. } => {
                return Err(DnsError::plugin(format!(
                    "{} target must be plugin tag reference ($tag), quick setup syntax is not supported",
                    op
                )));
            }
        };

        let plugin = self
            .registry
            .get_plugin(&tag)
            .ok_or_else(|| DnsError::plugin(format!("plugin does not exist for {}", tag)))?;
        Ok(plugin.to_executor())
    }

    async fn resolve_executor_ref(
        &mut self,
        expr: &str,
        node_index: usize,
    ) -> Result<Arc<dyn Executor>> {
        match parse_sequence_ref(expr)? {
            SequenceRef::PluginTag(tag) => {
                let plugin = self.registry.get_plugin(&tag).ok_or_else(|| {
                    DnsError::plugin(format!("plugin does not exist for {}", tag))
                })?;
                Ok(plugin.to_executor())
            }
            SequenceRef::QuickSetup { plugin_type, param } => {
                // Generate deterministic synthetic runtime tag for quick-setup executor.
                let quick_tag = format!("@qs:exec:{}:{}", self.sequence_tag, node_index);
                let uninitialized = self.registry.quick_setup(
                    &plugin_type,
                    &quick_tag,
                    param,
                    self.registry.clone(),
                )?;
                let executor = uninitialized.init_and_wrap().await;
                let executor = match executor {
                    PluginHolder::Executor(executor) => executor,
                    _ => panic!("Plugin {} is not executor", plugin_type),
                };
                self.quick_setup_executors.push(executor.clone());
                Ok(executor)
            }
        }
    }

    async fn resolve_matcher_ref(
        &mut self,
        expr: &str,
        node_index: usize,
        match_index: usize,
    ) -> Result<Arc<dyn Matcher>> {
        match parse_sequence_ref(expr)? {
            SequenceRef::PluginTag(tag) => {
                let plugin = self.registry.get_plugin(&tag).ok_or_else(|| {
                    DnsError::plugin(format!("matcher plugin does not exist for {}", tag))
                })?;
                Ok(plugin.to_matcher())
            }
            SequenceRef::QuickSetup { plugin_type, param } => {
                // Generate deterministic synthetic runtime tag for quick-setup matcher.
                let quick_tag = format!(
                    "@qs:match:{}:{}:{}",
                    self.sequence_tag, node_index, match_index
                );
                let uninitialized: UninitializedPlugin = self.registry.quick_setup(
                    &plugin_type,
                    &quick_tag,
                    param,
                    self.registry.clone(),
                )?;
                let matcher = uninitialized.init_and_wrap().await;
                let matcher = match matcher {
                    PluginHolder::Matcher(matcher) => matcher,
                    _ => panic!("Plugin {} is not matcher", plugin_type),
                };
                self.quick_setup_matchers.push(matcher.clone());
                Ok(matcher)
            }
        }
    }
}

/// Parse optional `reject` argument into DNS rcode.
///
/// Supported inputs:
/// - numeric code (e.g. `5`)
/// - symbolic names (e.g. `REFUSED`, `SERVFAIL`)
/// - omitted argument defaults to `REFUSED`
fn parse_reject_rcode(arg: Option<&str>) -> Result<ResponseCode> {
    let Some(rcode_raw) = arg else {
        return Ok(ResponseCode::Refused);
    };

    if let Ok(code) = rcode_raw.parse::<u16>() {
        return Ok(code.into());
    }

    parse_named_response_code(rcode_raw)
        .ok_or_else(|| DnsError::plugin(format!("invalid reject rcode argument: {}", rcode_raw)))
}

/// Parse matcher expression and optional reverse prefix (`!`).
///
/// Examples:
/// - `$qname` -> `(false, "$qname")`
/// - `!$qname` -> `(true, "$qname")`
fn parse_matcher_expr(raw: &str) -> Result<(bool, &str)> {
    let matcher_expr = raw.trim_start();
    if let Some(matcher_expr) = matcher_expr.strip_prefix('!') {
        let matcher_expr = matcher_expr.trim_start();
        if matcher_expr.is_empty() {
            return Err(DnsError::plugin(format!(
                "invalid matcher reference: '{}'",
                raw
            )));
        }
        Ok((true, matcher_expr))
    } else {
        Ok((false, matcher_expr))
    }
}

/// Parse optional `mark` arguments into normalized mark strings.
///
/// Supported syntax:
/// - `mark 1`
/// - `mark 1,2,3`
/// - `mark 1 2 3`
fn parse_mark_values(arg: Option<&str>) -> Result<AHashSet<String>> {
    let Some(raw) = arg else {
        return Err(DnsError::plugin("mark requires at least one value"));
    };

    let mut marks = AHashSet::new();
    for token in raw
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mark = token
            .parse::<u32>()
            .map_err(|e| DnsError::plugin(format!("invalid mark value '{}': {}", token, e)))?;
        marks.insert(mark.to_string());
    }

    if marks.is_empty() {
        return Err(DnsError::plugin("mark requires at least one value"));
    }

    Ok(marks)
}
