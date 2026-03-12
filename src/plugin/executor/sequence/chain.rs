/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::dns_utils::{build_response_plan_from_request, parse_named_response_code};
use crate::core::error::{DnsError, Result};
use crate::message::ResponseCode;
use crate::message::build_response_packet;
use crate::plugin::UninitializedPlugin;
use crate::plugin::executor::sequence::Rule;
use crate::plugin::executor::sequence::{
    SequenceRef, parse_control_flow_sequence_tag, parse_sequence_ref,
};
use crate::plugin::executor::{ExecState, ExecStep, Executor, execute_with_post};
use crate::plugin::matcher::Matcher;
use crate::plugin::{PluginHolder, PluginRegistry};
use ahash::AHashSet;
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
        let mut run_error: Option<DnsError> = None;

        while pc < self.instructions.len() {
            let instruction = &self.instructions[pc];
            if !instruction.matches(context) {
                pc += 1;
                continue;
            }

            match &instruction.op {
                OpCode::Executor(executor) => match executor.execute(context).await {
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
                },
                OpCode::Builtin(op) => match op {
                    BuiltinOp::Accept => {
                        context.set_flow(ExecFlowState::Broken);
                        break;
                    }
                    BuiltinOp::Return => break,
                    BuiltinOp::Reject(rcode) => {
                        if let Some(packet) = context.request_packet() {
                            let code = u16::from(*rcode);
                            if code <= 0x0f {
                                if let Ok(response) = build_response_packet(packet, code) {
                                    context.set_response_packet(response)?;
                                    context.set_flow(ExecFlowState::Broken);
                                    break;
                                }
                            }
                        }

                        context
                            .response
                            .set_plan(build_response_plan_from_request(&context.request, *rcode));
                        context.set_flow(ExecFlowState::Broken);
                        break;
                    }
                    BuiltinOp::Jump(executor) => {
                        let step = match execute_with_post(executor.as_ref(), context).await {
                            Ok(step) => step,
                            Err(e) => {
                                run_error = Some(e);
                                break;
                            }
                        };
                        match step {
                            ExecStep::Stop => break,
                            ExecStep::Next => {
                                if context.flow() == ExecFlowState::Broken {
                                    break;
                                }
                                if context.flow() == ExecFlowState::ReachedTail {
                                    context.set_flow(ExecFlowState::Running);
                                }
                                pc += 1;
                            }
                            ExecStep::NextWithPost(_) => {
                                run_error = Some(DnsError::plugin(
                                    "unexpected NextWithPost after execute_with_post in jump",
                                ));
                                break;
                            }
                        }
                    }
                    BuiltinOp::Goto(executor) => {
                        if let Err(e) = execute_with_post(executor.as_ref(), context).await {
                            run_error = Some(e);
                        }
                        break;
                    }
                    BuiltinOp::Mark(marks) => {
                        context.marks_mut().extend(marks.iter().cloned());
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
                let field = format!("args[{}].matches[{}]", node_index, match_index);
                let (reverse, matcher_expr) = parse_matcher_expr(matcher_raw)?;
                matchers.push(MatcherRef {
                    matcher: self
                        .resolve_matcher_ref(matcher_expr, node_index, match_index, &field)
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
        let op = if let Some(op) = self.parse_builtin(exec, node_index).await? {
            OpCode::Builtin(op)
        } else {
            OpCode::Executor(self.resolve_executor_ref(exec, node_index).await?)
        };

        Ok(Instruction { matchers, op })
    }

    async fn parse_builtin(&mut self, expr: &str, node_index: usize) -> Result<Option<BuiltinOp>> {
        let mut split = expr.trim().splitn(2, char::is_whitespace);
        let op = split.next().unwrap_or_default();
        let arg = split.next().map(str::trim).filter(|s| !s.is_empty());

        match op {
            "accept" => Ok(Some(BuiltinOp::Accept)),
            "return" => Ok(Some(BuiltinOp::Return)),
            "reject" => Ok(Some(BuiltinOp::Reject(parse_reject_rcode(arg)?))),
            "mark" => Ok(Some(BuiltinOp::Mark(parse_mark_values(arg)?))),
            "jump" => Ok(Some(BuiltinOp::Jump(
                self.resolve_jump_or_goto_executor("jump", arg, node_index)
                    .await?,
            ))),
            "goto" => Ok(Some(BuiltinOp::Goto(
                self.resolve_jump_or_goto_executor("goto", arg, node_index)
                    .await?,
            ))),
            _ => Ok(None),
        }
    }

    async fn resolve_jump_or_goto_executor(
        &mut self,
        op: &str,
        arg: Option<&str>,
        node_index: usize,
    ) -> Result<Arc<dyn Executor>> {
        let raw =
            arg.ok_or_else(|| DnsError::plugin(format!("{} requires sequence tag argument", op)))?;
        let tag = parse_control_flow_sequence_tag(op, raw)?;

        let field = format!("args[{}].exec", node_index);
        self.registry
            .get_executor_dependency_of_type(&self.sequence_tag, &field, &tag, "sequence")
    }

    async fn resolve_executor_ref(
        &mut self,
        expr: &str,
        node_index: usize,
    ) -> Result<Arc<dyn Executor>> {
        match parse_sequence_ref(expr)? {
            SequenceRef::PluginTag(tag) => {
                let field = format!("args[{}].exec", node_index);
                self.registry
                    .get_executor_dependency(&self.sequence_tag, &field, &tag)
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
                let executor = uninitialized.init_and_wrap().await?;
                let executor = match executor {
                    PluginHolder::Executor(executor) => executor,
                    _ => {
                        return Err(DnsError::plugin(format!(
                            "quick setup plugin '{}' is not an executor",
                            plugin_type
                        )));
                    }
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
        field: &str,
    ) -> Result<Arc<dyn Matcher>> {
        match parse_sequence_ref(expr)? {
            SequenceRef::PluginTag(tag) => {
                self.registry
                    .get_matcher_dependency(&self.sequence_tag, field, &tag)
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
                let matcher = uninitialized.init_and_wrap().await?;
                let matcher = match matcher {
                    PluginHolder::Matcher(matcher) => matcher,
                    _ => {
                        return Err(DnsError::plugin(format!(
                            "quick setup plugin '{}' is not a matcher",
                            plugin_type
                        )));
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ExecFlowState;
    use crate::message::Packet;
    use crate::message::{Message, Question};
    use crate::message::{Name, RecordType};
    use crate::plugin::Plugin;
    use crate::plugin::executor::ExecResult;
    use async_trait::async_trait;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy)]
    enum StubBehavior {
        Next,
        NextWithPost,
        Error(&'static str),
    }

    #[derive(Debug)]
    struct StubExecutor {
        tag: &'static str,
        behavior: StubBehavior,
        execute_log: Option<&'static str>,
        post_log: Option<&'static str>,
        next_flow_state: Option<ExecFlowState>,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl StubExecutor {
        fn new(
            tag: &'static str,
            behavior: StubBehavior,
            execute_log: Option<&'static str>,
            post_log: Option<&'static str>,
            next_flow_state: Option<ExecFlowState>,
            log: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                tag,
                behavior,
                execute_log,
                post_log,
                next_flow_state,
                log,
            }
        }
    }

    #[async_trait]
    impl Plugin for StubExecutor {
        fn tag(&self) -> &str {
            self.tag
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for StubExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            if let Some(label) = self.execute_log {
                self.log.lock().unwrap().push(label);
            }
            if let Some(state) = self.next_flow_state {
                context.set_flow(state);
            }

            match self.behavior {
                StubBehavior::Next => Ok(ExecStep::Next),
                StubBehavior::NextWithPost => Ok(ExecStep::NextWithPost(None)),
                StubBehavior::Error(message) => Err(DnsError::plugin(message)),
            }
        }

        async fn post_execute(
            &self,
            _context: &mut DnsContext,
            _state: Option<ExecState>,
        ) -> ExecResult {
            if let Some(label) = self.post_log {
                self.log.lock().unwrap().push(label);
            }
            Ok(())
        }
    }

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.set_id(42);
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn executor_instruction(executor: Arc<dyn Executor>) -> Instruction {
        Instruction {
            matchers: Vec::new(),
            op: OpCode::Executor(executor),
        }
    }

    fn builtin_instruction(op: BuiltinOp) -> Instruction {
        Instruction {
            matchers: Vec::new(),
            op: OpCode::Builtin(op),
        }
    }

    #[tokio::test]
    async fn test_run_executes_post_callbacks_in_lifo_order() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let first: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "first",
            StubBehavior::NextWithPost,
            None,
            Some("post:first"),
            None,
            log.clone(),
        ));
        let second: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "second",
            StubBehavior::NextWithPost,
            None,
            Some("post:second"),
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![executor_instruction(first), executor_instruction(second)],
        });
        let mut context = make_context();

        // Act
        program.run(&mut context).await.unwrap();

        // Assert
        assert_eq!(
            log.lock().unwrap().clone(),
            vec!["post:second", "post:first"]
        );
    }

    #[tokio::test]
    async fn test_run_bubbles_execute_error_after_running_deferred_posts() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let deferred: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "deferred",
            StubBehavior::NextWithPost,
            None,
            Some("post:deferred"),
            None,
            log.clone(),
        ));
        let failing: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "failing",
            StubBehavior::Error("boom"),
            None,
            None,
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                executor_instruction(deferred),
                executor_instruction(failing),
            ],
        });
        let mut context = make_context();

        // Act
        let error = program.run(&mut context).await.unwrap_err();

        // Assert
        assert!(matches!(error, DnsError::Plugin(message) if message == "boom"));
        assert_eq!(log.lock().unwrap().clone(), vec!["post:deferred"]);
    }

    #[tokio::test]
    async fn test_run_reject_sets_response_and_breaks_flow() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let skipped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "skipped",
            StubBehavior::Next,
            Some("execute:skipped"),
            None,
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Reject(ResponseCode::ServFail)),
                executor_instruction(skipped),
            ],
        });
        let mut context = make_context();

        // Act
        program.run(&mut context).await.unwrap();

        // Assert
        let response = context
            .response
            .expect("reject should build a response")
            .to_message()
            .expect("response should materialize");
        assert_eq!(response.id(), 42);
        assert_eq!(response.response_code(), ResponseCode::ServFail);
        assert_eq!(context.flow(), ExecFlowState::Broken);
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_run_reject_builds_response_when_request_packet_exists() {
        let program = Arc::new(ChainProgram {
            instructions: vec![builtin_instruction(BuiltinOp::Reject(
                ResponseCode::ServFail,
            ))],
        });
        let mut context = make_context();
        let packet = Packet::from_vec(context.request.to_bytes().unwrap());
        context.set_request_packet(packet);

        program.run(&mut context).await.unwrap();

        let response = context
            .response
            .expect("reject should build response")
            .to_message()
            .expect("response should materialize");
        assert_eq!(response.id(), 42);
        assert_eq!(response.response_code(), ResponseCode::ServFail);
        assert_eq!(context.flow(), ExecFlowState::Broken);
    }

    #[tokio::test]
    async fn test_run_accept_breaks_flow_without_building_response() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let skipped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "skipped",
            StubBehavior::Next,
            Some("execute:skipped"),
            None,
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Accept),
                executor_instruction(skipped),
            ],
        });
        let mut context = make_context();

        // Act
        program.run(&mut context).await.unwrap();

        // Assert
        assert!(context.response.is_none());
        assert_eq!(context.flow(), ExecFlowState::Broken);
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_run_return_stops_without_breaking_flow() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let skipped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "skipped",
            StubBehavior::Next,
            Some("execute:skipped"),
            None,
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Return),
                executor_instruction(skipped),
            ],
        });
        let mut context = make_context();

        // Act
        program.run(&mut context).await.unwrap();

        // Assert
        assert!(context.response.is_none());
        assert_eq!(context.flow(), ExecFlowState::Running);
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_run_jump_resets_reached_tail_and_continues_parent_program() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let jumped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "jumped",
            StubBehavior::Next,
            Some("execute:jumped"),
            None,
            Some(ExecFlowState::ReachedTail),
            log.clone(),
        ));
        let after_jump: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "after_jump",
            StubBehavior::Next,
            Some("execute:after_jump"),
            None,
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Jump(jumped)),
                executor_instruction(after_jump),
            ],
        });
        let mut context = make_context();

        // Act
        program.run(&mut context).await.unwrap();

        // Assert
        assert_eq!(
            log.lock().unwrap().clone(),
            vec!["execute:jumped", "execute:after_jump"]
        );
        assert_eq!(context.flow(), ExecFlowState::Running);
    }
}
