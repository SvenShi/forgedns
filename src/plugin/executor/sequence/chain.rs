/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::UninitializedPlugin;
use crate::plugin::executor::sequence::Rule;
use crate::plugin::executor::sequence::{
    SequenceRef, parse_control_flow_sequence_tag, parse_sequence_ref,
};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::matcher::Matcher;
use crate::plugin::{PluginHolder, PluginRegistry};
use crate::proto::Rcode;
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
    /// Build and set a DNS response with the specified numeric rcode, then stop.
    ///
    /// Sequence config currently accepts only decimal numeric rcode values such as
    /// `reject 2`; mnemonic names like `SERVFAIL` are not parsed here.
    Reject(Rcode),
    /// Execute another sequence executor, then continue current program.
    Jump(Arc<dyn Executor>),
    /// Execute another sequence executor and stop current program immediately.
    Goto(Arc<dyn Executor>),
    /// Insert marks into context and continue execution.
    Mark(AHashSet<u32>),
}

#[derive(Debug)]
enum InstructionOp {
    /// Normal executor plugin dispatch.
    Executor(Arc<dyn Executor>),
    ExecutorWithNext(Arc<dyn Executor>),
    /// Builtin control-flow operation.
    Builtin(BuiltinOp),
}

#[derive(Debug)]
struct Instruction {
    /// All matchers that must pass before the op is executed.
    matchers: Vec<MatcherRef>,
    /// The operation to run once matchers pass.
    op: InstructionOp,
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
    pub async fn run(self: &Arc<Self>, context: &mut DnsContext) -> Result<ExecStep> {
        self.run_from_inner(context, 0).await
    }

    async fn run_from_inner(
        self: &Arc<Self>,
        context: &mut DnsContext,
        mut pc: usize,
    ) -> Result<ExecStep> {
        while pc < self.instructions.len() {
            let instruction = &self.instructions[pc];
            if !instruction.matches(context) {
                pc += 1;
                continue;
            }

            match &instruction.op {
                InstructionOp::Executor(executor) => match executor.execute(context).await? {
                    ExecStep::Next => pc += 1,
                    step @ (ExecStep::Stop | ExecStep::Return) => return Ok(step),
                },
                InstructionOp::ExecutorWithNext(executor) => {
                    let next = ExecutorNext::new(self.clone(), pc + 1);
                    return executor.execute_with_next(context, Some(next)).await;
                }
                InstructionOp::Builtin(op) => match op {
                    BuiltinOp::Accept => return Ok(ExecStep::Stop),
                    BuiltinOp::Return => return Ok(ExecStep::Return),
                    BuiltinOp::Reject(rcode) => {
                        context.set_response(context.request().response(*rcode));
                        return Ok(ExecStep::Stop);
                    }
                    BuiltinOp::Jump(executor) => {
                        let step = executor.execute_with_next(context, None).await?;
                        match step {
                            ExecStep::Stop => return Ok(ExecStep::Stop),
                            ExecStep::Next | ExecStep::Return => {
                                pc += 1;
                            }
                        }
                    }
                    BuiltinOp::Goto(executor) => {
                        return executor.execute_with_next(context, None).await;
                    }
                    BuiltinOp::Mark(marks) => {
                        context.marks_mut().extend(marks.iter().cloned());
                        pc += 1;
                    }
                },
            }
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct ExecutorNext {
    program: Arc<ChainProgram>,
    pc: usize,
}

impl ExecutorNext {
    pub(crate) fn new(program: Arc<ChainProgram>, pc: usize) -> Self {
        Self { program, pc }
    }

    pub async fn next(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.program.run_from_inner(context, self.pc).await
    }
}

#[cfg(test)]
impl ExecutorNext {
    pub(crate) fn from_program_for_test(program: Arc<ChainProgram>, pc: usize) -> Self {
        Self { program, pc }
    }
}

#[cfg(test)]
impl ChainProgram {
    pub(crate) fn single_with_next_executor_for_test(executor: Arc<dyn Executor>) -> Arc<Self> {
        Arc::new(Self {
            instructions: vec![Instruction {
                matchers: Vec::new(),
                op: InstructionOp::ExecutorWithNext(executor),
            }],
        })
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

type BuildArtifacts = (
    Arc<ChainProgram>,
    Vec<Arc<dyn Executor>>,
    Vec<Arc<dyn Matcher>>,
);

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

    pub fn build(self) -> BuildArtifacts {
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
            InstructionOp::Builtin(op)
        } else {
            let exec = self.resolve_executor_ref(exec, node_index).await?;
            if exec.with_next() {
                InstructionOp::ExecutorWithNext(exec)
            } else {
                InstructionOp::Executor(exec)
            }
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
            "reject" => {
                if let Some(code) = arg {
                    if let Ok(code) = code.parse::<u16>() {
                        Ok(Some(BuiltinOp::Reject(Rcode::from(code))))
                    } else {
                        Err(DnsError::plugin(
                            "invalid code argument: reject expects a decimal numeric rcode",
                        ))
                    }
                } else {
                    Ok(Some(BuiltinOp::Reject(Rcode::Refused)))
                }
            }
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
fn parse_mark_values(arg: Option<&str>) -> Result<AHashSet<u32>> {
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
        marks.insert(mark);
    }

    if marks.is_empty() {
        return Err(DnsError::plugin("mark requires at least one value"));
    }

    Ok(marks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continue_next;
    use crate::plugin::Plugin;
    use crate::proto::{Message, Question};
    use crate::proto::{Name, RecordType};
    use async_trait::async_trait;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy)]
    enum StubBehavior {
        Next,
        Return,
        AroundNext,
        Error(&'static str),
    }

    #[derive(Debug)]
    struct StubExecutor {
        tag: &'static str,
        behavior: StubBehavior,
        execute_log: Option<&'static str>,
        post_log: Option<&'static str>,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl StubExecutor {
        fn new(
            tag: &'static str,
            behavior: StubBehavior,
            execute_log: Option<&'static str>,
            post_log: Option<&'static str>,
            log: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                tag,
                behavior,
                execute_log,
                post_log,
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
        fn with_next(&self) -> bool {
            matches!(self.behavior, StubBehavior::AroundNext)
        }

        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            if let Some(label) = self.execute_log {
                self.log.lock().unwrap().push(label);
            }

            match self.behavior {
                StubBehavior::Next => Ok(ExecStep::Next),
                StubBehavior::Return => Ok(ExecStep::Return),
                StubBehavior::Error(message) => Err(DnsError::plugin(message)),
                StubBehavior::AroundNext => Ok(ExecStep::Next),
            }
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            next: Option<ExecutorNext>,
        ) -> Result<ExecStep> {
            match self.behavior {
                StubBehavior::AroundNext => {
                    if let Some(label) = self.execute_log {
                        self.log.lock().unwrap().push(label);
                    }

                    let result = continue_next!(next, context);
                    if let Some(label) = self.post_log {
                        self.log.lock().unwrap().push(label);
                    }
                    result
                }
                StubBehavior::Next | StubBehavior::Return | StubBehavior::Error(_) => {
                    let result = self.execute(context).await?;
                    match result {
                        ExecStep::Next => continue_next!(next, context),
                        ExecStep::Stop | ExecStep::Return => Ok(result),
                    }
                }
            }
        }
    }

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.set_id(42);
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));

        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn executor_instruction(executor: Arc<dyn Executor>) -> Instruction {
        let op = if executor.with_next() {
            InstructionOp::ExecutorWithNext(executor)
        } else {
            InstructionOp::Executor(executor)
        };
        Instruction {
            matchers: Vec::new(),
            op,
        }
    }

    fn builtin_instruction(op: BuiltinOp) -> Instruction {
        Instruction {
            matchers: Vec::new(),
            op: InstructionOp::Builtin(op),
        }
    }

    #[tokio::test]
    async fn test_run_executes_continuation_callbacks_in_lifo_order() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let first: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "first",
            StubBehavior::AroundNext,
            None,
            Some("post:first"),
            log.clone(),
        ));
        let second: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "second",
            StubBehavior::AroundNext,
            None,
            Some("post:second"),
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
    async fn test_run_bubbles_execute_error_after_running_with_next_cleanup() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let deferred: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "deferred",
            StubBehavior::AroundNext,
            None,
            Some("post:deferred"),
            log.clone(),
        ));
        let failing: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "failing",
            StubBehavior::Error("boom"),
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
    async fn test_run_reject_sets_response_and_stops() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let skipped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "skipped",
            StubBehavior::Next,
            Some("execute:skipped"),
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Reject(Rcode::ServFail)),
                executor_instruction(skipped),
            ],
        });
        let mut context = make_context();

        // Act
        program.run(&mut context).await.unwrap();

        // Assert
        let response = context.response().expect("reject should build a response");
        assert_eq!(response.id(), 42);
        assert_eq!(response.rcode(), Rcode::ServFail);
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_standalone_execute_with_next_supports_with_next_executor() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let executor = StubExecutor::new(
            "terminal",
            StubBehavior::AroundNext,
            Some("execute:terminal"),
            Some("post:terminal"),
            log.clone(),
        );
        let mut context = make_context();

        let step = executor
            .execute_with_next(&mut context, None)
            .await
            .unwrap();

        assert!(matches!(step, ExecStep::Next));
        assert_eq!(
            log.lock().unwrap().clone(),
            vec!["execute:terminal", "post:terminal"]
        );
    }

    #[tokio::test]
    async fn test_run_reject_builds_response_from_request_message() {
        let program = Arc::new(ChainProgram {
            instructions: vec![builtin_instruction(BuiltinOp::Reject(Rcode::ServFail))],
        });
        let mut context = make_context();

        program.run(&mut context).await.unwrap();

        let response = context.response().expect("reject should build response");
        assert_eq!(response.id(), 42);
        assert_eq!(response.rcode(), Rcode::ServFail);
    }

    #[tokio::test]
    async fn test_parse_builtin_reject_defaults_to_refused() {
        let registry = crate::plugin::test_utils::test_registry();
        let mut builder = ChainBuilder::new(registry, "seq".to_string());

        let op = builder
            .parse_builtin("reject", 0)
            .await
            .expect("reject without argument should parse");

        assert!(matches!(op, Some(BuiltinOp::Reject(Rcode::Refused))));
    }

    #[tokio::test]
    async fn test_run_accept_stops_without_building_response() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let skipped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "skipped",
            StubBehavior::Next,
            Some("execute:skipped"),
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
        assert!(context.response().is_none());
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_run_return_returns_to_caller() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let skipped: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "skipped",
            StubBehavior::Next,
            Some("execute:skipped"),
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
        let step = program.run(&mut context).await.unwrap();

        // Assert
        assert!(matches!(step, ExecStep::Return));
        assert!(context.response().is_none());
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_run_jump_resumes_parent_program_after_child_return() {
        // Arrange
        let log = Arc::new(Mutex::new(Vec::new()));
        let after_jump: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "after_jump",
            StubBehavior::Next,
            Some("execute:after_jump"),
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Jump(Arc::new(StubExecutor::new(
                    "jumped",
                    StubBehavior::Return,
                    Some("execute:jumped"),
                    None,
                    log.clone(),
                )))),
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
    }

    #[tokio::test]
    async fn test_run_goto_propagates_child_return_without_resuming_parent() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let after_goto: Arc<dyn Executor> = Arc::new(StubExecutor::new(
            "after_goto",
            StubBehavior::Next,
            Some("execute:after_goto"),
            None,
            log.clone(),
        ));
        let program = Arc::new(ChainProgram {
            instructions: vec![
                builtin_instruction(BuiltinOp::Goto(Arc::new(StubExecutor::new(
                    "goto_child",
                    StubBehavior::Return,
                    Some("execute:goto_child"),
                    None,
                    log.clone(),
                )))),
                executor_instruction(after_goto),
            ],
        });
        let mut context = make_context();

        let step = program.run(&mut context).await.unwrap();

        assert!(matches!(step, ExecStep::Return));
        assert_eq!(log.lock().unwrap().clone(), vec!["execute:goto_child"]);
    }
}
