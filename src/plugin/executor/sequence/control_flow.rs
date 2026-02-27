/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::error::{DnsError, Result};
use crate::plugin::PluginRegistry;
use crate::plugin::executor::sequence::chain::ChainNode;
use crate::plugin::executor::sequence::{SequenceRef, parse_sequence_ref};
use crate::plugin::executor::{ExecResult, Executor};
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use std::fmt::Debug;
use std::sync::Arc;

#[async_trait]
pub trait ControlFlowBuiltin: Debug + Send + Sync + 'static {
    async fn run(&self, context: &mut DnsContext, next: Option<&Arc<dyn ChainNode>>) -> ExecResult;
}

#[derive(Debug)]
pub struct AcceptControl;

#[async_trait]
impl ControlFlowBuiltin for AcceptControl {
    async fn run(
        &self,
        context: &mut DnsContext,
        _next: Option<&Arc<dyn ChainNode>>,
    ) -> ExecResult {
        context.exec_flow_state = ExecFlowState::Broken;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReturnControl;

#[async_trait]
impl ControlFlowBuiltin for ReturnControl {
    async fn run(
        &self,
        _context: &mut DnsContext,
        _next: Option<&Arc<dyn ChainNode>>,
    ) -> ExecResult {
        Ok(())
    }
}

#[derive(Debug)]
pub struct RejectControl {
    rcode: ResponseCode,
}

impl RejectControl {
    pub fn new(rcode: ResponseCode) -> Self {
        Self { rcode }
    }
}

#[async_trait]
impl ControlFlowBuiltin for RejectControl {
    async fn run(
        &self,
        context: &mut DnsContext,
        _next: Option<&Arc<dyn ChainNode>>,
    ) -> ExecResult {
        context.response = Some(build_response_with_rcode(&context.request, self.rcode));
        context.exec_flow_state = ExecFlowState::Broken;
        Ok(())
    }
}

#[derive(Debug)]
pub struct JumpControl {
    executor: Arc<dyn Executor>,
}

impl JumpControl {
    pub fn new(executor: Arc<dyn Executor>) -> Self {
        Self { executor }
    }
}

#[async_trait]
impl ControlFlowBuiltin for JumpControl {
    async fn run(&self, context: &mut DnsContext, next: Option<&Arc<dyn ChainNode>>) -> ExecResult {
        self.executor.execute(context, None).await?;
        if context.exec_flow_state == ExecFlowState::Broken {
            return Ok(());
        }
        if next.is_some() && context.exec_flow_state == ExecFlowState::ReachedTail {
            context.exec_flow_state = ExecFlowState::Running;
        }
        continue_next!(next, context)
    }
}

#[derive(Debug)]
pub struct GotoControl {
    executor: Arc<dyn Executor>,
}

impl GotoControl {
    pub fn new(executor: Arc<dyn Executor>) -> Self {
        Self { executor }
    }
}

#[async_trait]
impl ControlFlowBuiltin for GotoControl {
    async fn run(
        &self,
        context: &mut DnsContext,
        _next: Option<&Arc<dyn ChainNode>>,
    ) -> ExecResult {
        self.executor.execute(context, None).await
    }
}

pub fn parse_builtin(
    expr: &str,
    registry: &Arc<PluginRegistry>,
) -> Result<Option<Box<dyn ControlFlowBuiltin>>> {
    let mut split = expr.trim().splitn(2, char::is_whitespace);
    let op = split.next().unwrap_or_default();
    let arg = split.next().map(str::trim).filter(|s| !s.is_empty());

    match op {
        "accept" => Ok(Some(Box::new(AcceptControl))),
        "return" => Ok(Some(Box::new(ReturnControl))),
        "reject" => Ok(Some(Box::new(RejectControl::new(parse_reject_rcode(arg)?)))),
        "jump" => Ok(Some(Box::new(JumpControl::new(
            resolve_jump_or_goto_executor("jump", arg, registry)?,
        )))),
        "goto" => Ok(Some(Box::new(GotoControl::new(
            resolve_jump_or_goto_executor("goto", arg, registry)?,
        )))),
        _ => Ok(None),
    }
}

fn resolve_jump_or_goto_executor(
    op: &str,
    arg: Option<&str>,
    registry: &Arc<PluginRegistry>,
) -> Result<Arc<dyn Executor>> {
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

    let plugin = registry
        .get_plugin(&tag)
        .ok_or_else(|| DnsError::plugin(format!("plugin does not exist for {}", tag)))?;
    Ok(plugin.to_executor())
}

fn parse_reject_rcode(arg: Option<&str>) -> Result<ResponseCode> {
    let Some(rcode_raw) = arg else {
        return Ok(ResponseCode::Refused);
    };

    if let Ok(code) = rcode_raw.parse::<u16>() {
        return Ok(code.into());
    }

    match rcode_raw.to_ascii_uppercase().as_str() {
        "NOERROR" => Ok(ResponseCode::NoError),
        "FORMERR" => Ok(ResponseCode::FormErr),
        "SERVFAIL" => Ok(ResponseCode::ServFail),
        "NXDOMAIN" => Ok(ResponseCode::NXDomain),
        "NOTIMP" => Ok(ResponseCode::NotImp),
        "REFUSED" => Ok(ResponseCode::Refused),
        "YXDOMAIN" => Ok(ResponseCode::YXDomain),
        "YXRRSET" => Ok(ResponseCode::YXRRSet),
        "NXRRSET" => Ok(ResponseCode::NXRRSet),
        "NOTAUTH" => Ok(ResponseCode::NotAuth),
        "NOTZONE" => Ok(ResponseCode::NotZone),
        _ => Err(DnsError::plugin(format!(
            "invalid reject rcode argument: {}",
            rcode_raw
        ))),
    }
}

fn build_response_with_rcode(request: &Message, rcode: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_op_code(request.op_code());
    response.set_message_type(MessageType::Response);
    response.set_response_code(rcode);
    *response.queries_mut() = request.queries().to_vec();
    response
}
