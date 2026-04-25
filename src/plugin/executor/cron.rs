// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cron` executor plugin.
//!
//! This executor is a background scheduler instead of a request-path action.
//! It resolves a list of executor references, then triggers them on a fixed
//! interval or standard 5-field cron expression after plugin initialization.
//!
//! Design notes:
//! - jobs run with an empty [`DnsContext`];
//! - job executors always run serially;
//! - executor `Stop`, response mutation, or errors never stop later executors;
//! - overlapping triggers are skipped rather than queued; and
//! - quick-setup executors are owned and destroyed by this plugin.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cronexpr::Crontab;
use cronexpr::jiff::Timestamp;
use serde::Deserialize;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::{
    parse_simple_duration, system_timezone_name, unix_timestamp_millis,
};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{
    Plugin, PluginFactory, PluginHolder, PluginRegistry, UninitializedPlugin,
    expand_quick_setup_dependency_specs, registered_plugin_kind,
};
use crate::proto::Message;
use crate::register_plugin_factory;

const ATTR_PLUGIN_TAG: &str = "cron.plugin_tag";
const ATTR_JOB_NAME: &str = "cron.job_name";
const ATTR_SCHEDULED_AT_UNIX_MS: &str = "cron.scheduled_at_unix_ms";
const ATTR_TRIGGER_KIND: &str = "cron.trigger_kind";
const CRON_PLUGIN_TYPE: &str = "cron";
const MIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
struct CronConfig {
    timezone: Option<String>,
    jobs: Vec<JobConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct JobConfig {
    name: String,
    schedule: Option<String>,
    interval: Option<String>,
    executors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecutorRef {
    PluginTag(String),
    QuickSetup {
        plugin_type: String,
        param: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum JobTrigger {
    Cron {
        schedule: String,
        crontab: Arc<Crontab>,
        timezone_name: String,
    },
    Interval {
        interval: Duration,
    },
}

impl JobTrigger {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Cron { .. } => "schedule",
            Self::Interval { .. } => "interval",
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedJob {
    name: String,
    trigger: JobTrigger,
    executors: Vec<Arc<dyn Executor>>,
}

#[derive(Debug)]
struct RuntimeJob {
    name: String,
    trigger: JobTrigger,
    next_run_ms: i64,
    executors: Vec<Arc<dyn Executor>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct SchedulerClock {
    base_wall_ms: i64,
    base_instant: Instant,
}

impl SchedulerClock {
    fn new() -> Self {
        Self {
            base_wall_ms: unix_timestamp_millis(),
            base_instant: Instant::now(),
        }
    }

    fn now_ms(&self) -> i64 {
        let elapsed_ms = self.base_instant.elapsed().as_millis();
        let elapsed_ms = elapsed_ms.min(i64::MAX as u128) as i64;
        self.base_wall_ms.saturating_add(elapsed_ms)
    }
}

#[derive(Debug)]
struct CronExecutor {
    tag: String,
    registry: Arc<PluginRegistry>,
    config: CronConfig,
    quick_setup_executors: Vec<Arc<dyn Executor>>,
    stop_tx: Mutex<Option<oneshot::Sender<()>>>,
    scheduler_handle: Mutex<Option<JoinHandle<()>>>,
}

#[async_trait]
impl Plugin for CronExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        let mut prepared_jobs = Vec::with_capacity(self.config.jobs.len());
        let jobs = self.config.jobs.clone();
        for (job_index, job) in jobs.iter().enumerate() {
            prepared_jobs.push(self.prepare_job(job, job_index).await?);
        }

        let clock = SchedulerClock::new();
        let mut runtime_jobs = Vec::with_capacity(prepared_jobs.len());
        for job in prepared_jobs {
            let next_run_ms = compute_next_run_ms(&job.trigger, clock.now_ms())?;
            runtime_jobs.push(RuntimeJob {
                name: job.name,
                trigger: job.trigger,
                next_run_ms,
                executors: job.executors,
                handle: None,
            });
        }

        let (stop_tx, stop_rx) = oneshot::channel();
        let handle = tokio::spawn(run_scheduler(
            self.tag.clone(),
            self.registry.clone(),
            clock,
            runtime_jobs,
            stop_rx,
        ));

        *self.stop_tx.get_mut() = Some(stop_tx);
        *self.scheduler_handle.get_mut() = Some(handle);
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(stop_tx) = self.stop_tx.lock().await.take() {
            let _ = stop_tx.send(());
        }

        if let Some(handle) = self.scheduler_handle.lock().await.take() {
            match handle.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {}
                Err(err) if err.is_panic() => {
                    return Err(DnsError::plugin(format!(
                        "cron scheduler task panicked: {}",
                        err
                    )));
                }
                Err(err) => {
                    return Err(DnsError::plugin(format!(
                        "cron scheduler task exited unexpectedly: {}",
                        err
                    )));
                }
            }
        }

        let mut first_err = None;
        for executor in &self.quick_setup_executors {
            if let Err(err) = executor.destroy().await
                && first_err.is_none()
            {
                first_err = Some(err);
            }
        }

        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Executor for CronExecutor {
    #[hotpath::measure]
    async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
        Err(DnsError::plugin(
            "cron can only run as a background scheduled executor",
        ))
    }
}

impl CronExecutor {
    async fn prepare_job(&mut self, job: &JobConfig, job_index: usize) -> Result<PreparedJob> {
        let timezone_name = resolve_timezone_name(self.config.timezone.as_deref());
        let trigger = parse_job_trigger_with_timezone(job, &timezone_name)?;
        let mut executors = Vec::with_capacity(job.executors.len());
        for (exec_index, raw) in job.executors.iter().enumerate() {
            let field = format!("args.jobs[{}].executors[{}]", job_index, exec_index);
            executors.push(
                self.resolve_executor_ref(raw, job_index, exec_index, &field)
                    .await?,
            );
        }

        Ok(PreparedJob {
            name: job.name.trim().to_string(),
            trigger,
            executors,
        })
    }

    async fn resolve_executor_ref(
        &mut self,
        raw: &str,
        job_index: usize,
        exec_index: usize,
        field: &str,
    ) -> Result<Arc<dyn Executor>> {
        match parse_executor_ref(raw)? {
            ExecutorRef::PluginTag(tag) => {
                if tag == self.tag {
                    return Err(DnsError::plugin(format!(
                        "plugin '{}' field '{}' references itself",
                        self.tag, field
                    )));
                }

                let plugin = self.registry.get_plugin(&tag).ok_or_else(|| {
                    DnsError::plugin(format!(
                        "plugin '{}' field '{}' references missing plugin '{}'",
                        self.tag, field, tag
                    ))
                })?;
                if plugin.plugin_type != crate::plugin::PluginType::Executor {
                    return Err(DnsError::plugin(format!(
                        "plugin '{}' field '{}' expects executor plugin, but '{}' is {} (type '{}')",
                        self.tag,
                        field,
                        tag,
                        plugin_type_kind_name(plugin.plugin_type),
                        plugin.plugin_name
                    )));
                }
                if plugin.plugin_name == CRON_PLUGIN_TYPE {
                    return Err(DnsError::plugin(format!(
                        "plugin '{}' field '{}' cannot reference cron executor '{}'",
                        self.tag, field, tag
                    )));
                }
                Ok(plugin.to_executor())
            }
            ExecutorRef::QuickSetup { plugin_type, param } => {
                if plugin_type == CRON_PLUGIN_TYPE {
                    return Err(DnsError::plugin(format!(
                        "plugin '{}' field '{}' cannot reference cron executor type '{}'",
                        self.tag, field, plugin_type
                    )));
                }

                let quick_tag = format!("@qs:cron:{}:{}:{}", self.tag, job_index, exec_index);
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
}

#[derive(Debug, Clone)]
pub struct CronFactory;

register_plugin_factory!("cron", CronFactory {});

impl PluginFactory for CronFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Some(args) = plugin_config.args.clone() else {
            return vec![];
        };
        let Ok(config) = serde_yaml_ng::from_value::<CronConfig>(args) else {
            return vec![];
        };

        let mut deps = Vec::new();
        for (job_index, job) in config.jobs.into_iter().enumerate() {
            for (exec_index, raw) in job.executors.into_iter().enumerate() {
                let field = format!("args.jobs[{}].executors[{}]", job_index, exec_index);
                match parse_executor_ref(&raw) {
                    Ok(ExecutorRef::PluginTag(tag)) => {
                        deps.push(DependencySpec::executor(field, tag));
                    }
                    Ok(ExecutorRef::QuickSetup { plugin_type, param }) => {
                        deps.extend(expand_quick_setup_dependency_specs(
                            &field,
                            &plugin_type,
                            param.as_deref(),
                        ));
                    }
                    Err(_) => {}
                }
            }
        }
        deps
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let args = plugin_config
            .args
            .clone()
            .ok_or_else(|| DnsError::plugin("cron requires configuration arguments"))?;
        let config = serde_yaml_ng::from_value::<CronConfig>(args)
            .map_err(|e| DnsError::plugin(format!("failed to parse cron config: {}", e)))?;
        validate_config(plugin_config, &config)?;

        Ok(UninitializedPlugin::Executor(Box::new(CronExecutor {
            tag: plugin_config.tag.clone(),
            registry,
            config,
            quick_setup_executors: Vec::new(),
            stop_tx: Mutex::new(None),
            scheduler_handle: Mutex::new(None),
        })))
    }
}

fn validate_config(plugin_config: &PluginConfig, config: &CronConfig) -> Result<()> {
    if config.jobs.is_empty() {
        return Err(DnsError::plugin("cron requires at least one job"));
    }

    let timezone_name = resolve_timezone_name(config.timezone.as_deref());
    let mut seen_names = std::collections::HashSet::new();
    for (job_index, job) in config.jobs.iter().enumerate() {
        let name = job.name.trim();
        if name.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' args.jobs[{}].name cannot be empty",
                plugin_config.tag, job_index
            )));
        }
        if !seen_names.insert(name.to_string()) {
            return Err(DnsError::plugin(format!(
                "plugin '{}' has duplicate cron job name '{}'",
                plugin_config.tag, name
            )));
        }
        if job.executors.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' args.jobs[{}].executors cannot be empty",
                plugin_config.tag, job_index
            )));
        }
        parse_job_trigger_with_timezone(job, &timezone_name)?;

        for (exec_index, raw) in job.executors.iter().enumerate() {
            let field = format!("args.jobs[{}].executors[{}]", job_index, exec_index);
            match parse_executor_ref(raw)? {
                ExecutorRef::PluginTag(tag) if tag == plugin_config.tag => {
                    return Err(DnsError::plugin(format!(
                        "plugin '{}' field '{}' references itself",
                        plugin_config.tag, field
                    )));
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn parse_job_trigger_with_timezone(job: &JobConfig, timezone_name: &str) -> Result<JobTrigger> {
    let has_schedule = job.schedule.as_ref().is_some_and(|v| !v.trim().is_empty());
    let has_interval = job.interval.as_ref().is_some_and(|v| !v.trim().is_empty());

    match (has_schedule, has_interval) {
        (true, true) => {
            return Err(DnsError::plugin(format!(
                "cron job '{}' must configure exactly one of schedule or interval",
                job.name
            )));
        }
        (false, false) => {
            return Err(DnsError::plugin(format!(
                "cron job '{}' must configure exactly one of schedule or interval",
                job.name
            )));
        }
        _ => {}
    }

    if let Some(schedule) = job.schedule.as_deref().map(str::trim)
        && !schedule.is_empty()
    {
        let field_count = schedule.split_whitespace().count();
        if field_count != 5 {
            return Err(DnsError::plugin(format!(
                "cron job '{}' schedule must use standard 5-field cron format; second-level cron is not supported",
                job.name
            )));
        }

        let schedule_with_timezone = format!("{} {}", schedule, timezone_name);
        let crontab = cronexpr::parse_crontab(&schedule_with_timezone).map_err(|e| {
            DnsError::plugin(format!(
                "failed to parse cron schedule for job '{}': {}",
                job.name, e
            ))
        })?;

        return Ok(JobTrigger::Cron {
            schedule: schedule.to_string(),
            crontab: Arc::new(crontab),
            timezone_name: timezone_name.to_string(),
        });
    }

    let interval = parse_interval(
        job.name.as_str(),
        job.interval.as_deref().unwrap_or_default(),
    )?;
    Ok(JobTrigger::Interval { interval })
}

fn parse_executor_ref(raw: &str) -> Result<ExecutorRef> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DnsError::plugin("executor reference cannot be empty"));
    }
    if let Some(tag) = raw.strip_prefix('$') {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(DnsError::plugin(format!(
                "invalid executor reference '{}'",
                raw
            )));
        }
        return Ok(ExecutorRef::PluginTag(tag.to_string()));
    }

    let mut split = raw.splitn(2, char::is_whitespace);
    let first = split
        .next()
        .ok_or_else(|| DnsError::plugin(format!("invalid executor reference '{}'", raw)))?;
    let param = split
        .next()
        .map(str::trim)
        .filter(|param| !param.is_empty());

    if matches!(
        registered_plugin_kind(first),
        Some(crate::plugin::dependency::DependencyKind::Executor)
    ) {
        return Ok(ExecutorRef::QuickSetup {
            plugin_type: first.to_string(),
            param: param.map(ToOwned::to_owned),
        });
    }

    Ok(ExecutorRef::PluginTag(raw.to_string()))
}

fn parse_interval(job_name: &str, raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let duration = parse_simple_duration(raw).map_err(|err| {
        let detail = if raw.chars().all(|c| c.is_ascii_digit()) {
            format!(
                "cron job '{}' interval must include a unit and second-level tasks are not supported",
                job_name
            )
        } else if raw.is_empty() {
            format!("cron job '{}' interval cannot be empty", job_name)
        } else {
            format!("invalid interval '{}' for cron job '{}': {}", raw, job_name, err)
        };
        DnsError::plugin(detail)
    })?;

    if duration < MIN_INTERVAL {
        return Err(DnsError::plugin(format!(
            "cron job '{}' interval must be at least 1 minute; second-level tasks are not supported",
            job_name
        )));
    }

    Ok(duration)
}

fn resolve_timezone_name(configured: Option<&str>) -> String {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            let timezone = system_timezone_name();
            if timezone == "UTC" {
                warn!("system timezone name is unavailable; falling back to UTC for cron jobs");
            }
            timezone
        })
}

fn plugin_type_kind_name(plugin_type: crate::plugin::PluginType) -> &'static str {
    match plugin_type {
        crate::plugin::PluginType::Server => "server",
        crate::plugin::PluginType::Executor => "executor",
        crate::plugin::PluginType::Matcher => "matcher",
        crate::plugin::PluginType::Provider => "provider",
    }
}

fn compute_next_run_ms(trigger: &JobTrigger, reference_ms: i64) -> Result<i64> {
    match trigger {
        JobTrigger::Cron {
            crontab,
            timezone_name,
            ..
        } => {
            let timestamp = Timestamp::from_millisecond(reference_ms).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to build timestamp from '{}': {}",
                    reference_ms, e
                ))
            })?;
            let zoned = timestamp.in_tz(timezone_name).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to project timestamp into timezone '{}': {}",
                    timezone_name, e
                ))
            })?;
            let next = crontab.find_next(zoned.to_string().as_str()).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to compute next run for cron schedule '{}': {}",
                    trigger_description(trigger),
                    e
                ))
            })?;
            Ok(next.timestamp().as_millisecond())
        }
        JobTrigger::Interval { interval } => {
            let interval_ms = interval.as_millis().min(i64::MAX as u128) as i64;
            Ok(reference_ms.saturating_add(interval_ms))
        }
    }
}

fn trigger_description(trigger: &JobTrigger) -> String {
    match trigger {
        JobTrigger::Cron { schedule, .. } => schedule.clone(),
        JobTrigger::Interval { interval } => format!("{:?}", interval),
    }
}

fn advance_next_run_past_now(job: &mut RuntimeJob, now_ms: i64) -> Result<()> {
    loop {
        let next = compute_next_run_ms(&job.trigger, job.next_run_ms)?;
        job.next_run_ms = next;
        if job.next_run_ms > now_ms {
            return Ok(());
        }
    }
}

async fn run_scheduler(
    plugin_tag: String,
    registry: Arc<PluginRegistry>,
    clock: SchedulerClock,
    mut jobs: Vec<RuntimeJob>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        reap_finished_job_handles(&plugin_tag, &mut jobs).await;

        let now_ms = clock.now_ms();
        let mut due = Vec::new();
        let mut next_delay_ms: Option<u64> = None;

        for (idx, job) in jobs.iter().enumerate() {
            if job.next_run_ms <= now_ms {
                due.push(idx);
                continue;
            }

            let delta = (job.next_run_ms - now_ms) as u64;
            next_delay_ms = Some(next_delay_ms.map_or(delta, |current| current.min(delta)));
        }

        if !due.is_empty() {
            for idx in due {
                let job = &mut jobs[idx];
                let scheduled_at_ms = job.next_run_ms;
                if let Err(err) = advance_next_run_past_now(job, now_ms) {
                    error!(
                        plugin = %plugin_tag,
                        job = %job.name,
                        error = %err,
                        "failed to advance cron job schedule"
                    );
                    let fallback = MIN_INTERVAL.as_millis().min(i64::MAX as u128) as i64;
                    job.next_run_ms = now_ms.saturating_add(fallback);
                    continue;
                }

                if job.handle.is_some() {
                    warn!(
                        plugin = %plugin_tag,
                        job = %job.name,
                        trigger = %job.trigger.kind_name(),
                        "cron job trigger skipped because the previous run is still active"
                    );
                    continue;
                }

                let run_name = job.name.clone();
                let trigger_kind = job.trigger.kind_name().to_string();
                let executors = job.executors.clone();
                let run_registry = registry.clone();
                let run_plugin_tag = plugin_tag.clone();
                job.handle = Some(tokio::spawn(async move {
                    run_job(
                        run_plugin_tag,
                        run_name,
                        trigger_kind,
                        scheduled_at_ms,
                        run_registry,
                        executors,
                    )
                    .await;
                }));
            }
            continue;
        }

        let Some(delay_ms) = next_delay_ms else {
            debug!(plugin = %plugin_tag, "cron scheduler has no jobs left to process");
            break;
        };

        tokio::select! {
            _ = &mut stop_rx => break,
            _ = tokio::time::sleep(Duration::from_millis(delay_ms.max(1))) => {}
        }
    }

    for job in &mut jobs {
        if let Some(handle) = job.handle.take() {
            handle.abort();
            await_job_handle(&plugin_tag, &job.name, handle).await;
        }
    }
}

async fn reap_finished_job_handles(plugin_tag: &str, jobs: &mut [RuntimeJob]) {
    let mut finished = Vec::new();
    for job in jobs {
        if job
            .handle
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
            && let Some(handle) = job.handle.take()
        {
            finished.push((job.name.clone(), handle));
        }
    }

    for (job_name, handle) in finished {
        await_job_handle(plugin_tag, &job_name, handle).await;
    }
}

async fn await_job_handle(plugin_tag: &str, job_name: &str, handle: JoinHandle<()>) {
    match handle.await {
        Ok(()) => {}
        Err(err) if err.is_cancelled() => {}
        Err(err) if err.is_panic() => {
            error!(
                plugin = %plugin_tag,
                job = %job_name,
                error = %err,
                "cron job task panicked"
            );
        }
        Err(err) => {
            warn!(
                plugin = %plugin_tag,
                job = %job_name,
                error = %err,
                "cron job task exited unexpectedly"
            );
        }
    }
}

async fn run_job(
    plugin_tag: String,
    job_name: String,
    trigger_kind: String,
    scheduled_at_ms: i64,
    registry: Arc<PluginRegistry>,
    executors: Vec<Arc<dyn Executor>>,
) {
    info!(
        plugin = %plugin_tag,
        job = %job_name,
        trigger = %trigger_kind,
        executor_count = executors.len(),
        "cron job started"
    );

    let mut context = DnsContext::new(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        Message::new(),
        registry,
    );
    context.set_attr(ATTR_PLUGIN_TAG, plugin_tag.clone());
    context.set_attr(ATTR_JOB_NAME, job_name.clone());
    context.set_attr(ATTR_SCHEDULED_AT_UNIX_MS, scheduled_at_ms);
    context.set_attr(ATTR_TRIGGER_KIND, trigger_kind.clone());

    for executor in executors {
        match executor.execute(&mut context).await {
            Ok(ExecStep::Next) | Ok(ExecStep::Stop) | Ok(ExecStep::Return) => {}
            Err(err) => {
                warn!(
                    plugin = %plugin_tag,
                    job = %job_name,
                    executor = %executor.tag(),
                    error = %err,
                    "cron job executor failed"
                );
            }
        }
    }

    info!(
        plugin = %plugin_tag,
        job = %job_name,
        trigger = %trigger_kind,
        "cron job finished"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_yaml_ng::Value;
    use tokio::sync::Notify;

    use super::*;
    use crate::plugin::dependency::DependencySpec;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::{plugin_config, test_registry};
    use crate::register_plugin_factory;

    #[derive(Debug, Clone, Copy)]
    enum StubBehavior {
        Next,
        Stop,
        Error(&'static str),
    }

    #[derive(Debug)]
    struct StubExecutor {
        tag: String,
        behavior: StubBehavior,
        log: Arc<StdMutex<Vec<String>>>,
        destroyed: Arc<AtomicBool>,
        started: Arc<AtomicUsize>,
        blocker: Option<Arc<Notify>>,
    }

    impl StubExecutor {
        fn new(tag: &str, behavior: StubBehavior, log: Arc<StdMutex<Vec<String>>>) -> Self {
            Self {
                tag: tag.to_string(),
                behavior,
                log,
                destroyed: Arc::new(AtomicBool::new(false)),
                started: Arc::new(AtomicUsize::new(0)),
                blocker: None,
            }
        }

        fn with_blocker(mut self, blocker: Arc<Notify>) -> Self {
            self.blocker = Some(blocker);
            self
        }
    }

    #[async_trait]
    impl Plugin for StubExecutor {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            self.destroyed.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for StubExecutor {
        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            self.started.fetch_add(1, Ordering::Relaxed);
            self.log.lock().unwrap().push(self.tag.clone());
            if let Some(blocker) = &self.blocker {
                blocker.notified().await;
            }
            match self.behavior {
                StubBehavior::Next => Ok(ExecStep::Next),
                StubBehavior::Stop => Ok(ExecStep::Stop),
                StubBehavior::Error(msg) => Err(DnsError::plugin(msg)),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct TestQuickSetupDependencyExecutorFactory;

    register_plugin_factory!(
        "test_cron_quick_dep_exec",
        TestQuickSetupDependencyExecutorFactory {}
    );

    impl PluginFactory for TestQuickSetupDependencyExecutorFactory {
        fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
            let Some(tag) = param.map(str::trim).filter(|tag| !tag.is_empty()) else {
                return vec![];
            };
            vec![DependencySpec::provider(
                "provider_tags[0]",
                tag.to_string(),
            )]
        }

        fn create(
            &self,
            plugin_config: &PluginConfig,
            _registry: Arc<PluginRegistry>,
            _context: &crate::plugin::PluginCreateContext,
        ) -> Result<UninitializedPlugin> {
            Ok(UninitializedPlugin::Executor(Box::new(StubExecutor::new(
                &plugin_config.tag,
                StubBehavior::Next,
                Arc::new(StdMutex::new(Vec::new())),
            ))))
        }

        fn quick_setup(
            &self,
            tag: &str,
            _param: Option<String>,
            _registry: Arc<PluginRegistry>,
        ) -> Result<UninitializedPlugin> {
            Ok(UninitializedPlugin::Executor(Box::new(StubExecutor::new(
                tag,
                StubBehavior::Next,
                Arc::new(StdMutex::new(Vec::new())),
            ))))
        }
    }

    #[test]
    fn test_parse_executor_ref_supports_tag_and_quick_setup() {
        assert_eq!(
            parse_executor_ref("$abc").unwrap(),
            ExecutorRef::PluginTag("abc".to_string())
        );
        assert_eq!(
            parse_executor_ref("plain_tag").unwrap(),
            ExecutorRef::PluginTag("plain_tag".to_string())
        );
        assert_eq!(
            parse_executor_ref("debug_print hello").unwrap(),
            ExecutorRef::QuickSetup {
                plugin_type: "debug_print".to_string(),
                param: Some("hello".to_string())
            }
        );
    }

    #[test]
    fn test_factory_dependency_specs_expand_quick_setup_dependencies() {
        let cfg = plugin_config(
            "cron",
            "cron",
            Some(
                serde_yaml_ng::from_str(
                    r#"
jobs:
  - name: job
    schedule: "0 * * * *"
    executors:
      - test_cron_quick_dep_exec dep_provider
"#,
                )
                .expect("cron args should parse"),
            ),
        );

        let deps = CronFactory.get_dependency_specs(&cfg);
        assert_eq!(
            deps,
            vec![DependencySpec::provider(
                "args.jobs[0].executors[0] -> quick_setup(test_cron_quick_dep_exec).provider_tags[0]",
                "dep_provider",
            )]
        );
    }

    #[test]
    fn test_parse_job_trigger_rejects_second_level_cron() {
        let job = JobConfig {
            name: "bad".to_string(),
            schedule: Some("0 0 * * * *".to_string()),
            interval: None,
            executors: vec!["$a".to_string()],
        };
        let err = parse_job_trigger_with_timezone(&job, "UTC")
            .expect_err("6-field cron should be rejected");
        assert!(err.to_string().contains("second-level cron"));
    }

    #[test]
    fn test_parse_job_trigger_accepts_explicit_timezone() {
        let job = JobConfig {
            name: "ok".to_string(),
            schedule: Some("0 */6 * * *".to_string()),
            interval: None,
            executors: vec!["$a".to_string()],
        };
        let trigger =
            parse_job_trigger_with_timezone(&job, "Asia/Shanghai").expect("timezone should work");
        match trigger {
            JobTrigger::Cron { timezone_name, .. } => assert_eq!(timezone_name, "Asia/Shanghai"),
            JobTrigger::Interval { .. } => panic!("expected cron trigger"),
        }
    }

    #[test]
    fn test_parse_interval_requires_minute_granularity() {
        assert!(parse_interval("ok", "5m").is_ok());
        assert!(parse_interval("ok", "1h").is_ok());
        let err = parse_interval("bad", "30s").expect_err("30s should be rejected");
        assert!(err.to_string().contains("at least 1 minute"));
    }

    #[tokio::test]
    async fn test_run_job_continues_after_stop_and_error() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let executors: Vec<Arc<dyn Executor>> = vec![
            Arc::new(StubExecutor::new("first", StubBehavior::Stop, log.clone())),
            Arc::new(StubExecutor::new(
                "second",
                StubBehavior::Error("boom"),
                log.clone(),
            )),
            Arc::new(StubExecutor::new("third", StubBehavior::Next, log.clone())),
        ];

        run_job(
            "cron".to_string(),
            "job".to_string(),
            "interval".to_string(),
            123,
            test_registry(),
            executors,
        )
        .await;

        assert_eq!(
            log.lock().unwrap().clone(),
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string()
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_interval_scheduler_waits_full_interval_before_first_run() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let executor = Arc::new(StubExecutor::new("probe", StubBehavior::Next, log.clone()));
        let clock = SchedulerClock::new();
        let first_run_at = compute_next_run_ms(
            &JobTrigger::Interval {
                interval: Duration::from_secs(60),
            },
            clock.now_ms(),
        )
        .unwrap();

        let job = RuntimeJob {
            name: "job".to_string(),
            trigger: JobTrigger::Interval {
                interval: Duration::from_secs(60),
            },
            next_run_ms: first_run_at,
            executors: vec![executor.clone()],
            handle: None,
        };
        let (stop_tx, stop_rx) = oneshot::channel();
        let scheduler = tokio::spawn(run_scheduler(
            "cron".to_string(),
            test_registry(),
            clock,
            vec![job],
            stop_rx,
        ));

        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(executor.started.load(Ordering::Relaxed), 0);

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(executor.started.load(Ordering::Relaxed), 1);

        let _ = stop_tx.send(());
        scheduler.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_scheduler_skips_overlapping_job_runs() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let blocker = Arc::new(Notify::new());
        let executor = Arc::new(
            StubExecutor::new("probe", StubBehavior::Next, log.clone())
                .with_blocker(blocker.clone()),
        );
        let clock = SchedulerClock::new();
        let first_run_at = compute_next_run_ms(
            &JobTrigger::Interval {
                interval: Duration::from_secs(60),
            },
            clock.now_ms(),
        )
        .unwrap();

        let job = RuntimeJob {
            name: "job".to_string(),
            trigger: JobTrigger::Interval {
                interval: Duration::from_secs(60),
            },
            next_run_ms: first_run_at,
            executors: vec![executor.clone()],
            handle: None,
        };
        let (stop_tx, stop_rx) = oneshot::channel();
        let scheduler = tokio::spawn(run_scheduler(
            "cron".to_string(),
            test_registry(),
            clock,
            vec![job],
            stop_rx,
        ));

        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(executor.started.load(Ordering::Relaxed), 1);

        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(executor.started.load(Ordering::Relaxed), 1);

        blocker.notify_waiters();
        tokio::task::yield_now().await;

        let _ = stop_tx.send(());
        scheduler.await.unwrap();
    }

    #[tokio::test]
    async fn test_destroy_cleans_up_quick_setup_executors() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let quick = Arc::new(StubExecutor::new("quick", StubBehavior::Next, log));
        let destroyed = quick.destroyed.clone();
        let cron = CronExecutor {
            tag: "cron".to_string(),
            registry: test_registry(),
            config: CronConfig {
                timezone: None,
                jobs: vec![JobConfig {
                    name: "job".to_string(),
                    schedule: Some("0 * * * *".to_string()),
                    interval: None,
                    executors: vec!["$x".to_string()],
                }],
            },
            quick_setup_executors: vec![quick],
            stop_tx: Mutex::new(None),
            scheduler_handle: Mutex::new(None),
        };

        cron.destroy().await.unwrap();
        assert!(destroyed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_factory_create_rejects_invalid_args() {
        let factory = CronFactory;
        let cfg = plugin_config("cron", "cron", Some(Value::String("bad".into())));
        assert!(
            factory
                .create(&cfg, test_registry(), &Default::default())
                .is_err()
        );
    }

    #[test]
    fn test_resolve_timezone_name_prefers_configured_value() {
        assert_eq!(resolve_timezone_name(Some("UTC")), "UTC");
        assert_eq!(
            resolve_timezone_name(Some("  Asia/Shanghai  ")),
            "Asia/Shanghai"
        );
    }
}
