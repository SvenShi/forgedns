// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS forwarding plugin
//!
//! Forwards DNS queries to configured upstream resolvers.
//! Supports:
//! - single-upstream forwarding
//! - multi-upstream concurrent racing (`concurrent`) with first-success return

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use rand::RngExt;
use serde::Deserialize;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info, warn};

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::metrics::{
    MetricLabel, MetricSample, MetricSink, MetricSource, register_metric_source,
    unregister_metric_source,
};
use crate::network::upstream::{ConnectionInfo, Upstream, UpstreamBuilder, UpstreamConfig};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;
use crate::proto::{Message, Rcode};

const MAX_CONCURRENT_QUERIES: usize = 3;

#[derive(Debug)]
struct ForwardMetrics {
    tag: String,
    query_total: AtomicU64,
    success_total: AtomicU64,
    error_total: AtomicU64,
    timeout_total: AtomicU64,
    latency_count: AtomicU64,
    latency_sum_ms: AtomicU64,
}

impl ForwardMetrics {
    fn new(tag: String) -> Self {
        Self {
            tag,
            query_total: AtomicU64::new(0),
            success_total: AtomicU64::new(0),
            error_total: AtomicU64::new(0),
            timeout_total: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        }
    }

    #[inline]
    fn record_query_start(&self) -> u64 {
        self.query_total.fetch_add(1, Ordering::Relaxed);
        AppClock::elapsed_millis()
    }

    #[inline]
    fn record_success(&self, start_ms: u64) {
        self.success_total.fetch_add(1, Ordering::Relaxed);
        self.record_latency(start_ms);
    }

    #[inline]
    fn record_error(&self, start_ms: u64, timeout: bool) {
        self.error_total.fetch_add(1, Ordering::Relaxed);
        if timeout {
            self.timeout_total.fetch_add(1, Ordering::Relaxed);
        }
        self.record_latency(start_ms);
    }

    #[inline]
    fn record_latency(&self, start_ms: u64) {
        let elapsed = AppClock::elapsed_millis().saturating_sub(start_ms);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_ms.fetch_add(elapsed, Ordering::Relaxed);
    }
}

impl MetricSource for ForwardMetrics {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn plugin_type(&self) -> &'static str {
        "forward"
    }

    fn collect(&self, sink: &mut dyn MetricSink) {
        let labels = [MetricLabel::new("plugin_tag", self.tag.as_str())];
        sink.emit(MetricSample::counter(
            "forward_query_total",
            "Total forward executor queries.",
            &labels,
            self.query_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "forward_success_total",
            "Total successful forward queries.",
            &labels,
            self.success_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "forward_error_total",
            "Total failed forward queries.",
            &labels,
            self.error_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "forward_timeout_total",
            "Total forward queries that timed out.",
            &labels,
            self.timeout_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "forward_latency_count",
            "Total forward queries included in latency statistics.",
            &labels,
            self.latency_count.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "forward_latency_sum_ms",
            "Total forward query latency in milliseconds.",
            &labels,
            self.latency_sum_ms.load(Ordering::Relaxed),
        ));
    }
}

/// Single-upstream DNS forwarder
///
/// Forwards DNS queries to a single configured upstream server.
/// Handles timeouts and logs errors appropriately.
#[allow(unused)]
#[derive(Debug)]
pub struct SingleDnsForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Upstream DNS resolver
    pub upstream: Box<dyn Upstream>,

    /// Whether to stop the executor chain after a successful upstream response.
    pub short_circuit: bool,

    metrics: Arc<ForwardMetrics>,
}

#[async_trait]
impl Plugin for SingleDnsForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        info!("DNS SingleDnsForwarder initialized tag: {}", self.tag);
        register_metric_source(self.metrics.clone())
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);
        Ok(())
    }
}

#[async_trait]
impl Executor for SingleDnsForwarder {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let start_ms = self.metrics.record_query_start();
        match self.upstream.query(context.request.clone()).await {
            Ok(res) => {
                context.set_response(res);
                self.metrics.record_success(start_ms);
            }
            Err(e) => {
                self.metrics.record_error(start_ms, is_timeout_error(&e));
                warn!(
                    "DNS query failed - source: {}, queries: {:?}, id: {}, reason: {}",
                    context.peer_addr(),
                    context.request.questions(),
                    context.request.id(),
                    e
                );
                return Err(DnsError::plugin(format!(
                    "forward plugin '{}' query failed: {}",
                    self.tag, e
                )));
            }
        }
        Ok(self.completion_step())
    }
}

impl SingleDnsForwarder {
    #[inline]
    fn completion_step(&self) -> ExecStep {
        if self.short_circuit {
            ExecStep::Stop
        } else {
            ExecStep::Next
        }
    }
}

#[derive(Debug)]
pub struct ConcurrentForwarder {
    /// Plugin identifier
    pub tag: String,

    /// Fixed active upstream fanout, computed at creation time.
    pub active_concurrent: usize,

    pub upstreams: Vec<Arc<dyn Upstream>>,

    /// Whether to stop the executor chain after a successful upstream response.
    pub short_circuit: bool,

    metrics: Arc<ForwardMetrics>,
}

#[async_trait]
impl Plugin for ConcurrentForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        info!("DNS ConcurrentForwarder initialized tag: {}", self.tag);
        register_metric_source(self.metrics.clone())
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);
        Ok(())
    }
}

#[async_trait]
impl Executor for ConcurrentForwarder {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let start_ms = self.metrics.record_query_start();
        let (response, last_error, timed_out) =
            self.query_any_upstream(context.request.clone()).await;
        if let Some(response) = response {
            context.set_response(response);
            self.metrics.record_success(start_ms);
            return Ok(self.completion_step());
        }

        let err = last_error.unwrap_or_else(|| "no upstream response".to_string());
        self.metrics.record_error(start_ms, timed_out);
        warn!(
            "forward plugin '{}' failed across all concurrent upstreams: {}",
            self.tag, err
        );
        Err(DnsError::plugin(format!(
            "forward plugin '{}' failed across all concurrent upstreams: {}",
            self.tag, err
        )))
    }
}

impl ConcurrentForwarder {
    #[inline]
    fn completion_step(&self) -> ExecStep {
        if self.short_circuit {
            ExecStep::Stop
        } else {
            ExecStep::Next
        }
    }

    async fn query_any_upstream(
        &self,
        request: Message,
    ) -> (Option<Message>, Option<String>, bool) {
        let total_upstreams = self.upstreams.len();
        if total_upstreams == 0 {
            return (None, Some("no upstream configured".to_string()), false);
        }

        let mut join_set = JoinSet::new();
        let mut last_error: Option<String> = None;
        let mut last_timeout = false;
        let mut completed = 0usize;
        let start_idx = rand::rng().random_range(0..total_upstreams);

        for i in 0..self.active_concurrent {
            let selected_idx = (start_idx + i) % total_upstreams;
            let upstream = self.upstreams[selected_idx].clone();
            let message = request.clone();
            join_set.spawn(async move {
                let result: Result<Message> = upstream.query(message).await;
                if event_enabled!(Level::DEBUG) {
                    debug!(
                        "DNS ConcurrentForwarder received message {}, remote_addr: {}",
                        selected_idx,
                        upstream.connection_info().raw_addr
                    );
                }
                result
            });
        }

        while let Some(joined) = join_set.join_next().await {
            completed += 1;
            match joined {
                Ok(Ok(response)) => {
                    if completed < self.active_concurrent && !is_preferred_rcode(response.rcode()) {
                        continue;
                    }
                    join_set.abort_all();
                    return (Some(response), None, false);
                }
                Ok(Err(e)) => {
                    warn!("DNS query failed: {}", e);
                    last_timeout |= is_timeout_error(&e);
                    last_error = Some(e.to_string());
                }
                Err(e) => {
                    last_error = Some(format!("forward subtask join failed: {}", e));
                }
            }
        }

        (None, last_error, last_timeout)
    }
}

#[inline]
fn is_preferred_rcode(code: Rcode) -> bool {
    code == Rcode::NoError || code == Rcode::NXDomain
}

fn is_timeout_error(err: &DnsError) -> bool {
    err.to_string().to_ascii_lowercase().contains("timeout")
}

fn parse_forward_config(plugin_config: &PluginConfig) -> Result<ForwardConfig> {
    let cfg = plugin_config.args.clone().ok_or_else(|| {
        DnsError::plugin("forward plugin requires 'concurrent' and 'upstreams' configuration")
    })?;
    let cfg = serde_yaml_ng::from_value::<ForwardConfig>(cfg)
        .map_err(|e| DnsError::plugin(format!("failed to parse forward plugin config: {}", e)))?;
    validate_forward_config(&cfg)?;
    Ok(cfg)
}

fn validate_forward_config(cfg: &ForwardConfig) -> Result<()> {
    if cfg.upstreams.is_empty() {
        return Err(DnsError::plugin(
            "forward plugin requires at least one upstream",
        ));
    }

    for (idx, upstream) in cfg.upstreams.iter().enumerate() {
        validate_upstream_addr(&upstream.addr).map_err(|e| {
            DnsError::plugin(format!(
                "forward plugin upstream[{}] addr '{}' is invalid: {}",
                idx, upstream.addr, e
            ))
        })?;
    }

    Ok(())
}

fn validate_upstream_addr(addr: &str) -> std::result::Result<(), String> {
    ConnectionInfo::with_addr(addr)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn build_upstream(upstream_config: UpstreamConfig) -> Result<Box<dyn Upstream>> {
    UpstreamBuilder::with_upstream_config(upstream_config)
}

#[inline]
fn resolve_active_concurrent(concurrent: Option<usize>) -> usize {
    concurrent.unwrap_or(1).clamp(1, MAX_CONCURRENT_QUERIES)
}

fn parse_quick_setup_param(param: Option<String>) -> Result<(Vec<String>, bool)> {
    let param = param.ok_or_else(|| {
        DnsError::plugin("forward quick setup requires non-empty upstream address parameter")
    })?;
    let (param, short_circuit) = strip_short_circuit_suffix(&param)?;
    let upstream_addrs: Vec<String> = param
        .split_whitespace()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if upstream_addrs.is_empty() {
        return Err(DnsError::plugin(
            "forward quick setup requires non-empty upstream address parameter",
        ));
    }
    Ok((upstream_addrs, short_circuit))
}

fn strip_short_circuit_suffix(raw: &str) -> Result<(String, bool)> {
    let mut tokens: Vec<&str> = raw.split_whitespace().collect();
    let mut short_circuit = false;

    while let Some(last) = tokens.last().copied() {
        let Some(value) = parse_short_circuit_token(last)? else {
            break;
        };
        short_circuit = value;
        tokens.pop();
    }

    Ok((tokens.join(" "), short_circuit))
}

fn parse_short_circuit_token(token: &str) -> Result<Option<bool>> {
    if token == "short_circuit" {
        return Ok(Some(true));
    }

    let Some(value) = token.strip_prefix("short_circuit=") else {
        return Ok(None);
    };

    match value {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(DnsError::plugin(format!(
            "invalid short_circuit value '{}', expected true or false",
            value
        ))),
    }
}

#[inline]
fn make_default_upstream_config(addr: String) -> UpstreamConfig {
    UpstreamConfig {
        tag: None,
        addr,
        dial_addr: None,
        port: None,
        bootstrap: None,
        bootstrap_version: None,
        socks5: None,
        idle_timeout: None,
        max_conns: None,
        insecure_skip_verify: None,
        timeout: None,
        enable_pipeline: None,
        enable_http3: None,
        so_mark: None,
        bind_to_device: None,
    }
}

/// Forward plugin configuration
#[derive(Deserialize)]
#[allow(unused)]
pub struct ForwardConfig {
    /// Number of upstreams to query concurrently in multi-upstream mode.
    ///
    /// Defaults to `1`, and clamped to `1..=3`.
    pub concurrent: Option<usize>,

    /// List of upstream DNS servers
    pub upstreams: Vec<UpstreamConfig>,

    /// Whether to stop the executor chain after a successful upstream response.
    #[serde(default)]
    pub short_circuit: bool,
}

/// Factory for creating DNS forwarder plugins
#[derive(Debug)]
#[plugin_factory("forward")]
pub struct ForwardFactory;

impl PluginFactory for ForwardFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        let forward_config = parse_forward_config(plugin_config)?;
        let short_circuit = forward_config.short_circuit;

        if forward_config.upstreams.len() == 1 {
            // Single upstream configuration
            let upstream_config = &forward_config.upstreams[0];
            info!(
                "Creating single DNS forwarder (tag: {}) with upstream: {}",
                plugin_config.tag, upstream_config.addr
            );

            Ok(UninitializedPlugin::Executor(Box::new(
                SingleDnsForwarder {
                    tag: plugin_config.tag.clone(),
                    upstream: build_upstream(upstream_config.clone())?,
                    short_circuit,
                    metrics: Arc::new(ForwardMetrics::new(plugin_config.tag.clone())),
                },
            )))
        } else {
            let active_concurrent = resolve_active_concurrent(forward_config.concurrent);

            let mut upstreams = Vec::with_capacity(forward_config.upstreams.len());

            for upstream_config in forward_config.upstreams {
                upstreams.push(build_upstream(upstream_config)?.into());
            }

            // Multi-upstream concurrent configuration
            Ok(UninitializedPlugin::Executor(Box::new(
                ConcurrentForwarder {
                    tag: plugin_config.tag.clone(),
                    active_concurrent,
                    upstreams,
                    short_circuit,
                    metrics: Arc::new(ForwardMetrics::new(plugin_config.tag.clone())),
                },
            )))
        }
    }

    fn quick_setup(&self, tag: &str, param: Option<String>) -> Result<UninitializedPlugin> {
        let (upstream_addrs, short_circuit) = parse_quick_setup_param(param)?;
        let mut upstream_configs = Vec::with_capacity(upstream_addrs.len());

        for (idx, upstream_addr) in upstream_addrs.into_iter().enumerate() {
            validate_upstream_addr(&upstream_addr).map_err(|e| {
                DnsError::plugin(format!(
                    "forward quick setup upstream[{}] '{}' is invalid: {}",
                    idx, upstream_addr, e
                ))
            })?;
            upstream_configs.push(make_default_upstream_config(upstream_addr));
        }

        if upstream_configs.len() == 1 {
            let upstream_config = upstream_configs.pop().unwrap();
            Ok(UninitializedPlugin::Executor(Box::new(
                SingleDnsForwarder {
                    tag: tag.to_string(),
                    upstream: build_upstream(upstream_config)?,
                    short_circuit,
                    metrics: Arc::new(ForwardMetrics::new(tag.to_string())),
                },
            )))
        } else {
            let mut upstreams = Vec::with_capacity(upstream_configs.len());
            for upstream_config in upstream_configs {
                upstreams.push(build_upstream(upstream_config)?.into());
            }
            Ok(UninitializedPlugin::Executor(Box::new(
                ConcurrentForwarder {
                    tag: tag.to_string(),
                    active_concurrent: MAX_CONCURRENT_QUERIES,
                    upstreams,
                    short_circuit,
                    metrics: Arc::new(ForwardMetrics::new(tag.to_string())),
                },
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::proto::{Name, Question, Rcode, RecordType};

    #[derive(Debug)]
    struct MockUpstream {
        connection_info: ConnectionInfo,
        response_code: Option<Rcode>,
        fail_message: Option<String>,
        delay: Duration,
    }

    impl MockUpstream {
        fn ok() -> Self {
            Self::response(Rcode::NoError, Duration::ZERO)
        }

        fn response(response_code: Rcode, delay: Duration) -> Self {
            Self {
                connection_info: ConnectionInfo::with_addr("1.1.1.1")
                    .expect("mock upstream addr must be valid"),
                response_code: Some(response_code),
                fail_message: None,
                delay,
            }
        }

        fn fail(msg: &str, delay: Duration) -> Self {
            Self {
                connection_info: ConnectionInfo::with_addr("1.1.1.1")
                    .expect("mock upstream addr must be valid"),
                response_code: None,
                fail_message: Some(msg.to_string()),
                delay,
            }
        }
    }

    #[async_trait]
    impl Upstream for MockUpstream {
        async fn inner_query(&self, request: Message) -> Result<Message> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if let Some(err) = self.fail_message.as_ref() {
                return Err(DnsError::plugin(err.clone()));
            }
            let response_code = self.response_code.unwrap_or(Rcode::NoError);
            Ok(request.response(response_code))
        }

        fn connection_info(&self) -> &ConnectionInfo {
            &self.connection_info
        }
    }

    fn make_context() -> DnsContext {
        AppClock::start();
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));
        DnsContext::new("127.0.0.1:5533".parse().unwrap(), request)
    }

    fn make_plugin_config(args: &str) -> PluginConfig {
        PluginConfig {
            tag: "forward-test".to_string(),
            plugin_type: "forward".to_string(),
            args: Some(serde_yaml_ng::from_str(args).unwrap()),
        }
    }

    fn test_metrics() -> Arc<ForwardMetrics> {
        Arc::new(ForwardMetrics::new("forward-test".to_string()))
    }

    #[tokio::test]
    async fn concurrent_returns_error_when_all_upstreams_fail() {
        let metrics = test_metrics();
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 2,
            upstreams: vec![
                Arc::new(MockUpstream::fail("u1 fail", Duration::ZERO)),
                Arc::new(MockUpstream::fail("u2 fail", Duration::ZERO)),
            ],
            short_circuit: false,
            metrics: metrics.clone(),
        };

        let mut context = make_context();
        let err = forwarder.execute(&mut context).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("failed across all concurrent upstreams")
        );
        assert!(context.response().is_none());
        assert_eq!(metrics.query_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.error_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn validate_rejects_empty_upstreams() {
        let factory = ForwardFactory;
        let cfg = make_plugin_config("upstreams: []");
        let err = match crate::plugin::test_utils::create_plugin_for_test(&factory, &cfg) {
            Ok(_) => panic!("expected create to fail for empty upstreams"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("at least one upstream"));
    }

    #[test]
    fn validate_rejects_invalid_upstream_addr() {
        let factory = ForwardFactory;
        let cfg = make_plugin_config(
            r#"
upstreams:
  - addr: "udp://"
"#,
        );
        let err = match crate::plugin::test_utils::create_plugin_for_test(&factory, &cfg) {
            Ok(_) => panic!("expected create to fail for invalid upstream addr"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("is invalid"));
    }

    #[test]
    fn quick_setup_rejects_invalid_upstream_addr() {
        let factory = ForwardFactory;
        let result = factory.quick_setup("forward-test", Some("udp://".to_string()));
        let err = match result {
            Ok(_) => panic!("expected quick_setup to fail for invalid upstream addr"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("is invalid"));
    }

    #[test]
    fn parse_forward_config_accepts_short_circuit() {
        let cfg = parse_forward_config(&make_plugin_config(
            r#"
short_circuit: true
upstreams:
  - addr: "udp://1.1.1.1:53"
"#,
        ))
        .expect("forward config should parse");

        assert!(cfg.short_circuit);
    }

    #[test]
    fn quick_setup_supports_short_circuit_flag() {
        let (upstreams, short_circuit) =
            parse_quick_setup_param(Some("1.1.1.1 8.8.8.8 short_circuit=true".to_string()))
                .expect("quick setup should parse");

        assert_eq!(
            upstreams,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
        assert!(short_circuit);
    }

    #[tokio::test]
    async fn quick_setup_accepts_multiple_upstreams() {
        let factory = ForwardFactory;
        let result = factory.quick_setup("forward-test", Some("1.1.1.1 8.8.8.8".to_string()));
        match result {
            Ok(UninitializedPlugin::Executor(_)) => {}
            Ok(_) => panic!("expected quick setup forward to return an executor plugin"),
            Err(err) => panic!("expected quick setup with multi upstreams to succeed, got {err}"),
        }
    }

    #[test]
    fn active_concurrent_defaults_to_one() {
        assert_eq!(resolve_active_concurrent(None), 1);
    }

    #[test]
    fn active_concurrent_caps_at_three() {
        assert_eq!(resolve_active_concurrent(Some(10)), MAX_CONCURRENT_QUERIES);
    }

    #[tokio::test]
    async fn concurrent_success_sets_response() {
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 1,
            upstreams: vec![Arc::new(MockUpstream::ok())],
            short_circuit: false,
            metrics: test_metrics(),
        };

        let mut context = make_context();
        let step = forwarder.execute(&mut context).await.unwrap();
        assert!(matches!(step, ExecStep::Next));
        assert!(context.response().is_some());
    }

    #[tokio::test]
    async fn single_success_stops_when_short_circuit_enabled() {
        let metrics = test_metrics();
        let forwarder = SingleDnsForwarder {
            tag: "forward-test".to_string(),
            upstream: Box::new(MockUpstream::ok()),
            short_circuit: true,
            metrics: metrics.clone(),
        };

        let mut context = make_context();
        let step = forwarder.execute(&mut context).await.unwrap();
        assert!(matches!(step, ExecStep::Stop));
        assert!(context.response().is_some());
        assert_eq!(metrics.query_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.success_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn single_metrics_record_error_and_timeout() {
        let metrics = test_metrics();
        let forwarder = SingleDnsForwarder {
            tag: "forward-test".to_string(),
            upstream: Box::new(MockUpstream::fail(
                "DNS query timeout after 1s",
                Duration::ZERO,
            )),
            short_circuit: false,
            metrics: metrics.clone(),
        };

        let mut context = make_context();
        let err = forwarder.execute(&mut context).await.unwrap_err();

        assert!(err.to_string().contains("query failed"));
        assert_eq!(metrics.query_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.error_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.timeout_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.latency_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn concurrent_success_stops_when_short_circuit_enabled() {
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 1,
            upstreams: vec![Arc::new(MockUpstream::ok())],
            short_circuit: true,
            metrics: test_metrics(),
        };

        let mut context = make_context();
        let step = forwarder.execute(&mut context).await.unwrap();
        assert!(matches!(step, ExecStep::Stop));
        assert!(context.response().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_prefers_noerror_over_early_servfail() {
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 2,
            upstreams: vec![
                Arc::new(MockUpstream::response(Rcode::ServFail, Duration::ZERO)),
                Arc::new(MockUpstream::response(
                    Rcode::NoError,
                    Duration::from_millis(20),
                )),
            ],
            short_circuit: false,
            metrics: test_metrics(),
        };

        let mut context = make_context();
        let step = forwarder.execute(&mut context).await.unwrap();
        assert!(matches!(step, ExecStep::Next));
        assert_eq!(
            context.response().expect("response must exist").rcode(),
            Rcode::NoError
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_returns_last_non_preferred_rcode_when_no_preferred_response() {
        let forwarder = ConcurrentForwarder {
            tag: "forward-test".to_string(),
            active_concurrent: 2,
            upstreams: vec![
                Arc::new(MockUpstream::response(Rcode::ServFail, Duration::ZERO)),
                Arc::new(MockUpstream::response(
                    Rcode::Refused,
                    Duration::from_millis(20),
                )),
            ],
            short_circuit: false,
            metrics: test_metrics(),
        };

        let mut context = make_context();
        let step = forwarder.execute(&mut context).await.unwrap();
        assert!(matches!(step, ExecStep::Next));
        assert_eq!(
            context.response().expect("response must exist").rcode(),
            Rcode::Refused
        );
    }
}
