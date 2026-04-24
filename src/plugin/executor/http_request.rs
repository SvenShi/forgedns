/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `http_request` executor plugin.
//!
//! Sends outbound HTTP callbacks based on the current `DnsContext`.
//!
//! Runtime behavior:
//! - supports `before` and `after` trigger phases through the continuation API;
//! - supports `sync` inline dispatch and `async` fire-and-queue mode;
//! - follows redirects up to a configured limit; and
//! - does not write HTTP responses back into DNS context in v1.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::core::system_utils::parse_simple_duration;
use crate::network::http_client::{HttpClient, HttpClientOptions, HttpRequestOptions};
use crate::network::upstream::{Socks5Opt, parse_socks5_opt};
use crate::plugin::executor::template::{JsonTemplateValue, Template};
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::{continue_next, register_plugin_factory};
use async_trait::async_trait;
use bytes::Bytes;
use http::Method;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ASYNC_MODE: bool = true;
const DEFAULT_MAX_REDIRECTS: usize = 5;
const DEFAULT_QUEUE_SIZE: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRequestConfig {
    method: String,
    url: String,
    phase: Option<HttpRequestPhase>,
    #[serde(rename = "async")]
    async_mode: Option<bool>,
    timeout: Option<String>,
    error_mode: Option<HttpRequestErrorMode>,
    headers: Option<HashMap<String, String>>,
    query_params: Option<HashMap<String, String>>,
    body: Option<String>,
    json: Option<JsonValue>,
    form: Option<HashMap<String, String>>,
    content_type: Option<String>,
    socks5: Option<String>,
    insecure_skip_verify: Option<bool>,
    max_redirects: Option<usize>,
    queue_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HttpRequestPhase {
    Before,
    #[default]
    After,
}

impl HttpRequestPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HttpRequestErrorMode {
    #[default]
    Continue,
    Stop,
    Fail,
}

#[derive(Debug, Clone)]
struct HttpRequestRuntimeConfig {
    method: Method,
    url: Template,
    phase: HttpRequestPhase,
    async_mode: bool,
    timeout: Duration,
    error_mode: HttpRequestErrorMode,
    headers: Vec<(HeaderName, Template)>,
    query_params: Vec<(String, Template)>,
    body: Option<BodyTemplate>,
    parsed_socks5: Option<Socks5Opt>,
    insecure_skip_verify: bool,
    max_redirects: usize,
    queue_size: usize,
}

#[derive(Debug, Clone)]
enum BodyTemplate {
    Raw {
        body: Template,
        content_type: Option<HeaderValue>,
    },
    Json {
        body: JsonTemplateValue,
    },
    Form {
        fields: Vec<(String, Template)>,
    },
}

#[derive(Debug, Clone)]
struct RenderedHttpRequest {
    method: Method,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

impl RenderedHttpRequest {
    fn label(&self) -> String {
        format!("{} {}", self.method, self.url)
    }
}

#[derive(Debug)]
struct HttpRequestExecutor {
    tag: String,
    config: HttpRequestRuntimeConfig,
    client: HttpClient,
    async_tx: Option<mpsc::Sender<RenderedHttpRequest>>,
    stop_tx: Mutex<Option<oneshot::Sender<()>>>,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
pub struct HttpRequestFactory;

register_plugin_factory!("http_request", HttpRequestFactory {});

#[async_trait]
impl Plugin for HttpRequestExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        if !self.config.async_mode || self.async_tx.is_some() {
            return Ok(());
        }

        let (tx, rx) = mpsc::channel(self.config.queue_size);
        let (stop_tx, stop_rx) = oneshot::channel();
        let handle = tokio::spawn(run_async_worker(
            self.tag.clone(),
            self.client.clone(),
            self.config.timeout,
            self.config.max_redirects,
            rx,
            stop_rx,
        ));

        self.async_tx = Some(tx);
        *self
            .stop_tx
            .get_mut()
            .expect("http_request stop mutex poisoned") = Some(stop_tx);
        *self
            .worker_handle
            .get_mut()
            .expect("http_request handle mutex poisoned") = Some(handle);
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        if let Some(stop_tx) = self.stop_tx.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = stop_tx.send(());
        }

        if let Some(handle) = self
            .worker_handle
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        {
            match handle.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {}
                Err(err) if err.is_panic() => {
                    return Err(DnsError::plugin(format!(
                        "http_request worker task panicked: {}",
                        err
                    )));
                }
                Err(err) => {
                    return Err(DnsError::plugin(format!(
                        "http_request worker task exited unexpectedly: {}",
                        err
                    )));
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Executor for HttpRequestExecutor {
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
        match self.config.phase {
            HttpRequestPhase::Before => {
                let dispatch_result = self.dispatch_context(context).await;
                match dispatch_result {
                    Ok(()) => continue_next!(next, context),
                    Err(err) => self.handle_dispatch_failure(err, None, next, context).await,
                }
            }
            HttpRequestPhase::After => {
                let next_result = continue_next!(next, context);
                let dispatch_result = self.dispatch_context(context).await;
                match next_result {
                    Ok(step) => match dispatch_result {
                        Ok(()) => Ok(step),
                        Err(err) => {
                            self.handle_dispatch_failure(err, Some(step), None, context)
                                .await
                        }
                    },
                    Err(err) => {
                        if let Err(dispatch_err) = dispatch_result {
                            self.log_dispatch_failure(
                                &dispatch_err,
                                "downstream execution already failed",
                            );
                        }
                        Err(err)
                    }
                }
            }
        }
    }
}

impl HttpRequestExecutor {
    async fn dispatch_context(&self, context: &DnsContext) -> Result<()> {
        let rendered = self.render_request(context)?;
        if self.config.async_mode {
            let tx = self.async_tx.as_ref().ok_or_else(|| {
                DnsError::plugin(format!(
                    "http_request plugin '{}' async worker is not initialized",
                    self.tag
                ))
            })?;

            tx.try_send(rendered).map_err(|err| match err {
                mpsc::error::TrySendError::Full(request) => DnsError::plugin(format!(
                    "http_request plugin '{}' async queue is full for '{}'",
                    self.tag,
                    request.label()
                )),
                mpsc::error::TrySendError::Closed(request) => DnsError::plugin(format!(
                    "http_request plugin '{}' async queue is closed for '{}'",
                    self.tag,
                    request.label()
                )),
            })?;
            return Ok(());
        }

        dispatch_rendered_request(
            &self.client,
            self.config.timeout,
            self.config.max_redirects,
            rendered,
        )
        .await
    }

    async fn handle_dispatch_failure(
        &self,
        err: DnsError,
        success_step: Option<ExecStep>,
        next: Option<ExecutorNext>,
        context: &mut DnsContext,
    ) -> Result<ExecStep> {
        match self.config.error_mode {
            HttpRequestErrorMode::Continue => {
                self.log_dispatch_failure(&err, "continuing");
                if let Some(step) = success_step {
                    Ok(step)
                } else {
                    continue_next!(next, context)
                }
            }
            HttpRequestErrorMode::Stop => {
                self.log_dispatch_failure(&err, "stopping");
                Ok(ExecStep::Stop)
            }
            HttpRequestErrorMode::Fail => Err(DnsError::plugin(format!(
                "http_request plugin '{}' failed: {}",
                self.tag, err
            ))),
        }
    }

    fn log_dispatch_failure(&self, err: &DnsError, action: &str) {
        warn!(
            plugin = %self.tag,
            phase = self.config.phase.as_str(),
            async_mode = self.config.async_mode,
            error = %err,
            "http_request dispatch failed; {action}"
        );
    }

    fn render_request(&self, context: &DnsContext) -> Result<RenderedHttpRequest> {
        let rendered_url = self.config.url.render(context);
        let mut url = Url::parse(rendered_url.as_str()).map_err(|err| {
            DnsError::plugin(format!(
                "http_request plugin '{}' rendered invalid url '{}': {}",
                self.tag, rendered_url, err
            ))
        })?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(DnsError::plugin(format!(
                    "http_request plugin '{}' rendered url '{}' uses unsupported scheme '{}'",
                    self.tag, rendered_url, scheme
                )));
            }
        }

        for (key, template) in &self.config.query_params {
            url.query_pairs_mut()
                .append_pair(key.as_str(), template.render(context).as_str());
        }

        let mut headers = Vec::with_capacity(self.config.headers.len() + 1);
        for (name, template) in &self.config.headers {
            let rendered = template.render(context);
            let value = HeaderValue::from_str(rendered.as_str()).map_err(|err| {
                DnsError::plugin(format!(
                    "http_request plugin '{}' rendered invalid header '{}' value '{}': {}",
                    self.tag, name, rendered, err
                ))
            })?;
            headers.push((name.clone(), value));
        }

        let has_content_type_header = headers.iter().any(|(name, _)| *name == CONTENT_TYPE);
        let (body, content_type) = match &self.config.body {
            Some(body) => body.render(context)?,
            None => (Bytes::new(), None),
        };
        if !has_content_type_header && let Some(content_type) = content_type {
            headers.push((CONTENT_TYPE, content_type));
        }

        Ok(RenderedHttpRequest {
            method: self.config.method.clone(),
            url: url.to_string(),
            headers,
            body,
        })
    }
}

impl BodyTemplate {
    fn render(&self, context: &DnsContext) -> Result<(Bytes, Option<HeaderValue>)> {
        match self {
            Self::Raw { body, content_type } => {
                Ok((Bytes::from(body.render(context)), content_type.clone()))
            }
            Self::Json { body } => serde_json::to_vec(&body.render(context))
                .map(|bytes| (Bytes::from(bytes), self.content_type()))
                .map_err(|err| DnsError::plugin(format!("failed to serialize json body: {}", err))),
            Self::Form { fields } => {
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                for (key, template) in fields {
                    serializer.append_pair(key.as_str(), template.render(context).as_str());
                }
                Ok((Bytes::from(serializer.finish()), self.content_type()))
            }
        }
    }

    fn content_type(&self) -> Option<HeaderValue> {
        match self {
            Self::Raw { content_type, .. } => content_type.clone(),
            Self::Json { .. } => Some(HeaderValue::from_static("application/json")),
            Self::Form { .. } => Some(HeaderValue::from_static(
                "application/x-www-form-urlencoded",
            )),
        }
    }
}

impl PluginFactory for HttpRequestFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> Result<UninitializedPlugin> {
        let config = build_http_request_runtime_config(plugin_config)?;
        Ok(UninitializedPlugin::Executor(Box::new(
            HttpRequestExecutor {
                tag: plugin_config.tag.clone(),
                client: build_http_client(
                    config.insecure_skip_verify,
                    config.parsed_socks5.clone(),
                ),
                config,
                async_tx: None,
                stop_tx: Mutex::new(None),
                worker_handle: Mutex::new(None),
            },
        )))
    }
}

fn build_http_request_runtime_config(
    plugin_config: &PluginConfig,
) -> Result<HttpRequestRuntimeConfig> {
    let raw = plugin_config
        .args
        .clone()
        .ok_or_else(|| DnsError::plugin("http_request requires configuration arguments"))?;
    let config = serde_yaml_ng::from_value::<HttpRequestConfig>(raw)
        .map_err(|err| DnsError::plugin(format!("failed to parse http_request config: {}", err)))?;

    let method = parse_method(plugin_config.tag.as_str(), config.method.as_str())?;
    let url = parse_template_field(plugin_config.tag.as_str(), "args.url", config.url.as_str())?;
    let headers = parse_header_templates(plugin_config.tag.as_str(), config.headers)?;
    let query_params = parse_string_template_map(
        plugin_config.tag.as_str(),
        "args.query_params",
        config.query_params,
        true,
    )?;
    let form =
        parse_string_template_map(plugin_config.tag.as_str(), "args.form", config.form, false)?;
    let body = parse_body_template(
        plugin_config.tag.as_str(),
        config.body,
        config.json,
        form,
        config.content_type,
    )?;
    let timeout = parse_timeout(plugin_config.tag.as_str(), config.timeout.as_deref())?;
    let parsed_socks5 = parse_socks5(plugin_config.tag.as_str(), config.socks5.as_deref())?;
    let queue_size = config.queue_size.unwrap_or(DEFAULT_QUEUE_SIZE);
    if queue_size == 0 {
        return Err(DnsError::plugin(format!(
            "plugin '{}' field 'args.queue_size' must be greater than 0",
            plugin_config.tag
        )));
    }

    Ok(HttpRequestRuntimeConfig {
        method,
        url,
        phase: config.phase.unwrap_or_default(),
        async_mode: config.async_mode.unwrap_or(DEFAULT_ASYNC_MODE),
        timeout,
        error_mode: config.error_mode.unwrap_or_default(),
        headers,
        query_params,
        body,
        parsed_socks5,
        insecure_skip_verify: config.insecure_skip_verify.unwrap_or(false),
        max_redirects: config.max_redirects.unwrap_or(DEFAULT_MAX_REDIRECTS),
        queue_size,
    })
}

fn parse_method(plugin_tag: &str, raw: &str) -> Result<Method> {
    let method = raw.trim();
    if method.is_empty() {
        return Err(DnsError::plugin(format!(
            "plugin '{}' field 'args.method' must not be empty",
            plugin_tag
        )));
    }

    Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|err| {
        DnsError::plugin(format!(
            "plugin '{}' field 'args.method' is invalid: {}",
            plugin_tag, err
        ))
    })
}

fn parse_timeout(plugin_tag: &str, raw: Option<&str>) -> Result<Duration> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(DEFAULT_TIMEOUT);
    };
    parse_simple_duration(raw).map_err(|err| {
        DnsError::plugin(format!(
            "plugin '{}' field 'args.timeout' is invalid '{}': {}",
            plugin_tag, raw, err
        ))
    })
}

fn parse_socks5(plugin_tag: &str, raw: Option<&str>) -> Result<Option<Socks5Opt>> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };
    parse_socks5_opt(raw).map(Some).ok_or_else(|| {
        DnsError::plugin(format!(
            "plugin '{}' field 'args.socks5' is invalid: '{}'",
            plugin_tag, raw
        ))
    })
}

fn parse_template_field(plugin_tag: &str, field: &str, raw: &str) -> Result<Template> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(DnsError::plugin(format!(
            "plugin '{}' field '{}' must not be empty",
            plugin_tag, field
        )));
    }
    Template::parse(value).map_err(|err| {
        DnsError::plugin(format!(
            "plugin '{}' field '{}' is invalid: {}",
            plugin_tag, field, err
        ))
    })
}

fn parse_header_templates(
    plugin_tag: &str,
    map: Option<HashMap<String, String>>,
) -> Result<Vec<(HeaderName, Template)>> {
    let mut entries = Vec::new();
    let mut keys = map.unwrap_or_default().into_iter().collect::<Vec<_>>();
    keys.sort_by(|left, right| left.0.cmp(&right.0));

    for (key, value) in keys {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field 'args.headers' contains an empty header name",
                plugin_tag
            )));
        }
        let header_name = HeaderName::from_bytes(trimmed.as_bytes()).map_err(|err| {
            DnsError::plugin(format!(
                "plugin '{}' field 'args.headers[{}]' is invalid: {}",
                plugin_tag, trimmed, err
            ))
        })?;
        let template = parse_template_field(
            plugin_tag,
            format!("args.headers[{}]", trimmed).as_str(),
            value.as_str(),
        )?;
        entries.push((header_name, template));
    }

    Ok(entries)
}

fn parse_string_template_map(
    plugin_tag: &str,
    field: &str,
    map: Option<HashMap<String, String>>,
    allow_empty_key: bool,
) -> Result<Vec<(String, Template)>> {
    let mut entries = Vec::new();
    let mut pairs = map.unwrap_or_default().into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));

    for (key, value) in pairs {
        let trimmed = key.trim().to_string();
        if !allow_empty_key && trimmed.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field '{}' contains an empty key",
                plugin_tag, field
            )));
        }
        let template = parse_template_field(
            plugin_tag,
            format!("{field}[{trimmed}]").as_str(),
            value.as_str(),
        )?;
        entries.push((trimmed, template));
    }

    Ok(entries)
}

fn parse_body_template(
    plugin_tag: &str,
    body: Option<String>,
    json: Option<JsonValue>,
    form: Vec<(String, Template)>,
    content_type: Option<String>,
) -> Result<Option<BodyTemplate>> {
    let body_count =
        usize::from(body.is_some()) + usize::from(json.is_some()) + usize::from(!form.is_empty());
    if body_count > 1 {
        return Err(DnsError::plugin(format!(
            "plugin '{}' fields 'args.body', 'args.json', and 'args.form' are mutually exclusive",
            plugin_tag
        )));
    }

    let helper_content_type = match content_type.map(|value| value.trim().to_string()) {
        Some(value) if value.is_empty() => {
            return Err(DnsError::plugin(format!(
                "plugin '{}' field 'args.content_type' must not be empty",
                plugin_tag
            )));
        }
        Some(value) => Some(HeaderValue::from_str(value.as_str()).map_err(|err| {
            DnsError::plugin(format!(
                "plugin '{}' field 'args.content_type' is invalid: {}",
                plugin_tag, err
            ))
        })?),
        None => None,
    };

    if helper_content_type.is_some() && (json.is_some() || !form.is_empty()) {
        return Err(DnsError::plugin(format!(
            "plugin '{}' field 'args.content_type' can only be used with raw 'args.body'",
            plugin_tag
        )));
    }

    match (body, json, form.is_empty()) {
        (Some(body), None, true) => Ok(Some(BodyTemplate::Raw {
            body: parse_template_field(plugin_tag, "args.body", body.as_str())?,
            content_type: helper_content_type,
        })),
        (None, Some(json), true) => Ok(Some(BodyTemplate::Json {
            body: JsonTemplateValue::compile(json).map_err(|err| {
                DnsError::plugin(format!(
                    "plugin '{}' field 'args.json' is invalid: {}",
                    plugin_tag, err
                ))
            })?,
        })),
        (None, None, false) => Ok(Some(BodyTemplate::Form { fields: form })),
        (None, None, true) => Ok(None),
        _ => Err(DnsError::plugin(format!(
            "plugin '{}' fields 'args.body', 'args.json', and 'args.form' are mutually exclusive",
            plugin_tag
        ))),
    }
}

fn build_http_client(insecure_skip_verify: bool, socks5: Option<Socks5Opt>) -> HttpClient {
    HttpClient::new(HttpClientOptions {
        insecure_skip_verify,
        socks5,
    })
}

async fn run_async_worker(
    plugin_tag: String,
    client: HttpClient,
    timeout_duration: Duration,
    max_redirects: usize,
    mut rx: mpsc::Receiver<RenderedHttpRequest>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            maybe_request = rx.recv() => {
                let Some(request) = maybe_request else {
                    break;
                };
                if let Err(err) = dispatch_rendered_request(&client, timeout_duration, max_redirects, request).await {
                    warn!(
                        plugin = %plugin_tag,
                        error = %err,
                        "http_request async dispatch failed"
                    );
                }
            }
        }
    }
}

async fn dispatch_rendered_request(
    client: &HttpClient,
    timeout_duration: Duration,
    max_redirects: usize,
    request: RenderedHttpRequest,
) -> Result<()> {
    let request_label = request.label();
    timeout(
        timeout_duration,
        dispatch_rendered_request_inner(client, max_redirects, request),
    )
    .await
    .map_err(|_| {
        DnsError::plugin(format!(
            "request timed out after {}ms for '{}'",
            timeout_duration.as_millis(),
            request_label
        ))
    })?
}

async fn dispatch_rendered_request_inner(
    client: &HttpClient,
    max_redirects: usize,
    request: RenderedHttpRequest,
) -> Result<()> {
    let method = request.method.clone();
    let options = HttpRequestOptions::from_url(request.url.clone())
        .with_headers(request.headers.clone())
        .with_body(request.body.clone())
        .with_max_redirects(max_redirects);
    if method == Method::GET {
        client.get_request(options).await?;
    } else if method == Method::POST {
        client.post_request(options).await?;
    } else {
        client.request(method, options).await?;
    }
    debug!(request = %request.label(), "http_request completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::{plugin_config, test_registry};
    use serde_yaml_ng::{Value, from_str};

    fn make_config(yaml: &str) -> PluginConfig {
        plugin_config(
            "http",
            "http_request",
            Some(from_str::<Value>(yaml).unwrap()),
        )
    }

    #[test]
    fn test_factory_create_accepts_valid_get_config() {
        let config = make_config(
            r#"
method: GET
url: "https://example.com/hook"
headers:
  X-Test: "${qname}"
query_params:
  client: "${client_ip}"
"#,
        );

        let plugin = HttpRequestFactory
            .create(&config, test_registry(), &Default::default())
            .expect("valid get config should build");
        assert!(matches!(plugin, UninitializedPlugin::Executor(_)));
    }

    #[test]
    fn test_factory_create_accepts_valid_post_json_config() {
        let config = make_config(
            r#"
method: post
url: "https://example.com/hook"
json:
  qname: "${qname}"
  nested:
    ok: true
"#,
        );

        let plugin = HttpRequestFactory
            .create(&config, test_registry(), &Default::default())
            .expect("valid json config should build");
        assert!(matches!(plugin, UninitializedPlugin::Executor(_)));
    }

    #[test]
    fn test_factory_create_rejects_invalid_method() {
        let config = make_config(
            r#"
method: "bad method"
url: "https://example.com/hook"
"#,
        );

        let err = match HttpRequestFactory.create(&config, test_registry(), &Default::default()) {
            Ok(_) => panic!("invalid method should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("args.method"));
    }

    #[test]
    fn test_factory_create_rejects_invalid_timeout() {
        let config = make_config(
            r#"
method: GET
url: "https://example.com/hook"
timeout: "xyz"
"#,
        );

        let err = match HttpRequestFactory.create(&config, test_registry(), &Default::default()) {
            Ok(_) => panic!("invalid timeout should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("args.timeout"));
    }

    #[test]
    fn test_factory_create_rejects_conflicting_body_fields() {
        let config = make_config(
            r#"
method: POST
url: "https://example.com/hook"
body: "abc"
json:
  ok: true
"#,
        );

        let err = match HttpRequestFactory.create(&config, test_registry(), &Default::default()) {
            Ok(_) => panic!("conflicting body config should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_factory_create_rejects_zero_queue_size() {
        let config = make_config(
            r#"
method: POST
url: "https://example.com/hook"
queue_size: 0
"#,
        );

        let err = match HttpRequestFactory.create(&config, test_registry(), &Default::default()) {
            Ok(_) => panic!("zero queue size should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("queue_size"));
    }
}
