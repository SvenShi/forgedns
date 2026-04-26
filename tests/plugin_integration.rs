// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::{Arc as StdArc, Arc};

use bytes::Bytes;
use forgedns::config::types::Config;
use forgedns::core::app_clock::AppClock;
use forgedns::core::context::{DnsContext, RequestMeta};
use forgedns::core::error::{DnsError, Result};
use forgedns::network::transport::udp_transport::UdpTransport;
use forgedns::plugin;
use forgedns::plugin::executor::ExecStep;
use forgedns::plugin::{PluginRegistry, PluginType};
use forgedns::proto::{DNSClass, Message, Name, Question, Rcode, RecordType};
use http_body_util::{BodyExt, Full};
use hyper::header::LOCATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tokio::time::sleep;
use tokio::time::{Duration, timeout};

fn parse_config(yaml: &str) -> Result<Config> {
    AppClock::start();
    let config: Config = serde_yaml_ng::from_str(yaml)?;
    config.validate()?;
    Ok(config)
}

fn make_context(registry: Arc<PluginRegistry>, qname: &str) -> DnsContext {
    make_context_with_qtype(registry, qname, RecordType::A)
}

fn make_context_with_qtype(
    registry: Arc<PluginRegistry>,
    qname: &str,
    qtype: RecordType,
) -> DnsContext {
    let mut request = Message::new();
    request.add_question(Question::new(
        Name::from_ascii(qname).expect("query name should be valid"),
        qtype,
        DNSClass::IN,
    ));

    DnsContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        request,
        registry,
    )
}

fn test_rule_path(relative_name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("testdata")
        .join("rules")
        .join(relative_name)
        .to_string_lossy()
        .replace('\\', "/")
}

fn yaml_path(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(unix)]
fn platform_script_command(script_path: &std::path::Path) -> (String, Vec<String>) {
    ("sh".to_string(), vec![yaml_path(script_path)])
}

#[cfg(windows)]
fn platform_script_command(script_path: &std::path::Path) -> (String, Vec<String>) {
    (
        "cmd.exe".to_string(),
        vec!["/C".to_string(), yaml_path(script_path)],
    )
}

#[cfg(unix)]
fn write_capture_script(
    script_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<()> {
    std::fs::write(
        script_path,
        format!(
            "#!/bin/sh\nprintf 'ARGS=%s\\n' \"$*\" > \"{}\"\nprintf 'QNAME=%s\\n' \"$FDNS_QNAME\" >> \"{}\"\nprintf 'CLIENT=%s\\n' \"$FDNS_CLIENT_IP\" >> \"{}\"\nprintf 'SERVER=%s\\n' \"$FDNS_SERVER_NAME\" >> \"{}\"\nprintf 'URL=%s\\n' \"$FDNS_URL_PATH\" >> \"{}\"\nprintf 'MARKS=%s\\n' \"$FDNS_MARKS\" >> \"{}\"\nprintf 'HAS_RESP=%s\\n' \"$FDNS_HAS_RESP\" >> \"{}\"\nprintf 'RCODE=%s\\n' \"$FDNS_RCODE\" >> \"{}\"\nprintf 'RESP_IP=%s\\n' \"$FDNS_RESP_IP\" >> \"{}\"\nprintf 'CRON_JOB=%s\\n' \"$FDNS_CRON_JOB\" >> \"{}\"\n",
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
            yaml_path(output_path),
        ),
    )?;
    Ok(())
}

#[cfg(windows)]
fn write_capture_script(
    script_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<()> {
    std::fs::write(
        script_path,
        format!(
            "@echo off\r\n> \"{0}\" echo ARGS=%*\r\n>> \"{0}\" echo QNAME=%FDNS_QNAME%\r\n>> \"{0}\" echo CLIENT=%FDNS_CLIENT_IP%\r\n>> \"{0}\" echo SERVER=%FDNS_SERVER_NAME%\r\n>> \"{0}\" echo URL=%FDNS_URL_PATH%\r\n>> \"{0}\" echo MARKS=%FDNS_MARKS%\r\n>> \"{0}\" echo HAS_RESP=%FDNS_HAS_RESP%\r\n>> \"{0}\" echo RCODE=%FDNS_RCODE%\r\n>> \"{0}\" echo RESP_IP=%FDNS_RESP_IP%\r\n>> \"{0}\" echo CRON_JOB=%FDNS_CRON_JOB%\r\n",
            yaml_path(output_path),
        ),
    )?;
    Ok(())
}

#[cfg(unix)]
fn write_timeout_script(script_path: &std::path::Path) -> Result<()> {
    std::fs::write(script_path, "#!/bin/sh\nsleep 3\n")?;
    Ok(())
}

#[cfg(windows)]
fn write_timeout_script(script_path: &std::path::Path) -> Result<()> {
    std::fs::write(script_path, "@echo off\r\nping 127.0.0.1 -n 4 >nul\r\n")?;
    Ok(())
}

#[cfg(unix)]
fn write_failure_script(script_path: &std::path::Path, code: i32) -> Result<()> {
    std::fs::write(script_path, format!("#!/bin/sh\nexit {}\n", code))?;
    Ok(())
}

#[cfg(windows)]
fn write_failure_script(script_path: &std::path::Path, code: i32) -> Result<()> {
    std::fs::write(script_path, format!("@echo off\r\nexit /b {}\r\n", code))?;
    Ok(())
}

fn reserve_local_udp_addr() -> Result<SocketAddr> {
    let socket = StdUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = socket.local_addr()?;
    drop(socket);
    Ok(addr)
}

async fn exchange_udp_query(server_addr: SocketAddr, qname: &str) -> Result<Message> {
    exchange_udp_query_with_qtype(server_addr, qname, RecordType::A).await
}

async fn exchange_udp_query_with_qtype(
    server_addr: SocketAddr,
    qname: &str,
    qtype: RecordType,
) -> Result<Message> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    socket.connect(server_addr).await?;
    let transport = UdpTransport::new(socket);

    let mut request = Message::new();
    request.set_id(0x1234);
    request.add_question(Question::new(
        Name::from_ascii(qname).expect("query name should be valid"),
        qtype,
        DNSClass::IN,
    ));

    transport
        .write_message_with_id(&request, request.id())
        .await?;

    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(1), transport.read_message(&mut buf))
        .await
        .map_err(|_| DnsError::runtime("timed out waiting for UDP server response"))?
}

async fn start_test_http_server(
    routes: Vec<(&'static str, StatusCode, &'static str)>,
) -> Result<SocketAddr> {
    let routes = routes
        .into_iter()
        .map(|(path, status, body)| {
            TestHttpRoute::new(path.to_string(), status, body.as_bytes().to_vec())
        })
        .collect();
    start_test_http_server_routes(routes).await
}

#[derive(Clone)]
struct TestHttpRoute {
    path: String,
    status: StatusCode,
    body: Vec<u8>,
    location: Option<String>,
    response_delay: Option<Duration>,
}

impl TestHttpRoute {
    fn new(path: String, status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            path,
            status,
            body,
            location: None,
            response_delay: None,
        }
    }
}

#[derive(Debug, Clone)]
struct CapturedHttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedHttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(self.body.as_slice()).into_owned()
    }
}

async fn start_test_http_server_routes(routes: Vec<TestHttpRoute>) -> Result<SocketAddr> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    let routes = Arc::new(routes);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let routes = routes.clone();
                    async move {
                        let path = request.uri().path();
                        let response = routes
                            .iter()
                            .find(|route| route.path == path)
                            .map(|route| {
                                let mut builder = Response::builder().status(route.status);
                                if let Some(location) = route.location.as_deref() {
                                    builder = builder.header(LOCATION, location);
                                }
                                let delay = route.response_delay;
                                builder
                                    .body(Full::new(Bytes::from(route.body.clone())))
                                    .map(|response| (response, delay))
                                    .expect("response should build")
                            })
                            .unwrap_or_else(|| {
                                (
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::from_static(b"not found")))
                                        .expect("response should build"),
                                    None,
                                )
                            });
                        if let Some(delay) = response.1 {
                            tokio::time::sleep(delay).await;
                        }
                        Ok::<_, std::convert::Infallible>(response.0)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Ok(addr)
}

async fn start_recording_http_server_routes(
    routes: Vec<TestHttpRoute>,
) -> Result<(SocketAddr, mpsc::UnboundedReceiver<CapturedHttpRequest>)> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    let routes = Arc::new(routes);
    let (tx, rx) = mpsc::unbounded_channel::<CapturedHttpRequest>();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let routes = routes.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let routes = routes.clone();
                    let tx = tx.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|collected| collected.to_bytes().to_vec())
                            .unwrap_or_default();
                        let captured = CapturedHttpRequest {
                            method: parts.method.to_string(),
                            path: parts.uri.path().to_string(),
                            query: parts.uri.query().map(str::to_string),
                            headers: parts
                                .headers
                                .iter()
                                .map(|(key, value)| {
                                    (
                                        key.as_str().to_string(),
                                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                    )
                                })
                                .collect(),
                            body,
                        };
                        let _ = tx.send(captured);

                        let response = routes
                            .iter()
                            .find(|route| route.path == parts.uri.path())
                            .map(|route| {
                                let mut builder = Response::builder().status(route.status);
                                if let Some(location) = route.location.as_deref() {
                                    builder = builder.header(LOCATION, location);
                                }
                                let delay = route.response_delay;
                                builder
                                    .body(Full::new(Bytes::from(route.body.clone())))
                                    .map(|response| (response, delay))
                                    .expect("response should build")
                            })
                            .unwrap_or_else(|| {
                                (
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::from_static(b"not found")))
                                        .expect("response should build"),
                                    None,
                                )
                            });
                        if let Some(delay) = response.1 {
                            tokio::time::sleep(delay).await;
                        }
                        Ok::<_, std::convert::Infallible>(response.0)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    Ok((addr, rx))
}

async fn wait_for_captured_request(
    rx: &mut mpsc::UnboundedReceiver<CapturedHttpRequest>,
) -> Result<CapturedHttpRequest> {
    timeout(Duration::from_secs(1), rx.recv())
        .await
        .map_err(|_| DnsError::runtime("timed out waiting for recorded HTTP request"))?
        .ok_or_else(|| DnsError::runtime("recording HTTP server channel closed unexpectedly"))
}

async fn start_test_socks5_proxy() -> Result<SocketAddr> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = handle_test_socks5_client(stream).await;
            });
        }
    });

    Ok(addr)
}

async fn handle_test_socks5_client(mut client: TcpStream) -> Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(DnsError::runtime("invalid SOCKS5 version in greeting"));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?;

    let mut header = [0u8; 4];
    client.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x01 {
        return Err(DnsError::runtime("unsupported SOCKS5 command"));
    }

    let target_host = match header[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|e| DnsError::runtime(format!("invalid SOCKS5 domain: {e}")))?
        }
        0x04 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        atyp => {
            return Err(DnsError::runtime(format!(
                "unsupported SOCKS5 address type: {atyp}"
            )));
        }
    };

    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes).await?;
    let target_port = u16::from_be_bytes(port_bytes);
    let mut upstream = TcpStream::connect((target_host.as_str(), target_port)).await?;

    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_system_plugin_tests_enabled() -> bool {
    std::env::var_os("TEST_LINUX_SYSTEM_PLUGINS").is_some()
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|uid| uid.trim() == "0")
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn command_exists(program: &str, version_arg: &str) -> bool {
    Command::new(program)
        .arg(version_arg)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn should_run_linux_system_plugin_tests(program: &str, version_arg: &str) -> bool {
    linux_system_plugin_tests_enabled() && running_as_root() && command_exists(program, version_arg)
}

#[cfg(target_os = "linux")]
fn unique_system_object_name(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let suffix = format!("{:x}", nanos);
    let max_prefix_len = 31usize.saturating_sub(1 + suffix.len());
    let trimmed_prefix = prefix.chars().take(max_prefix_len).collect::<String>();
    format!("{trimmed_prefix}_{suffix}")
}

#[cfg(target_os = "linux")]
fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| DnsError::runtime(format!("failed to execute {program}: {e}")))?;
    if !output.status.success() {
        return Err(DnsError::runtime(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
struct CommandCleanup {
    steps: Vec<(String, Vec<String>)>,
}

#[cfg(target_os = "linux")]
impl CommandCleanup {
    fn new(steps: Vec<(String, Vec<String>)>) -> Self {
        Self { steps }
    }
}

#[cfg(target_os = "linux")]
impl Drop for CommandCleanup {
    fn drop(&mut self) {
        for (program, args) in &self.steps {
            let _ = Command::new(program).args(args).output();
        }
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_command_output_contains(
    program: &str,
    args: &[&str],
    wanted: &str,
) -> Result<()> {
    for _ in 0..20 {
        let output = run_command(program, args)?;
        if output.contains(wanted) {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(DnsError::runtime(format!(
        "{program} {} did not contain '{wanted}' within timeout",
        args.join(" ")
    )))
}

#[test]
fn test_load_example_config_and_validate() -> Result<()> {
    let config = parse_config(include_str!("../config.yaml"))?;

    assert!(
        !config.plugins.is_empty(),
        "example config should contain plugins"
    );
    assert!(
        config.plugins.iter().any(|p| p.plugin_type == "udp_server"),
        "example config should include udp_server"
    );

    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_and_destroy_with_minimal_config() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: debug
    type: debug_print
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    assert_eq!(
        registry.plugin_count(),
        1,
        "one plugin should be initialized"
    );
    assert!(registry.get_plugin("debug").is_some());

    registry.destory().await;
    assert_eq!(registry.plugin_count(), 0, "plugins should be destroyed");
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_resolves_sequence_dependency_and_quick_setup() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: allow_all
    type: _true
  - tag: seq
    type: sequence
    args:
      - matches:
          - $allow_all
        exec: debug_print integration message
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    assert_eq!(registry.plugin_count(), 2);

    let matcher = registry
        .get_plugin("allow_all")
        .expect("matcher plugin should be registered");
    assert_eq!(matcher.plugin_type, PluginType::Matcher);

    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should be registered");
    assert_eq!(sequence.plugin_type, PluginType::Executor);
    assert_eq!(sequence.plugin_name, "sequence");

    registry.destory().await;
    assert_eq!(registry.plugin_count(), 0);
    Ok(())
}

#[test]
fn test_analyze_configuration_expands_sequence_quick_setup_dependency_edges() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches:
          - qname $zzz_set
        exec: accept
  - tag: zzz_set
    type: domain_set
    args:
      exps:
        - example.com
"#;

    let config = parse_config(yaml)?;
    let report = plugin::analyze_configuration(&config)?;

    assert_eq!(
        report.init_order,
        vec!["zzz_set".to_string(), "seq".to_string()]
    );
    assert!(report.edges.iter().any(|edge| {
        edge.source_tag == "seq"
            && edge.target_tag == "zzz_set"
            && edge.field == "args[0].matches[0] -> quick_setup(qname).domain_set_tags[0]"
    }));
    Ok(())
}

#[test]
fn test_analyze_configuration_tracks_negated_sequence_matcher_tag_dependency() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches: "!$allow_all"
        exec: accept
  - tag: allow_all
    type: _true
"#;

    let config = parse_config(yaml)?;
    let report = plugin::analyze_configuration(&config)?;

    assert_eq!(
        report.init_order,
        vec!["allow_all".to_string(), "seq".to_string()]
    );
    assert!(report.edges.iter().any(|edge| {
        edge.source_tag == "seq"
            && edge.target_tag == "allow_all"
            && edge.field == "args[0].matches[0]"
    }));
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_resolves_sequence_quick_setup_provider_dependency() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches:
          - qname $zzz_set
        exec: accept
      - exec: reject 2
  - tag: zzz_set
    type: domain_set
    args:
      exps:
        - example.com
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    assert!(
        registry.get_plugin("zzz_set").is_some(),
        "provider used by quick setup should still be visible"
    );

    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");
    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    assert!(context.response().is_none());

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_supports_single_match_string_dependency_and_execution() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: allow_all
    type: _true
  - tag: seq
    type: sequence
    args:
      - matches: $allow_all
        exec: mark 100
      - exec: reject 2
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    assert!(context.marks().contains(&100));
    assert_eq!(
        context
            .response()
            .expect("reject should set a response")
            .rcode(),
        Rcode::ServFail
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_reports_missing_dependency_with_field_context() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches:
          - $missing_matcher
        exec: debug_print integration message
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("missing dependency should fail plugin init");
    let msg = err.to_string();

    assert!(msg.contains("plugin 'seq'"));
    assert!(msg.contains("args[0].matches[0]"));
    assert!(msg.contains("missing plugin 'missing_matcher'"));
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_reports_single_match_dependency_with_field_context() -> Result<()>
{
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches: $missing_matcher
        exec: debug_print integration message
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("missing dependency should fail plugin init");
    let msg = err.to_string();

    assert!(msg.contains("plugin 'seq'"));
    assert!(msg.contains("args[0].matches[0]"));
    assert!(msg.contains("missing plugin 'missing_matcher'"));
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_reports_missing_quick_setup_dependency_with_field_context()
-> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches:
          - qname $missing_set
        exec: accept
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("missing quick setup dependency should fail plugin init");
    let msg = err.to_string();

    assert!(msg.contains("plugin 'seq'"));
    assert!(msg.contains("args[0].matches[0] -> quick_setup(qname).domain_set_tags[0]"));
    assert!(msg.contains("missing plugin 'missing_set'"));
    Ok(())
}

#[tokio::test]
async fn test_sequence_executor_runs_quick_setup_matcher_and_builtin_ops() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - matches:
          - _true
        exec: mark 100 200
      - exec: reject 2
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    assert!(context.marks().contains(&100));
    assert!(context.marks().contains(&200));
    assert_eq!(
        context
            .response()
            .expect("reject should set a response")
            .rcode(),
        Rcode::ServFail
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_accept_in_jump_stops_current_and_parent_sequences() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: child
    type: sequence
    args:
      - exec: mark 2
      - exec: accept
      - exec: mark 3
  - tag: parent
    type: sequence
    args:
      - exec: mark 1
      - exec: jump child
      - exec: mark 4
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("parent")
        .expect("parent sequence should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    assert!(context.marks().contains(&1));
    assert!(context.marks().contains(&2));
    assert!(!context.marks().contains(&3));
    assert!(!context.marks().contains(&4));
    assert!(context.response().is_none());

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_reject_defaults_to_refused_and_stops_parent_sequences() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: child
    type: sequence
    args:
      - exec: mark 2
      - exec: reject
      - exec: mark 3
  - tag: parent
    type: sequence
    args:
      - exec: mark 1
      - exec: jump child
      - exec: mark 4
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("parent")
        .expect("parent sequence should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    assert!(context.marks().contains(&1));
    assert!(context.marks().contains(&2));
    assert!(!context.marks().contains(&3));
    assert!(!context.marks().contains(&4));
    assert_eq!(
        context
            .response()
            .expect("reject should set a response")
            .rcode(),
        Rcode::Refused
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_jump_return_resumes_parent_execution() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: child
    type: sequence
    args:
      - exec: mark 2
      - exec: return
      - exec: mark 3
  - tag: parent
    type: sequence
    args:
      - exec: mark 1
      - exec: jump child
      - exec: mark 4
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("parent")
        .expect("parent sequence should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    assert!(context.marks().contains(&1));
    assert!(context.marks().contains(&2));
    assert!(!context.marks().contains(&3));
    assert!(context.marks().contains(&4));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_goto_does_not_resume_source_sequence() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: child
    type: sequence
    args:
      - exec: mark 2
      - exec: return
      - exec: mark 3
  - tag: parent
    type: sequence
    args:
      - exec: mark 1
      - exec: goto child
      - exec: mark 4
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("parent")
        .expect("parent sequence should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Return));
    assert!(context.marks().contains(&1));
    assert!(context.marks().contains(&2));
    assert!(!context.marks().contains(&3));
    assert!(!context.marks().contains(&4));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_direct_child_return_propagates_to_parent_caller() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: child
    type: sequence
    args:
      - exec: mark 2
      - exec: return
      - exec: mark 3
  - tag: parent
    type: sequence
    args:
      - exec: mark 1
      - exec: $child
      - exec: mark 4
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("parent")
        .expect("parent sequence should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Return));
    assert!(context.marks().contains(&1));
    assert!(context.marks().contains(&2));
    assert!(!context.marks().contains(&3));
    assert!(!context.marks().contains(&4));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_jump_short_circuit_child_stops_parent() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: child
    type: sequence
    args:
      - exec: "black_hole 0.0.0.0 short_circuit=true"
      - exec: mark 3
  - tag: parent
    type: sequence
    args:
      - exec: mark 1
      - exec: jump child
      - exec: mark 4
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("parent")
        .expect("parent sequence should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    assert!(context.marks().contains(&1));
    assert!(!context.marks().contains(&3));
    assert!(!context.marks().contains(&4));
    assert_eq!(
        context
            .response()
            .expect("black_hole should synthesize a response")
            .rcode(),
        Rcode::NoError
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_udp_server_returns_hosts_answer_for_matching_query() -> Result<()> {
    let mut registry_and_addr = None;
    for _ in 0..16 {
        let listen = reserve_local_udp_addr()?;
        let yaml = format!(
            r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
  - tag: udp
    type: udp_server
    args:
      entry: hosts
      listen: "{listen}"
"#
        );

        let config = parse_config(&yaml)?;
        match plugin::init(config, None).await {
            Ok(registry) => {
                registry_and_addr = Some((registry, listen));
                break;
            }
            Err(err) if err.to_string().contains("Failed to bind UDP socket") => continue,
            Err(err) => return Err(err),
        }
    }

    let (registry, listen) =
        registry_and_addr.expect("UDP server should bind to a local port within retry budget");
    let response_result = exchange_udp_query(listen, "example.test.").await;
    registry.destory().await;
    let response = response_result?;

    assert_eq!(response.id(), 0x1234);
    assert_eq!(response.rcode(), Rcode::NoError);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].rr_type(), RecordType::A);
    assert_eq!(
        response.answers()[0].data().ip_addr(),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    Ok(())
}

#[tokio::test]
async fn test_hosts_short_circuit_stops_sequence_after_local_answer() -> Result<()> {
    let mut registry_and_addr = None;
    for _ in 0..16 {
        let listen = reserve_local_udp_addr()?;
        let yaml = format!(
            r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
      short_circuit: true
  - tag: seq
    type: sequence
    args:
      - exec: $hosts
      - exec: "reject 2"
  - tag: udp
    type: udp_server
    args:
      entry: seq
      listen: "{listen}"
"#
        );

        let config = parse_config(&yaml)?;
        match plugin::init(config, None).await {
            Ok(registry) => {
                registry_and_addr = Some((registry, listen));
                break;
            }
            Err(err) if err.to_string().contains("Failed to bind UDP socket") => continue,
            Err(err) => return Err(err),
        }
    }

    let (registry, listen) =
        registry_and_addr.expect("UDP server should bind to a local port within retry budget");
    let response_result = exchange_udp_query(listen, "example.test.").await;
    registry.destory().await;
    let response = response_result?;

    assert_eq!(response.rcode(), Rcode::NoError);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(
        response.answers()[0].data().ip_addr(),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    Ok(())
}

#[tokio::test]
async fn test_udp_server_hosts_file_rules_override_inline_entries() -> Result<()> {
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    let hosts_file = tmp_dir.path().join("hosts.txt");
    std::fs::write(&hosts_file, "full:example.test 192.0.2.11\n")?;
    let file_path = yaml_path(&hosts_file);

    let mut registry_and_addr = None;
    for _ in 0..16 {
        let listen = reserve_local_udp_addr()?;
        let yaml = format!(
            r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
      files:
        - "{file_path}"
  - tag: udp
    type: udp_server
    args:
      entry: hosts
      listen: "{listen}"
"#
        );

        let config = parse_config(&yaml)?;
        match plugin::init(config, None).await {
            Ok(registry) => {
                registry_and_addr = Some((registry, listen));
                break;
            }
            Err(err) if err.to_string().contains("Failed to bind UDP socket") => continue,
            Err(err) => return Err(err),
        }
    }

    let (registry, listen) =
        registry_and_addr.expect("UDP server should bind to a local port within retry budget");
    let response_result = exchange_udp_query(listen, "example.test.").await;
    registry.destory().await;
    let response = response_result?;

    assert_eq!(response.rcode(), Rcode::NoError);
    assert_eq!(
        response.answers()[0].data().ip_addr(),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)))
    );
    Ok(())
}

#[tokio::test]
async fn test_hosts_short_circuit_stops_sequence_after_local_nodata_answer() -> Result<()> {
    let mut registry_and_addr = None;
    for _ in 0..16 {
        let listen = reserve_local_udp_addr()?;
        let yaml = format!(
            r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
      short_circuit: true
  - tag: seq
    type: sequence
    args:
      - exec: $hosts
      - exec: "reject 2"
  - tag: udp
    type: udp_server
    args:
      entry: seq
      listen: "{listen}"
"#
        );

        let config = parse_config(&yaml)?;
        match plugin::init(config, None).await {
            Ok(registry) => {
                registry_and_addr = Some((registry, listen));
                break;
            }
            Err(err) if err.to_string().contains("Failed to bind UDP socket") => continue,
            Err(err) => return Err(err),
        }
    }

    let (registry, listen) =
        registry_and_addr.expect("UDP server should bind to a local port within retry budget");
    let response_result =
        exchange_udp_query_with_qtype(listen, "example.test.", RecordType::AAAA).await;
    registry.destory().await;
    let response = response_result?;

    assert_eq!(response.rcode(), Rcode::NoError);
    assert!(response.answers().is_empty());
    assert_eq!(response.authorities().len(), 1);
    assert_eq!(response.authorities()[0].rr_type(), RecordType::SOA);
    Ok(())
}

#[tokio::test]
async fn test_cache_quick_setup_short_circuit_stops_sequence_after_cache_hit() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
      short_circuit: true
  - tag: seq
    type: sequence
    args:
      - exec: "cache short_circuit=true"
      - exec: $hosts
      - exec: "reject 2"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let seq = registry
        .get_plugin("seq")
        .expect("sequence should exist")
        .to_executor();

    let mut first_ctx = make_context(registry.clone(), "example.test.");
    let first_step = seq.execute(&mut first_ctx).await?;
    assert!(matches!(first_step, ExecStep::Stop));
    assert_eq!(
        first_ctx.response().expect("response should exist").rcode(),
        Rcode::NoError
    );

    let mut second_ctx = make_context(registry.clone(), "example.test.");
    let second_step = seq.execute(&mut second_ctx).await?;
    assert!(matches!(second_step, ExecStep::Stop));
    assert_eq!(
        second_ctx
            .response()
            .expect("response should exist")
            .rcode(),
        Rcode::NoError
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_unused_provider_plugins_are_skipped_at_runtime() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: orphan_domain
    type: domain_set
    args:
      exps:
        - example.com
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    assert_eq!(registry.plugin_count(), 0);
    assert!(registry.get_plugin("orphan_domain").is_none());

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_unused_provider_chains_are_skipped_transitively() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: shared_domain
    type: domain_set
    args:
      exps:
        - shared.example
  - tag: combined_domain
    type: domain_set
    args:
      exps:
        - full:local.example
      sets:
        - shared_domain
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    assert_eq!(registry.plugin_count(), 0);
    assert!(registry.get_plugin("shared_domain").is_none());
    assert!(registry.get_plugin("combined_domain").is_none());

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_domain_set_provider_references_composed_providers() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: shared_domain
    type: domain_set
    args:
      exps:
        - shared.example
  - tag: combined_domain
    type: domain_set
    args:
      exps:
        - full:local.example
      sets:
        - shared_domain
  - tag: domain_match
    type: qname
    args:
      - "$combined_domain"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    let matcher = registry
        .get_plugin("domain_match")
        .expect("domain matcher should exist")
        .to_matcher();

    let mut local_ctx = make_context(registry.clone(), "local.example.");
    assert!(matcher.is_match(&mut local_ctx));

    let mut shared_ctx = make_context(registry.clone(), "www.shared.example.");
    assert!(matcher.is_match(&mut shared_ctx));

    let mut missing_ctx = make_context(registry.clone(), "missing.example.");
    assert!(!matcher.is_match(&mut missing_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_domain_set_can_compose_adguard_rule_provider() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: ad_rules
    type: adguard_rule
    args:
      rules:
        - "||ads.example^"
        - "@@||safe.ads.example^"
        - "||ipv6-only.example^$dnstype=AAAA"
  - tag: combined_domain
    type: domain_set
    args:
      sets:
        - ad_rules
  - tag: qname_match
    type: qname
    args:
      - "$combined_domain"
  - tag: question_match
    type: question
    args:
      - "$combined_domain"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    let qname_matcher = registry
        .get_plugin("qname_match")
        .expect("qname matcher should exist")
        .to_matcher();
    let question_matcher = registry
        .get_plugin("question_match")
        .expect("question matcher should exist")
        .to_matcher();

    let mut blocked_ctx = make_context(registry.clone(), "cdn.ads.example.");
    assert!(qname_matcher.is_match(&mut blocked_ctx));

    let mut exception_ctx = make_context(registry.clone(), "safe.ads.example.");
    assert!(!qname_matcher.is_match(&mut exception_ctx));

    let mut a_ctx = make_context_with_qtype(registry.clone(), "ipv6-only.example.", RecordType::A);
    assert!(!question_matcher.is_match(&mut a_ctx));

    let mut aaaa_ctx =
        make_context_with_qtype(registry.clone(), "ipv6-only.example.", RecordType::AAAA);
    assert!(question_matcher.is_match(&mut aaaa_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_domain_set_provider_loads_rules_from_file() -> Result<()> {
    let domain_rules = test_rule_path("domain_set_1.txt");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: domain_rules
    type: domain_set
    args:
      files:
        - "{domain_rules}"
  - tag: domain_match
    type: qname
    args:
      - "$domain_rules"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;

    let matcher = registry
        .get_plugin("domain_match")
        .expect("domain matcher should exist")
        .to_matcher();

    let matching_names = [
        "www.example.test.",
        "img.cdn.example.test.",
        "exact-only.test.",
        "cdn.analytics-node.test.",
        "api12.service.test.",
    ];
    for qname in matching_names {
        let mut ctx = make_context(registry.clone(), qname);
        assert!(matcher.is_match(&mut ctx), "{qname} should match");
    }

    let missing_names = [
        "www.exact-only.test.",
        "api.service.test.",
        "missing.example.",
    ];
    for qname in missing_names {
        let mut ctx = make_context(registry.clone(), qname);
        assert!(!matcher.is_match(&mut ctx), "{qname} should not match");
    }

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_ip_set_provider_references_composed_providers() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: shared_ip
    type: ip_set
    args:
      ips:
        - 203.0.113.7
  - tag: combined_ip
    type: ip_set
    args:
      ips:
        - 198.51.100.0/24
      sets:
        - shared_ip
  - tag: match_client
    type: client_ip
    args:
      - "$combined_ip"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    let matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();

    let mut shared_ctx = make_context(registry.clone(), "example.com.");
    shared_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 5300)));
    assert!(matcher.is_match(&mut shared_ctx));

    let mut range_ctx = make_context(registry.clone(), "example.com.");
    range_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 42), 5300)));
    assert!(matcher.is_match(&mut range_ctx));

    let mut missing_ctx = make_context(registry.clone(), "example.com.");
    missing_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(198, 51, 101, 1), 5300)));
    assert!(!matcher.is_match(&mut missing_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_ip_set_provider_loads_rules_from_file() -> Result<()> {
    let ip_rules = test_rule_path("ip_set_1.txt");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: ip_rules
    type: ip_set
    args:
      files:
        - "{ip_rules}"
  - tag: match_client
    type: client_ip
    args:
      - "$ip_rules"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;

    let matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();

    for ip in [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0xDB8, 0, 0, 0, 0, 0, 7])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0xDB8, 0xABCD, 0, 0, 0, 0, 0x1234])),
    ] {
        let mut ctx = make_context(registry.clone(), "example.com.");
        ctx.set_peer_addr(SocketAddr::new(ip, 5300));
        assert!(matcher.is_match(&mut ctx), "{ip} should match");
    }

    for ip in [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1)),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0xDB8, 0, 0, 0, 0, 0, 8])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0xDB8, 0xABCE, 0, 0, 0, 0, 1])),
    ] {
        let mut ctx = make_context(registry.clone(), "example.com.");
        ctx.set_peer_addr(SocketAddr::new(ip, 5300));
        assert!(!matcher.is_match(&mut ctx), "{ip} should not match");
    }

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_geoip_provider_loads_cn_rules_and_is_case_insensitive() -> Result<()> {
    let geoip_dat = test_rule_path("geoip.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geoip_cn
    type: geoip
    args:
      file: "{geoip_dat}"
      selectors:
        - "CN"
  - tag: match_client
    type: client_ip
    args:
      - "$geoip_cn"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();

    let mut cn_ctx = make_context(registry.clone(), "example.com.");
    cn_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(1, 0, 1, 1), 5300)));
    assert!(matcher.is_match(&mut cn_ctx));

    let mut foreign_ctx = make_context(registry.clone(), "example.com.");
    foreign_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 5300)));
    assert!(!matcher.is_match(&mut foreign_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_geoip_provider_without_selectors_loads_full_union() -> Result<()> {
    let geoip_dat = test_rule_path("geoip.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geoip_all
    type: geoip
    args:
      file: "{geoip_dat}"
  - tag: match_client
    type: client_ip
    args:
      - "$geoip_all"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();

    let mut cn_ctx = make_context(registry.clone(), "example.com.");
    cn_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(1, 0, 1, 1), 5300)));
    assert!(matcher.is_match(&mut cn_ctx));

    let mut foreign_ctx = make_context(registry.clone(), "example.com.");
    foreign_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 5300)));
    assert!(matcher.is_match(&mut foreign_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_geosite_provider_loads_requested_selectors_and_supports_question() -> Result<()> {
    let geosite_dat = test_rule_path("geosite.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geosite_target
    type: geosite
    args:
      file: "{geosite_dat}"
      selectors:
        - "cn"
        - "geolocation-!cn"
  - tag: match_qname
    type: qname
    args:
      - "$geosite_target"
  - tag: match_question
    type: question
    args:
      - "$geosite_target"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let qname_matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();
    let question_matcher = registry
        .get_plugin("match_question")
        .expect("question matcher should exist")
        .to_matcher();

    let mut cn_ctx = make_context(registry.clone(), "265.com.");
    assert!(qname_matcher.is_match(&mut cn_ctx));

    let mut foreign_ctx = make_context(registry.clone(), "a.ppy.sh.");
    assert!(qname_matcher.is_match(&mut foreign_ctx));

    let mut question_ctx = make_context_with_qtype(registry.clone(), "a.ppy.sh.", RecordType::A);
    assert!(question_matcher.is_match(&mut question_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_geosite_provider_without_selectors_loads_full_union() -> Result<()> {
    let geosite_dat = test_rule_path("geosite.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geosite_all
    type: geosite
    args:
      file: "{geosite_dat}"
  - tag: match_qname
    type: qname
    args:
      - "$geosite_all"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();

    let mut cn_ctx = make_context(registry.clone(), "265.com.");
    assert!(matcher.is_match(&mut cn_ctx));

    let mut foreign_ctx = make_context(registry.clone(), "a.ppy.sh.");
    assert!(matcher.is_match(&mut foreign_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_geosite_provider_supports_code_attribute_selector() -> Result<()> {
    let geosite_dat = test_rule_path("geosite.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geosite_mastercard_cn
    type: geosite
    args:
      file: "{geosite_dat}"
      selectors:
        - "mastercard@cn"
  - tag: match_qname
    type: qname
    args:
      - "$geosite_mastercard_cn"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();

    let mut cn_ctx = make_context(registry.clone(), "mastercard.cn.");
    assert!(matcher.is_match(&mut cn_ctx));

    let mut foreign_ctx = make_context(registry.clone(), "a.ppy.sh.");
    assert!(!matcher.is_match(&mut foreign_ctx));

    let mut global_ctx = make_context(registry.clone(), "mastercard.com.");
    assert!(!matcher.is_match(&mut global_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_matchers_can_reference_geo_providers_directly() -> Result<()> {
    let geoip_dat = test_rule_path("geoip.dat");
    let geosite_dat = test_rule_path("geosite.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geoip_cn
    type: geoip
    args:
      file: "{geoip_dat}"
      selectors: ["cn"]
  - tag: geosite_cn
    type: geosite
    args:
      file: "{geosite_dat}"
      selectors: ["cn"]
  - tag: geosite_foreign
    type: geosite
    args:
      file: "{geosite_dat}"
      selectors: ["geolocation-!cn"]
  - tag: match_client
    type: client_ip
    args:
      - "$geoip_cn"
  - tag: match_qname
    type: qname
    args:
      - "$geosite_cn"
  - tag: match_question
    type: question
    args:
      - "$geosite_foreign"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    assert!(registry.get_plugin("geoip_cn").is_some());
    assert!(registry.get_plugin("geosite_cn").is_some());
    assert!(registry.get_plugin("geosite_foreign").is_some());

    let client_matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();
    let qname_matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();
    let question_matcher = registry
        .get_plugin("match_question")
        .expect("question matcher should exist")
        .to_matcher();

    let mut cn_ctx = make_context(registry.clone(), "265.com.");
    cn_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(1, 0, 1, 1), 5300)));
    assert!(client_matcher.is_match(&mut cn_ctx));
    assert!(qname_matcher.is_match(&mut cn_ctx));

    let mut foreign_ctx = make_context(registry.clone(), "a.ppy.sh.");
    assert!(question_matcher.is_match(&mut foreign_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_set_providers_can_compose_geo_providers() -> Result<()> {
    let geoip_dat = test_rule_path("geoip.dat");
    let geosite_dat = test_rule_path("geosite.dat");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geoip_cn
    type: geoip
    args:
      file: "{geoip_dat}"
      selectors: ["cn"]
  - tag: geosite_cn
    type: geosite
    args:
      file: "{geosite_dat}"
      selectors: ["cn"]
  - tag: mixed_ip
    type: ip_set
    args:
      ips:
        - "198.51.100.0/24"
      sets:
        - "geoip_cn"
  - tag: mixed_domain
    type: domain_set
    args:
      exps:
        - "full:custom.example"
      sets:
        - "geosite_cn"
  - tag: match_client
    type: client_ip
    args:
      - "$mixed_ip"
  - tag: match_qname
    type: qname
    args:
      - "$mixed_domain"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;

    let ip_matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();
    let domain_matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();

    let mut geo_ctx = make_context(registry.clone(), "example.com.");
    geo_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(1, 0, 1, 1), 5300)));
    assert!(ip_matcher.is_match(&mut geo_ctx));

    let mut inline_ip_ctx = make_context(registry.clone(), "example.com.");
    inline_ip_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 5300)));
    assert!(ip_matcher.is_match(&mut inline_ip_ctx));

    let mut geo_domain_ctx = make_context(registry.clone(), "265.com.");
    assert!(domain_matcher.is_match(&mut geo_domain_ctx));

    let mut inline_domain_ctx = make_context(registry.clone(), "custom.example.");
    assert!(domain_matcher.is_match(&mut inline_domain_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_reload_provider_registry_refreshes_file_backed_domain_provider_without_full_reload()
-> Result<()> {
    let temp_dir = TempDir::new()?;
    let shared_file = temp_dir.path().join("shared-domain.txt");
    std::fs::write(&shared_file, "old.example\n")?;

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: shared_domain
    type: domain_set
    args:
      files:
        - "{}"
  - tag: combined_domain
    type: domain_set
    args:
      exps:
        - "full:static.example"
      sets:
        - "shared_domain"
  - tag: match_qname
    type: qname
    args:
      - "$combined_domain"
"#,
        yaml_path(&shared_file)
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();

    let mut old_ctx = make_context(registry.clone(), "old.example.");
    assert!(matcher.is_match(&mut old_ctx));
    let mut static_ctx = make_context(registry.clone(), "static.example.");
    assert!(matcher.is_match(&mut static_ctx));
    let mut new_ctx = make_context(registry.clone(), "new.example.");
    assert!(!matcher.is_match(&mut new_ctx));

    std::fs::write(&shared_file, "new.example\n")?;
    registry.reload_provider("shared_domain").await?;

    let mut old_ctx = make_context(registry.clone(), "old.example.");
    assert!(!matcher.is_match(&mut old_ctx));
    let mut static_ctx = make_context(registry.clone(), "static.example.");
    assert!(matcher.is_match(&mut static_ctx));
    let mut new_ctx = make_context(registry.clone(), "new.example.");
    assert!(matcher.is_match(&mut new_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_reload_provider_registry_refreshes_file_backed_ip_provider_without_full_reload()
-> Result<()> {
    let temp_dir = TempDir::new()?;
    let shared_file = temp_dir.path().join("shared-ip.txt");
    std::fs::write(&shared_file, "203.0.113.7\n")?;

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: shared_ip
    type: ip_set
    args:
      files:
        - "{}"
  - tag: combined_ip
    type: ip_set
    args:
      ips:
        - "198.51.100.0/24"
      sets:
        - "shared_ip"
  - tag: match_client
    type: client_ip
    args:
      - "$combined_ip"
"#,
        yaml_path(&shared_file)
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_client")
        .expect("client matcher should exist")
        .to_matcher();

    let mut old_ctx = make_context(registry.clone(), "example.com.");
    old_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 5300)));
    assert!(matcher.is_match(&mut old_ctx));
    let mut static_ctx = make_context(registry.clone(), "example.com.");
    static_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 5300)));
    assert!(matcher.is_match(&mut static_ctx));
    let mut new_ctx = make_context(registry.clone(), "example.com.");
    new_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 5300)));
    assert!(!matcher.is_match(&mut new_ctx));

    std::fs::write(&shared_file, "203.0.113.8\n")?;
    registry.reload_provider("shared_ip").await?;

    let mut old_ctx = make_context(registry.clone(), "example.com.");
    old_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 5300)));
    assert!(!matcher.is_match(&mut old_ctx));
    let mut static_ctx = make_context(registry.clone(), "example.com.");
    static_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 5300)));
    assert!(matcher.is_match(&mut static_ctx));
    let mut new_ctx = make_context(registry.clone(), "example.com.");
    new_ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), 5300)));
    assert!(matcher.is_match(&mut new_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_reload_provider_executor_refreshes_domain_provider() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let shared_file = temp_dir.path().join("reload-domain.txt");
    std::fs::write(&shared_file, "old.example\n")?;

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: shared_domain
    type: domain_set
    args:
      files:
        - "{}"
  - tag: refresh_domain
    type: reload_provider
    args:
      - "$shared_domain"
  - tag: match_qname
    type: qname
    args:
      - "$shared_domain"
"#,
        yaml_path(&shared_file)
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();
    let executor = registry
        .get_plugin("refresh_domain")
        .expect("reload_provider executor should exist")
        .to_executor();

    let mut old_ctx = make_context(registry.clone(), "old.example.");
    assert!(matcher.is_match(&mut old_ctx));
    let mut new_ctx = make_context(registry.clone(), "new.example.");
    assert!(!matcher.is_match(&mut new_ctx));

    std::fs::write(&shared_file, "new.example\n")?;
    let mut trigger_ctx = make_context(registry.clone(), "trigger.example.");
    assert!(matches!(
        executor.execute(&mut trigger_ctx).await?,
        ExecStep::Next
    ));

    let mut old_ctx = make_context(registry.clone(), "old.example.");
    assert!(!matcher.is_match(&mut old_ctx));
    let mut new_ctx = make_context(registry.clone(), "new.example.");
    assert!(matcher.is_match(&mut new_ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_geo_provider_failure_paths_are_reported() -> Result<()> {
    let geoip_dat = test_rule_path("geoip.dat");
    let geosite_dat = test_rule_path("geosite.dat");

    let missing_code_yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geoip_missing
    type: geoip
    args:
      file: "{geoip_dat}"
      selectors: ["not-found-code"]
  - tag: match_client
    type: client_ip
    args:
      - "$geoip_missing"
"#
    );
    let err = plugin::init(parse_config(&missing_code_yaml)?, None)
        .await
        .expect_err("missing geoip code should fail");
    assert!(err.to_string().contains("found no geoip entries"));

    let wrong_set_yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geosite_cn
    type: geosite
    args:
      file: "{geosite_dat}"
      selectors: ["cn"]
  - tag: invalid_ip_set
    type: ip_set
    args:
      sets:
        - "geosite_cn"
  - tag: match_client
    type: client_ip
    args:
      - "$invalid_ip_set"
"#
    );
    let err = plugin::init(parse_config(&wrong_set_yaml)?, None)
        .await
        .expect_err("ip_set should reject non-ip provider");
    assert!(err.to_string().contains("support IP matching"));

    let wrong_matcher_yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: geoip_cn
    type: geoip
    args:
      file: "{geoip_dat}"
      selectors: ["cn"]
  - tag: invalid_qname
    type: qname
    args:
      - "$geoip_cn"
"#
    );
    let err = plugin::init(parse_config(&wrong_matcher_yaml)?, None)
        .await
        .expect_err("qname should reject non-domain provider");
    assert!(err.to_string().contains("support domain matching"));

    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_reports_dependency_kind_mismatch() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: debug
    type: debug_print
  - tag: seq
    type: sequence
    args:
      - matches:
          - $debug
        exec: reject 2
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("kind mismatch should fail plugin init");
    let msg = err.to_string();

    assert!(msg.contains("plugin 'seq'"));
    assert!(msg.contains("args[0].matches[0]"));
    assert!(msg.contains("expects matcher plugin"));
    assert!(msg.contains("'debug' is executor"));
    Ok(())
}

#[tokio::test]
async fn test_adguard_rule_provider_drives_question_matcher_branch() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: agh_rules
    type: adguard_rule
    args:
      rules:
        - "||ads.example.com^"
        - "@@||safe.ads.example.com^"
        - "||rewrite.example.com^$dnsrewrite=1.2.3.4"
  - tag: agh_match
    type: question
    args:
      - "$agh_rules"
  - tag: blocked
    type: sequence
    args:
      - exec: "black_hole 0.0.0.0 ::"
      - exec: accept
  - tag: main
    type: sequence
    args:
      - matches: $agh_match
        exec: goto blocked
      - exec: reject 2
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let main = registry
        .get_plugin("main")
        .expect("main sequence should exist")
        .to_executor();

    let mut blocked_ctx = make_context(registry.clone(), "ads.example.com.");
    let blocked_step = main.execute(&mut blocked_ctx).await?;
    assert!(matches!(blocked_step, ExecStep::Stop));
    let blocked_response = blocked_ctx
        .response()
        .expect("blocked query should synthesize a response");
    assert_eq!(blocked_response.rcode(), Rcode::NoError);
    assert_eq!(blocked_response.answers().len(), 1);
    assert_eq!(blocked_response.answers()[0].rr_type(), RecordType::A);

    let mut allow_ctx = make_context(registry.clone(), "safe.ads.example.com.");
    let allow_step = main.execute(&mut allow_ctx).await?;
    assert!(matches!(allow_step, ExecStep::Stop));
    assert_eq!(
        allow_ctx
            .response()
            .expect("fallback reject should build response")
            .rcode(),
        Rcode::ServFail
    );

    let mut unsupported_ctx = make_context(registry.clone(), "rewrite.example.com.");
    let unsupported_step = main.execute(&mut unsupported_ctx).await?;
    assert!(matches!(unsupported_step, ExecStep::Stop));
    assert_eq!(
        unsupported_ctx
            .response()
            .expect("unsupported dnsrewrite rule should be skipped")
            .rcode(),
        Rcode::ServFail
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_adguard_rule_provider_drives_qname_matcher_branch() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: agh_rules
    type: adguard_rule
    args:
      rules:
        - "||ads.example.com^"
        - "@@||safe.ads.example.com^"
        - "||type-only.example.com^$dnstype=AAAA"
  - tag: agh_match
    type: qname
    args:
      - "$agh_rules"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("agh_match")
        .expect("qname matcher should exist")
        .to_matcher();

    let mut blocked_ctx = make_context(registry.clone(), "ads.example.com.");
    assert!(matcher.is_match(&mut blocked_ctx));

    let mut allow_ctx = make_context(registry.clone(), "safe.ads.example.com.");
    assert!(!matcher.is_match(&mut allow_ctx));

    let mut dnstype_only_ctx = make_context(registry.clone(), "type-only.example.com.");
    assert!(
        !matcher.is_match(&mut dnstype_only_ctx),
        "qname should use name-only projection and ignore dnstype-only rules"
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_adguard_rule_provider_loads_rules_from_file() -> Result<()> {
    let adguard_rules = test_rule_path("adguard_rule_1.txt");
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: agh_rules
    type: adguard_rule
    args:
      files:
        - "{adguard_rules}"
  - tag: agh_match
    type: question
    args:
      - "$agh_rules"
  - tag: blocked
    type: sequence
    args:
      - exec: "black_hole 0.0.0.0"
      - exec: accept
  - tag: main
    type: sequence
    args:
      - matches: $agh_match
        exec: goto blocked
      - exec: reject 2
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let agh_rules = registry
        .get_plugin("agh_rules")
        .expect("agh_rules provider should exist")
        .to_provider();
    let main = registry
        .get_plugin("main")
        .expect("main sequence should exist")
        .to_executor();

    let assert_blocked = |label: &str, ctx: &DnsContext| {
        let response = ctx
            .response()
            .unwrap_or_else(|| panic!("{label} should synthesize a blocked response"));
        assert_eq!(response.rcode(), Rcode::NoError);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(
            response.answers()[0].rr_type(),
            ctx.request
                .first_question()
                .expect("request should contain one question")
                .qtype()
        );
    };

    let assert_rejected = |label: &str, ctx: &DnsContext| {
        assert_eq!(
            ctx.response()
                .unwrap_or_else(|| panic!("{label} should fall through to reject"))
                .rcode(),
            Rcode::ServFail
        );
    };

    let mut plain_exact = make_context(registry.clone(), "plain-match.example.");
    assert!(matches!(
        main.execute(&mut plain_exact).await?,
        ExecStep::Stop
    ));
    assert_blocked("plain_exact", &plain_exact);

    let mut plain_subdomain = make_context(registry.clone(), "www.plain-match.example.");
    assert!(matches!(
        main.execute(&mut plain_subdomain).await?,
        ExecStep::Stop
    ));
    assert_rejected("plain_subdomain", &plain_subdomain);

    let mut suffix = make_context(registry.clone(), "cdn.suffix.example.");
    assert!(matches!(main.execute(&mut suffix).await?, ExecStep::Stop));
    assert_blocked("suffix", &suffix);

    let mut exception = make_context(registry.clone(), "allow.suffix.example.");
    assert!(matches!(
        main.execute(&mut exception).await?,
        ExecStep::Stop
    ));
    assert_rejected("exception", &exception);

    let mut wildcard = make_context(registry.clone(), "ad-banner.wild.example.");
    assert!(matches!(main.execute(&mut wildcard).await?, ExecStep::Stop));
    assert_blocked("wildcard", &wildcard);

    let mut regex = make_context(registry.clone(), "metrics12.service.test.");
    assert!(matches!(main.execute(&mut regex).await?, ExecStep::Stop));
    assert_blocked("regex", &regex);

    let mut denyallow_root = make_context(registry.clone(), "deny.example.");
    assert!(matches!(
        main.execute(&mut denyallow_root).await?,
        ExecStep::Stop
    ));
    assert_blocked("denyallow_root", &denyallow_root);

    let mut denyallow_sub = make_context(registry.clone(), "sub.deny.example.");
    assert!(matches!(
        main.execute(&mut denyallow_sub).await?,
        ExecStep::Stop
    ));
    assert_rejected("denyallow_sub", &denyallow_sub);

    let dnstype_aaaa =
        make_context_with_qtype(registry.clone(), "ipv6-only.example.", RecordType::AAAA);
    assert!(
        agh_rules.contains_question(
            dnstype_aaaa
                .request()
                .first_question()
                .expect("question should exist")
        )
    );

    let dnstype_a = make_context_with_qtype(registry.clone(), "ipv6-only.example.", RecordType::A);
    assert!(
        !agh_rules.contains_question(
            dnstype_a
                .request()
                .first_question()
                .expect("question should exist")
        )
    );

    assert!(agh_rules.contains_name(&Name::from_ascii("plain-match.example.").unwrap()));
    assert!(!agh_rules.contains_name(&Name::from_ascii("ipv6-only.example.").unwrap()));

    let mut important_exception = make_context(registry.clone(), "important.example.");
    assert!(matches!(
        main.execute(&mut important_exception).await?,
        ExecStep::Stop
    ));
    assert_rejected("important_exception", &important_exception);

    let mut badfilter_disabled = make_context(registry.clone(), "disabled.example.");
    assert!(matches!(
        main.execute(&mut badfilter_disabled).await?,
        ExecStep::Stop
    ));
    assert_rejected("badfilter_disabled", &badfilter_disabled);

    let mut unsupported_modifier = make_context(registry.clone(), "rewrite.example.");
    assert!(matches!(
        main.execute(&mut unsupported_modifier).await?,
        ExecStep::Stop
    ));
    assert_rejected("unsupported_modifier", &unsupported_modifier);

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_question_matcher_matches_when_any_question_matches() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: domain_rules
    type: domain_set
    args:
      exps:
        - full:second.example
  - tag: q_match
    type: question
    args:
      - "$domain_rules"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("q_match")
        .expect("question matcher should exist")
        .to_matcher();

    let mut request = Message::new();
    request.add_question(Question::new(
        Name::from_ascii("first.example.").unwrap(),
        RecordType::A,
        DNSClass::IN,
    ));
    request.add_question(Question::new(
        Name::from_ascii("second.example.").unwrap(),
        RecordType::AAAA,
        DNSClass::IN,
    ));
    let mut ctx = DnsContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        request,
        registry.clone(),
    );

    assert!(matcher.is_match(&mut ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_reports_circular_sequence_dependencies() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq_a
    type: sequence
    args:
      - exec: jump seq_b
  - tag: seq_b
    type: sequence
    args:
      - exec: jump seq_a
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("circular dependencies should fail plugin init");
    let msg = err.to_string();

    assert!(msg.contains("Circular dependency detected"));
    assert!(msg.contains("seq_a"));
    assert!(msg.contains("seq_b"));
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_rejects_dollar_prefixed_jump_target() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: seq_a
    type: sequence
    args:
      - exec: jump $seq_b
  - tag: seq_b
    type: sequence
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("dollar-prefixed jump target should fail plugin init");
    let msg = err.to_string();

    assert!(msg.contains("jump target must be sequence tag without '$' prefix"));
    Ok(())
}

#[tokio::test]
async fn test_plugin_system_init_reports_jump_target_must_be_sequence() -> Result<()> {
    let yaml = r#"
log:
  level: info
plugins:
  - tag: debug
    type: debug_print
  - tag: seq
    type: sequence
    args:
      - exec: jump debug
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config, None)
        .await
        .expect_err("jump target should require sequence plugin");
    let msg = err.to_string();

    assert!(msg.contains("plugin 'seq'"));
    assert!(msg.contains("args[0].exec"));
    assert!(
        msg.contains("plugin type 'sequence'") || msg.contains("executor plugin type 'sequence'")
    );
    assert!(msg.contains("'debug'"));
    assert!(msg.contains("debug_print"));
    Ok(())
}

#[tokio::test]
async fn test_cron_plugin_init_accepts_interval_and_quick_setup_executor() -> Result<()> {
    let yaml = r#"
plugins:
  - tag: child
    type: sequence
    args:
      - exec: accept
  - tag: cron_main
    type: cron
    args:
      jobs:
        - name: refresh
          interval: 1m
          executors:
            - "$child"
            - "debug_print cron interval"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    assert_eq!(
        registry
            .get_plugin("cron_main")
            .expect("cron plugin should exist")
            .plugin_name,
        "cron"
    );
    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_cron_plugin_init_accepts_schedule_job() -> Result<()> {
    let yaml = r#"
plugins:
  - tag: child
    type: sequence
    args:
      - exec: accept
  - tag: cron_main
    type: cron
    args:
      timezone: "UTC"
      jobs:
        - name: cleanup
          schedule: "0 */6 * * *"
          executors:
            - "$child"
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;
    assert_eq!(
        registry
            .get_plugin("cron_main")
            .expect("cron plugin should exist")
            .plugin_name,
        "cron"
    );
    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_cron_plugin_init_rejects_invalid_timezone() -> Result<()> {
    let yaml = r#"
plugins:
  - tag: child
    type: sequence
    args:
      - exec: accept
  - tag: cron_main
    type: cron
    args:
      timezone: "Mars/Base"
      jobs:
        - name: cleanup
          schedule: "0 */6 * * *"
          executors:
            - "$child"
"#;

    let err = plugin::init(parse_config(yaml)?, None)
        .await
        .expect_err("invalid timezone should be rejected");
    assert!(err.to_string().contains("failed to parse cron schedule"));
    Ok(())
}

#[tokio::test]
async fn test_cron_plugin_init_rejects_second_level_schedule() -> Result<()> {
    let yaml = r#"
plugins:
  - tag: child
    type: sequence
    args:
      - exec: accept
  - tag: cron_main
    type: cron
    args:
      jobs:
        - name: bad
          schedule: "0 0 * * * *"
          executors:
            - "$child"
"#;

    let err = plugin::init(parse_config(yaml)?, None)
        .await
        .expect_err("6-field cron should be rejected");
    assert!(err.to_string().contains("second-level cron"));
    Ok(())
}

#[tokio::test]
async fn test_cron_plugin_init_rejects_second_level_interval() -> Result<()> {
    let yaml = r#"
plugins:
  - tag: child
    type: sequence
    args:
      - exec: accept
  - tag: cron_main
    type: cron
    args:
      jobs:
        - name: bad
          interval: 30s
          executors:
            - "$child"
"#;

    let err = plugin::init(parse_config(yaml)?, None)
        .await
        .expect_err("sub-minute interval should be rejected");
    assert!(err.to_string().contains("at least 1 minute"));
    Ok(())
}

#[tokio::test]
async fn test_cron_plugin_init_rejects_cron_dependency() -> Result<()> {
    let yaml = r#"
plugins:
  - tag: child_cron
    type: cron
    args:
      jobs:
        - name: child
          interval: 1m
          executors:
            - "debug_print child"
  - tag: parent_cron
    type: cron
    args:
      jobs:
        - name: parent
          interval: 1m
          executors:
            - "$child_cron"
"#;

    let err = plugin::init(parse_config(yaml)?, None)
        .await
        .expect_err("cron should not reference another cron");
    let msg = err.to_string();
    assert!(msg.contains("cannot reference cron executor"));
    Ok(())
}

#[tokio::test]
async fn test_download_executor_continues_after_item_failure() -> Result<()> {
    let server_addr = start_test_http_server(vec![
        ("/ok.txt", StatusCode::OK, "download-ok"),
        ("/missing.txt", StatusCode::NOT_FOUND, "missing"),
    ])
    .await?;
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    let output_dir = tmp_dir.path().join("rules");
    let output_dir_yaml = yaml_path(&output_dir);

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: dl
    type: download
    args:
      startup_if_missing: false
      downloads:
        - url: "http://{server_addr}/missing.txt"
          dir: "{output_dir_yaml}"
          filename: "missing.txt"
        - url: "http://{server_addr}/ok.txt"
          dir: "{output_dir_yaml}"
          filename: "ok.txt"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("dl")
        .expect("download plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    assert!(!output_dir.join("missing.txt").exists());
    assert_eq!(
        tokio::fs::read_to_string(output_dir.join("ok.txt")).await?,
        "download-ok"
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_download_executor_supports_socks5_proxy() -> Result<()> {
    let server_addr =
        start_test_http_server(vec![("/proxied.txt", StatusCode::OK, "proxied-download")]).await?;
    let socks5_addr = start_test_socks5_proxy().await?;
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    let output_dir = tmp_dir.path().join("proxied");
    let output_dir_yaml = yaml_path(&output_dir);

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: dl
    type: download
    args:
      socks5: "{socks5_addr}"
      downloads:
        - url: "http://{server_addr}/proxied.txt"
          dir: "{output_dir_yaml}"
          filename: "proxied.txt"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("dl")
        .expect("download plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(
        tokio::fs::read_to_string(output_dir.join("proxied.txt")).await?,
        "proxied-download"
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_download_executor_startup_if_missing_bootstraps_files_before_provider_init()
-> Result<()> {
    let geosite_dat = tokio::fs::read(test_rule_path("geosite.dat")).await?;
    let server_addr = start_test_http_server_routes(vec![
        TestHttpRoute {
            path: "/geosite.dat".to_string(),
            status: StatusCode::FOUND,
            body: Vec::new(),
            location: Some("/assets/geosite.dat".to_string()),
            response_delay: None,
        },
        TestHttpRoute::new(
            "/assets/geosite.dat".to_string(),
            StatusCode::OK,
            geosite_dat,
        ),
    ])
    .await?;
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    let dat_dir = tmp_dir.path().join("rules");
    let dat_dir_yaml = yaml_path(&dat_dir);
    let dat_file = dat_dir.join("geosite.dat");
    let dat_file_yaml = yaml_path(&dat_file);

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: bootstrap_download
    type: download
    args:
      downloads:
        - url: "http://{server_addr}/geosite.dat"
          dir: "{dat_dir_yaml}"
          filename: "geosite.dat"
  - tag: geosite_cn
    type: geosite
    args:
      file: "{dat_file_yaml}"
      selectors:
        - "cn"
  - tag: match_qname
    type: qname
    args:
      - "$geosite_cn"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let matcher = registry
        .get_plugin("match_qname")
        .expect("qname matcher should exist")
        .to_matcher();

    assert!(dat_file.exists());
    let mut ctx = make_context(registry.clone(), "265.com.");
    assert!(matcher.is_match(&mut ctx));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_sequence_download_quick_setup_executes_and_overwrites_target() -> Result<()> {
    let server_addr =
        start_test_http_server(vec![("/quick.txt", StatusCode::OK, "quick-setup")]).await?;
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    let output_dir = tmp_dir.path().join("download");
    let output_dir_yaml = yaml_path(&output_dir);

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: seq
    type: sequence
    args:
      - exec: "download http://{server_addr}/quick.txt {output_dir_yaml}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(
        tokio::fs::read_to_string(output_dir.join("quick.txt")).await?,
        "quick-setup"
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_script_executor_injects_context_into_args_and_env() -> Result<()> {
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    #[cfg(unix)]
    let script_path = tmp_dir.path().join("capture.sh");
    #[cfg(windows)]
    let script_path = tmp_dir.path().join("capture.cmd");
    let output_path = tmp_dir.path().join("script_output.txt");
    write_capture_script(&script_path, &output_path)?;
    let (command, command_args) = platform_script_command(&script_path);
    let command_args_yaml = command_args
        .iter()
        .map(|arg| format!("        - \"{}\"\n", arg))
        .collect::<String>();

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: script_main
    type: script
    args:
      command: "{command}"
      args:
{command_args_yaml}        - "qname=${{qname}}"
        - "client=${{client_ip}}"
      env:
        FDNS_QNAME: "${{qname}}"
        FDNS_CLIENT_IP: "${{client_ip}}"
        FDNS_SERVER_NAME: "${{server_name}}"
        FDNS_URL_PATH: "${{url_path}}"
        FDNS_MARKS: "${{marks}}"
        FDNS_HAS_RESP: "${{has_resp}}"
        FDNS_RCODE: "${{rcode_name}}"
        FDNS_RESP_IP: "${{resp_ip}}"
        FDNS_CRON_JOB: "${{cron_job_name}}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("script_main")
        .expect("script plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");
    context.set_request_meta(RequestMeta {
        server_name: Some(StdArc::from("dns.example.com")),
        url_path: Some(StdArc::from("/dns-query")),
    });
    context.marks_mut().insert(2);
    context.marks_mut().insert(1);
    context.set_attr("cron.job_name", "nightly".to_string());
    let mut response = context.request().response(Rcode::NoError);
    response.add_answer(forgedns::proto::Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        forgedns::proto::RData::A(forgedns::proto::rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    context.set_response(response);

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let output = tokio::fs::read_to_string(&output_path).await?;
    assert!(output.contains("ARGS=qname=example.com client=127.0.0.1"));
    assert!(output.contains("QNAME=example.com"));
    assert!(output.contains("CLIENT=127.0.0.1"));
    assert!(output.contains("SERVER=dns.example.com"));
    assert!(output.contains("URL=/dns-query"));
    assert!(output.contains("MARKS=1,2"));
    assert!(output.contains("HAS_RESP=true"));
    assert!(output.contains("RCODE=NoError"));
    assert!(output.contains("RESP_IP=192.0.2.1"));
    assert!(output.contains("CRON_JOB=nightly"));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_script_executor_timeout_continue_returns_next() -> Result<()> {
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    #[cfg(unix)]
    let script_path = tmp_dir.path().join("timeout.sh");
    #[cfg(windows)]
    let script_path = tmp_dir.path().join("timeout.cmd");
    write_timeout_script(&script_path)?;
    let (command, command_args) = platform_script_command(&script_path);
    let command_args_yaml = command_args
        .iter()
        .map(|arg| format!("        - \"{}\"\n", arg))
        .collect::<String>();

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: script_main
    type: script
    args:
      command: "{command}"
      args:
{command_args_yaml}      timeout: "100ms"
      error_mode: continue
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("script_main")
        .expect("script plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_script_executor_failure_stop_returns_stop() -> Result<()> {
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    #[cfg(unix)]
    let script_path = tmp_dir.path().join("fail_stop.sh");
    #[cfg(windows)]
    let script_path = tmp_dir.path().join("fail_stop.cmd");
    write_failure_script(&script_path, 7)?;
    let (command, command_args) = platform_script_command(&script_path);
    let command_args_yaml = command_args
        .iter()
        .map(|arg| format!("        - \"{}\"\n", arg))
        .collect::<String>();

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: script_main
    type: script
    args:
      command: "{command}"
      args:
{command_args_yaml}      error_mode: stop
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("script_main")
        .expect("script plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Stop));
    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_script_executor_failure_fail_returns_error() -> Result<()> {
    let tmp_dir = TempDir::new().expect("temp dir should be created");
    #[cfg(unix)]
    let script_path = tmp_dir.path().join("fail_err.sh");
    #[cfg(windows)]
    let script_path = tmp_dir.path().join("fail_err.cmd");
    write_failure_script(&script_path, 9)?;
    let (command, command_args) = platform_script_command(&script_path);
    let command_args_yaml = command_args
        .iter()
        .map(|arg| format!("        - \"{}\"\n", arg))
        .collect::<String>();

    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: script_main
    type: script
    args:
      command: "{command}"
      args:
{command_args_yaml}      error_mode: fail
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("script_main")
        .expect("script plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let err = executor
        .execute(&mut context)
        .await
        .expect_err("fail mode should return error");

    assert!(err.to_string().contains("script plugin"));
    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_sync_before_get_sends_headers_and_query_params() -> Result<()> {
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![TestHttpRoute::new(
        "/hook".to_string(),
        StatusCode::OK,
        b"ok".to_vec(),
    )])
    .await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: GET
      url: "http://{server_addr}/hook"
      phase: before
      async: false
      headers:
        X-Qname: "${{qname}}"
      query_params:
        client: "${{client_ip}}"
        name: "${{qname}}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let captured = wait_for_captured_request(&mut rx).await?;
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.path, "/hook");
    assert_eq!(captured.header("x-qname"), Some("example.com"));
    assert!(
        captured
            .query
            .as_deref()
            .unwrap_or_default()
            .contains("client=127.0.0.1")
    );
    assert!(
        captured
            .query
            .as_deref()
            .unwrap_or_default()
            .contains("name=example.com")
    );

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_sync_after_post_json_uses_response_placeholders() -> Result<()>
{
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![TestHttpRoute::new(
        "/notify".to_string(),
        StatusCode::OK,
        b"ok".to_vec(),
    )])
    .await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: POST
      url: "http://{server_addr}/notify"
      phase: after
      async: false
      json:
        qname: "${{qname}}"
        rcode: "${{rcode_name}}"
        resp_ip: "${{resp_ip}}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");
    let mut response = context.request().response(Rcode::NoError);
    response.add_answer(forgedns::proto::Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        forgedns::proto::RData::A(forgedns::proto::rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    context.set_response(response);

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let captured = wait_for_captured_request(&mut rx).await?;
    let body: serde_json::Value = serde_json::from_slice(&captured.body)
        .map_err(|e| DnsError::runtime(format!("invalid json body: {e}")))?;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(body["qname"], "example.com");
    assert_eq!(body["rcode"], "NoError");
    assert_eq!(body["resp_ip"], "192.0.2.1");

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_supports_raw_body_and_content_type() -> Result<()> {
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![TestHttpRoute::new(
        "/raw".to_string(),
        StatusCode::OK,
        b"ok".to_vec(),
    )])
    .await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: POST
      url: "http://{server_addr}/raw"
      async: false
      body: "q=${{qname}}&client=${{client_ip}}"
      content_type: "text/plain"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let captured = wait_for_captured_request(&mut rx).await?;
    assert_eq!(captured.header("content-type"), Some("text/plain"));
    assert_eq!(captured.body_text(), "q=example.com&client=127.0.0.1");

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_supports_form_body_encoding() -> Result<()> {
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![TestHttpRoute::new(
        "/form".to_string(),
        StatusCode::OK,
        b"ok".to_vec(),
    )])
    .await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: POST
      url: "http://{server_addr}/form"
      async: false
      form:
        client: "${{client_ip}}"
        name: "${{qname}}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let captured = wait_for_captured_request(&mut rx).await?;
    let form = url::form_urlencoded::parse(captured.body.as_slice())
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        captured.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(form.get("client").map(String::as_str), Some("127.0.0.1"));
    assert_eq!(form.get("name").map(String::as_str), Some("example.com"));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_follows_redirects() -> Result<()> {
    let mut redirect = TestHttpRoute::new("/start".to_string(), StatusCode::FOUND, Vec::new());
    redirect.location = Some("/final".to_string());
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![
        redirect,
        TestHttpRoute::new("/final".to_string(), StatusCode::OK, b"ok".to_vec()),
    ])
    .await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: GET
      url: "http://{server_addr}/start"
      async: false
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let first = wait_for_captured_request(&mut rx).await?;
    let second = wait_for_captured_request(&mut rx).await?;
    assert_eq!(first.path, "/start");
    assert_eq!(second.path, "/final");

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_supports_socks5_proxy() -> Result<()> {
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![TestHttpRoute::new(
        "/proxy".to_string(),
        StatusCode::OK,
        b"ok".to_vec(),
    )])
    .await?;
    let socks5_addr = start_test_socks5_proxy().await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: GET
      url: "http://{server_addr}/proxy"
      async: false
      socks5: "{socks5_addr}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let captured = wait_for_captured_request(&mut rx).await?;
    assert_eq!(captured.path, "/proxy");

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_error_modes_map_sync_failures() -> Result<()> {
    let server_addr =
        start_test_http_server(vec![("/missing", StatusCode::NOT_FOUND, "missing")]).await?;

    async fn run_case(
        server_addr: SocketAddr,
        error_mode: &str,
    ) -> Result<std::result::Result<ExecStep, DnsError>> {
        let yaml = format!(
            r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: GET
      url: "http://{server_addr}/missing"
      async: false
      error_mode: {error_mode}
"#,
        );

        let config = parse_config(&yaml)?;
        let registry = plugin::init(config, None).await?;
        let executor = registry
            .get_plugin("http_main")
            .expect("http_request plugin should exist")
            .to_executor();
        let mut context = make_context(registry.clone(), "example.com.");
        let result = executor.execute(&mut context).await;
        registry.destory().await;
        Ok(result)
    }

    let continue_result = run_case(server_addr, "continue").await?;
    assert!(matches!(continue_result?, ExecStep::Next));

    let stop_result = run_case(server_addr, "stop").await?;
    assert!(matches!(stop_result?, ExecStep::Stop));

    let fail_result = run_case(server_addr, "fail").await?;
    let fail_err = fail_result.expect_err("fail mode should return an error");
    assert!(fail_err.to_string().contains("http_request plugin"));
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_async_mode_enqueues_and_sends_in_background() -> Result<()> {
    let (server_addr, mut rx) = start_recording_http_server_routes(vec![TestHttpRoute::new(
        "/async".to_string(),
        StatusCode::OK,
        b"ok".to_vec(),
    )])
    .await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: POST
      url: "http://{server_addr}/async"
      async: true
      body: "${{qname}}"
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = executor.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    let captured = wait_for_captured_request(&mut rx).await?;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.body_text(), "example.com");

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_async_queue_full_returns_stop() -> Result<()> {
    let mut slow_route = TestHttpRoute::new("/slow".to_string(), StatusCode::OK, b"ok".to_vec());
    slow_route.response_delay = Some(Duration::from_millis(400));
    let (server_addr, _rx) = start_recording_http_server_routes(vec![slow_route]).await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: GET
      url: "http://{server_addr}/slow"
      async: true
      queue_size: 1
      error_mode: stop
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();

    let mut saw_stop = false;
    for _ in 0..16 {
        let mut context = make_context(registry.clone(), "example.com.");
        let step = executor.execute(&mut context).await?;
        if matches!(step, ExecStep::Stop) {
            saw_stop = true;
            break;
        }
    }

    assert!(saw_stop, "async queue should eventually become full");
    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_http_request_executor_async_closed_channel_returns_stop() -> Result<()> {
    let server_addr = start_test_http_server(vec![("/closed", StatusCode::OK, "ok")]).await?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: http_main
    type: http_request
    args:
      method: GET
      url: "http://{server_addr}/closed"
      async: true
      error_mode: stop
"#,
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let executor = registry
        .get_plugin("http_main")
        .expect("http_request plugin should exist")
        .to_executor();

    registry.destory().await;

    let mut context = make_context(registry.clone(), "example.com.");
    let step = executor.execute(&mut context).await?;
    assert!(matches!(step, ExecStep::Stop));
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_linux_ipset_executor_writes_masked_prefix_to_kernel_set() -> Result<()> {
    if !should_run_linux_system_plugin_tests("ipset", "help") {
        return Ok(());
    }

    let set_name = unique_system_object_name("forgedns_test_ipset");
    let _cleanup = CommandCleanup::new(vec![(
        "ipset".to_string(),
        vec!["destroy".to_string(), set_name.clone()],
    )]);
    run_command(
        "ipset",
        &["create", &set_name, "hash:net", "family", "inet"],
    )?;

    let listen = reserve_local_udp_addr()?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
  - tag: ipset_main
    type: ipset
    args:
      set_name4: "{set_name}"
      mask4: 24
  - tag: seq
    type: sequence
    args:
      - exec: $hosts
      - exec: $ipset_main
  - tag: udp
    type: udp_server
    args:
      entry: seq
      listen: "{listen}"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let response_result = exchange_udp_query(listen, "example.test.").await;
    let kernel_result =
        wait_for_command_output_contains("ipset", &["list", &set_name], "192.0.2.0/24").await;
    registry.destory().await;

    let response = response_result?;
    assert_eq!(response.rcode(), Rcode::NoError);
    kernel_result?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_linux_nftset_executor_writes_masked_prefix_to_kernel_set() -> Result<()> {
    if !should_run_linux_system_plugin_tests("nft", "--version") {
        return Ok(());
    }

    let table_name = unique_system_object_name("forgedns_test_nft");
    let set_name = "forgedns_test_v4".to_string();
    let _cleanup = CommandCleanup::new(vec![(
        "nft".to_string(),
        vec![
            "delete".to_string(),
            "table".to_string(),
            "ip".to_string(),
            table_name.clone(),
        ],
    )]);
    run_command("nft", &["add", "table", "ip", &table_name])?;
    run_command(
        "nft",
        &[
            "add",
            "set",
            "ip",
            &table_name,
            &set_name,
            "{ type ipv4_addr; flags interval; }",
        ],
    )?;

    let listen = reserve_local_udp_addr()?;
    let yaml = format!(
        r#"
log:
  level: info
plugins:
  - tag: hosts
    type: hosts
    args:
      entries:
        - "full:example.test 192.0.2.10"
  - tag: nftset_main
    type: nftset
    args:
      ipv4:
        table_family: ip
        table_name: "{table_name}"
        set_name: "{set_name}"
        mask: 24
  - tag: seq
    type: sequence
    args:
      - exec: $hosts
      - exec: $nftset_main
  - tag: udp
    type: udp_server
    args:
      entry: seq
      listen: "{listen}"
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;
    let response_result = exchange_udp_query(listen, "example.test.").await;
    let kernel_result = wait_for_command_output_contains(
        "nft",
        &["list", "table", "ip", &table_name],
        "192.0.2.0/24",
    )
    .await;
    registry.destory().await;

    let response = response_result?;
    assert_eq!(response.rcode(), Rcode::NoError);
    kernel_result?;
    Ok(())
}
