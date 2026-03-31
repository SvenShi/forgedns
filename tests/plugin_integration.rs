/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use forgedns::config::types::Config;
use forgedns::core::context::{DnsContext, ExecFlowState};
use forgedns::core::error::{DnsError, Result};
use forgedns::network::transport::udp_transport::UdpTransport;
use forgedns::plugin;
use forgedns::plugin::executor::ExecStep;
use forgedns::plugin::{PluginRegistry, PluginType};
use forgedns::proto::{DNSClass, Message, Question, Rcode};
use forgedns::proto::{Name, RecordType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::Arc;
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::time::sleep;
use tokio::time::{Duration, timeout};

fn parse_config(yaml: &str) -> Result<Config> {
    let config: Config = serde_yml::from_str(yaml)?;
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

fn reserve_local_udp_addr() -> Result<SocketAddr> {
    let socket = StdUdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = socket.local_addr()?;
    drop(socket);
    Ok(addr)
}

async fn exchange_udp_query(server_addr: SocketAddr, qname: &str) -> Result<Message> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    socket.connect(server_addr).await?;
    let transport = UdpTransport::new(socket);

    let mut request = Message::new();
    request.set_id(0x1234);
    request.add_question(Question::new(
        Name::from_ascii(qname).expect("query name should be valid"),
        RecordType::A,
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

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.flow(), ExecFlowState::Broken);
    assert!(context.marks().contains("100"));
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

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.flow(), ExecFlowState::Broken);
    assert!(context.marks().contains("100"));
    assert!(context.marks().contains("200"));
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

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.flow(), ExecFlowState::Broken);
    assert!(context.marks().contains("1"));
    assert!(context.marks().contains("2"));
    assert!(!context.marks().contains("3"));
    assert!(!context.marks().contains("4"));
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

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.flow(), ExecFlowState::Broken);
    assert!(context.marks().contains("1"));
    assert!(context.marks().contains("2"));
    assert!(!context.marks().contains("3"));
    assert!(!context.marks().contains("4"));
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
    assert_eq!(context.flow(), ExecFlowState::ReachedTail);
    assert!(context.marks().contains("1"));
    assert!(context.marks().contains("2"));
    assert!(!context.marks().contains("3"));
    assert!(context.marks().contains("4"));

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

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.flow(), ExecFlowState::ReachedTail);
    assert!(context.marks().contains("1"));
    assert!(context.marks().contains("2"));
    assert!(!context.marks().contains("3"));
    assert!(!context.marks().contains("4"));

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
async fn test_domain_set_provider_flattens_referenced_sets() -> Result<()> {
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

    let provider = registry
        .get_plugin("combined_domain")
        .expect("combined domain provider should exist")
        .to_provider();

    assert!(provider.contains_name(&Name::from_ascii("local.example").unwrap()));
    assert!(provider.contains_name(&Name::from_ascii("www.shared.example").unwrap()));
    assert!(!provider.contains_name(&Name::from_ascii("missing.example").unwrap()));

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
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;

    let provider = registry
        .get_plugin("domain_rules")
        .expect("domain_rules provider should exist")
        .to_provider();

    assert!(provider.contains_name(&Name::from_ascii("www.example.test").unwrap()));
    assert!(provider.contains_name(&Name::from_ascii("img.cdn.example.test").unwrap()));
    assert!(provider.contains_name(&Name::from_ascii("exact-only.test").unwrap()));
    assert!(provider.contains_name(&Name::from_ascii("cdn.analytics-node.test").unwrap()));
    assert!(provider.contains_name(&Name::from_ascii("api12.service.test").unwrap()));
    assert!(!provider.contains_name(&Name::from_ascii("www.exact-only.test").unwrap()));
    assert!(!provider.contains_name(&Name::from_ascii("api.service.test").unwrap()));
    assert!(!provider.contains_name(&Name::from_ascii("missing.example").unwrap()));

    registry.destory().await;
    Ok(())
}

#[tokio::test]
async fn test_ip_set_provider_flattens_referenced_sets() -> Result<()> {
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
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config, None).await?;

    let provider = registry
        .get_plugin("combined_ip")
        .expect("combined ip provider should exist")
        .to_provider();

    assert!(provider.contains_ip("203.0.113.7".parse().unwrap()));
    assert!(provider.contains_ip("198.51.100.42".parse().unwrap()));
    assert!(!provider.contains_ip("198.51.101.1".parse().unwrap()));

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
"#
    );

    let config = parse_config(&yaml)?;
    let registry = plugin::init(config, None).await?;

    let provider = registry
        .get_plugin("ip_rules")
        .expect("ip_rules provider should exist")
        .to_provider();

    assert!(provider.contains_ip("203.0.113.7".parse().unwrap()));
    assert!(provider.contains_ip("198.51.100.42".parse().unwrap()));
    assert!(provider.contains_ip("2001:db8::7".parse().unwrap()));
    assert!(provider.contains_ip("2001:db8:abcd::1234".parse().unwrap()));
    assert!(!provider.contains_ip("203.0.113.8".parse().unwrap()));
    assert!(!provider.contains_ip("198.51.101.1".parse().unwrap()));
    assert!(!provider.contains_ip("2001:db8::8".parse().unwrap()));
    assert!(!provider.contains_ip("2001:db8:abce::1".parse().unwrap()));

    registry.destory().await;
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
    assert!(matches!(blocked_step, ExecStep::Next));
    assert_eq!(blocked_ctx.flow(), ExecFlowState::Broken);
    let blocked_response = blocked_ctx
        .response()
        .expect("blocked query should synthesize a response");
    assert_eq!(blocked_response.rcode(), Rcode::NoError);
    assert_eq!(blocked_response.answers().len(), 1);
    assert_eq!(blocked_response.answers()[0].rr_type(), RecordType::A);

    let mut allow_ctx = make_context(registry.clone(), "safe.ads.example.com.");
    let allow_step = main.execute(&mut allow_ctx).await?;
    assert!(matches!(allow_step, ExecStep::Next));
    assert_eq!(allow_ctx.flow(), ExecFlowState::Broken);
    assert_eq!(
        allow_ctx
            .response()
            .expect("fallback reject should build response")
            .rcode(),
        Rcode::ServFail
    );

    let mut unsupported_ctx = make_context(registry.clone(), "rewrite.example.com.");
    let unsupported_step = main.execute(&mut unsupported_ctx).await?;
    assert!(matches!(unsupported_step, ExecStep::Next));
    assert_eq!(unsupported_ctx.flow(), ExecFlowState::Broken);
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
        assert_eq!(ctx.flow(), ExecFlowState::Broken);
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
        assert_eq!(ctx.flow(), ExecFlowState::Broken);
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
        ExecStep::Next
    ));
    assert_blocked("plain_exact", &plain_exact);

    let mut plain_subdomain = make_context(registry.clone(), "www.plain-match.example.");
    assert!(matches!(
        main.execute(&mut plain_subdomain).await?,
        ExecStep::Next
    ));
    assert_rejected("plain_subdomain", &plain_subdomain);

    let mut suffix = make_context(registry.clone(), "cdn.suffix.example.");
    assert!(matches!(main.execute(&mut suffix).await?, ExecStep::Next));
    assert_blocked("suffix", &suffix);

    let mut exception = make_context(registry.clone(), "allow.suffix.example.");
    assert!(matches!(
        main.execute(&mut exception).await?,
        ExecStep::Next
    ));
    assert_rejected("exception", &exception);

    let mut wildcard = make_context(registry.clone(), "ad-banner.wild.example.");
    assert!(matches!(main.execute(&mut wildcard).await?, ExecStep::Next));
    assert_blocked("wildcard", &wildcard);

    let mut regex = make_context(registry.clone(), "metrics12.service.test.");
    assert!(matches!(main.execute(&mut regex).await?, ExecStep::Next));
    assert_blocked("regex", &regex);

    let mut denyallow_root = make_context(registry.clone(), "deny.example.");
    assert!(matches!(
        main.execute(&mut denyallow_root).await?,
        ExecStep::Next
    ));
    assert_blocked("denyallow_root", &denyallow_root);

    let mut denyallow_sub = make_context(registry.clone(), "sub.deny.example.");
    assert!(matches!(
        main.execute(&mut denyallow_sub).await?,
        ExecStep::Next
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
        ExecStep::Next
    ));
    assert_rejected("important_exception", &important_exception);

    let mut badfilter_disabled = make_context(registry.clone(), "disabled.example.");
    assert!(matches!(
        main.execute(&mut badfilter_disabled).await?,
        ExecStep::Next
    ));
    assert_rejected("badfilter_disabled", &badfilter_disabled);

    let mut unsupported_modifier = make_context(registry.clone(), "rewrite.example.");
    assert!(matches!(
        main.execute(&mut unsupported_modifier).await?,
        ExecStep::Next
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
