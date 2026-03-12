/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use forgedns::config::types::Config;
use forgedns::core::context::{DnsContext, ExecFlowState};
use forgedns::core::error::{DnsError, Result};
use forgedns::message::{Message, Question, ResponseCode};
use forgedns::message::{Name, RecordType};
use forgedns::network::transport::udp_transport::UdpTransport;
use forgedns::plugin;
use forgedns::plugin::executor::ExecStep;
use forgedns::plugin::{PluginRegistry, PluginType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

fn parse_config(yaml: &str) -> Result<Config> {
    let config: Config = serde_yml::from_str(yaml)?;
    config.validate()?;
    Ok(config)
}

fn make_context(registry: Arc<PluginRegistry>, qname: &str) -> DnsContext {
    let mut request = Message::new();
    request.add_question(Question::new(
        Name::from_ascii(qname).expect("query name should be valid"),
        RecordType::A,
    ));

    DnsContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        request,
        registry,
    )
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
    ));

    transport.write_message(&request).await?;

    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(1), transport.read_message(&mut buf))
        .await
        .map_err(|_| DnsError::runtime("timed out waiting for UDP server response"))?
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
    let registry = plugin::init(config).await?;

    assert_eq!(
        registry.plugin_count(),
        1,
        "one plugin should be initialized"
    );
    assert!(registry.get_plugin("debug").is_some());

    registry.destroy_plugins().await;
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
    let registry = plugin::init(config).await?;

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

    registry.destroy_plugins().await;
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
      - exec: reject SERVFAIL
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config).await?;

    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.exec_flow_state, ExecFlowState::Broken);
    assert!(context.marks.contains("100"));
    assert_eq!(
        context
            .response
            .as_ref()
            .expect("reject should set a response")
            .response_code_hint(),
        Some(ResponseCode::ServFail)
    );

    registry.destroy_plugins().await;
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
    let err = plugin::init(config)
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
    let err = plugin::init(config)
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
      - exec: reject SERVFAIL
"#;

    let config = parse_config(yaml)?;
    let registry = plugin::init(config).await?;

    let sequence = registry
        .get_plugin("seq")
        .expect("sequence plugin should exist")
        .to_executor();
    let mut context = make_context(registry.clone(), "example.com.");

    let step = sequence.execute(&mut context).await?;

    assert!(matches!(step, ExecStep::Next));
    assert_eq!(context.exec_flow_state, ExecFlowState::Broken);
    assert!(context.marks.contains("100"));
    assert!(context.marks.contains("200"));
    assert_eq!(
        context
            .response
            .as_ref()
            .expect("reject should set a response")
            .response_code_hint(),
        Some(ResponseCode::ServFail)
    );

    registry.destroy_plugins().await;
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
        match plugin::init(config).await {
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
    registry.destroy_plugins().await;
    let response = response_result?;

    assert_eq!(response.id(), 0x1234);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].record_type(), RecordType::A);
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
    let registry = plugin::init(config).await?;

    let provider = registry
        .get_plugin("combined_domain")
        .expect("combined domain provider should exist")
        .to_provider();

    assert!(provider.contains_domain("local.example"));
    assert!(provider.contains_domain("www.shared.example"));
    assert!(!provider.contains_domain("missing.example"));

    registry.destroy_plugins().await;
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
    let registry = plugin::init(config).await?;

    let provider = registry
        .get_plugin("combined_ip")
        .expect("combined ip provider should exist")
        .to_provider();

    assert!(provider.contains_ip("203.0.113.7".parse().unwrap()));
    assert!(provider.contains_ip("198.51.100.42".parse().unwrap()));
    assert!(!provider.contains_ip("198.51.101.1".parse().unwrap()));

    registry.destroy_plugins().await;
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
        exec: reject SERVFAIL
"#;

    let config = parse_config(yaml)?;
    let err = plugin::init(config)
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
    let err = plugin::init(config)
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
    let err = plugin::init(config)
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
    let err = plugin::init(config)
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
