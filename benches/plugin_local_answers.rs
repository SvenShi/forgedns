use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use forgedns::config::types::{ApiConfig, Config, LogConfig, PluginConfig, RuntimeConfig};
use forgedns::core::context::DnsContext;
use forgedns::message::{DNSClass, Message, Name, Question, RecordType};
use forgedns::plugin::{PluginRegistry, init as init_plugins};
use serde_yml::Value;
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::runtime::Runtime;

fn runtime() -> Runtime {
    Runtime::new().expect("benchmark tokio runtime should start")
}

fn plugin_config(tag: &str, plugin_type: &str, args: Value) -> PluginConfig {
    PluginConfig {
        tag: tag.to_string(),
        plugin_type: plugin_type.to_string(),
        args: Some(args),
    }
}

fn make_config(plugin: PluginConfig) -> Config {
    Config {
        runtime: RuntimeConfig::default(),
        api: ApiConfig::default(),
        log: LogConfig::default(),
        plugins: vec![plugin],
    }
}

fn make_context(registry: Arc<PluginRegistry>, name: &str, qtype: RecordType) -> DnsContext {
    let mut request = Message::new();
    request.add_question(Question::new(
        Name::from_ascii(name).expect("benchmark qname should parse"),
        qtype,
        DNSClass::IN,
    ));
    DnsContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        request,
        registry,
    )
}

fn load_executor(
    rt: &Runtime,
    plugin: PluginConfig,
) -> (
    Arc<dyn forgedns::plugin::executor::Executor>,
    Arc<PluginRegistry>,
) {
    let registry = rt
        .block_on(init_plugins(make_config(plugin)))
        .expect("benchmark plugin should initialize");
    let executor = registry
        .get_plugin("bench")
        .expect("benchmark plugin should exist")
        .to_executor();
    (executor, registry)
}

fn bench_black_hole(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("plugin_black_hole");

    for (label, qtype, ips) in [
        ("a_1", RecordType::A, vec!["192.0.2.10"]),
        (
            "a_8",
            RecordType::A,
            vec![
                "192.0.2.10",
                "192.0.2.11",
                "192.0.2.12",
                "192.0.2.13",
                "192.0.2.14",
                "192.0.2.15",
                "192.0.2.16",
                "192.0.2.17",
            ],
        ),
        ("aaaa_1", RecordType::AAAA, vec!["2001:db8::10"]),
        (
            "aaaa_8",
            RecordType::AAAA,
            vec![
                "2001:db8::10",
                "2001:db8::11",
                "2001:db8::12",
                "2001:db8::13",
                "2001:db8::14",
                "2001:db8::15",
                "2001:db8::16",
                "2001:db8::17",
            ],
        ),
    ] {
        let args: Value = serde_yml::from_str(&format!(
            "ips:\n{}",
            ips.iter()
                .map(|ip| format!("  - {ip}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
        .expect("black_hole args should parse");
        let (executor, registry) = load_executor(&rt, plugin_config("bench", "black_hole", args));

        group.bench_function(BenchmarkId::new("execute", label), |b| {
            b.iter(|| {
                let mut ctx = make_context(registry.clone(), "bench.test.", qtype);
                let step = rt
                    .block_on(executor.execute_with_next(&mut ctx, None))
                    .expect("black_hole execute should succeed");
                black_box(step);
                black_box(ctx.response().expect("response should be present"));
            })
        });
    }

    group.finish();
}

fn bench_hosts(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("plugin_hosts");

    for (label, entry, qname) in [
        (
            "full",
            "full:bench.test 192.0.2.10 192.0.2.11",
            "bench.test.",
        ),
        (
            "domain",
            "domain:bench.test 192.0.2.10 192.0.2.11",
            "api.bench.test.",
        ),
        (
            "keyword",
            "keyword:bench 192.0.2.10 192.0.2.11",
            "api-bench-edge.test.",
        ),
        (
            "regex",
            "regexp:^api[0-9]+\\.bench\\.test$ 192.0.2.10 192.0.2.11",
            "api42.bench.test.",
        ),
    ] {
        let args: Value = serde_yml::from_str(&format!("entries:\n  - '{entry}'"))
            .expect("hosts args should parse");
        let (executor, registry) = load_executor(&rt, plugin_config("bench", "hosts", args));

        group.bench_function(BenchmarkId::new("execute", label), |b| {
            b.iter(|| {
                let mut ctx = make_context(registry.clone(), qname, RecordType::A);
                let step = rt
                    .block_on(executor.execute_with_next(&mut ctx, None))
                    .expect("hosts execute should succeed");
                black_box(step);
                black_box(ctx.response().expect("response should be present"));
            })
        });
    }

    group.finish();
}

fn bench_arbitrary(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("plugin_arbitrary");

    for (label, rules, qname, qtype) in [
        (
            "a_1",
            vec!["bench.test. 60 IN A 192.0.2.10"],
            "bench.test.",
            RecordType::A,
        ),
        (
            "a_8",
            vec![
                "bench.test. 60 IN A 192.0.2.10",
                "bench.test. 60 IN A 192.0.2.11",
                "bench.test. 60 IN A 192.0.2.12",
                "bench.test. 60 IN A 192.0.2.13",
                "bench.test. 60 IN A 192.0.2.14",
                "bench.test. 60 IN A 192.0.2.15",
                "bench.test. 60 IN A 192.0.2.16",
                "bench.test. 60 IN A 192.0.2.17",
            ],
            "bench.test.",
            RecordType::A,
        ),
        (
            "aaaa",
            vec!["bench-v6.test. 60 IN AAAA 2001:db8::10"],
            "bench-v6.test.",
            RecordType::AAAA,
        ),
        (
            "txt",
            vec!["txt.bench.test. 60 IN TXT \"forge-bench\""],
            "txt.bench.test.",
            RecordType::TXT,
        ),
        (
            "cname",
            vec!["alias.bench.test. 60 IN CNAME target.bench.test."],
            "alias.bench.test.",
            RecordType::CNAME,
        ),
        (
            "any",
            vec![
                "multi.bench.test. 60 IN A 192.0.2.10",
                "multi.bench.test. 60 IN AAAA 2001:db8::10",
                "multi.bench.test. 60 IN TXT \"ok\"",
                "multi.bench.test. 60 IN CNAME target.bench.test.",
            ],
            "multi.bench.test.",
            RecordType::ANY,
        ),
    ] {
        let args: Value = serde_yml::from_str(&format!(
            "rules:\n{}",
            rules
                .iter()
                .map(|rule| format!("  - '{rule}'"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
        .expect("arbitrary args should parse");
        let (executor, registry) = load_executor(&rt, plugin_config("bench", "arbitrary", args));

        group.bench_function(BenchmarkId::new("execute", label), |b| {
            b.iter(|| {
                let mut ctx = make_context(registry.clone(), qname, qtype);
                let step = rt
                    .block_on(executor.execute_with_next(&mut ctx, None))
                    .expect("arbitrary execute should succeed");
                black_box(step);
                black_box(ctx.response().expect("response should be present"));
            })
        });
    }

    group.finish();
}

criterion_group!(
    plugin_local_answers,
    bench_black_hole,
    bench_hosts,
    bench_arbitrary
);
criterion_main!(plugin_local_answers);
