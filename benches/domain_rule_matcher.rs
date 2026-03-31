use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use forgedns::core::rule_matcher::DomainRuleMatcher;
use forgedns::proto::Name;
use std::hint::black_box;

fn make_domain_rules() -> Vec<String> {
    let mut rules = Vec::with_capacity(4_000);

    for idx in 0..1_000usize {
        rules.push(format!("full:edge-{idx}.bench.example"));
        rules.push(format!("domain:zone-{idx}.bench.example"));
        rules.push(format!("keyword:tenant-{idx}"));
    }

    for idx in 0..1_000usize {
        rules.push(format!(r"regexp:^svc{idx}-[a-z0-9-]+\.bench\.example$"));
    }

    rules
}

fn build_domain_matcher(rules: &[String]) -> DomainRuleMatcher {
    let mut matcher = DomainRuleMatcher::default();
    for rule in rules {
        matcher
            .add_expression(rule, "benchmark")
            .expect("benchmark domain rule should be valid");
    }
    matcher
        .finalize()
        .expect("benchmark domain matcher should finalize");
    matcher
}

fn bench_domain_matcher(c: &mut Criterion) {
    let rules = make_domain_rules();
    let matcher = build_domain_matcher(&rules);
    let full_hit = Name::from_ascii("edge-777.bench.example.").expect("name should parse");
    let suffix_hit = Name::from_ascii("api.zone-777.bench.example.").expect("name should parse");
    let keyword_hit =
        Name::from_ascii("tenant-777-gateway.prod.example.").expect("name should parse");
    let regex_hit = Name::from_ascii("svc777-alpha.bench.example.").expect("name should parse");
    let miss = Name::from_ascii("miss.case.example.").expect("name should parse");

    let mut group = c.benchmark_group("rule_matcher_domain");

    group.bench_function(BenchmarkId::new("build", rules.len()), |b| {
        b.iter(|| {
            let matcher = build_domain_matcher(black_box(&rules));
            black_box(matcher);
        })
    });

    for (label, name) in [
        ("match_full", &full_hit),
        ("match_suffix", &suffix_hit),
        ("match_keyword", &keyword_hit),
        ("match_regexp", &regex_hit),
        ("miss", &miss),
    ] {
        group.bench_function(BenchmarkId::new("lookup", label), |b| {
            b.iter(|| {
                let matched = matcher.is_match_name(black_box(name));
                black_box(matched);
            })
        });
    }

    group.finish();
}

criterion_group!(domain_rule_matcher, bench_domain_matcher);
criterion_main!(domain_rule_matcher);
