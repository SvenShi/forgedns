use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use forgedns::core::rule_matcher::IpPrefixMatcher;

fn make_ip_rules() -> Vec<String> {
    let mut rules = Vec::with_capacity(3_000);

    for idx in 0..1_500u16 {
        let second = (idx / 256) as u8;
        let third = (idx % 256) as u8;
        rules.push(format!("10.{second}.{third}.0/24"));
    }

    for idx in 0..1_500u16 {
        rules.push(format!("2001:db8:{idx:x}::/48"));
    }

    rules
}

fn build_ip_matcher(rules: &[String]) -> IpPrefixMatcher {
    let mut matcher = IpPrefixMatcher::default();
    for rule in rules {
        matcher
            .add_rule(rule)
            .expect("benchmark ip rule should be valid");
    }
    matcher.finalize();
    matcher
}

fn bench_ip_matcher(c: &mut Criterion) {
    let rules = make_ip_rules();
    let matcher = build_ip_matcher(&rules);
    let ipv4_hit = IpAddr::V4(Ipv4Addr::new(10, 3, 9, 42));
    let ipv4_miss = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let ipv6_hit = IpAddr::V6(Ipv6Addr::new(0x2001, 0xDB8, 0x04D2, 0, 0, 0, 0, 1));
    let ipv6_miss = IpAddr::V6(Ipv6Addr::new(0x2001, 0xDB9, 0, 0, 0, 0, 0, 1));

    let mut group = c.benchmark_group("rule_matcher_ip");

    group.bench_function(BenchmarkId::new("build", rules.len()), |b| {
        b.iter(|| {
            let matcher = build_ip_matcher(black_box(&rules));
            black_box(matcher);
        })
    });

    for (label, ip) in [
        ("match_ipv4", ipv4_hit),
        ("miss_ipv4", ipv4_miss),
        ("match_ipv6", ipv6_hit),
        ("miss_ipv6", ipv6_miss),
    ] {
        group.bench_function(BenchmarkId::new("lookup", label), |b| {
            b.iter(|| {
                let matched = matcher.contains_ip(black_box(ip));
                black_box(matched);
            })
        });
    }

    group.finish();
}

criterion_group!(ip_rule_matcher, bench_ip_matcher);
criterion_main!(ip_rule_matcher);
