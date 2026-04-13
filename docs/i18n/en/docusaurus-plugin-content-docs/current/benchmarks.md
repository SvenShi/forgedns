---
title: Performance and Benchmarks
sidebar_position: 8
---

This page collects the performance notes moved out of the README together with the current benchmark results. The goal is not to claim an absolute winner, but to show the performance profile of ForgeDNS under different levels of policy complexity.

## What ForgeDNS Cares About

ForgeDNS is not only interested in peak numbers for the simplest possible case. The more relevant questions are:

* Is the hot path still controlled when cache, rules, fallback, and rewrites are enabled?
* Is overall latency acceptable when several upstreams race concurrently?
* Can the structure still be optimized after adding more protocols and plugins?
* Do system integrations and observability stay off the critical response path enough to avoid dragging performance down?

## One Comparison Set Against mosdns

Test environment:

* CPU: Intel N100, 4 cores
* Memory: 1 GB
* Environment: LXC inside a PVE VM
* System: Linux 6.8.12-2-pve x86_64
* Date: 2026-03-26
* Versions tested: `forgedns v0.1.0`, mosdns `v5.3.4-0-gb732318`

Load-test parameters:

* Tool: `dnsperf`
* `warmup_seconds=2`
* `bench_seconds=8`
* `bench_repeats=3`
* `dnsperf_clients=32`
* `dnsperf_threads=4`
* `dnsperf_outstanding=1024`
* `dnsperf_max_qps=unlimited`

The table below shows the average of three runs for each scenario.

Additional note:

* The public table above is still throughput-biased and comes from `run_dnsperf_compare.sh`
* The repository now also ships `run_dnsperf_latency_compare.sh` for low-concurrency latency sweeps with `1 / 2 / 4` client levels by default

Legend:

* <span className="benchmark-delta benchmark-delta--up">Green</span> means ForgeDNS performs better on that metric
* <span className="benchmark-delta benchmark-delta--down">Red</span> means mosdns performs better on that metric
* <span className="benchmark-delta benchmark-delta--neutral">Neutral</span> means the gap is small and shown only as a reading aid, not as a claim of statistical significance

| Scenario               | ForgeDNS QPS | mosdns QPS | QPS Delta | ForgeDNS Avg Latency | mosdns Avg Latency |
| ---------------------- | -----------: | ---------: | --------: | -------------------: | -----------------: |
| baseline UDP forward   |     37,789.6 |   37,269.2 | <span className="benchmark-delta benchmark-delta--neutral">+1.4%</span> | <span className="benchmark-latency benchmark-latency--better">9.142 ms</span> | <span className="benchmark-latency benchmark-latency--worse">12.312 ms</span> |
| cache hotpath          |    131,982.3 |  133,380.3 | <span className="benchmark-delta benchmark-delta--neutral">-1.0%</span> | <span className="benchmark-latency benchmark-latency--worse">1.235 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.696 ms</span> |
| dual-entry UDP         |     39,614.4 |   34,356.8 | <span className="benchmark-delta benchmark-delta--up">+15.3%</span> | <span className="benchmark-latency benchmark-latency--better">8.946 ms</span> | <span className="benchmark-latency benchmark-latency--worse">10.009 ms</span> |
| dual-entry TCP         |     36,257.9 |   35,975.4 | <span className="benchmark-delta benchmark-delta--neutral">+0.8%</span> | <span className="benchmark-latency benchmark-latency--better">25.403 ms</span> | <span className="benchmark-latency benchmark-latency--worse">25.577 ms</span> |
| concurrent upstreams   |     21,694.8 |   13,195.4 | <span className="benchmark-delta benchmark-delta--up">+64.4%</span> | <span className="benchmark-latency benchmark-latency--better">15.065 ms</span> | <span className="benchmark-latency benchmark-latency--worse">23.790 ms</span> |
| fallback standby       |     22,259.9 |   23,223.9 | <span className="benchmark-delta benchmark-delta--neutral">-4.2%</span> | <span className="benchmark-latency benchmark-latency--worse">16.376 ms</span> | <span className="benchmark-latency benchmark-latency--better">10.616 ms</span> |
| local answers          |    132,286.6 |  146,754.3 | <span className="benchmark-delta benchmark-delta--down">-9.9%</span> | <span className="benchmark-latency benchmark-latency--worse">1.250 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.636 ms</span> |
| DoH upstream (HTTP/2)  |     29,781.6 |   25,835.7 | <span className="benchmark-delta benchmark-delta--up">+15.3%</span> | <span className="benchmark-latency benchmark-latency--worse">13.363 ms</span> | <span className="benchmark-latency benchmark-latency--better">11.445 ms</span> |
| domain set             |    172,061.7 |   35,966.1 | <span className="benchmark-delta benchmark-delta--up">+378.4%</span> | <span className="benchmark-latency benchmark-latency--better">0.901 ms</span> | <span className="benchmark-latency benchmark-latency--worse">4.210 ms</span> |
| ip set                 |    134,257.4 |  150,923.0 | <span className="benchmark-delta benchmark-delta--down">-11.0%</span> | <span className="benchmark-latency benchmark-latency--worse">1.227 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.625 ms</span> |
| sequence base          |    131,995.6 |  150,301.5 | <span className="benchmark-delta benchmark-delta--down">-12.2%</span> | <span className="benchmark-latency benchmark-latency--worse">1.265 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.622 ms</span> |
| match true             |    135,326.0 |  153,289.5 | <span className="benchmark-delta benchmark-delta--down">-11.7%</span> | <span className="benchmark-latency benchmark-latency--worse">1.217 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.629 ms</span> |
| match false            |    136,740.1 |  152,297.5 | <span className="benchmark-delta benchmark-delta--down">-10.2%</span> | <span className="benchmark-latency benchmark-latency--worse">1.201 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.630 ms</span> |
| match qname            |    132,289.4 |  152,203.6 | <span className="benchmark-delta benchmark-delta--down">-13.1%</span> | <span className="benchmark-latency benchmark-latency--worse">1.248 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.638 ms</span> |

## How to Read These Results

From this sample set:

* ForgeDNS is stronger in concurrent upstream races, DoH upstreams, dual-entry UDP, and large `domain_set` scenarios.
* mosdns is still faster in cache-hit paths, local answers, basic `sequence`, and lighter matcher scenarios.
* `fallback standby` still has room for further optimization.

So the more accurate conclusion is not "ForgeDNS is faster across the board", but:

> In scenarios closer to real policy complexity, ForgeDNS already shows clear potential. In pure hot-path scenarios, there is still optimization headroom.

## Raw Materials

* Benchmark directory: [`benchmarks/mosdns_compare/README.md`](https://github.com/SvenShi/forgedns/tree/main/benchmarks/mosdns_compare)
* Scenario list: [`benchmarks/mosdns_compare/scenarios.tsv`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/scenarios.tsv)
* Load-test script: [`benchmarks/mosdns_compare/run_dnsperf_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_compare.sh)
* Low-concurrency latency script: [`benchmarks/mosdns_compare/run_dnsperf_latency_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_latency_compare.sh)
