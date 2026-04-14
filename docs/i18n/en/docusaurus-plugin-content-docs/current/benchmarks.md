---
title: Performance and Benchmarks
sidebar_position: 8
---

This page collects the performance notes moved out of the README and keeps public benchmark snapshots by version. The goal is not to claim an absolute winner, but to show the performance profile of ForgeDNS under different levels of policy complexity, concurrency, and transport-path pressure.

## What ForgeDNS Cares About

ForgeDNS is not only interested in peak numbers for the simplest possible case. The more relevant questions are:

* Is the hot path still controlled when cache, rules, fallback, and rewrites are enabled?
* Is overall latency acceptable when several upstreams race concurrently?
* Can the structure still be optimized after adding more protocols and plugins?
* Do system integrations and observability stay off the critical response path enough to avoid dragging performance down?

## Metric Notes

* Higher `QPS` is better
* Lower average latency and latency stddev are better
* `run_dnsperf_compare.sh` is better for saturated or higher-concurrency throughput and queueing behavior
* `run_dnsperf_latency_compare.sh` is better for low-concurrency latency, with `clients == outstanding`
* These snapshots are better read as version-specific distributions of strengths against mosdns
* Because the 2026-04-13 compare pack updated the scenario catalog, query sets, and some workload definitions, the absolute numbers in `v0.1.0` and `v0.3.0` should not be treated as a direct regression chart across versions

Legend:

* <span className="benchmark-delta benchmark-delta--up">Green</span> means ForgeDNS performs better on that metric
* <span className="benchmark-delta benchmark-delta--down">Red</span> means mosdns performs better on that metric
* <span className="benchmark-delta benchmark-delta--neutral">Neutral</span> means the gap is small and shown only as a reading aid, not as a claim of statistical significance

## v0.3.0

### Higher-Concurrency Throughput and Average Latency

Test environment:

* Date: 2026-04-13
* System: Linux `6.8.12-2-pve` `x86_64`
* Selector: `core`
* Compared versions: ForgeDNS `v0.3.0`, mosdns `v5.3.4-0-gb732318`

Load-test parameters:

* Tool: `dnsperf`
* `warmup_seconds=2`
* `bench_seconds=8`
* `bench_repeats=3`
* `dnsperf_clients=32`
* `dnsperf_threads=4`
* `dnsperf_outstanding=1024`
* `dnsperf_max_qps=unlimited`

How to read these results:

* Scenarios such as `baseline UDP forward`, `concurrent upstreams`, and `dual-entry UDP/TCP` include upstream forwarding or upstream races, so they mainly reflect end-to-end proxy behavior; upstream RTT, upstream response stability, and race strategy matter more here than small local processing differences
* `cache hotpath`, `local answers`, and `server local UDP/TCP` are closer to local processing cost
* `domain set` and `composite provider chain` are better indicators for rule-heavy and dataset-heavy policy workloads

The table below shows the per-scenario medians aggregated from repeats:

| Scenario | ForgeDNS QPS | mosdns QPS | QPS Delta | ForgeDNS Avg Latency | mosdns Avg Latency |
| ------------------------ | -----------: | ---------: | --------: | -------------------: | -----------------: |
| baseline UDP forward     |     35,498.1 |   36,883.2 | <span className="benchmark-delta benchmark-delta--neutral">-3.8%</span> | <span className="benchmark-latency benchmark-latency--better">7.735 ms</span> | <span className="benchmark-latency benchmark-latency--worse">11.244 ms</span> |
| cache hotpath            |    139,133.9 |  134,881.6 | <span className="benchmark-delta benchmark-delta--neutral">+3.1%</span> | <span className="benchmark-latency benchmark-latency--better">0.637 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.721 ms</span> |
| dual-entry UDP           |     35,800.9 |   35,382.3 | <span className="benchmark-delta benchmark-delta--neutral">+1.2%</span> | <span className="benchmark-latency benchmark-latency--better">7.092 ms</span> | <span className="benchmark-latency benchmark-latency--worse">10.170 ms</span> |
| dual-entry TCP           |     37,295.1 |   37,221.2 | <span className="benchmark-delta benchmark-delta--neutral">+0.2%</span> | <span className="benchmark-latency benchmark-latency--better">24.646 ms</span> | <span className="benchmark-latency benchmark-latency--worse">25.083 ms</span> |
| concurrent upstreams     |     21,038.7 |   13,319.4 | <span className="benchmark-delta benchmark-delta--up">+58.0%</span> | <span className="benchmark-latency benchmark-latency--better">10.404 ms</span> | <span className="benchmark-latency benchmark-latency--worse">20.601 ms</span> |
| local answers            |    126,268.4 |  149,119.6 | <span className="benchmark-delta benchmark-delta--down">-15.3%</span> | <span className="benchmark-latency benchmark-latency--worse">0.783 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.639 ms</span> |
| domain set               |    165,647.7 |   36,383.7 | <span className="benchmark-delta benchmark-delta--up">+355.3%</span> | <span className="benchmark-latency benchmark-latency--better">0.549 ms</span> | <span className="benchmark-latency benchmark-latency--worse">4.078 ms</span> |
| ip set                   |    133,355.1 |  150,756.7 | <span className="benchmark-delta benchmark-delta--down">-11.5%</span> | <span className="benchmark-latency benchmark-latency--worse">0.740 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.637 ms</span> |
| composite provider chain |    158,693.6 |   25,972.4 | <span className="benchmark-delta benchmark-delta--up">+511.0%</span> | <span className="benchmark-latency benchmark-latency--better">0.532 ms</span> | <span className="benchmark-latency benchmark-latency--worse">6.251 ms</span> |

### Low-Concurrency Latency Sweep

Test environment:

* Date: 2026-04-13
* System: Linux `6.8.12-2-pve` `x86_64`
* Selector: `latency-core`
* Compared versions: ForgeDNS `v0.3.0`, mosdns `v5.3.4-0-gb732318`

Load-test parameters:

* Tool: `dnsperf`
* `warmup_seconds=1`
* `bench_seconds=5`
* `bench_repeats=3`
* `latency_client_levels=1 2 4`
* `dnsperf_threads=1`
* `dnsperf_timeout=5`
* `dnsperf_outstanding=matches_client_count`

The three tables below focus on average latency and jitter first, while `QPS` remains a secondary sanity metric. They use the same color rule as above: lower latency or jitter is green, higher latency or jitter is red, and ties are neutral.

#### clients=1, outstanding=1

| Scenario | ForgeDNS Avg Latency | mosdns Avg Latency | Latency Delta | ForgeDNS Jitter | mosdns Jitter | Jitter Delta |
| ------------------------ | -------------------: | -----------------: | ------------: | ---------------: | -------------: | -----------: |
| baseline UDP forward     | <span className="benchmark-latency benchmark-latency--worse">6.716 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.708 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+17.66%</span> | <span className="benchmark-latency benchmark-latency--better">0.170 ms</span> | <span className="benchmark-latency benchmark-latency--worse">1.140 ms</span> | <span className="benchmark-latency benchmark-latency--better">-85.09%</span> |
| cache hotpath            | <span className="benchmark-latency benchmark-latency--better">0.029 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.031 ms</span> | <span className="benchmark-latency benchmark-latency--better">-6.45%</span> | <span className="benchmark-latency benchmark-latency--better">0.017 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.021 ms</span> | <span className="benchmark-latency benchmark-latency--better">-19.05%</span> |
| dual-entry UDP           | <span className="benchmark-latency benchmark-latency--better">5.949 ms</span> | <span className="benchmark-latency benchmark-latency--worse">6.394 ms</span> | <span className="benchmark-latency benchmark-latency--better">-6.96%</span> | <span className="benchmark-latency benchmark-latency--better">0.426 ms</span> | <span className="benchmark-latency benchmark-latency--worse">2.364 ms</span> | <span className="benchmark-latency benchmark-latency--better">-81.98%</span> |
| dual-entry TCP           | <span className="benchmark-latency benchmark-latency--better">5.984 ms</span> | <span className="benchmark-latency benchmark-latency--worse">6.118 ms</span> | <span className="benchmark-latency benchmark-latency--better">-2.19%</span> | <span className="benchmark-latency benchmark-latency--better">0.380 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.829 ms</span> | <span className="benchmark-latency benchmark-latency--better">-54.16%</span> |
| local answers            | <span className="benchmark-latency benchmark-latency--better">0.026 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.029 ms</span> | <span className="benchmark-latency benchmark-latency--better">-10.34%</span> | <span className="benchmark-latency benchmark-latency--better">0.016 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.019 ms</span> | <span className="benchmark-latency benchmark-latency--better">-15.79%</span> |
| domain set               | <span className="benchmark-latency benchmark-latency--better">0.025 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.108 ms</span> | <span className="benchmark-latency benchmark-latency--better">-76.85%</span> | <span className="benchmark-latency benchmark-latency--better">0.011 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.095 ms</span> | <span className="benchmark-latency benchmark-latency--better">-88.42%</span> |
| composite provider chain | <span className="benchmark-latency benchmark-latency--better">0.025 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.156 ms</span> | <span className="benchmark-latency benchmark-latency--better">-83.97%</span> | <span className="benchmark-latency benchmark-latency--better">0.012 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.129 ms</span> | <span className="benchmark-latency benchmark-latency--better">-90.70%</span> |
| server local UDP         | <span className="benchmark-latency benchmark-latency--better">0.025 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.027 ms</span> | <span className="benchmark-latency benchmark-latency--better">-7.41%</span> | <span className="benchmark-delta benchmark-delta--neutral">0.013 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">0.013 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">+0.00%</span> |
| server local TCP         | <span className="benchmark-latency benchmark-latency--better">0.027 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.030 ms</span> | <span className="benchmark-latency benchmark-latency--better">-10.00%</span> | <span className="benchmark-latency benchmark-latency--better">0.009 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.018 ms</span> | <span className="benchmark-latency benchmark-latency--better">-50.00%</span> |

#### clients=2, outstanding=2

| Scenario | ForgeDNS Avg Latency | mosdns Avg Latency | Latency Delta | ForgeDNS Jitter | mosdns Jitter | Jitter Delta |
| ------------------------ | -------------------: | -----------------: | ------------: | ---------------: | -------------: | -----------: |
| baseline UDP forward     | <span className="benchmark-latency benchmark-latency--better">6.001 ms</span> | <span className="benchmark-latency benchmark-latency--worse">7.382 ms</span> | <span className="benchmark-latency benchmark-latency--better">-18.71%</span> | <span className="benchmark-latency benchmark-latency--better">0.262 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.858 ms</span> | <span className="benchmark-latency benchmark-latency--better">-69.46%</span> |
| cache hotpath            | <span className="benchmark-latency benchmark-latency--better">0.033 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.037 ms</span> | <span className="benchmark-latency benchmark-latency--better">-10.81%</span> | <span className="benchmark-latency benchmark-latency--better">0.050 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.053 ms</span> | <span className="benchmark-latency benchmark-latency--better">-5.66%</span> |
| dual-entry UDP           | <span className="benchmark-latency benchmark-latency--worse">6.408 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.923 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+8.19%</span> | <span className="benchmark-latency benchmark-latency--worse">1.247 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.488 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+155.53%</span> |
| dual-entry TCP           | <span className="benchmark-latency benchmark-latency--worse">5.651 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.633 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+0.32%</span> | <span className="benchmark-latency benchmark-latency--better">0.417 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.518 ms</span> | <span className="benchmark-latency benchmark-latency--better">-19.50%</span> |
| local answers            | <span className="benchmark-latency benchmark-latency--worse">0.040 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.031 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+29.03%</span> | <span className="benchmark-latency benchmark-latency--worse">0.021 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.018 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+16.67%</span> |
| domain set               | <span className="benchmark-latency benchmark-latency--better">0.029 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.111 ms</span> | <span className="benchmark-latency benchmark-latency--better">-73.87%</span> | <span className="benchmark-latency benchmark-latency--better">0.013 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.104 ms</span> | <span className="benchmark-latency benchmark-latency--better">-87.50%</span> |
| composite provider chain | <span className="benchmark-latency benchmark-latency--better">0.029 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.165 ms</span> | <span className="benchmark-latency benchmark-latency--better">-82.42%</span> | <span className="benchmark-latency benchmark-latency--better">0.014 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.141 ms</span> | <span className="benchmark-latency benchmark-latency--better">-90.07%</span> |
| server local UDP         | <span className="benchmark-latency benchmark-latency--worse">0.030 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.029 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+3.45%</span> | <span className="benchmark-delta benchmark-delta--neutral">0.016 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">0.016 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">+0.00%</span> |
| server local TCP         | <span className="benchmark-latency benchmark-latency--better">0.028 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.030 ms</span> | <span className="benchmark-latency benchmark-latency--better">-6.67%</span> | <span className="benchmark-latency benchmark-latency--better">0.014 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.015 ms</span> | <span className="benchmark-latency benchmark-latency--better">-6.67%</span> |

#### clients=4, outstanding=4

| Scenario | ForgeDNS Avg Latency | mosdns Avg Latency | Latency Delta | ForgeDNS Jitter | mosdns Jitter | Jitter Delta |
| ------------------------ | -------------------: | -----------------: | ------------: | ---------------: | -------------: | -----------: |
| baseline UDP forward     | <span className="benchmark-latency benchmark-latency--worse">5.977 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.910 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+1.13%</span> | <span className="benchmark-latency benchmark-latency--better">0.355 ms</span> | <span className="benchmark-latency benchmark-latency--worse">2.700 ms</span> | <span className="benchmark-latency benchmark-latency--better">-86.85%</span> |
| cache hotpath            | <span className="benchmark-latency benchmark-latency--better">0.044 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.060 ms</span> | <span className="benchmark-latency benchmark-latency--better">-26.67%</span> | <span className="benchmark-latency benchmark-latency--better">0.028 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.063 ms</span> | <span className="benchmark-latency benchmark-latency--better">-55.56%</span> |
| dual-entry UDP           | <span className="benchmark-latency benchmark-latency--worse">6.637 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.426 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+22.32%</span> | <span className="benchmark-latency benchmark-latency--worse">25.556 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.435 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+5774.94%</span> |
| dual-entry TCP           | <span className="benchmark-latency benchmark-latency--better">6.451 ms</span> | <span className="benchmark-latency benchmark-latency--worse">6.941 ms</span> | <span className="benchmark-latency benchmark-latency--better">-7.06%</span> | <span className="benchmark-latency benchmark-latency--better">4.422 ms</span> | <span className="benchmark-latency benchmark-latency--worse">26.437 ms</span> | <span className="benchmark-latency benchmark-latency--better">-83.27%</span> |
| local answers            | <span className="benchmark-latency benchmark-latency--worse">0.056 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.040 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+40.00%</span> | <span className="benchmark-latency benchmark-latency--worse">0.030 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.025 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+20.00%</span> |
| domain set               | <span className="benchmark-latency benchmark-latency--better">0.034 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.155 ms</span> | <span className="benchmark-latency benchmark-latency--better">-78.06%</span> | <span className="benchmark-latency benchmark-latency--better">0.016 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.141 ms</span> | <span className="benchmark-latency benchmark-latency--better">-88.65%</span> |
| composite provider chain | <span className="benchmark-latency benchmark-latency--better">0.034 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.221 ms</span> | <span className="benchmark-latency benchmark-latency--better">-84.62%</span> | <span className="benchmark-latency benchmark-latency--better">0.015 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.172 ms</span> | <span className="benchmark-latency benchmark-latency--better">-91.28%</span> |
| server local UDP         | <span className="benchmark-latency benchmark-latency--worse">0.042 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.038 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+10.53%</span> | <span className="benchmark-delta benchmark-delta--neutral">0.024 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">0.024 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">+0.00%</span> |
| server local TCP         | <span className="benchmark-latency benchmark-latency--worse">0.042 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.039 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+7.69%</span> | <span className="benchmark-latency benchmark-latency--worse">0.026 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.022 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+18.18%</span> |

### v0.3.0 Result Readout

* If your real deployment relies on complex rule sets, large datasets, or multi-upstream racing, ForgeDNS is in a stronger position in `v0.3.0`; `domain set`, `composite provider chain`, and `concurrent upstreams` are all clearly ahead.
* `cache hotpath` now shows a small lead for ForgeDNS, which means the gap on high-frequency cache-hit traffic has narrowed substantially.
* In local-answer workloads, the gap between ForgeDNS and mosdns is already fairly small; the `ip set` result is also more constrained by the local-answer performance ceiling than by a completely separate bottleneck.
* For `forward`, `dual-entry`, and `concurrent upstreams`, the numbers should be read as end-to-end proxy behavior. Upstream latency and upstream response stability are the dominant factors there, not just local implementation overhead.
* In the low-concurrency latency sweep, `domain set`, `composite provider chain`, `cache hotpath`, and `server local TCP` are the most stable strong areas; `dual-entry UDP` shows noticeably higher jitter at `clients=4`, so that scenario still needs more stability work.

## v0.1.0

The following public result set is preserved as the historical `v0.1.0` snapshot from March 26, 2026.

### Higher-Concurrency Throughput and Average Latency

Test environment:

* CPU: Intel N100, 4 cores
* Memory: 1 GB
* Environment: LXC inside a PVE VM
* System: Linux `6.8.12-2-pve` `x86_64`
* Date: 2026-03-26
* Compared versions: `forgedns v0.1.0`, mosdns `v5.3.4-0-gb732318`

Load-test parameters:

* Tool: `dnsperf`
* `warmup_seconds=2`
* `bench_seconds=8`
* `bench_repeats=3`
* `dnsperf_clients=32`
* `dnsperf_threads=4`
* `dnsperf_outstanding=1024`
* `dnsperf_max_qps=unlimited`

The table below shows the average of three runs for each scenario:

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

### v0.1.0 Historical Readout

* ForgeDNS was stronger in concurrent upstream races, DoH upstreams, dual-entry UDP, and large `domain_set` scenarios
* mosdns was still faster in cache-hit paths, local answers, basic `sequence`, and lighter matcher scenarios
* `fallback standby` still showed room for further optimization

## Raw Materials

* Benchmark directory: [`benchmarks/mosdns_compare/README.md`](https://github.com/SvenShi/forgedns/tree/main/benchmarks/mosdns_compare)
* Scenario list: [`benchmarks/mosdns_compare/scenarios.tsv`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/scenarios.tsv)
* Higher-concurrency script: [`benchmarks/mosdns_compare/run_dnsperf_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_compare.sh)
* Low-concurrency latency script: [`benchmarks/mosdns_compare/run_dnsperf_latency_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_latency_compare.sh)
