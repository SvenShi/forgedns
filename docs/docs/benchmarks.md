---
title: 性能与基准
sidebar_position: 8
---

本文档收纳 README 中移出的性能说明，并按版本保留公开基准快照。目标不是宣称绝对胜负，而是展示 ForgeDNS 在不同策略复杂度、并发水平和传输路径下的性能轮廓。

## 性能关注点

ForgeDNS 关注的不是“最简单场景下的极限数字”，而是下面这些更接近真实部署的问题：

* 开启缓存、规则、回退、重写后，热路径是否仍然可控
* 多上游并发竞争时，整体时延是否可接受
* 新增协议和插件后，结构是否还能继续优化
* 系统联动和观测逻辑是否会拖慢主响应路径

## 指标说明

* `QPS` 越高越好
* 平均延迟与抖动（latency stddev）越低越好
* `run_dnsperf_compare.sh` 更适合看中高并发吞吐与排队效应
* `run_dnsperf_latency_compare.sh` 更适合看低并发延迟，固定 `clients == outstanding`
* 这两组快照更适合分别观察 ForgeDNS 相对 mosdns 的优势分布
* 由于 2026-04-13 的 compare pack 已更新场景目录、查询集和部分 workload 口径，`v0.1.0` 与 `v0.3.0` 的绝对数字不建议直接做版本回归比较

说明：

* <span className="benchmark-delta benchmark-delta--up">绿色</span> 表示 ForgeDNS 在该指标上更优
* <span className="benchmark-delta benchmark-delta--down">红色</span> 表示 mosdns 在该指标上更优
* <span className="benchmark-delta benchmark-delta--neutral">中性色</span> 表示差距较小，仅用于辅助阅读，不代表统计显著性

## v0.3.0

### 高并发吞吐与平均延迟

测试环境：

* 时间：2026-04-13
* 系统：Linux `6.8.12-2-pve` `x86_64`
* 选择器：`core`
* 对比版本：ForgeDNS `v0.3.0`，mosdns `v5.3.4-0-gb732318`

压测参数：

* 工具：`dnsperf`
* `warmup_seconds=2`
* `bench_seconds=8`
* `bench_repeats=3`
* `dnsperf_clients=32`
* `dnsperf_threads=4`
* `dnsperf_outstanding=1024`
* `dnsperf_max_qps=unlimited`

结果阅读方式：

* `baseline UDP forward`、`concurrent upstreams`、`dual-entry UDP/TCP` 这类带上游转发或上游竞争的场景，主要反映的是端到端体验，结果会明显受到上游链路时延、上游响应稳定性和竞争策略影响，不应简单理解为“本地处理开销谁更小”
* `cache hotpath`、`local answers`、`server local UDP/TCP` 更接近本地处理成本
* `domain set`、`composite provider chain` 更适合看复杂规则、数据集和插件组合下的表现

下表展示按 repeat 聚合后的中位数：

| 场景 | ForgeDNS QPS | mosdns QPS | QPS 对比 | ForgeDNS 平均延迟 | mosdns 平均延迟 |
| ------------------------ | -----------: | ---------: | --------: | ----------------: | --------------: |
| baseline UDP forward     |     35,498.1 |   36,883.2 | <span className="benchmark-delta benchmark-delta--neutral">-3.8%</span> | <span className="benchmark-latency benchmark-latency--better">7.735 ms</span> | <span className="benchmark-latency benchmark-latency--worse">11.244 ms</span> |
| cache hotpath            |    139,133.9 |  134,881.6 | <span className="benchmark-delta benchmark-delta--neutral">+3.1%</span> | <span className="benchmark-latency benchmark-latency--better">0.637 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.721 ms</span> |
| dual-entry UDP           |     35,800.9 |   35,382.3 | <span className="benchmark-delta benchmark-delta--neutral">+1.2%</span> | <span className="benchmark-latency benchmark-latency--better">7.092 ms</span> | <span className="benchmark-latency benchmark-latency--worse">10.170 ms</span> |
| dual-entry TCP           |     37,295.1 |   37,221.2 | <span className="benchmark-delta benchmark-delta--neutral">+0.2%</span> | <span className="benchmark-latency benchmark-latency--better">24.646 ms</span> | <span className="benchmark-latency benchmark-latency--worse">25.083 ms</span> |
| concurrent upstreams     |     21,038.7 |   13,319.4 | <span className="benchmark-delta benchmark-delta--up">+58.0%</span> | <span className="benchmark-latency benchmark-latency--better">10.404 ms</span> | <span className="benchmark-latency benchmark-latency--worse">20.601 ms</span> |
| local answers            |    126,268.4 |  149,119.6 | <span className="benchmark-delta benchmark-delta--down">-15.3%</span> | <span className="benchmark-latency benchmark-latency--worse">0.783 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.639 ms</span> |
| domain set               |    165,647.7 |   36,383.7 | <span className="benchmark-delta benchmark-delta--up">+355.3%</span> | <span className="benchmark-latency benchmark-latency--better">0.549 ms</span> | <span className="benchmark-latency benchmark-latency--worse">4.078 ms</span> |
| ip set                   |    133,355.1 |  150,756.7 | <span className="benchmark-delta benchmark-delta--down">-11.5%</span> | <span className="benchmark-latency benchmark-latency--worse">0.740 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.637 ms</span> |
| composite provider chain |    158,693.6 |   25,972.4 | <span className="benchmark-delta benchmark-delta--up">+511.0%</span> | <span className="benchmark-latency benchmark-latency--better">0.532 ms</span> | <span className="benchmark-latency benchmark-latency--worse">6.251 ms</span> |

### 低并发延迟扫图

测试环境：

* 时间：2026-04-13
* 系统：Linux `6.8.12-2-pve` `x86_64`
* 选择器：`latency-core`
* 对比版本：ForgeDNS `v0.3.0`，mosdns `v5.3.4-0-gb732318`

压测参数：

* 工具：`dnsperf`
* `warmup_seconds=1`
* `bench_seconds=5`
* `bench_repeats=3`
* `latency_client_levels=1 2 4`
* `dnsperf_threads=1`
* `dnsperf_timeout=5`
* `dnsperf_outstanding=matches_client_count`

下面三张表优先展示平均延迟与抖动，`QPS` 只作为辅助校验指标。颜色沿用上面的规则：延迟或抖动更低的一侧为绿色，更高的一侧为红色，持平时使用中性色。

#### clients=1, outstanding=1

| 场景 | ForgeDNS 平均延迟 | mosdns 平均延迟 | 延迟对比 | ForgeDNS 抖动 | mosdns 抖动 | 抖动对比 |
| ------------------------ | ----------------: | --------------: | -------: | ------------: | ----------: | -------: |
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

| 场景 | ForgeDNS 平均延迟 | mosdns 平均延迟 | 延迟对比 | ForgeDNS 抖动 | mosdns 抖动 | 抖动对比 |
| ------------------------ | ----------------: | --------------: | -------: | ------------: | ----------: | -------: |
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

| 场景 | ForgeDNS 平均延迟 | mosdns 平均延迟 | 延迟对比 | ForgeDNS 抖动 | mosdns 抖动 | 抖动对比 |
| ------------------------ | ----------------: | --------------: | -------: | ------------: | ----------: | -------: |
| baseline UDP forward     | <span className="benchmark-latency benchmark-latency--worse">5.977 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.910 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+1.13%</span> | <span className="benchmark-latency benchmark-latency--better">0.355 ms</span> | <span className="benchmark-latency benchmark-latency--worse">2.700 ms</span> | <span className="benchmark-latency benchmark-latency--better">-86.85%</span> |
| cache hotpath            | <span className="benchmark-latency benchmark-latency--better">0.044 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.060 ms</span> | <span className="benchmark-latency benchmark-latency--better">-26.67%</span> | <span className="benchmark-latency benchmark-latency--better">0.028 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.063 ms</span> | <span className="benchmark-latency benchmark-latency--better">-55.56%</span> |
| dual-entry UDP           | <span className="benchmark-latency benchmark-latency--worse">6.637 ms</span> | <span className="benchmark-latency benchmark-latency--better">5.426 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+22.32%</span> | <span className="benchmark-latency benchmark-latency--worse">25.556 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.435 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+5774.94%</span> |
| dual-entry TCP           | <span className="benchmark-latency benchmark-latency--better">6.451 ms</span> | <span className="benchmark-latency benchmark-latency--worse">6.941 ms</span> | <span className="benchmark-latency benchmark-latency--better">-7.06%</span> | <span className="benchmark-latency benchmark-latency--better">4.422 ms</span> | <span className="benchmark-latency benchmark-latency--worse">26.437 ms</span> | <span className="benchmark-latency benchmark-latency--better">-83.27%</span> |
| local answers            | <span className="benchmark-latency benchmark-latency--worse">0.056 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.040 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+40.00%</span> | <span className="benchmark-latency benchmark-latency--worse">0.030 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.025 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+20.00%</span> |
| domain set               | <span className="benchmark-latency benchmark-latency--better">0.034 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.155 ms</span> | <span className="benchmark-latency benchmark-latency--better">-78.06%</span> | <span className="benchmark-latency benchmark-latency--better">0.016 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.141 ms</span> | <span className="benchmark-latency benchmark-latency--better">-88.65%</span> |
| composite provider chain | <span className="benchmark-latency benchmark-latency--better">0.034 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.221 ms</span> | <span className="benchmark-latency benchmark-latency--better">-84.62%</span> | <span className="benchmark-latency benchmark-latency--better">0.015 ms</span> | <span className="benchmark-latency benchmark-latency--worse">0.172 ms</span> | <span className="benchmark-latency benchmark-latency--better">-91.28%</span> |
| server local UDP         | <span className="benchmark-latency benchmark-latency--worse">0.042 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.038 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+10.53%</span> | <span className="benchmark-delta benchmark-delta--neutral">0.024 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">0.024 ms</span> | <span className="benchmark-delta benchmark-delta--neutral">+0.00%</span> |
| server local TCP         | <span className="benchmark-latency benchmark-latency--worse">0.042 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.039 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+7.69%</span> | <span className="benchmark-latency benchmark-latency--worse">0.026 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.022 ms</span> | <span className="benchmark-latency benchmark-latency--worse">+18.18%</span> |

### v0.3.0 结果分析

* 如果你的策略依赖复杂规则集、多数据集匹配，或者经常做多上游并发竞争，`v0.3.0` 下 ForgeDNS 的整体表现更有优势；`domain set`、`composite provider chain` 和 `concurrent upstreams` 都明显领先。
* `cache hotpath` 这一轮已经转为小幅领先，说明在缓存命中这类高频路径上，ForgeDNS 与 mosdns 的差距已经明显缩小。
* 本地应答场景下，ForgeDNS 与 mosdns 的差距已经不大；响应侧 `ip set` 过滤的结果也更多是在受本地应答路径性能上限影响，而不是一条完全独立的短板。
* 对于 `forward`、`dual-entry`、`concurrent upstreams` 这类场景，应把结果理解为端到端代理体验，其中上游链路延迟和上游响应稳定性是主要因素，而不是单纯的本地实现差异。
* 低并发延迟扫图里，`domain set`、`composite provider chain`、`cache hotpath` 和 `server local TCP` 的延迟和抖动都更稳定；`dual-entry UDP` 在 `clients=4` 时抖动明显偏高，说明这个场景的稳定性还需要继续观察。

## v0.1.0

下面保留 2026-03-26 公开结果，作为 `v0.1.0` 历史快照。

### 高并发吞吐与平均延迟

测试环境：

* CPU：Intel N100，4 核
* 内存：1 GB
* 环境：PVE 虚拟机内的 LXC
* 系统：Linux `6.8.12-2-pve` `x86_64`
* 时间：2026-03-26
* 被测版本：`forgedns v0.1.0`，mosdns `v5.3.4-0-gb732318`

压测参数：

* 工具：`dnsperf`
* `warmup_seconds=2`
* `bench_seconds=8`
* `bench_repeats=3`
* `dnsperf_clients=32`
* `dnsperf_threads=4`
* `dnsperf_outstanding=1024`
* `dnsperf_max_qps=unlimited`

下表为每个场景 3 次测试平均值：

| 场景                    | ForgeDNS QPS | mosdns QPS | QPS 对比 | ForgeDNS 平均延迟 | mosdns 平均延迟 |
| --------------------- | -----------: | ---------: | ------: | ------------: | ----------: |
| baseline UDP forward  |     37,789.6 |   37,269.2 | <span className="benchmark-delta benchmark-delta--neutral">+1.4%</span> | <span className="benchmark-latency benchmark-latency--better">9.142 ms</span> | <span className="benchmark-latency benchmark-latency--worse">12.312 ms</span> |
| cache hotpath         |    131,982.3 |  133,380.3 | <span className="benchmark-delta benchmark-delta--neutral">-1.0%</span> | <span className="benchmark-latency benchmark-latency--worse">1.235 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.696 ms</span> |
| dual-entry UDP        |     39,614.4 |   34,356.8 | <span className="benchmark-delta benchmark-delta--up">+15.3%</span> | <span className="benchmark-latency benchmark-latency--better">8.946 ms</span> | <span className="benchmark-latency benchmark-latency--worse">10.009 ms</span> |
| dual-entry TCP        |     36,257.9 |   35,975.4 | <span className="benchmark-delta benchmark-delta--neutral">+0.8%</span> | <span className="benchmark-latency benchmark-latency--better">25.403 ms</span> | <span className="benchmark-latency benchmark-latency--worse">25.577 ms</span> |
| concurrent upstreams  |     21,694.8 |   13,195.4 | <span className="benchmark-delta benchmark-delta--up">+64.4%</span> | <span className="benchmark-latency benchmark-latency--better">15.065 ms</span> | <span className="benchmark-latency benchmark-latency--worse">23.790 ms</span> |
| fallback standby      |     22,259.9 |   23,223.9 | <span className="benchmark-delta benchmark-delta--neutral">-4.2%</span> | <span className="benchmark-latency benchmark-latency--worse">16.376 ms</span> | <span className="benchmark-latency benchmark-latency--better">10.616 ms</span> |
| local answers         |    132,286.6 |  146,754.3 | <span className="benchmark-delta benchmark-delta--down">-9.9%</span> | <span className="benchmark-latency benchmark-latency--worse">1.250 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.636 ms</span> |
| DoH upstream (HTTP/2) |     29,781.6 |   25,835.7 | <span className="benchmark-delta benchmark-delta--up">+15.3%</span> | <span className="benchmark-latency benchmark-latency--worse">13.363 ms</span> | <span className="benchmark-latency benchmark-latency--better">11.445 ms</span> |
| domain set            |    172,061.7 |   35,966.1 | <span className="benchmark-delta benchmark-delta--up">+378.4%</span> | <span className="benchmark-latency benchmark-latency--better">0.901 ms</span> | <span className="benchmark-latency benchmark-latency--worse">4.210 ms</span> |
| ip set                |    134,257.4 |  150,923.0 | <span className="benchmark-delta benchmark-delta--down">-11.0%</span> | <span className="benchmark-latency benchmark-latency--worse">1.227 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.625 ms</span> |
| sequence base         |    131,995.6 |  150,301.5 | <span className="benchmark-delta benchmark-delta--down">-12.2%</span> | <span className="benchmark-latency benchmark-latency--worse">1.265 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.622 ms</span> |
| match true            |    135,326.0 |  153,289.5 | <span className="benchmark-delta benchmark-delta--down">-11.7%</span> | <span className="benchmark-latency benchmark-latency--worse">1.217 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.629 ms</span> |
| match false           |    136,740.1 |  152,297.5 | <span className="benchmark-delta benchmark-delta--down">-10.2%</span> | <span className="benchmark-latency benchmark-latency--worse">1.201 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.630 ms</span> |
| match qname           |    132,289.4 |  152,203.6 | <span className="benchmark-delta benchmark-delta--down">-13.1%</span> | <span className="benchmark-latency benchmark-latency--worse">1.248 ms</span> | <span className="benchmark-latency benchmark-latency--better">0.638 ms</span> |

### v0.1.0 当时的结论

* ForgeDNS 在多上游并发、DoH 上游、双入口 UDP 和大规模 `domain_set` 场景下更有优势
* mosdns 在缓存命中、本地应答、基础 `sequence` 和轻量 matcher 场景下目前仍然更快
* `fallback standby` 这类链路还有继续优化空间

## 原始资料

* 基准目录：[`benchmarks/mosdns_compare/README.md`](https://github.com/SvenShi/forgedns/tree/main/benchmarks/mosdns_compare)
* 场景列表：[`benchmarks/mosdns_compare/scenarios.tsv`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/scenarios.tsv)
* 高并发脚本：[`benchmarks/mosdns_compare/run_dnsperf_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_compare.sh)
* 低并发延迟脚本：[`benchmarks/mosdns_compare/run_dnsperf_latency_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_latency_compare.sh)
