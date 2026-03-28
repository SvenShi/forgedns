---
title: 性能与基准
sidebar_position: 8
---

本文档收纳 README 中移出的性能说明与当前基准结果。这里的目标不是宣称绝对胜负，而是给出 ForgeDNS 在不同策略复杂度下的性能轮廓。

## 性能关注点

ForgeDNS 关注的不是“最简单场景下的极限数字”，而是下面这些更接近真实部署的问题：

* 开启缓存、规则、回退、重写后，热路径是否仍然可控
* 多上游并发竞争时，整体时延是否可接受
* 新增协议和插件后，结构是否还能继续优化
* 系统联动和观测逻辑是否会拖慢主响应路径

## 与 mosdns 的一组对比

测试环境：

* CPU：Intel N100，4 核
* 内存：1 GB
* 环境：PVE 虚拟机内的 LXC
* 系统：Linux 6.8.12-2-pve x86\_64
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

说明：

* <span className="benchmark-delta benchmark-delta--up">绿色</span> 表示 ForgeDNS 在该指标上更优
* <span className="benchmark-delta benchmark-delta--down">红色</span> 表示 mosdns 在该指标上更优
* <span className="benchmark-delta benchmark-delta--neutral">中性色</span> 表示差距较小，仅用于辅助阅读，不代表统计显著性

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

## 结果怎么看

从这组样本可以看到：

* ForgeDNS 在多上游并发、DoH 上游、双入口 UDP 和大规模 `domain_set` 场景下更有优势
* mosdns 在缓存命中、本地应答、基础 `sequence` 和轻量 matcher 场景下目前仍然更快
* `fallback standby` 这类链路还有继续优化空间

所以当前更准确的结论不是“ForgeDNS 全面更快”，而是：

> 在更接近真实策略复杂度的场景里，ForgeDNS 已经展示出明显潜力；在纯热路径场景里，仍有进一步优化空间。

## 原始资料

* 基准目录：[`benchmarks/mosdns_compare/README.md`](https://github.com/SvenShi/forgedns/tree/main/benchmarks/mosdns_compare)
* 场景列表：[`benchmarks/mosdns_compare/scenarios.tsv`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/scenarios.tsv)
* 压测脚本：[`benchmarks/mosdns_compare/run_dnsperf_compare.sh`](https://github.com/SvenShi/forgedns/blob/main/benchmarks/mosdns_compare/run_dnsperf_compare.sh)
