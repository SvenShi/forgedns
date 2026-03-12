# ForgeDNS vs mosdns dnsperf Compare Pack

This directory keeps a compare pack for ForgeDNS vs mosdns.

The pack now treats `scenarios.tsv` as a single scenario catalog instead of a flat
"run everything" list. Each row carries tags and a short purpose string so the
runner can default to the most decision-relevant scenarios first.

The YAML layout follows mosdns v5 plugin configuration style:

- basic format: https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v5/ru-he-pei-zhi-mosdns
- sequence: https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v5/ru-he-pei-zhi-mosdns/sequence-cha-jian
- executable plugins: https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v5/ru-he-pei-zhi-mosdns/ke-zhi-xing-cha-jian
- server plugins: https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v5/ru-he-pei-zhi-mosdns/fu-wu-qi-cha-jian
- data plugins: https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v5/ru-he-pei-zhi-mosdns/shu-ju-cha-jian

`reject` rules intentionally use numeric RCODEs to stay aligned with the official
mosdns examples.

## How to use

1. Put `forgedns` and `mosdns` binaries into this directory.
2. Make sure `dnsperf` is available in `PATH`.
3. Run `./run_dnsperf_compare.sh`.

With no selector, the runner now defaults to the `core` tag instead of running
all microbenchmarks. That makes the default report much closer to an actual
selection workflow.

Useful commands:

- `./run_dnsperf_compare.sh`
  - run the default `core` scenarios
- `./run_dnsperf_compare.sh macro`
  - only run end-to-end macro scenarios
- `./run_dnsperf_compare.sh micro`
  - only run isolated plugin microbenchmarks
- `./run_dnsperf_compare.sh composite`
  - only run integrated multi-plugin pipelines
- `./run_dnsperf_compare.sh plugin-matchers`
  - run one family from `scenarios.tsv`
- `./run_dnsperf_compare.sh 01-baseline-udp-forward 08-domain-set`
  - run selected labels directly
- `./run_dnsperf_compare.sh all`
  - run the full catalog
- `BENCH_REPEATS=1 ./run_dnsperf_compare.sh`
  - quick smoke run with no repeat aggregation
- `BENCH_REPEATS=3 BENCH_SECONDS=15 DNSPERF_CLIENTS=64 ./run_dnsperf_compare.sh macro`
  - slower but much more publishable macro compare
- `BENCH_PLUGIN_FLAG=1 ./run_dnsperf_compare.sh 18-match-env`
  - override the shared env matcher input when needed

## Scenario Catalog

- [scenarios.tsv](/Users/sven/Documents/Codes/Rust/forgedns/benchmarks/mosdns_compare/scenarios.tsv)
  - columns:
    `label | forgedns_config | mosdns_config | query_file | mode | family | warmup_query_file | tags | description | notes`
  - `warmup_query_file` falls back to `query_file` when set to `-`
  - selectors match any of:
    `label`, `family`, or one tag from `tags`

Common tags:

- `core`
  - default, highest reference value for product selection
- `macro`
  - end-to-end paths such as forward, cache, local answers, domain set, IP set
- `micro`
  - isolated plugin overhead measurements
- `composite`
  - integrated multi-plugin chains
- `extended`
  - useful, but not part of the default shortlist
- `edge`
  - more environment-sensitive and weaker as a default conclusion source
- `stable`
  - expected to be reproducible without special host-side setup
- `unstable`
  - success rate or upstream behavior can dominate the result
- `io-heavy`
  - observer/logging cost dominates, so avoid reading it as pure request-path cost
- `artificial`
  - synthetic control scenarios rather than real workloads

## Output Files

The runner writes raw logs and derived reports into `results/<timestamp>/`.

Important artifacts:

- `environment.txt`
  - binary hashes, versions, runtime parameters, host snapshot
- `summary.raw.tsv`
  - one line per repeat and engine
- `summary.tsv`
  - per-engine aggregated metrics using median over repeats plus spread
- `pair_summary.tsv`
  - head-to-head ForgeDNS vs mosdns table for each selected scenario
- `report.md`
  - ready-to-read Markdown report with parameters, environment, and pair table

Interpretation rules:

- `QPS diff` uses mosdns as the baseline:
  `(ForgeDNS - mosdns) / mosdns`
- `Latency diff` also uses mosdns as the baseline:
  a negative value means ForgeDNS has lower latency
- `BENCH_REPEATS=3` is the recommended floor for results you plan to quote
- observer scenarios such as `debug_print` and `query_summary` are useful for
  overhead comparison, but not for broad "which server is faster" claims

## Workload Notes

- `forward.txt` and `cache-hotpath.txt` now use a broader small working set
  instead of a tiny handful of names, so cache and forward numbers are less
  likely to overfit one or two repeated keys
- `41-composite-cache-forward` now uses a warmed subset plus a mixed measured
  query set, so it no longer collapses into a pure cache-hit benchmark
- `08-domain-set` and `09-ip-set` now use hit and miss mixes in the macro path,
  while the provider-only scenarios keep pure positive-match inputs for
  isolating raw dataset lookup cost
- `43-composite-provider-chain` now uses real `domain_set` and `ip_set` data
  files instead of one inline domain and one inline IP
- `local-answers.txt` and the related YAML now cover more local names and
  record types
- `ip-set.txt` and the related YAML now use multiple synthetic answers so the
  response-side IP set compare is not a single-name degenerate loop

## Current Tooling Gaps

- `http_server` and `quic_server` are not in the default catalog because this
  compare pack is still driven by `dnsperf` in UDP/TCP mode
- `ipset`, `nftset`, and `mikrotik` are not in the default catalog because
  they require host-level side-effect setup that is harder to keep reproducible
  across compare runs

## Reports

- [reports/20260311-152028.md](/Users/sven/Documents/Codes/Rust/forgedns/benchmarks/mosdns_compare/reports/20260311-152028.md)
  - detailed manual analysis for the Debian / Intel N100 / 4-core / 512 MB run
    on 2026-03-11

## Note

- Older runs may contain a `summary.tsv` filled with `n/a` because `dnsperf`
  summary lines include leading spaces. `run_dnsperf_compare.sh` now strips
  that prefix and also generates paired summaries and a Markdown report.
- The runner exports `BENCH_PLUGIN_FLAG=1` by default so `18-match-env` works
  on both engines.
