// Prometheus text-format parsing and plugin-level metric curation.
//
// The backend exposes a single Prometheus endpoint (`/metrics`). Every plugin
// series carries a `plugin_tag` label, so metrics are grouped by that tag and
// associated with the matching `PluginInstance` (whose `name` is the tag).

export interface MetricSeries {
  name: string;
  kind?: MetricKind;
  help?: string;
  /** Labels excluding `plugin_tag` (kept for dimensional breakdowns). */
  labels: Record<string, string>;
  value: number;
}

export type MetricKind =
  | "counter"
  | "gauge"
  | "histogram"
  | "summary"
  | "untyped";

export interface MetricGroup {
  name: string;
  label: string;
  help?: string;
  series: MetricSeries[];
  /** Sum of all series values for this metric name. */
  total: number;
  highValue: boolean;
}

/** Plugin tag -> flat list of its series. */
export type PluginMetricsMap = Record<string, MetricSeries[]>;

export interface ParsedMetrics {
  byTag: PluginMetricsMap;
  help: Record<string, string>;
  kind: Record<string, MetricKind>;
}

const SAMPLE_RE = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(.+?)(?:\s+\d+)?$/;

function unescapeLabelValue(raw: string): string {
  return raw.replace(/\\(["\\n])/g, (_m, ch) => (ch === "n" ? "\n" : ch));
}

function parseLabels(block: string | undefined): Record<string, string> {
  if (!block) return {};
  const inner = block.slice(1, -1).trim();
  if (!inner) return {};
  const labels: Record<string, string> = {};
  // Labels are `key="value"` pairs; values may contain commas, so match
  // explicitly rather than splitting on `,`.
  const re = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) {
    labels[m[1]] = unescapeLabelValue(m[2]);
  }
  return labels;
}

function parseValue(raw: string): number {
  const trimmed = raw.trim();
  if (trimmed === "+Inf") return Number.POSITIVE_INFINITY;
  if (trimmed === "-Inf") return Number.NEGATIVE_INFINITY;
  if (trimmed === "NaN") return Number.NaN;
  const v = Number(trimmed);
  return Number.isNaN(v) ? 0 : v;
}

export function parsePrometheusMetrics(text: string): ParsedMetrics {
  const byTag: PluginMetricsMap = {};
  const help: Record<string, string> = {};
  const kind: Record<string, MetricKind> = {};

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      const helpMatch = /^#\s+HELP\s+(\S+)\s+(.*)$/.exec(line);
      if (helpMatch) help[helpMatch[1]] = helpMatch[2];
      const typeMatch = /^#\s+TYPE\s+(\S+)\s+(\S+)\s*$/.exec(line);
      if (typeMatch) kind[typeMatch[1]] = normalizeMetricKind(typeMatch[2]);
      continue;
    }
    const match = SAMPLE_RE.exec(line);
    if (!match) continue;
    const [, name, labelBlock, valueRaw] = match;
    const labels = parseLabels(labelBlock);
    const tag = labels["plugin_tag"];
    if (!tag) continue;
    const rest: Record<string, string> = {};
    for (const [k, v] of Object.entries(labels)) {
      if (k !== "plugin_tag") rest[k] = v;
    }
    (byTag[tag] ??= []).push({
      name,
      kind: kind[name],
      help: help[name],
      labels: rest,
      value: parseValue(valueRaw),
    });
  }

  return { byTag, help, kind };
}

function normalizeMetricKind(raw: string): MetricKind {
  switch (raw) {
    case "counter":
    case "gauge":
    case "histogram":
    case "summary":
      return raw;
    default:
      return "untyped";
  }
}

// ---------------------------------------------------------------------------
// Curation: friendly labels + which metrics are worth surfacing on cards.
// ---------------------------------------------------------------------------

/** Friendly Chinese labels keyed by raw metric name. */
const METRIC_LABELS: Record<string, string> = {
  // global query (query_recorder / metrics_collector)
  query_total: "总查询",
  query_error_total: "查询错误",
  query_inflight: "处理中",
  query_latency_count: "延迟样本",
  query_latency_sum_ms: "延迟累计(ms)",
  // cache
  cache_lookup_total: "缓存查询",
  cache_hit_total: "命中",
  cache_miss_total: "未命中",
  cache_expired_total: "过期",
  cache_insert_total: "写入",
  cache_skip_total: "跳过",
  cache_lazy_refresh_total: "懒刷新",
  cache_entry_count: "条目数",
  // forward
  forward_query_total: "转发查询",
  forward_success_total: "成功",
  forward_error_total: "失败",
  forward_timeout_total: "超时",
  forward_latency_count: "延迟样本",
  forward_latency_sum_ms: "延迟累计(ms)",
  forward_upstream_query_total: "上游查询",
  forward_upstream_success_total: "上游成功",
  forward_upstream_error_total: "上游失败",
  forward_upstream_timeout_total: "上游超时",
  forward_upstream_latency_count: "上游延迟样本",
  forward_upstream_latency_sum_ms: "上游延迟累计(ms)",
  // fallback
  fallback_primary_total: "主链",
  fallback_primary_error_total: "主链失败",
  fallback_secondary_total: "降级",
  // misc executors
  blackhole_block_total: "拦截",
  hosts_hit_total: "命中",
  hosts_miss_total: "未命中",
  ratelimit_allowed_total: "放行",
  ratelimit_rejected_total: "限流拒绝",
  // server
  server_request_total: "请求总数",
  server_completed_total: "完成",
  server_controlled_total: "提前结束",
  server_failed_total: "失败(SERVFAIL)",
  server_inflight: "处理中",
  server_latency_count: "延迟样本",
  server_latency_sum_ms: "延迟累计(ms)",
  // ipset / nftset
  ipset_entries_total: "入队条目",
  ipset_dropped_total: "丢弃批次",
  ipset_write_total: "写入条目",
  ipset_write_error_total: "写入失败",
  nftset_entries_total: "入队前缀",
  nftset_dropped_total: "丢弃批次",
  nftset_write_total: "写入前缀",
  nftset_write_error_total: "写入失败",
  // ros_address_list
  ros_address_list_observe_total: "观测域名",
  ros_address_list_dropped_total: "异步丢弃",
  ros_address_list_sync_error_total: "同步失败",
  ros_address_list_sync_timeout_total: "同步超时",
  // reverse_lookup
  reverse_lookup_ptr_hit_total: "PTR 命中",
  reverse_lookup_ptr_miss_total: "PTR 未命中",
  reverse_lookup_cache_insert_total: "缓存写入",
  reverse_lookup_cache_entries: "缓存条目",
  // download
  download_success_total: "下载成功",
  download_failure_total: "下载失败",
  download_timeout_total: "下载超时",
  // http_request
  http_request_dispatch_total: "请求发起",
  http_request_error_total: "请求失败",
  http_request_dropped_total: "队列丢弃",
  // script
  script_run_total: "执行",
  script_success_total: "成功",
  script_error_total: "失败",
  script_timeout_total: "超时",
  // reload / reload_provider
  reload_trigger_total: "重载触发",
  reload_error_total: "重载失败",
  reload_provider_reload_total: "数据源重载",
  reload_provider_reload_error_total: "重载失败",
  // cron
  cron_job_run_total: "任务运行",
  cron_job_skipped_total: "重叠跳过",
  cron_executor_error_total: "执行器失败",
};

/** Metrics prominent enough to surface directly on a plugin card. */
const HIGH_VALUE_METRICS = new Set<string>([
  "query_total",
  "query_inflight",
  "query_error_total",
  "cache_lookup_total",
  "cache_hit_total",
  "cache_miss_total",
  "cache_expired_total",
  "cache_entry_count",
  "forward_query_total",
  "forward_success_total",
  "forward_error_total",
  "forward_timeout_total",
  "fallback_secondary_total",
  "fallback_primary_error_total",
  "blackhole_block_total",
  "hosts_hit_total",
  "hosts_miss_total",
  "ratelimit_allowed_total",
  "ratelimit_rejected_total",
  "server_request_total",
  "server_failed_total",
  "server_inflight",
  "ipset_write_total",
  "ipset_write_error_total",
  "nftset_write_total",
  "nftset_write_error_total",
  "ros_address_list_observe_total",
  "ros_address_list_sync_error_total",
  "reverse_lookup_ptr_hit_total",
  "reverse_lookup_cache_entries",
  "download_success_total",
  "download_failure_total",
  "http_request_dispatch_total",
  "http_request_error_total",
  "script_run_total",
  "script_error_total",
  "reload_trigger_total",
  "reload_provider_reload_total",
  "cron_job_run_total",
  "cron_executor_error_total",
]);

const HIGH_VALUE_ORDER = Array.from(HIGH_VALUE_METRICS);

const SERVER_PLUGIN_KINDS = new Set([
  "udp_server",
  "tcp_server",
  "http_server",
  "quic_server",
]);

const CARD_METRIC_PRIORITY: Record<string, string[]> = {
  metrics_collector: ["query_total", "query_error_total", "query_inflight"],
  cache: [
    "cache_entry_count",
    "cache_lookup_total",
    "cache_miss_total",
    "cache_expired_total",
  ],
  forward: [
    "forward_query_total",
    "forward_timeout_total",
    "forward_error_total",
  ],
  fallback: [
    "fallback_secondary_total",
    "fallback_primary_error_total",
    "fallback_primary_total",
  ],
  black_hole: ["blackhole_block_total"],
  hosts: ["hosts_hit_total", "hosts_miss_total"],
  rate_limiter: ["ratelimit_rejected_total", "ratelimit_allowed_total"],
  ipset: ["ipset_write_total", "ipset_write_error_total"],
  nftset: ["nftset_write_total", "nftset_write_error_total"],
  ros_address_list: [
    "ros_address_list_observe_total",
    "ros_address_list_sync_error_total",
  ],
  reverse_lookup: [
    "reverse_lookup_cache_entries",
    "reverse_lookup_ptr_hit_total",
    "reverse_lookup_ptr_miss_total",
  ],
  download: [
    "download_success_total",
    "download_failure_total",
    "download_timeout_total",
  ],
  http_request: [
    "http_request_dispatch_total",
    "http_request_error_total",
    "http_request_dropped_total",
  ],
  script: ["script_run_total", "script_error_total", "script_timeout_total"],
  reload: ["reload_trigger_total", "reload_error_total"],
  reload_provider: [
    "reload_provider_reload_total",
    "reload_provider_reload_error_total",
  ],
  cron: [
    "cron_job_run_total",
    "cron_job_skipped_total",
    "cron_executor_error_total",
  ],
};

export function metricLabel(name: string): string {
  if (METRIC_LABELS[name]) return METRIC_LABELS[name];
  return name
    .replace(/_total$/, "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

const intFormatter = new Intl.NumberFormat("en-US");

export function formatMetricValue(value: number): string {
  if (!Number.isFinite(value)) return String(value);
  if (Number.isInteger(value)) return intFormatter.format(value);
  return value.toFixed(2);
}

export interface DisplayMetric {
  label: string;
  value: string;
}

function sumByName(series: MetricSeries[]): Map<string, number> {
  const totals = new Map<string, number>();
  for (const s of series) {
    totals.set(s.name, (totals.get(s.name) ?? 0) + s.value);
  }
  return totals;
}

function metricValue(
  totals: Map<string, number>,
  name: string,
): number | undefined {
  return totals.get(name);
}

function metricRatio(
  totals: Map<string, number>,
  numerator: string,
  denominator: string,
): number | undefined {
  const top = totals.get(numerator);
  const bottom = totals.get(denominator);
  if (top === undefined || !bottom || bottom <= 0) return undefined;
  return top / bottom;
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(value >= 0.995 || value < 0.1 ? 1 : 0)}%`;
}

function pushDisplayMetric(
  out: DisplayMetric[],
  seen: Set<string>,
  label: string,
  value: string,
  limit: number,
) {
  if (out.length >= limit || seen.has(label)) return;
  seen.add(label);
  out.push({ label, value });
}

function pushRawMetric(
  out: DisplayMetric[],
  seen: Set<string>,
  totals: Map<string, number>,
  name: string,
  limit: number,
) {
  const value = metricValue(totals, name);
  if (value === undefined) return;
  pushDisplayMetric(
    out,
    seen,
    metricLabel(name),
    formatMetricValue(value),
    limit,
  );
}

function averageLatencyForPrefix(
  totals: Map<string, number>,
  prefix: string,
): number | undefined {
  const sum = totals.get(`${prefix}_latency_sum_ms`);
  const count = totals.get(`${prefix}_latency_count`);
  if (sum === undefined || !count || count <= 0) return undefined;
  return sum / count;
}

/** Derive `平均延迟` for any `<x>_latency_sum_ms` / `<x>_latency_count` pair. */
function derivedLatency(totals: Map<string, number>): DisplayMetric[] {
  const out: DisplayMetric[] = [];
  for (const [name, sum] of totals) {
    const m = /^(.*)_latency_sum_ms$/.exec(name);
    if (!m) continue;
    const count = totals.get(`${m[1]}_latency_count`);
    if (!count || count <= 0) continue;
    out.push({
      label: "平均延迟",
      value: `${(sum / count).toFixed(1)} ms`,
    });
  }
  return out;
}

function pushDerivedCardMetrics(
  out: DisplayMetric[],
  seen: Set<string>,
  totals: Map<string, number>,
  pluginKind: string | undefined,
  limit: number,
) {
  if (!pluginKind) return;

  if (SERVER_PLUGIN_KINDS.has(pluginKind)) {
    const failedRate = metricRatio(
      totals,
      "server_failed_total",
      "server_request_total",
    );
    const latency = averageLatencyForPrefix(totals, "server");
    if (latency !== undefined) {
      pushDisplayMetric(
        out,
        seen,
        "平均延迟",
        `${latency.toFixed(1)} ms`,
        limit,
      );
    }
    if (failedRate !== undefined) {
      pushDisplayMetric(out, seen, "失败率", formatPercent(failedRate), limit);
    }
    return;
  }

  switch (pluginKind) {
    case "metrics_collector": {
      const latency = averageLatencyForPrefix(totals, "query");
      const errorRate = metricRatio(totals, "query_error_total", "query_total");
      if (latency !== undefined) {
        pushDisplayMetric(
          out,
          seen,
          "平均延迟",
          `${latency.toFixed(1)} ms`,
          limit,
        );
      }
      if (errorRate !== undefined) {
        pushDisplayMetric(out, seen, "错误率", formatPercent(errorRate), limit);
      }
      break;
    }
    case "cache": {
      const lookup = totals.get("cache_lookup_total");
      const hit = totals.get("cache_hit_total");
      if (hit !== undefined && lookup && lookup > 0) {
        pushDisplayMetric(
          out,
          seen,
          "命中率",
          formatPercent(hit / lookup),
          limit,
        );
      }
      break;
    }
    case "forward": {
      const successRate = metricRatio(
        totals,
        "forward_success_total",
        "forward_query_total",
      );
      const latency = averageLatencyForPrefix(totals, "forward");
      if (successRate !== undefined) {
        pushDisplayMetric(
          out,
          seen,
          "成功率",
          formatPercent(successRate),
          limit,
        );
      }
      if (latency !== undefined) {
        pushDisplayMetric(
          out,
          seen,
          "平均延迟",
          `${latency.toFixed(1)} ms`,
          limit,
        );
      }
      break;
    }
    case "hosts": {
      const hit = totals.get("hosts_hit_total");
      const miss = totals.get("hosts_miss_total");
      const total = (hit ?? 0) + (miss ?? 0);
      if (hit !== undefined && total > 0) {
        pushDisplayMetric(
          out,
          seen,
          "命中率",
          formatPercent(hit / total),
          limit,
        );
      }
      break;
    }
    case "rate_limiter": {
      const allowed = totals.get("ratelimit_allowed_total");
      const rejected = totals.get("ratelimit_rejected_total");
      const total = (allowed ?? 0) + (rejected ?? 0);
      if (rejected !== undefined && total > 0) {
        pushDisplayMetric(
          out,
          seen,
          "拒绝率",
          formatPercent(rejected / total),
          limit,
        );
      }
      break;
    }
    case "fallback": {
      const fallbackRate = metricRatio(
        totals,
        "fallback_secondary_total",
        "fallback_primary_total",
      );
      if (fallbackRate !== undefined) {
        pushDisplayMetric(
          out,
          seen,
          "降级率",
          formatPercent(fallbackRate),
          limit,
        );
      }
      break;
    }
  }
}

function cardMetricPriority(pluginKind: string | undefined): string[] {
  if (pluginKind && SERVER_PLUGIN_KINDS.has(pluginKind)) {
    return ["server_request_total", "server_inflight", "server_failed_total"];
  }
  if (pluginKind && CARD_METRIC_PRIORITY[pluginKind]) {
    return CARD_METRIC_PRIORITY[pluginKind];
  }
  return HIGH_VALUE_ORDER;
}

/** Up to `limit` high-value metrics for compact card display. */
export function selectCardMetrics(
  series: MetricSeries[] | undefined,
  pluginKind?: string,
  limit = 4,
): DisplayMetric[] {
  if (!series || series.length === 0) return [];
  const totals = sumByName(series);
  const result: DisplayMetric[] = [];
  const seen = new Set<string>();

  pushDerivedCardMetrics(result, seen, totals, pluginKind, limit);

  for (const name of cardMetricPriority(pluginKind)) {
    pushRawMetric(result, seen, totals, name, limit);
    if (result.length >= limit) break;
  }

  if (result.length < limit) {
    for (const dm of derivedLatency(totals)) {
      pushDisplayMetric(result, seen, dm.label, dm.value, limit);
      if (result.length >= limit) break;
    }
  }

  return result.slice(0, limit);
}

const LABEL_LABELS: Record<string, string> = {
  name: "名称",
  kind: "类型",
  reason: "原因",
  result: "结果",
  upstream_index: "上游",
};

const LABEL_VALUE_LABELS: Record<string, Record<string, string>> = {
  kind: {
    fresh: "新鲜",
    stale: "过期可用",
  },
  reason: {
    truncated: "截断响应",
    no_ttl: "无 TTL",
  },
  result: {
    started: "已启动",
    success: "成功",
    failed: "失败",
  },
};

function describeLabels(labels: Record<string, string>): string {
  const entries = Object.entries(labels);
  if (entries.length === 0) return "";
  return entries
    .map(([k, v]) => {
      const key = LABEL_LABELS[k] ?? k;
      const value = LABEL_VALUE_LABELS[k]?.[v] ?? v;
      return `${key}=${value}`;
    })
    .join(", ");
}

export interface MetricRow {
  name: string;
  kind?: MetricKind;
  help?: string;
  label: string;
  highValue: boolean;
  /** Single total when one series, or a labelled breakdown when many. */
  total: number;
  breakdown: { key: string; value: number }[];
}

/** Group a plugin's series by metric name for the full detail view. */
export function groupMetricRows(series: MetricSeries[]): MetricRow[] {
  const byName = new Map<string, MetricSeries[]>();
  for (const s of series) {
    const bucket = byName.get(s.name);
    if (bucket) {
      bucket.push(s);
    } else {
      byName.set(s.name, [s]);
    }
  }

  const rows: MetricRow[] = [];
  for (const [name, list] of byName) {
    const total = list.reduce((acc, s) => acc + s.value, 0);
    const hasDimensions = list.some((s) => Object.keys(s.labels).length > 0);
    const showBreakdown = list.length > 1 || hasDimensions;
    rows.push({
      name,
      kind: list[0]?.kind,
      help: list[0]?.help,
      label: metricLabel(name),
      highValue: HIGH_VALUE_METRICS.has(name),
      total,
      breakdown: showBreakdown
        ? list.map((s, index) => ({
            key:
              describeLabels(s.labels) ||
              (list.length > 1 ? `series ${index + 1}` : "(默认)"),
            value: s.value,
          }))
        : [],
    });
  }

  const orderIndex = (n: string) => {
    const i = HIGH_VALUE_ORDER.indexOf(n);
    return i === -1 ? Number.MAX_SAFE_INTEGER : i;
  };
  rows.sort((a, b) => {
    if (a.highValue !== b.highValue) return a.highValue ? -1 : 1;
    const oa = orderIndex(a.name);
    const ob = orderIndex(b.name);
    if (oa !== ob) return oa - ob;
    return a.name.localeCompare(b.name);
  });
  return rows;
}
