// Prometheus text-format parsing and plugin-level metric curation.
//
// The backend exposes a single Prometheus endpoint (`/metrics`). Every plugin
// series carries a `plugin_tag` label, so metrics are grouped by that tag and
// associated with the matching `PluginInstance` (whose `name` is the tag).
//
// Metric labels, card-priority lists, and derived metric specs are defined
// alongside each plugin kind in `lib/plugin-definitions/` — this file derives
// its runtime data structures from those definitions rather than duplicating them.

import { pluginKindDefinitions } from "./plugin-definitions";
import type { DerivedMetricSpec } from "./plugin-definitions/shared";

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
// Derived constants from plugin definitions.
// ---------------------------------------------------------------------------

/** Friendly Chinese labels keyed by raw metric name — merged from all plugin definitions. */
const METRIC_LABELS: Record<string, string> = Object.fromEntries(
  pluginKindDefinitions.flatMap((def) =>
    Object.entries(def.metrics?.metricLabels ?? {}),
  ),
);

/**
 * Global ordered list of high-value metric names, derived by concatenating each
 * plugin's `cardPriority` list in definition order (first occurrence wins).
 * Used for fallback ordering and sorting in the detail view.
 */
const HIGH_VALUE_ORDER: string[] = (() => {
  const seen = new Set<string>();
  const order: string[] = [];
  for (const def of pluginKindDefinitions) {
    for (const name of def.metrics?.cardPriority ?? []) {
      if (!seen.has(name)) {
        seen.add(name);
        order.push(name);
      }
    }
  }
  return order;
})();

/** Set of high-value metric names for O(1) lookup. */
const HIGH_VALUE_METRICS = new Set(HIGH_VALUE_ORDER);

// ---------------------------------------------------------------------------
// Curation: friendly labels + which metrics are worth surfacing on cards.
// ---------------------------------------------------------------------------

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

function applyDerivedSpec(
  spec: DerivedMetricSpec,
  totals: Map<string, number>,
  out: DisplayMetric[],
  seen: Set<string>,
  limit: number,
) {
  switch (spec.kind) {
    case "latency": {
      const latency = averageLatencyForPrefix(totals, spec.prefix);
      if (latency !== undefined) {
        pushDisplayMetric(out, seen, spec.label, `${latency.toFixed(1)} ms`, limit);
      }
      break;
    }
    case "percent": {
      const ratio = metricRatio(totals, spec.numerator, spec.denominator);
      if (ratio !== undefined) {
        pushDisplayMetric(out, seen, spec.label, formatPercent(ratio), limit);
      }
      break;
    }
    case "percent_of_sum": {
      const numerator = totals.get(spec.numerator);
      const total = spec.terms.reduce((acc, t) => acc + (totals.get(t) ?? 0), 0);
      if (numerator !== undefined && total > 0) {
        pushDisplayMetric(out, seen, spec.label, formatPercent(numerator / total), limit);
      }
      break;
    }
  }
}

function pushDerivedCardMetrics(
  out: DisplayMetric[],
  seen: Set<string>,
  totals: Map<string, number>,
  pluginKind: string | undefined,
  limit: number,
) {
  if (!pluginKind) return;
  const def = pluginKindDefinitions.find((d) => d.kind === pluginKind);
  for (const spec of def?.metrics?.derivedCard ?? []) {
    if (out.length >= limit) break;
    applyDerivedSpec(spec, totals, out, seen, limit);
  }
}

function cardMetricPriority(pluginKind: string | undefined): string[] {
  if (!pluginKind) return HIGH_VALUE_ORDER;
  const def = pluginKindDefinitions.find((d) => d.kind === pluginKind);
  return def?.metrics?.cardPriority ?? HIGH_VALUE_ORDER;
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
