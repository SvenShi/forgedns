"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { BarChart3, Filter, Radio, RefreshCw, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { DateTimePicker } from "@/components/ui/datetime-picker";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  apiHeaders,
  apiUrl,
  fetchQueryRecordDetail,
  fetchQueryRecords,
  fetchQueryRecorderPluginStats,
  type QueryRecordDetail,
  type QueryRecordFilters,
  type QueryRecordRow,
  type QueryRecordStatusFilter,
  type QueryRecorderPluginStatsRow,
} from "@/lib/oxidns-api";
import { useAppStore } from "@/lib/store";
import type {
  PluginComponentDefinition,
  PluginDetailComponentProps,
} from "../types";
import { PluginDetailTemplate } from "../plugin-detail-template";
import { DnsRecordDetailDialog } from "../dns-record-detail-dialog";
import { QueryRecordFlowCanvas } from "../query-record-flow";

function QueryRecorderDetail(props: PluginDetailComponentProps) {
  return (
    <PluginDetailTemplate
      {...props}
      icon={<Radio className="h-5 w-5" />}
      summaryItems={[
        { label: "SQLite", value: String(props.plugin.config.path ?? "-") },
        {
          label: "内存 Tail",
          value: String(props.plugin.config.memory_tail ?? "默认"),
        },
        {
          label: "保留",
          value: `${String(props.plugin.config.retention_days ?? "默认")}天`,
        },
      ]}
      metricsContent={<QueryRecordsPanel tag={props.plugin.name} />}
    />
  );
}

type QueryRecordFilterForm = {
  qname: string;
  qtype: string;
  clientIp: string;
  rcode: string;
  status: QueryRecordStatusFilter;
  sinceLocal: string;
  untilLocal: string;
};

const EMPTY_FILTER_FORM: QueryRecordFilterForm = {
  qname: "",
  qtype: "all",
  clientIp: "",
  rcode: "all",
  status: "all",
  sinceLocal: "",
  untilLocal: "",
};

const QTYPE_OPTIONS = [
  "A",
  "AAAA",
  "HTTPS",
  "CNAME",
  "TXT",
  "MX",
  "NS",
  "SOA",
  "SRV",
  "PTR",
  "SVCB",
  "CAA",
  "DNSKEY",
  "DS",
];

const RCODE_OPTIONS = [
  "No Error",
  "Non-Existent Domain",
  "Server Failure",
  "Query Refused",
  "Format Error",
  "Not Implemented",
];

function QueryRecordsPanel({ tag }: { tag: string }) {
  const [records, setRecords] = useState<QueryRecordRow[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [matcherStats, setMatcherStats] = useState<
    QueryRecorderPluginStatsRow[]
  >([]);
  const [statsQueryTotal, setStatsQueryTotal] = useState(0);
  const [selected, setSelected] = useState<QueryRecordDetail | null>(null);
  const [filterForm, setFilterForm] = useState<QueryRecordFilterForm>({
    ...EMPTY_FILTER_FORM,
  });
  const [appliedFilters, setAppliedFilters] = useState<QueryRecordFilters>({});
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const filtersRef = useRef<QueryRecordFilters>({});

  useEffect(() => {
    filtersRef.current = appliedFilters;
  }, [appliedFilters]);

  const loadRecords = useCallback(
    async (filters: QueryRecordFilters, cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchQueryRecords(tag, {
          limit: 100,
          cursor,
          ...filters,
        });
        setRecords((current) =>
          cursor ? [...current, ...response.records] : response.records,
        );
        setNextCursor(response.next_cursor);
      } catch (err) {
        setError(err instanceof Error ? err.message : "读取查询记录失败");
      } finally {
        setLoading(false);
      }
    },
    [tag],
  );

  const loadMatcherStats = useCallback(
    async (filters: QueryRecordFilters) => {
      setStatsLoading(true);
      setStatsError(null);
      try {
        const response = await fetchQueryRecorderPluginStats(tag, {
          kind: "matcher",
          ...filters,
        });
        setMatcherStats(response.stats.filter((row) => row.kind === "matcher"));
        setStatsQueryTotal(response.query_total);
      } catch (err) {
        setStatsError(
          err instanceof Error ? err.message : "读取 matcher 命中率失败",
        );
      } finally {
        setStatsLoading(false);
      }
    },
    [tag],
  );

  const refresh = useCallback(
    async (filters: QueryRecordFilters = appliedFilters) => {
      await Promise.all([loadRecords(filters), loadMatcherStats(filters)]);
    },
    [appliedFilters, loadMatcherStats, loadRecords],
  );

  useEffect(() => {
    const initialFilters = filtersRef.current;
    const timer = window.setTimeout(() => {
      void Promise.all([
        loadRecords(initialFilters),
        loadMatcherStats(initialFilters),
      ]);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      abortRef.current?.abort();
    };
  }, [loadMatcherStats, loadRecords]);

  const applyFilters = () => {
    const nextFilters = filtersFromForm(filterForm);
    setAppliedFilters(nextFilters);
    void refresh(nextFilters);
  };

  const clearFilters = () => {
    setFilterForm({ ...EMPTY_FILTER_FORM });
    setAppliedFilters({});
    void refresh({});
  };

  const openDetail = async (record: QueryRecordRow) => {
    setError(null);
    try {
      const detail = await fetchQueryRecordDetail(tag, record.id);
      setSelected(detail.record);
    } catch (err) {
      setError(err instanceof Error ? err.message : "读取记录详情失败");
    }
  };

  const toggleStream = async () => {
    if (streaming) {
      abortRef.current?.abort();
      abortRef.current = null;
      setStreaming(false);
      return;
    }

    const controller = new AbortController();
    abortRef.current = controller;
    setStreaming(true);
    setError(null);
    try {
      const response = await fetch(
        apiUrl(`/plugins/${encodeURIComponent(tag)}/stream?tail=20`),
        { headers: apiHeaders(), signal: controller.signal },
      );
      if (!response.ok || !response.body) {
        throw new Error(`流式连接失败：HTTP ${response.status}`);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!controller.signal.aborted) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() ?? "";
        for (const chunk of chunks) {
          const data = chunk
            .split("\n")
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).trimStart())
            .join("\n");
          if (!data) continue;
          const record = JSON.parse(data) as QueryRecordDetail;
          if (!recordMatchesFilters(record, filtersRef.current)) continue;
          setRecords((current) =>
            [record, ...current.filter((item) => item.id !== record.id)].slice(
              0,
              200,
            ),
          );
        }
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        setError(err instanceof Error ? err.message : "流式连接失败");
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setStreaming(false);
      }
    }
  };

  const activeFilterCount = countActiveFilters(appliedFilters);

  return (
    <div className="space-y-4">
      <MatcherStatsCard
        stats={matcherStats}
        queryTotal={statsQueryTotal}
        loading={statsLoading}
        error={statsError}
        onRefresh={() => void loadMatcherStats(appliedFilters)}
      />
      <Card>
        <CardHeader className="grid gap-3 p-4 pb-2 sm:grid-cols-[1fr_auto] sm:items-center">
          <div className="min-w-0">
            <CardTitle className="text-sm">查询记录</CardTitle>
            <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
              <span className="rounded-full border bg-muted/30 px-2 py-0.5">
                已载入 {records.length} 条
              </span>
              {activeFilterCount > 0 && (
                <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary">
                  筛选 {activeFilterCount} 项
                </span>
              )}
              <span className="rounded-full border bg-muted/30 px-2 py-0.5">
                错误 {records.filter((record) => record.error).length} 条
              </span>
              {streaming && (
                <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary">
                  实时接收中
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={loading}
              onClick={() => void refresh(appliedFilters)}
            >
              <RefreshCw className="h-4 w-4" />
              刷新
            </Button>
            <Button
              variant={streaming ? "secondary" : "outline"}
              size="sm"
              onClick={() => void toggleStream()}
            >
              <Radio className="h-4 w-4" />
              {streaming ? "停止实时" : "实时"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-4 pt-0">
          <form
            className="mb-3 rounded-md border bg-muted/20 p-3"
            onSubmit={(event) => {
              event.preventDefault();
              applyFilters();
            }}
          >
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
              <FilterField label="QNAME 包含">
                <Input
                  value={filterForm.qname}
                  onChange={(event) =>
                    setFilterForm((current) => ({
                      ...current,
                      qname: event.target.value,
                    }))
                  }
                  placeholder="example.com"
                  className="h-8 font-mono"
                />
              </FilterField>
              <FilterField label="QTYPE">
                <Select
                  value={filterForm.qtype}
                  onValueChange={(qtype) =>
                    setFilterForm((current) => ({ ...current, qtype }))
                  }
                >
                  <SelectTrigger className="h-8 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部</SelectItem>
                    {QTYPE_OPTIONS.map((qtype) => (
                      <SelectItem key={qtype} value={qtype}>
                        {qtype}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FilterField>
              <FilterField label="客户端 IP 包含">
                <Input
                  value={filterForm.clientIp}
                  onChange={(event) =>
                    setFilterForm((current) => ({
                      ...current,
                      clientIp: event.target.value,
                    }))
                  }
                  placeholder="192.168 或 ::1"
                  className="h-8 font-mono"
                />
              </FilterField>
              <FilterField label="RCODE">
                <Select
                  value={filterForm.rcode}
                  onValueChange={(rcode) =>
                    setFilterForm((current) => ({ ...current, rcode }))
                  }
                >
                  <SelectTrigger className="h-8 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部</SelectItem>
                    {RCODE_OPTIONS.map((rcode) => (
                      <SelectItem key={rcode} value={rcode}>
                        {rcode}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FilterField>
              <FilterField label="状态">
                <Select
                  value={filterForm.status}
                  onValueChange={(status) =>
                    setFilterForm((current) => ({
                      ...current,
                      status: status as QueryRecordStatusFilter,
                    }))
                  }
                >
                  <SelectTrigger className="h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部</SelectItem>
                    <SelectItem value="error">错误</SelectItem>
                    <SelectItem value="has_response">有响应</SelectItem>
                    <SelectItem value="no_response">无响应</SelectItem>
                  </SelectContent>
                </Select>
              </FilterField>
              <FilterField label="开始">
                <DateTimePicker
                  value={filterForm.sinceLocal}
                  onChange={(sinceLocal) =>
                    setFilterForm((current) => ({
                      ...current,
                      sinceLocal,
                    }))
                  }
                  placeholder="开始时间"
                />
              </FilterField>
              <FilterField label="结束">
                <DateTimePicker
                  value={filterForm.untilLocal}
                  onChange={(untilLocal) =>
                    setFilterForm((current) => ({
                      ...current,
                      untilLocal,
                    }))
                  }
                  placeholder="结束时间"
                />
              </FilterField>
              <div className="flex items-end gap-2">
                <Button type="submit" size="sm" className="h-8">
                  <Filter className="h-4 w-4" />
                  应用
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8"
                  onClick={clearFilters}
                >
                  <X className="h-4 w-4" />
                  清空
                </Button>
              </div>
            </div>
          </form>
          {error && (
            <div className="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <div className="overflow-hidden rounded-md border">
            <Table className="min-w-[760px]">
              <TableHeader>
                <TableRow className="bg-muted/30 hover:bg-muted/30">
                  <TableHead>查询</TableHead>
                  <TableHead>客户端</TableHead>
                  <TableHead>时间</TableHead>
                  <TableHead>结果</TableHead>
                  <TableHead>耗时</TableHead>
                  <TableHead>记录数</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {records.map((record) => (
                  <TableRow
                    key={record.id}
                    className="cursor-pointer"
                    onClick={() => openDetail(record)}
                  >
                    <TableCell className="max-w-[22rem]">
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          className="truncate font-mono"
                          title={formatQuestion(record)}
                        >
                          {formatQuestion(record)}
                        </span>
                        {record.has_response && (
                          <Badge variant="outline" className="font-mono">
                            resp
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {record.client_ip}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatTime(record.created_at_ms)}
                    </TableCell>
                    <TableCell>{queryStatusBadge(record)}</TableCell>
                    <TableCell className="font-mono">
                      {record.elapsed_ms}ms
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1 font-mono text-xs">
                        <span>{record.answer_count}</span>
                        <span className="text-muted-foreground">
                          / {record.authority_count} / {record.additional_count}
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {!records.length && (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="h-24 text-center text-muted-foreground"
                    >
                      {loading ? "正在读取查询记录..." : "暂无查询记录"}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
          {nextCursor && (
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              disabled={loading}
              onClick={() => void loadRecords(appliedFilters, nextCursor)}
            >
              加载更多
            </Button>
          )}
        </CardContent>
        <RecordDetailDialog
          record={selected}
          onClose={() => setSelected(null)}
        />
      </Card>
    </div>
  );
}

function MatcherStatsCard({
  stats,
  queryTotal,
  loading,
  error,
  onRefresh,
}: {
  stats: QueryRecorderPluginStatsRow[];
  queryTotal: number;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}) {
  return (
    <Card>
      <CardHeader className="grid gap-3 p-4 pb-2 sm:grid-cols-[1fr_auto] sm:items-center">
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2 text-sm">
            <BarChart3 className="h-4 w-4 text-primary" />
            Matcher 命中率
          </CardTitle>
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span className="rounded-full border bg-muted/30 px-2 py-0.5">
              样本 {queryTotal} 条
            </span>
            <span className="rounded-full border bg-muted/30 px-2 py-0.5">
              Matcher {stats.length} 个
            </span>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={loading}
          onClick={onRefresh}
        >
          <RefreshCw className="h-4 w-4" />
          刷新
        </Button>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {error && (
          <div className="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
        <div className="overflow-hidden rounded-md border">
          <Table className="min-w-[680px]">
            <TableHeader>
              <TableRow className="bg-muted/30 hover:bg-muted/30">
                <TableHead>Matcher</TableHead>
                <TableHead>检查次数</TableHead>
                <TableHead>命中</TableHead>
                <TableHead>命中率</TableHead>
                <TableHead>查询占比</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {stats.map((row) => (
                <TableRow key={row.tag ?? "(unknown)"}>
                  <TableCell className="font-mono">
                    {row.tag ?? "(unknown)"}
                  </TableCell>
                  <TableCell className="font-mono">{row.checked}</TableCell>
                  <TableCell className="font-mono">{row.matched}</TableCell>
                  <TableCell className="font-mono">
                    {formatPercent(safeRatio(row.matched, row.checked))}
                  </TableCell>
                  <TableCell className="font-mono">
                    {formatPercent(row.query_share)}
                  </TableCell>
                </TableRow>
              ))}
              {!stats.length && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="h-20 text-center text-muted-foreground"
                  >
                    {loading ? "正在读取命中率..." : "暂无 matcher 统计"}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

function FilterField({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      {children}
    </div>
  );
}

function RecordDetailDialog({
  record,
  onClose,
}: {
  record: QueryRecordDetail | null;
  onClose: () => void;
}) {
  const dependencyGraph = useAppStore((state) => state.dependencyGraph);
  const plugins = useAppStore((state) => state.plugins);

  return (
    <DnsRecordDetailDialog
      open={Boolean(record)}
      onOpenChange={(open) => !open && onClose()}
      title={`查询详情 #${record?.id ?? ""}`}
      subtitle={record ? formatFullTime(record.created_at_ms) : undefined}
      status={record ? queryStatusBadge(record) : undefined}
      summaryItems={
        record
          ? [
              { label: "客户端", value: record.client_ip, mono: true },
              {
                label: "请求 ID",
                value: String(record.request_id),
                mono: true,
              },
              { label: "耗时", value: `${record.elapsed_ms}ms`, mono: true },
              { label: "RCODE", value: record.rcode ?? "-", mono: true },
              {
                label: "响应记录",
                value: `${record.answer_count} / ${record.authority_count} / ${record.additional_count}`,
                title: "answer / authority / additional",
                mono: true,
              },
              {
                label: "请求标志",
                value: `RD=${flag(record.req_rd)} CD=${flag(record.req_cd)} AD=${flag(record.req_ad)}`,
                mono: true,
                wide: true,
              },
              {
                label: "响应标志",
                value: record.has_response
                  ? `AA=${flag(record.resp_aa)} TC=${flag(record.resp_tc)} RA=${flag(record.resp_ra)} AD=${flag(record.resp_ad)} CD=${flag(record.resp_cd)}`
                  : "-",
                mono: true,
                wide: true,
              },
            ]
          : []
      }
      questions={record?.questions_json}
      sections={
        record
          ? [
              {
                title: "应答记录",
                records: record.answers_json,
                emptyLabel: "无 answer",
              },
              {
                title: "权威记录",
                records: record.authorities_json,
                emptyLabel: "无 authority",
              },
              {
                title: "附加记录",
                records: record.additionals_json,
                emptyLabel: "无 additional",
              },
              {
                title: "签名记录",
                records: record.signature_json,
                emptyLabel: "无 signature",
              },
            ]
          : []
      }
      error={record?.error ?? null}
      bottomBlocks={
        record
          ? [
              {
                title: "执行流程",
                children: (
                  <QueryRecordFlowCanvas
                    record={record}
                    dependencyGraph={dependencyGraph}
                    plugins={plugins}
                  />
                ),
              },
            ]
          : []
      }
      wide
    />
  );
}

function queryStatusBadge(record: QueryRecordRow | QueryRecordDetail) {
  if (record.error) {
    return <Badge variant="destructive">ERR</Badge>;
  }
  if (record.rcode?.toLowerCase() === "no error") {
    return <Badge variant="secondary">No Error</Badge>;
  }
  return <Badge variant="outline">{record.rcode ?? "-"}</Badge>;
}

function filtersFromForm(form: QueryRecordFilterForm): QueryRecordFilters {
  return {
    qname: optionalTrimmed(form.qname),
    qtype: form.qtype === "all" ? undefined : form.qtype,
    clientIp: optionalTrimmed(form.clientIp),
    rcode: form.rcode === "all" ? undefined : form.rcode,
    status: form.status === "all" ? undefined : form.status,
    sinceMs: parseLocalDateTime(form.sinceLocal),
    untilMs: parseLocalDateTime(form.untilLocal),
  };
}

function optionalTrimmed(value: string) {
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function parseLocalDateTime(value: string) {
  if (!value) return undefined;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : undefined;
}

function recordMatchesFilters(
  record: QueryRecordRow | QueryRecordDetail,
  filters: QueryRecordFilters,
) {
  if (filters.sinceMs !== undefined && record.created_at_ms < filters.sinceMs) {
    return false;
  }
  if (filters.untilMs !== undefined && record.created_at_ms > filters.untilMs) {
    return false;
  }
  if (filters.qname) {
    const needle = filters.qname.toLowerCase();
    if (
      !record.questions_json.some((question) =>
        question.name.toLowerCase().includes(needle),
      )
    ) {
      return false;
    }
  }
  if (filters.qtype) {
    const qtype = filters.qtype.toLowerCase();
    if (
      !record.questions_json.some(
        (question) => question.qtype.toLowerCase() === qtype,
      )
    ) {
      return false;
    }
  }
  if (
    filters.clientIp &&
    !record.client_ip.toLowerCase().includes(filters.clientIp.toLowerCase())
  ) {
    return false;
  }
  if (
    filters.rcode &&
    (record.rcode ?? "").toLowerCase() !== filters.rcode.toLowerCase()
  ) {
    return false;
  }
  if (filters.status === "error" && !record.error) return false;
  if (filters.status === "has_response" && !record.has_response) return false;
  if (
    filters.status === "no_response" &&
    (record.error || record.has_response)
  ) {
    return false;
  }
  return true;
}

function countActiveFilters(filters: QueryRecordFilters) {
  return [
    filters.qname,
    filters.qtype,
    filters.clientIp,
    filters.rcode,
    filters.status,
    filters.sinceMs,
    filters.untilMs,
  ].filter((value) => value !== undefined && value !== "").length;
}

function safeRatio(numerator: number, denominator: number) {
  if (denominator <= 0) return 0;
  return numerator / denominator;
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

function flag(value: unknown) {
  if (typeof value !== "boolean") return "-";
  return value ? "1" : "0";
}

function formatTime(ms: number) {
  return new Date(ms).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatFullTime(ms: number) {
  return new Date(ms).toLocaleString();
}

function formatQuestion(record: QueryRecordRow) {
  const first = record.questions_json[0];
  if (!first) return "-";
  return `${first.name} ${first.qtype}`;
}

export const queryRecorderPlugin: PluginComponentDefinition = {
  Detail: QueryRecorderDetail,
};
