"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Radio, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  type QueryRecordDetail,
  type QueryRecordRow,
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
          label: "Tail",
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

function QueryRecordsPanel({ tag }: { tag: string }) {
  const [records, setRecords] = useState<QueryRecordRow[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [selected, setSelected] = useState<QueryRecordDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchQueryRecords(tag, { limit: 100, cursor });
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

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => {
      window.clearTimeout(timer);
      abortRef.current?.abort();
    };
  }, [load]);

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

  return (
    <Card>
      <CardHeader className="grid gap-3 p-4 pb-2 sm:grid-cols-[1fr_auto] sm:items-center">
        <div className="min-w-0">
          <CardTitle className="text-sm">查询记录</CardTitle>
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span className="rounded-full border bg-muted/30 px-2 py-0.5">
              已载入 {records.length} 条
            </span>
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
            onClick={() => load()}
          >
            <RefreshCw className="h-4 w-4" />
            刷新
          </Button>
          <Button
            variant={streaming ? "secondary" : "outline"}
            size="sm"
            onClick={toggleStream}
          >
            <Radio className="h-4 w-4" />
            {streaming ? "停止实时" : "实时"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {error && (
          <div className="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
        <div className="overflow-hidden rounded-md border">
          <Table className="min-w-[760px]">
            <TableHeader>
              <TableRow className="bg-muted/30 hover:bg-muted/30">
                <TableHead>Query</TableHead>
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
            onClick={() => load(nextCursor)}
          >
            加载更多
          </Button>
        )}
      </CardContent>
      <RecordDetailDialog record={selected} onClose={() => setSelected(null)} />
    </Card>
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
              { label: "Client", value: record.client_ip, mono: true },
              {
                label: "Request ID",
                value: String(record.request_id),
                mono: true,
              },
              { label: "Elapsed", value: `${record.elapsed_ms}ms`, mono: true },
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
                title: "Answers",
                records: record.answers_json,
                emptyLabel: "无 answer",
              },
              {
                title: "Authorities",
                records: record.authorities_json,
                emptyLabel: "无 authority",
              },
              {
                title: "Additionals",
                records: record.additionals_json,
                emptyLabel: "无 additional",
              },
              {
                title: "Signatures",
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
  if (record.rcode === "NOERROR") {
    return <Badge variant="secondary">NOERROR</Badge>;
  }
  return <Badge variant="outline">{record.rcode ?? "-"}</Badge>;
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
