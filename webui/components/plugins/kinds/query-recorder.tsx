"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Radio, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import type {
  PluginComponentDefinition,
  PluginDetailComponentProps,
} from "../types";
import { PluginDetailTemplate } from "../plugin-detail-template";

function QueryRecorderDetail(props: PluginDetailComponentProps) {
  return (
    <PluginDetailTemplate
      {...props}
      icon={<Radio className="h-5 w-5" />}
      summaryItems={[
        { label: "SQLite", value: String(props.plugin.config.path ?? "-") },
        { label: "Tail", value: String(props.plugin.config.memory_tail ?? "默认") },
        { label: "保留", value: `${String(props.plugin.config.retention_days ?? "默认")}天` },
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

  const load = useCallback(async (cursor?: string) => {
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
  }, [tag]);

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
          setRecords((current) => [record, ...current.filter((item) => item.id !== record.id)].slice(0, 200));
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
      <CardHeader className="grid grid-cols-[1fr_auto] items-center p-4 pb-2">
        <div>
          <CardTitle className="text-sm">查询记录</CardTitle>
          <div className="mt-1 text-xs text-muted-foreground">
            列表与详情来自 query_recorder 插件 API
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => load()}>
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
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>客户端</TableHead>
                <TableHead>Query</TableHead>
                <TableHead>RCODE</TableHead>
                <TableHead>耗时</TableHead>
                <TableHead>答案</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {records.map((record) => (
                <TableRow
                  key={record.id}
                  className="cursor-pointer"
                  onClick={() => openDetail(record)}
                >
                  <TableCell className="font-mono text-xs">
                    {formatTime(record.created_at_ms)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{record.client_ip}</TableCell>
                  <TableCell className="max-w-[16rem] truncate font-mono">
                    {formatQuestion(record)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={record.error ? "destructive" : "outline"}>
                      {record.error ? "ERR" : (record.rcode ?? "-")}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono">{record.elapsed_ms}ms</TableCell>
                  <TableCell>{record.answer_count}</TableCell>
                </TableRow>
              ))}
              {!records.length && (
                <TableRow>
                  <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
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
  return (
    <Dialog open={Boolean(record)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>查询详情 #{record?.id}</DialogTitle>
        </DialogHeader>
        {record && (
          <div className="space-y-4 text-sm">
            <div className="grid gap-3 sm:grid-cols-3">
              <DetailItem label="Client" value={record.client_ip} />
              <DetailItem label="RCODE" value={record.rcode ?? "-"} />
              <DetailItem label="Elapsed" value={`${record.elapsed_ms}ms`} />
            </div>
            <DetailBlock title="Question">
              {record.questions_json.map((question) => (
                <div key={`${question.name}-${question.qtype}`} className="font-mono">
                  {question.name} {question.qclass} {question.qtype}
                </div>
              ))}
            </DetailBlock>
            <DetailBlock title="Answers">
              {record.answers_json.length ? (
                record.answers_json.map((answer, index) => (
                  <div key={index} className="font-mono">
                    {answer.name} {answer.ttl} {answer.class} {answer.rr_type}{" "}
                    {answer.payload_text}
                  </div>
                ))
              ) : (
                <span className="text-muted-foreground">无 answer</span>
              )}
            </DetailBlock>
            <DetailBlock title="Sequence Steps">
              {record.steps.map((step) => (
                <div key={step.event_index} className="font-mono">
                  #{step.event_index} {step.sequence_tag} {step.kind}
                  {step.tag ? `:${step.tag}` : ""} {step.outcome}
                </div>
              ))}
            </DetailBlock>
            {record.error && (
              <DetailBlock title="Error">
                <span className="text-destructive">{record.error}</span>
              </DetailBlock>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border px-3 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-mono">{value}</div>
    </div>
  );
}

function DetailBlock({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function formatTime(ms: number) {
  return new Date(ms).toLocaleTimeString();
}

function formatQuestion(record: QueryRecordRow) {
  const first = record.questions_json[0];
  if (!first) return "-";
  return `${first.name} ${first.qtype}`;
}

export const queryRecorderPlugin: PluginComponentDefinition = {
  Detail: QueryRecorderDetail,
};
