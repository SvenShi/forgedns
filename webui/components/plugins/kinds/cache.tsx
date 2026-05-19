"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { DatabaseZap, Download, RefreshCw, Trash2, Upload } from "lucide-react";
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
  deleteCacheEntry,
  fetchCacheDump,
  fetchCacheEntries,
  flushCache,
  loadCacheDump,
  type CacheEntryRow,
} from "@/lib/oxidns-api";
import type {
  PluginCardComponentProps,
  PluginComponentDefinition,
  PluginDetailComponentProps,
} from "../types";
import { DnsRecordDetailDialog } from "../dns-record-detail-dialog";
import { PluginCardTemplate } from "../plugin-card-template";
import { PluginDetailTemplate } from "../plugin-detail-template";

function CachePluginCard({
  plugin,
  compact = false,
}: PluginCardComponentProps) {
  return (
    <PluginCardTemplate
      plugin={plugin}
      compact={compact}
      icon={<DatabaseZap className="h-4 w-4 text-primary" />}
    >
      <div className="space-y-2 text-xs text-muted-foreground">
        <div>查看缓存项，按需清空、导出或导入缓存数据。</div>
        {!compact && (
          <div className="font-mono text-foreground">
            size={String(plugin.config.size ?? "default")}
          </div>
        )}
      </div>
    </PluginCardTemplate>
  );
}

function CachePluginDetail(props: PluginDetailComponentProps) {
  return (
    <PluginDetailTemplate
      {...props}
      icon={<DatabaseZap className="h-5 w-5" />}
      summaryItems={[
        { label: "容量", value: String(props.plugin.config.size ?? "默认") },
        {
          label: "负缓存",
          value: props.plugin.config.cache_negative === false ? "关闭" : "开启",
        },
        {
          label: "ECS 键",
          value: props.plugin.config.ecs_in_key ? "开启" : "关闭",
        },
      ]}
      metricsContent={<CacheEntriesPanel tag={props.plugin.name} />}
    />
  );
}

function CacheEntriesPanel({ tag }: { tag: string }) {
  const [entries, setEntries] = useState<CacheEntryRow[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<CacheEntryRow | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchCacheEntries(tag, { limit: 100, cursor });
        setEntries((current) =>
          cursor ? [...current, ...response.entries] : response.entries,
        );
        setNextCursor(response.next_cursor);
        setTotal(response.total_entries);
      } catch (err) {
        setError(err instanceof Error ? err.message : "读取缓存项失败");
      } finally {
        setLoading(false);
      }
    },
    [tag],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const handleDelete = async (entry: CacheEntryRow) => {
    if (!window.confirm(`删除缓存项 ${entry.domain} ${entry.record_type}？`)) {
      return;
    }
    await deleteCacheEntry(tag, entry.id);
    setEntries((current) => current.filter((item) => item.id !== entry.id));
    setTotal((current) => Math.max(0, current - 1));
  };

  const handleFlush = async () => {
    if (!window.confirm(`清空 ${tag} 的所有缓存项？`)) return;
    await flushCache(tag);
    setEntries([]);
    setTotal(0);
    setNextCursor(undefined);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="grid gap-3 p-4 pb-2 sm:grid-cols-[1fr_auto] sm:items-center">
          <div className="min-w-0">
            <CardTitle className="text-sm">缓存项</CardTitle>
            <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
              <span className="rounded-full border bg-muted/30 px-2 py-0.5">
                共 {total} 项
              </span>
              <span className="rounded-full border bg-muted/30 px-2 py-0.5">
                已载入 {entries.length} 项
              </span>
              <span className="rounded-full border bg-muted/30 px-2 py-0.5">
                新鲜 {entries.filter((entry) => entry.fresh).length}
              </span>
              <span className="rounded-full border bg-muted/30 px-2 py-0.5">
                过期可用 {entries.filter((entry) => entry.stale).length}
              </span>
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
            <Button variant="outline" size="sm" onClick={handleFlush}>
              <Trash2 className="h-4 w-4" />
              清空
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
            <Table className="min-w-[820px]">
              <TableHeader>
                <TableRow className="bg-muted/30 hover:bg-muted/30">
                  <TableHead>缓存键</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>TTL</TableHead>
                  <TableHead>RCODE</TableHead>
                  <TableHead>答案</TableHead>
                  <TableHead>最近访问</TableHead>
                  <TableHead className="w-16" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow
                    key={entry.id}
                    className="cursor-pointer"
                    onClick={() => setSelected(entry)}
                  >
                    <TableCell className="max-w-[24rem]">
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          className="truncate font-mono"
                          title={`${entry.domain} ${entry.dns_class} ${entry.record_type}`}
                        >
                          {entry.domain}
                        </span>
                        <Badge variant="secondary" className="font-mono">
                          {entry.record_type}
                        </Badge>
                        <Badge variant="outline" className="font-mono">
                          {entry.dns_class}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell>{cacheStatusBadge(entry)}</TableCell>
                    <TableCell className="font-mono">
                      <div className="flex items-baseline gap-1">
                        <span>{entry.remaining_ttl}s</span>
                        <span className="text-xs text-muted-foreground">
                          / {entry.ttl}s
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono">{entry.rcode}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1 font-mono text-xs">
                        <span>{entry.answer_count}</span>
                        <span className="text-muted-foreground">
                          /{" "}
                          {entry.authority_count ??
                            entry.authorities_json?.length ??
                            0}
                          /{" "}
                          {entry.additional_count ??
                            entry.additionals_json?.length ??
                            0}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          title={formatCacheFullTime(
                            entry.last_access_unix_ms,
                            entry.last_access_ms,
                          )}
                        >
                          {formatCacheShortTime(
                            entry.last_access_unix_ms,
                            entry.last_access_ms,
                          )}
                        </span>
                        {entry.ecs_scope && (
                          <Badge variant="outline" className="font-mono">
                            ECS {entry.ecs_scope.family}/
                            {entry.ecs_scope.source_prefix}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        onClick={(event) => {
                          event.stopPropagation();
                          void handleDelete(entry);
                        }}
                        aria-label="删除缓存项"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {!entries.length && (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="h-24 text-center text-muted-foreground"
                    >
                      {loading ? "正在读取缓存项..." : "暂无缓存项"}
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
        <CacheEntryDetailDialog
          entry={selected}
          onClose={() => setSelected(null)}
        />
      </Card>

      <CacheMaintenancePanel tag={tag} />
    </div>
  );
}

function CacheMaintenancePanel({ tag }: { tag: string }) {
  const [dumpLoading, setDumpLoading] = useState(false);
  const [loadLoading, setLoadLoading] = useState(false);
  const [loadResult, setLoadResult] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDump = async () => {
    setDumpLoading(true);
    setError(null);
    try {
      const blob = await fetchCacheDump(tag);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${tag}.dump`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "导出失败");
    } finally {
      setDumpLoading(false);
    }
  };

  const handleLoadDump = async (file: File) => {
    setLoadLoading(true);
    setError(null);
    setLoadResult(null);
    try {
      const buffer = await file.arrayBuffer();
      const result = await loadCacheDump(tag, buffer);
      setLoadResult(result.loaded_entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : "导入失败");
    } finally {
      setLoadLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <Card>
      <CardHeader className="p-4 pb-2">
        <CardTitle className="text-sm">维护</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 p-4 pt-0">
        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
        {loadResult !== null && (
          <div className="rounded-md border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-600 dark:text-green-400">
            已载入 {loadResult} 项缓存
          </div>
        )}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            disabled={dumpLoading}
            onClick={() => void handleDump()}
          >
            <Download className="h-4 w-4" />
            导出 dump
          </Button>
          <span className="text-xs text-muted-foreground">
            {dumpLoading ? "正在导出..." : "下载当前缓存快照"}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            disabled={loadLoading}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="h-4 w-4" />
            导入 dump
          </Button>
          <span className="text-xs text-muted-foreground">
            {loadLoading ? "正在导入..." : "选择 .dump 文件载入缓存"}
          </span>
          <input
            ref={fileInputRef}
            type="file"
            accept=".dump,application/octet-stream"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleLoadDump(file);
            }}
          />
        </div>
      </CardContent>
    </Card>
  );
}

function CacheEntryDetailDialog({
  entry,
  onClose,
}: {
  entry: CacheEntryRow | null;
  onClose: () => void;
}) {
  return (
    <DnsRecordDetailDialog
      open={Boolean(entry)}
      onOpenChange={(open) => !open && onClose()}
      title={entry ? `${entry.domain} ${entry.record_type}` : "缓存详情"}
      subtitle={
        entry
          ? `缓存项 · 写入 ${formatCacheFullTime(entry.cache_time_unix_ms, entry.cache_time_ms)}`
          : undefined
      }
      status={entry ? cacheStatusBadge(entry) : undefined}
      summaryItems={
        entry
          ? [
              {
                label: "域名",
                value: entry.domain,
                title: entry.domain,
                mono: true,
                wide: true,
              },
              { label: "记录类型", value: entry.record_type, mono: true },
              { label: "记录类", value: entry.dns_class, mono: true },
              { label: "RCODE", value: entry.rcode, mono: true },
              { label: "TTL", value: `${entry.ttl}s`, mono: true },
              {
                label: "剩余 TTL",
                value: `${entry.remaining_ttl}s`,
                mono: true,
              },
              {
                label: "响应记录",
                value: `${entry.answer_count} / ${entry.authority_count ?? entry.authorities_json?.length ?? 0} / ${entry.additional_count ?? entry.additionals_json?.length ?? 0}`,
                title: "answer / authority / additional",
                mono: true,
              },
              {
                label: "缓存标志",
                value: `DO=${entry.do_bit ? "1" : "0"} CD=${entry.cd_bit ? "1" : "0"}`,
                mono: true,
              },
              {
                label: "写入时间",
                value: formatCacheFullTime(
                  entry.cache_time_unix_ms,
                  entry.cache_time_ms,
                ),
                title: `runtime +${entry.cache_time_ms}ms`,
                mono: true,
                wide: true,
              },
              {
                label: "过期时间",
                value: formatCacheFullTime(
                  entry.expire_at_unix_ms,
                  entry.expire_at_ms,
                ),
                title: `runtime +${entry.expire_at_ms}ms`,
                mono: true,
                wide: true,
              },
              {
                label: "最近访问",
                value: formatCacheFullTime(
                  entry.last_access_unix_ms,
                  entry.last_access_ms,
                ),
                title: `runtime +${entry.last_access_ms}ms`,
                mono: true,
                wide: true,
              },
            ]
          : []
      }
      questions={
        entry
          ? [
              {
                name: entry.domain,
                qclass: entry.dns_class,
                qtype: entry.record_type,
              },
            ]
          : []
      }
      sections={
        entry
          ? [
              {
                title: "应答记录",
                records: entry.answers_json ?? [],
                emptyLabel: "无 answer",
              },
              {
                title: "权威记录",
                records: entry.authorities_json ?? [],
                emptyLabel: "无 authority",
              },
              {
                title: "附加记录",
                records: entry.additionals_json ?? [],
                emptyLabel: "无 additional",
              },
              {
                title: "签名记录",
                records: entry.signature_json ?? [],
                emptyLabel: "无 signature",
              },
            ]
          : []
      }
      blocks={
        entry
          ? [
              {
                title: "缓存键",
                children: (
                  <div className="break-all font-mono text-xs text-muted-foreground">
                    {entry.id}
                  </div>
                ),
              },
              ...(entry.ecs_scope
                ? [
                    {
                      title: "ECS 范围",
                      children: (
                        <div className="grid gap-2 font-mono text-xs text-muted-foreground sm:grid-cols-2">
                          <span>family={entry.ecs_scope.family}</span>
                          <span>source={entry.ecs_scope.source_prefix}</span>
                          <span>scope={entry.ecs_scope.scope_prefix}</span>
                          <span className="break-all">
                            network={entry.ecs_scope.network_hex}
                          </span>
                        </div>
                      ),
                    },
                  ]
                : []),
            ]
          : []
      }
    />
  );
}

function cacheStatusBadge(entry: CacheEntryRow) {
  if (entry.fresh) return <Badge variant="secondary">新鲜</Badge>;
  if (entry.stale) return <Badge variant="outline">过期可用</Badge>;
  return <Badge variant="destructive">已过期</Badge>;
}

function formatCacheShortTime(ms?: number, runtimeMs?: number) {
  if (typeof ms !== "number") {
    return typeof runtimeMs === "number" ? formatRuntimeMs(runtimeMs) : "-";
  }
  return new Date(ms).toLocaleString([], {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatCacheFullTime(ms?: number, runtimeMs?: number) {
  if (typeof ms !== "number") {
    return typeof runtimeMs === "number" ? formatRuntimeMs(runtimeMs) : "-";
  }
  return new Date(ms).toLocaleString([], {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatRuntimeMs(ms: number) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) {
    return `+${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `+${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `+${minutes}m ${seconds}s`;
  }
  return `+${seconds}s`;
}

export const cachePlugin: PluginComponentDefinition = {
  Card: CachePluginCard,
  Detail: CachePluginDetail,
};
