"use client";

import { useCallback, useEffect, useState } from "react";
import { DatabaseZap, RefreshCw, Trash2 } from "lucide-react";
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
  fetchCacheEntries,
  flushCache,
  type CacheEntryRow,
} from "@/lib/oxidns-api";
import type {
  PluginCardComponentProps,
  PluginComponentDefinition,
  PluginDetailComponentProps,
} from "../types";
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
        <div>缓存项、清空、dump/load 通过插件 API 管理。</div>
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
          label: "ECS Key",
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
        <CardHeader className="grid grid-cols-[1fr_auto] items-center p-4 pb-2">
          <div>
            <CardTitle className="text-sm">缓存项</CardTitle>
            <div className="mt-1 text-xs text-muted-foreground">
              共 {total} 项，按最近访问排序
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => load()}>
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
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>域名</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>RCODE</TableHead>
                  <TableHead>答案</TableHead>
                  <TableHead>TTL</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>ECS</TableHead>
                  <TableHead className="w-16" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="max-w-[14rem] truncate font-mono">
                      {entry.domain}
                    </TableCell>
                    <TableCell className="font-mono">
                      {entry.record_type}
                    </TableCell>
                    <TableCell className="font-mono">{entry.rcode}</TableCell>
                    <TableCell>{entry.answer_count}</TableCell>
                    <TableCell className="font-mono">
                      {entry.remaining_ttl}s
                    </TableCell>
                    <TableCell>
                      <Badge variant={entry.fresh ? "secondary" : "outline"}>
                        {entry.fresh
                          ? "fresh"
                          : entry.stale
                            ? "stale"
                            : "expired"}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {entry.ecs_scope
                        ? `${entry.ecs_scope.family}/${entry.ecs_scope.source_prefix}`
                        : "-"}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        onClick={() => handleDelete(entry)}
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
                      colSpan={8}
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
      </Card>

      <Card>
        <CardHeader className="p-4 pb-2">
          <CardTitle className="text-sm">维护</CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-0 text-sm text-muted-foreground">
          dump 与 load_dump API 已保留；文件上传/下载入口后续可按需要补到这里。
        </CardContent>
      </Card>
    </div>
  );
}

export const cachePlugin: PluginComponentDefinition = {
  Card: CachePluginCard,
  Detail: CachePluginDetail,
};
