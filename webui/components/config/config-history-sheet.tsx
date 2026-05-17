"use client";

import { useState } from "react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { GitCompare, Trash2, RotateCcw, History } from "lucide-react";
import { useAppStore } from "@/lib/store";
import type { ConfigSnapshot } from "@/lib/config-history";
import { ConfigDiffDialog } from "@/components/config/config-diff-dialog";

interface ConfigHistorySheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

export function ConfigHistorySheet({
  open,
  onOpenChange,
}: ConfigHistorySheetProps) {
  const configHistory = useAppStore((s) => s.configHistory);
  const configVersion = useAppStore((s) => s.configVersion);
  const runningVersion = useAppStore((s) => s.runningVersion);
  const rollbackToSnapshot = useAppStore((s) => s.rollbackToSnapshot);
  const deleteConfigSnapshot = useAppStore((s) => s.deleteConfigSnapshot);
  const clearConfigHistory = useAppStore((s) => s.clearConfigHistory);

  const [diffEntry, setDiffEntry] = useState<ConfigSnapshot | null>(null);

  // Live status is derived from what's actually running / on disk, never from
  // a frozen per-entry flag — so there is always exactly one 运行中 and at
  // most one 待应用.
  const runningContent = configHistory.find(
    (s) => s.version === runningVersion,
  )?.content;

  const handleRollback = async (id: string) => {
    onOpenChange(false);
    try {
      await rollbackToSnapshot(id);
    } catch {
      // Surfaced via the header sync pill (red) / editor error badge.
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col gap-0 bg-background p-0 sm:max-w-md">
        <SheetHeader className="border-b px-5 py-4">
          <SheetTitle className="flex items-center gap-2 text-base">
            <History className="h-4 w-4 text-muted-foreground" />
            配置历史
          </SheetTitle>
          <SheetDescription>
            仅保存在本浏览器，按服务实例隔离。「回滚此版本」会写入磁盘并热重载使其生效。
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-2 p-4">
            {configHistory.length === 0 && (
              <p className="py-12 text-center text-sm text-muted-foreground">
                暂无历史记录
              </p>
            )}
            {configHistory.map((entry) => {
              const isRunning = entry.version === runningVersion;
              const isPending =
                !isRunning && entry.version === configVersion;
              return (
                <div
                  key={entry.id}
                  className="rounded-lg border bg-card/40 p-3"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-sm font-medium">
                          {new Date(entry.createdAt).toLocaleString()}
                        </span>
                        {isRunning && (
                          <Badge
                            variant="outline"
                            className="border-primary/30 bg-primary/10 text-primary"
                          >
                            运行中
                          </Badge>
                        )}
                        {isPending && (
                          <Badge
                            variant="outline"
                            className="border-yellow-500/30 bg-yellow-500/10 text-yellow-600 dark:text-yellow-400"
                          >
                            待应用
                          </Badge>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                        <code className="rounded bg-muted px-1 py-0.5 font-mono">
                          {entry.version.slice(0, 8)}
                        </code>
                        <Badge variant="outline">
                          {entry.source === "server" ? "基线" : "保存"}
                        </Badge>
                        <span>{entry.pluginCount} 插件</span>
                        <span>{formatSize(entry.size)}</span>
                      </div>
                      {entry.applyError && (
                        <p className="text-xs text-destructive">
                          上次应用失败：{entry.applyError}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="mt-2.5 flex items-center gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => setDiffEntry(entry)}
                    >
                      <GitCompare className="mr-1 h-3.5 w-3.5" />
                      差异
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 px-2 text-xs"
                          disabled={isRunning}
                        >
                          <RotateCcw className="mr-1 h-3.5 w-3.5" />
                          回滚此版本
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>回滚到此版本？</AlertDialogTitle>
                          <AlertDialogDescription>
                            将把该版本写入磁盘配置文件并立即热重载，使其成为正在运行的配置。
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>取消</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => handleRollback(entry.id)}
                          >
                            回滚并应用
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="ml-auto h-7 px-2 text-xs text-muted-foreground hover:text-destructive"
                      onClick={() => deleteConfigSnapshot(entry.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      <span className="sr-only">删除该快照</span>
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </ScrollArea>

        {configHistory.length > 0 && (
          <div className="border-t p-4">
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="mr-1.5 h-4 w-4" />
                  清空历史
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>清空配置历史？</AlertDialogTitle>
                  <AlertDialogDescription>
                    将删除本浏览器为当前服务实例保存的所有配置快照，且无法恢复。
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>取消</AlertDialogCancel>
                  <AlertDialogAction onClick={() => clearConfigHistory()}>
                    清空
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        )}
      </SheetContent>

      {diffEntry && (
        <ConfigDiffDialog
          open={Boolean(diffEntry)}
          onOpenChange={(o) => {
            if (!o) setDiffEntry(null);
          }}
          original={runningContent ?? diffEntry.content}
          modified={diffEntry.content}
          originalTitle="正在运行"
          modifiedTitle={`快照 ${diffEntry.version.slice(0, 8)}`}
        />
      )}
    </Sheet>
  );
}
