"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Pause, Play, Trash2, WifiOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { streamLogs, type LogEntry } from "@/lib/oxidns-api";

const LEVEL_COLORS: Record<
  string,
  { dot: string; badge: string; text: string }
> = {
  ERROR: {
    dot: "bg-red-500",
    badge: "bg-red-500/15 text-red-400 border-red-500/20",
    text: "text-red-400",
  },
  WARN: {
    dot: "bg-amber-400",
    badge: "bg-amber-400/15 text-amber-400 border-amber-400/20",
    text: "text-amber-400",
  },
  INFO: {
    dot: "bg-emerald-500",
    badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/20",
    text: "text-emerald-400",
  },
  DEBUG: {
    dot: "bg-sky-500",
    badge: "bg-sky-500/15 text-sky-400 border-sky-500/20",
    text: "text-sky-400",
  },
  TRACE: {
    dot: "bg-gray-500",
    badge: "bg-gray-500/15 text-gray-400 border-gray-500/20",
    text: "text-gray-500",
  },
};

const MAX_ENTRIES = 2000;

function LevelBadge({ level }: { level: string }) {
  const colors = LEVEL_COLORS[level] ?? LEVEL_COLORS.INFO;
  return (
    <Badge
      variant="outline"
      className={`shrink-0 font-mono text-[10px] px-1 py-0 h-4 w-[42px] justify-center ${colors.badge}`}
    >
      {level}
    </Badge>
  );
}

function LogLine({ entry }: { entry: LogEntry }) {
  const colors = LEVEL_COLORS[entry.level] ?? LEVEL_COLORS.INFO;
  const elapsed = (entry.elapsed_ms / 1000).toFixed(3);
  return (
    <div className="flex min-w-full w-max items-baseline gap-2 rounded px-1 py-[1px] whitespace-nowrap hover:bg-white/5">
      <span className="shrink-0 text-zinc-600 tabular-nums">
        T+{elapsed}
      </span>
      <LevelBadge level={entry.level} />
      <span className="shrink-0 max-w-[28ch] truncate text-zinc-500">
        {entry.target}
      </span>
      <span className={`${colors.text} shrink-0`}>{entry.message}</span>
    </div>
  );
}

export function LogViewer() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [backlog, setBacklog] = useState(0);

  const scrollRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(false);
  const pendingRef = useRef<LogEntry[]>([]);

  // keep pausedRef in sync so the streaming callback sees current value
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  // auto-scroll to bottom when entries update and not paused
  useEffect(() => {
    if (!paused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [entries, paused]);

  // connect SSE stream; reconnect with exponential backoff on disconnect
  useEffect(() => {
    let mounted = true;
    const controller = new AbortController();
    let retryDelay = 1500;

    // clear stale entries so tail from the new stream doesn't produce duplicate keys
    setEntries([]);
    pendingRef.current = [];
    setBacklog(0);

    const run = async () => {
      while (mounted && !controller.signal.aborted) {
        try {
          setConnected(true);
          await streamLogs(
            {
              level: levelFilter !== "all" ? levelFilter : undefined,
              tail: 200,
            },
            (entry) => {
              if (pausedRef.current) {
                pendingRef.current.push(entry);
                setBacklog((b) => b + 1);
              } else {
                setEntries((prev) => {
                  const next = [...prev, entry];
                  return next.length > MAX_ENTRIES
                    ? next.slice(-MAX_ENTRIES)
                    : next;
                });
              }
            },
            controller.signal,
          );
        } catch {
          if (controller.signal.aborted) break;
        }
        if (!mounted || controller.signal.aborted) break;
        setConnected(false);
        await new Promise<void>((resolve) => setTimeout(resolve, retryDelay));
        retryDelay = Math.min(retryDelay * 2, 30_000);
      }
    };

    run();
    return () => {
      mounted = false;
      controller.abort();
      setConnected(false);
    };
  }, [levelFilter]);

  const togglePause = useCallback(() => {
    setPaused((prev) => {
      if (prev) {
        // resume: flush pending entries
        const pending = pendingRef.current;
        pendingRef.current = [];
        setBacklog(0);
        setEntries((current) => {
          const next = [...current, ...pending];
          return next.length > MAX_ENTRIES ? next.slice(-MAX_ENTRIES) : next;
        });
      }
      return !prev;
    });
  }, []);

  const clearLogs = useCallback(() => {
    setEntries([]);
    pendingRef.current = [];
    setBacklog(0);
  }, []);

  const filtered = entries.filter((e) => {
    if (search) {
      const q = search.toLowerCase();
      if (
        !e.message.toLowerCase().includes(q) &&
        !e.target.toLowerCase().includes(q)
      ) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="flex flex-1 flex-col min-h-0 w-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b shrink-0 flex-wrap">
        {/* Connection status */}
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0">
          {connected ? (
            <span className="relative flex size-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
            </span>
          ) : (
            <WifiOff className="size-3 text-rose-500" />
          )}
          <span>{connected ? "已连接" : "断开"}</span>
        </div>

        <div className="h-4 w-px bg-border shrink-0" />

        {/* Level filter */}
        <Select value={levelFilter} onValueChange={setLevelFilter}>
          <SelectTrigger className="h-7 w-28 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper" sideOffset={4}>
            <SelectItem value="all">全部级别</SelectItem>
            <SelectItem value="ERROR">ERROR+</SelectItem>
            <SelectItem value="WARN">WARN+</SelectItem>
            <SelectItem value="INFO">INFO+</SelectItem>
            <SelectItem value="DEBUG">DEBUG+</SelectItem>
            <SelectItem value="TRACE">TRACE</SelectItem>
          </SelectContent>
        </Select>

        {/* Search */}
        <Input
          className="h-7 w-48 text-xs"
          placeholder="搜索消息 / target…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <div className="flex-1" />

        {/* Entry count */}
        <span className="text-xs text-muted-foreground shrink-0">
          {filtered.length} 条
          {backlog > 0 && (
            <span className="ml-1 text-amber-400">+{backlog} 待显示</span>
          )}
        </span>

        {/* Clear */}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs"
          onClick={clearLogs}
        >
          <Trash2 className="size-3 mr-1" />
          清空
        </Button>

        {/* Pause / Resume */}
        <Button
          variant={paused ? "default" : "outline"}
          size="sm"
          className="h-7 px-2 text-xs"
          onClick={togglePause}
        >
          {paused ? (
            <>
              <Play className="size-3 mr-1" />
              继续 ({backlog})
            </>
          ) : (
            <>
              <Pause className="size-3 mr-1" />
              暂停
            </>
          )}
        </Button>
      </div>

      {/* Log content */}
      <div
        ref={scrollRef}
        className="oxidns-dialog-scrollbar min-h-0 flex-1 overflow-auto overscroll-contain bg-zinc-950 p-2 pb-4 font-mono text-xs leading-relaxed dark:bg-zinc-950"
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-zinc-600">
            {connected ? "等待日志…" : "正在连接后端…"}
          </div>
        ) : (
          filtered.map((entry, index) => (
            <LogLine
              key={`${entry.id}-${entry.elapsed_ms}-${index}`}
              entry={entry}
            />
          ))
        )}
      </div>
    </div>
  );
}
