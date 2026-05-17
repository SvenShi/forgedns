"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { Cpu, FileCode2, HardDrive, HeartPulse } from "lucide-react";
import { useAppStore } from "@/lib/store";

// Ticks locally every second; re-calibrates whenever backendUptimeMs changes.
function useLocalUptime(backendUptimeMs: number): number {
  const [syncedUptime, setSyncedUptime] = useState(backendUptimeMs);
  const [elapsedMs, setElapsedMs] = useState(0);

  // Adjust state during render when the backend reports a new uptime, so the
  // displayed value snaps to it immediately (no setState-in-effect needed).
  if (syncedUptime !== backendUptimeMs) {
    setSyncedUptime(backendUptimeMs);
    setElapsedMs(0);
  }

  // Restart the wall-clock ticker on each backend sync; reading the clock
  // inside an effect/interval keeps render pure.
  useEffect(() => {
    const syncedAt = Date.now();
    const id = setInterval(() => setElapsedMs(Date.now() - syncedAt), 1000);
    return () => clearInterval(id);
  }, [backendUptimeMs]);

  return syncedUptime + elapsedMs;
}

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return `${d}天 ${h}小时 ${m}分`;
  if (h > 0) return `${h}小时 ${m}分`;
  if (m > 0) return `${m}分 ${sec}秒`;
  return `${sec}秒`;
}

function formatMemory(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${mb} MB`;
}

function usageColor(pct: number) {
  if (pct >= 85) return "text-destructive";
  if (pct >= 60) return "text-amber-500";
  return "";
}

function usageBarColor(pct: number) {
  if (pct >= 85) return "bg-destructive";
  if (pct >= 60) return "bg-amber-500";
  return undefined;
}

function CheckDot({ status }: { status?: string }) {
  const ok = status === "ok";
  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 rounded-full",
        ok ? "bg-green-500" : "bg-destructive",
      )}
    />
  );
}

export function SystemMetrics() {
  const health = useAppStore((s) => s.health);
  const system = useAppStore((s) => s.system);
  const plugins = useAppStore((s) => s.plugins);
  const configPath = useAppStore((s) => s.configPath);
  const configError = useAppStore((s) => s.configError);

  const uptimeMs = useLocalUptime(system?.uptime_ms ?? health?.uptime_ms ?? 0);
  const cpuPct = system?.process_cpu_percent ?? 0;
  const memMb = system?.process_memory_mb ?? 0;
  const totalMemMb = system?.system_memory_total_mb ?? 0;
  const memPct = totalMemMb > 0 ? Math.min((memMb / totalMemMb) * 100, 100) : 0;

  const healthStatus = health?.status ?? "unknown";
  const isHealthy = healthStatus === "ok";

  const serverCount = health?.plugins.servers;
  const pluginTotal = health?.plugins.total ?? plugins.length;

  return (
    <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
      {/* 服务健康 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">服务健康</CardTitle>
          <HeartPulse className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent className="space-y-2">
          <div>
            <div
              className={cn(
                "text-2xl font-bold font-mono",
                isHealthy ? "text-green-500" : "text-destructive",
              )}
            >
              {healthStatus}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {uptimeMs > 0 ? `已运行 ${formatUptime(uptimeMs)}` : "等待数据"}
            </p>
          </div>
          {health && (
            <div className="border-t border-border/50 pt-2 flex items-center gap-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <CheckDot status={health.checks.api} />
                API
              </span>
              <span className="flex items-center gap-1">
                <CheckDot status={health.checks.plugin_init} />
                插件
              </span>
              <span className="flex items-center gap-1">
                <CheckDot status={health.checks.server_startup} />
                服务器
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* CPU 占用 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">CPU 占用</CardTitle>
          <Cpu className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent className="space-y-2">
          <div>
            <div
              className={cn(
                "text-2xl font-bold font-mono",
                usageColor(cpuPct),
              )}
            >
              {system ? `${cpuPct.toFixed(1)}%` : "-"}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">进程 CPU 使用率</p>
          </div>
          <Progress
            value={cpuPct}
            className="h-1.5"
            indicatorClassName={usageBarColor(cpuPct)}
          />
        </CardContent>
      </Card>

      {/* 内存占用 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">内存占用</CardTitle>
          <HardDrive className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent className="space-y-2">
          <div>
            <div
              className={cn(
                "text-2xl font-bold font-mono",
                usageColor(memPct),
              )}
            >
              {system ? formatMemory(memMb) : "-"}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {totalMemMb > 0
                ? `共 ${formatMemory(totalMemMb)} · ${memPct.toFixed(1)}%`
                : "进程 RSS"}
            </p>
          </div>
          <Progress
            value={memPct}
            className="h-1.5"
            indicatorClassName={usageBarColor(memPct)}
          />
        </CardContent>
      </Card>

      {/* 配置文件 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">配置文件</CardTitle>
          <FileCode2 className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent className="space-y-2">
          <div>
            <div className="text-2xl font-bold font-mono">{pluginTotal}</div>
            <p
              className="text-xs mt-0.5 truncate text-muted-foreground font-mono"
              title={configPath}
            >
              {configPath}
            </p>
          </div>
          <div className="border-t border-border/50 pt-2 flex items-center gap-3 text-xs text-muted-foreground">
            {serverCount !== undefined && (
              <span>{serverCount} 服务器</span>
            )}
            <span
              className={cn(
                configError ? "text-destructive" : "text-green-500",
              )}
            >
              {configError ? "配置有误" : "校验通过"}
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
