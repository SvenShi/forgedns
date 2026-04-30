"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Cpu, HardDrive, Puzzle } from "lucide-react";
import { useAppStore } from "@/lib/store";

export function SystemMetrics() {
  const systemMetrics = useAppStore((s) => s.systemMetrics);

  const formatMemory = (mb: number) => {
    if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
    return `${mb} MB`;
  };

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">插件状态</CardTitle>
          <Puzzle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold font-mono">
            {systemMetrics.runningPlugins}
            <span className="text-muted-foreground text-sm font-normal">
              {" "}
              / {systemMetrics.totalPlugins}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">运行中 / 总数</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">CPU 使用率</CardTitle>
          <Cpu className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold font-mono">
            {systemMetrics.cpuUsage.toFixed(1)}%
          </div>
          <Progress value={systemMetrics.cpuUsage} className="mt-2 h-1.5" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">内存占用</CardTitle>
          <HardDrive className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold font-mono">
            {formatMemory(systemMetrics.memoryUsage)} /{" "}
            {formatMemory(systemMetrics.memoryTotal)}
          </div>
          <Progress
            value={
              (systemMetrics.memoryUsage / systemMetrics.memoryTotal) * 100
            }
            className="mt-2 h-1.5"
          />
        </CardContent>
      </Card>
    </div>
  );
}
