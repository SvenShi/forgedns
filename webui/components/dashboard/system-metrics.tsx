"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FileCode2, GitBranch, HeartPulse, RotateCw } from "lucide-react";
import { useAppStore } from "@/lib/store";

export function SystemMetrics() {
  const health = useAppStore((s) => s.health);
  const reloadStatus = useAppStore((s) => s.reloadStatus);
  const dependencyGraph = useAppStore((s) => s.dependencyGraph);
  const configPath = useAppStore((s) => s.configPath);
  const configError = useAppStore((s) => s.configError);

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">服务健康</CardTitle>
          <HeartPulse className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold font-mono">
            {health?.status ?? "unknown"}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            API {health?.checks.api ?? "-"} · 插件 {health?.checks.plugin_init ?? "-"}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">插件配置</CardTitle>
          <GitBranch className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold font-mono">
            {health?.plugins.total ?? dependencyGraph?.nodes.length ?? 0}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Server {health?.plugins.servers ?? "-"} · init {dependencyGraph?.init_order.length ?? 0}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Reload</CardTitle>
          <RotateCw className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold font-mono">
            {reloadStatus?.status ?? "idle"}
          </div>
          <p className="text-xs text-muted-foreground mt-1 truncate">
            {reloadStatus?.last_error ?? "无 reload 错误"}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">配置文件</CardTitle>
          <FileCode2 className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="truncate font-mono text-sm font-semibold">
            {configPath}
          </div>
          <p className="text-xs text-muted-foreground mt-1 truncate">
            {configError ?? "配置校验通过"}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
