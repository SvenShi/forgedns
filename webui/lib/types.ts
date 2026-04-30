export type PluginType = "server" | "executor" | "matcher" | "provider";

export type PluginStatus = "running" | "stopped" | "error";

export interface PluginInstance {
  id: string;
  name: string;
  type: PluginType;
  pluginKind: string;
  status: PluginStatus;
  enabled: boolean;
  pinned: boolean;
  config: Record<string, unknown>;
  metrics: {
    calls: number;
    hitRate?: number;
    avgLatency: number;
    errorRate: number;
    qps: number;
  };
  createdAt: string;
  updatedAt: string;
}

export interface SystemMetrics {
  totalPlugins: number;
  runningPlugins: number;
  cpuUsage: number;
  memoryUsage: number;
  memoryTotal: number;
  currentQps: number;
  uptime: number;
}

export interface SystemInfo {
  version: string;
  latestVersion: string;
  os: string;
  arch: string;
  threads: number;
  maxConcurrency: number;
  logLevel: string;
  logRolling: string;
}

export const PLUGIN_TYPE_LABELS: Record<PluginType, string> = {
  server: "Server",
  executor: "Executor",
  matcher: "Matcher",
  provider: "Provider",
};

export const PLUGIN_TYPE_DESCRIPTIONS: Record<PluginType, string> = {
  server: "入口服务",
  executor: "执行器",
  matcher: "匹配器",
  provider: "数据源",
};

export const PLUGIN_STATUS_LABELS: Record<PluginStatus, string> = {
  running: "运行中",
  stopped: "已停止",
  error: "异常",
};
