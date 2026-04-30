import { Cog, Database, Filter, Server } from "lucide-react";
import type React from "react";
import type { PluginType } from "@/lib/types";

export const pluginTypeIcons: Record<PluginType, React.ReactNode> = {
  server: <Server className="h-4 w-4" />,
  executor: <Cog className="h-4 w-4" />,
  matcher: <Filter className="h-4 w-4" />,
  provider: <Database className="h-4 w-4" />,
};

export const pluginTypeColors: Record<PluginType, string> = {
  server: "bg-chart-1/15 text-chart-1 border-chart-1/30",
  executor: "bg-chart-2/15 text-chart-2 border-chart-2/30",
  matcher: "bg-chart-3/15 text-chart-3 border-chart-3/30",
  provider: "bg-chart-4/15 text-chart-4 border-chart-4/30",
};

export const pluginStatusColors: Record<string, string> = {
  running: "bg-primary/15 text-primary border-primary/30",
  stopped: "bg-muted text-muted-foreground border-muted-foreground/30",
  error: "bg-destructive/15 text-destructive border-destructive/30",
};

export function formatMetricNumber(num: number) {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
}
