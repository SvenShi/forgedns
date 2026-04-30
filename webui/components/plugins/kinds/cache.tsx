"use client";

import { DatabaseZap } from "lucide-react";
import { Area, AreaChart, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type {
  PluginCardComponentProps,
  PluginComponentDefinition,
  PluginDetailComponentProps,
} from "../types";
import { PluginCardTemplate } from "../plugin-card-template";
import { PluginDetailTemplate } from "../plugin-detail-template";
import { formatMetricNumber } from "../display";

function CachePluginCard({
  plugin,
  compact = false,
}: PluginCardComponentProps) {
  const hitRate = plugin.metrics.hitRate ?? 0;

  return (
    <PluginCardTemplate
      plugin={plugin}
      compact={compact}
      icon={<DatabaseZap className="h-4 w-4 text-primary" />}
      primaryMetric={{
        label: "命中率",
        value: `${(hitRate * 100).toFixed(1)}%`,
      }}
    >
      <div className="space-y-1.5">
        <Progress value={hitRate * 100} className="h-1.5" />
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>缓存命中率</span>
          <span>{formatMetricNumber(plugin.metrics.qps)} QPS</span>
        </div>
        {!compact && (
          <div className="grid grid-cols-2 gap-3 pt-2 text-xs text-muted-foreground">
            <span>
              调用{" "}
              <b className="font-medium text-foreground">
                {formatMetricNumber(plugin.metrics.calls)}
              </b>
            </span>
            <span>
              延迟{" "}
              <b className="font-medium text-foreground">
                {plugin.metrics.avgLatency.toFixed(2)}ms
              </b>
            </span>
          </div>
        )}
      </div>
    </PluginCardTemplate>
  );
}

function CachePluginDetail(props: PluginDetailComponentProps) {
  const hitRate = props.plugin.metrics.hitRate ?? 0;

  return (
    <PluginDetailTemplate
      {...props}
      icon={<DatabaseZap className="h-5 w-5" />}
      summaryItems={[
        { label: "命中率", value: `${(hitRate * 100).toFixed(1)}%` },
        { label: "QPS", value: formatMetricNumber(props.plugin.metrics.qps) },
        {
          label: "延迟",
          value: `${props.plugin.metrics.avgLatency.toFixed(2)}ms`,
        },
      ]}
      metricsContent={
        <>
          <Card>
            <CardHeader className="p-4 pb-2">
              <CardTitle className="text-sm">缓存命中率</CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              <div className="flex items-center gap-3">
                <div className="font-mono text-2xl font-semibold">
                  {(hitRate * 100).toFixed(1)}%
                </div>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary transition-all"
                    style={{ width: `${hitRate * 100}%` }}
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="p-4 pb-2">
              <CardTitle className="text-sm">24 小时 QPS 趋势</CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              <div className="h-[180px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={props.chartData}>
                    <defs>
                      <linearGradient
                        id="cacheQpsGradient"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor="var(--primary)"
                          stopOpacity={0.32}
                        />
                        <stop
                          offset="100%"
                          stopColor="var(--primary)"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="time"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 10 }}
                      interval={5}
                    />
                    <YAxis hide />
                    <Area
                      type="monotone"
                      dataKey="qps"
                      stroke="var(--primary)"
                      fill="url(#cacheQpsGradient)"
                      strokeWidth={1.8}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </>
      }
    />
  );
}

export const cachePlugin: PluginComponentDefinition = {
  Card: CachePluginCard,
  Detail: CachePluginDetail,
};
