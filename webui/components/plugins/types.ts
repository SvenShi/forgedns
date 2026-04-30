import type { ComponentType } from "react";
import type { ReactNode } from "react";
import type { PluginInstance } from "@/lib/types";

export interface PluginCardComponentProps {
  plugin: PluginInstance;
  compact?: boolean;
}

export interface PluginMetricPoint {
  time: string;
  qps: number;
  latency: number;
}

export interface PluginDetailComponentProps {
  plugin: PluginInstance;
  chartData: PluginMetricPoint[];
  onClose: () => void;
}

export interface PluginSummaryItem {
  label: string;
  value: string;
}

export interface PluginCardTemplateProps extends PluginCardComponentProps {
  icon?: ReactNode;
  primaryMetric?: {
    label: string;
    value: string;
  };
  children?: ReactNode;
}

export interface PluginDetailTemplateProps extends PluginDetailComponentProps {
  icon?: ReactNode;
  summaryItems?: PluginSummaryItem[];
  configContent?: ReactNode;
  metricsContent?: ReactNode;
}

export interface PluginComponentDefinition {
  Card?: ComponentType<PluginCardComponentProps>;
  Detail?: ComponentType<PluginDetailComponentProps>;
}
