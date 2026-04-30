import type { PluginType } from "@/lib/types";
import type { PluginKindDefinition } from "@/lib/plugin-definitions";
import { createElement, type SVGProps } from "react";
import {
  getPluginKindsByType,
  pluginKindDefinitions,
} from "@/lib/plugin-definitions";
import {
  ArrowUpRight,
  Ban,
  BarChart3,
  CheckCircle,
  Clock,
  Database,
  File,
  FileQuestion,
  FileText,
  Gauge,
  GitBranch,
  Globe,
  Hash,
  List,
  Lock,
  MapPin,
  Network,
  Pencil,
  RefreshCw,
  Regex,
  Settings,
  Shield,
  Shuffle,
  Wifi,
} from "lucide-react";

export type PluginCatalogItem = PluginKindDefinition;

export const pluginKindIconMap = {
  Wifi,
  Network,
  Lock,
  Shield,
  Database,
  ArrowUpRight,
  Ban,
  CheckCircle,
  Clock,
  Pencil,
  RefreshCw,
  GitBranch,
  List,
  MapPin,
  Globe,
  FileQuestion,
  FileText,
  File,
  BarChart3,
  Regex,
  Gauge,
  Hash,
  Settings,
  Shuffle,
} as const;

export const pluginCatalog: PluginCatalogItem[] = pluginKindDefinitions;

export function getPluginCatalogItem(
  kind: string,
): PluginCatalogItem | undefined {
  return pluginCatalog.find((plugin) => plugin.kind === kind);
}

export function getPluginCatalogItemsByType(
  type: PluginType,
): PluginCatalogItem[] {
  return getPluginKindsByType(type);
}

export function getSupportedPluginCatalog(
  supportedKinds?: string[],
): PluginCatalogItem[] {
  if (!supportedKinds || supportedKinds.length === 0) return pluginCatalog;

  const supported = new Set(supportedKinds);
  return pluginCatalog.filter((plugin) => supported.has(plugin.kind));
}

export function getPluginKindIconComponent(icon: string) {
  return pluginKindIconMap[icon as keyof typeof pluginKindIconMap] ?? Database;
}

export function renderPluginKindIcon(
  icon: string,
  props?: SVGProps<SVGSVGElement>,
) {
  return createElement(getPluginKindIconComponent(icon), props);
}
