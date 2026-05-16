import { Cog, Database, Filter, Server } from "lucide-react";
import type React from "react";
import type { PluginType } from "@/lib/types";

export const pluginTypeIcons: Record<PluginType, React.ReactNode> = {
  server: <Server className="h-4 w-4" />,
  executor: <Cog className="h-4 w-4" />,
  matcher: <Filter className="h-4 w-4" />,
  provider: <Database className="h-4 w-4" />,
};

// ─── Plugin colour system ────────────────────────────────────────────────────
//
// Single source of truth used by the plugin list, plugin detail sheet, and
// the dependency-graph topology view. Every plugin type maps to one of four
// Tailwind palettes and all visual treatments (badges, icon chips, accent
// dots, hex strings for inline SVG fills) are derived from that mapping so
// the colour system stays in sync everywhere.

export const pluginTypePalette: Record<
  PluginType,
  "emerald" | "sky" | "amber" | "indigo"
> = {
  server: "emerald",
  executor: "sky",
  matcher: "amber",
  provider: "indigo",
};

// Hex codes (Tailwind 500 step) for inline SVG / ReactFlow style props.
export const pluginTypeAccentHex: Record<PluginType, string> = {
  server: "#10b981",
  executor: "#0ea5e9",
  matcher: "#f59e0b",
  provider: "#6366f1",
};

// Subtle tinted badge (filled bg + same-hue text + tinted border). Used in
// plugin cards, the plugins table, and the detail sheet header.
export const pluginTypeColors: Record<PluginType, string> = {
  server:
    "bg-emerald-500/15 text-emerald-700 border-emerald-500/30 dark:text-emerald-300",
  executor:
    "bg-sky-500/15 text-sky-700 border-sky-500/30 dark:text-sky-300",
  matcher:
    "bg-amber-500/15 text-amber-700 border-amber-500/30 dark:text-amber-300",
  provider:
    "bg-indigo-500/15 text-indigo-700 border-indigo-500/30 dark:text-indigo-300",
};

// Solid accent fill — legend swatches, status dots, decorative bars.
export const pluginTypeAccentBg: Record<PluginType, string> = {
  server: "bg-emerald-500",
  executor: "bg-sky-500",
  matcher: "bg-amber-500",
  provider: "bg-indigo-500",
};

// Soft tinted icon chip background with matching text colour.
export const pluginTypeIconBg: Record<PluginType, string> = {
  server: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
  executor: "bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300",
  matcher: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
  provider:
    "bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300",
};

// Outline-style badge (transparent bg, tinted border + text). Secondary
// "kind" badge inside topology cards.
export const pluginTypeBadgeOutline: Record<PluginType, string> = {
  server:
    "border-emerald-300 text-emerald-700 dark:border-emerald-700 dark:text-emerald-300",
  executor:
    "border-sky-300 text-sky-700 dark:border-sky-700 dark:text-sky-300",
  matcher:
    "border-amber-300 text-amber-700 dark:border-amber-700 dark:text-amber-300",
  provider:
    "border-indigo-300 text-indigo-700 dark:border-indigo-700 dark:text-indigo-300",
};

// Fallback styles for unknown plugin kinds (e.g. graph nodes whose kind
// string doesn't match any PluginType). The topology view feeds raw string
// kinds in from the backend and may occasionally see something off the
// PluginType enum.
const NEUTRAL_ACCENT_HEX = "#94a3b8"; // slate-400
const NEUTRAL_ICON_BG = "bg-muted text-muted-foreground";
const NEUTRAL_BADGE_OUTLINE = "border-border text-muted-foreground";
const NEUTRAL_ACCENT_BG = "bg-slate-400";

function isPluginType(kind: string): kind is PluginType {
  return (
    kind === "server" ||
    kind === "executor" ||
    kind === "matcher" ||
    kind === "provider"
  );
}

export function pluginKindAccentHex(kind: string): string {
  return isPluginType(kind) ? pluginTypeAccentHex[kind] : NEUTRAL_ACCENT_HEX;
}

export function pluginKindIconBgClass(kind: string): string {
  return isPluginType(kind) ? pluginTypeIconBg[kind] : NEUTRAL_ICON_BG;
}

export function pluginKindBadgeOutlineClass(kind: string): string {
  return isPluginType(kind)
    ? pluginTypeBadgeOutline[kind]
    : NEUTRAL_BADGE_OUTLINE;
}

export function pluginKindAccentBgClass(kind: string): string {
  return isPluginType(kind) ? pluginTypeAccentBg[kind] : NEUTRAL_ACCENT_BG;
}

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
