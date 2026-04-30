"use client";

import type { PluginCardComponentProps } from "./types";
import { PluginCardTemplate } from "./plugin-card-template";
import { getPluginCatalogItem } from "./catalog";

export function DefaultPluginCard(props: PluginCardComponentProps) {
  const definition = getPluginCatalogItem(props.plugin.pluginKind);
  const configFields = definition?.configSchema.slice(0, 3) ?? [];

  return (
    <PluginCardTemplate {...props}>
      <div className="space-y-1">
        {configFields.map((field) => (
          <div
            key={field.key}
            className="flex min-w-0 items-center justify-between gap-3 text-xs leading-5"
          >
            <span className="truncate text-muted-foreground">
              {field.label}
            </span>
            <span className="truncate text-right font-mono text-foreground">
              {formatCardConfigValue(props.plugin.config[field.key])}
            </span>
          </div>
        ))}
      </div>
    </PluginCardTemplate>
  );
}

function formatCardConfigValue(value: unknown) {
  if (value === undefined || value === null || value === "") return "未配置";
  if (typeof value === "boolean") return value ? "是" : "否";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value))
    return value.length > 0 ? `${value.length} 项` : "空";
  if (typeof value === "object") {
    return Object.keys(value).length > 0 ? "已配置" : "空";
  }
  return String(value);
}
