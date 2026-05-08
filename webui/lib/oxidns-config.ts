"use client";

import { parseDocument, stringify } from "yaml";
import { getPluginKindDefinition } from "@/lib/plugin-definitions";
import type { PluginInstance, PluginType } from "@/lib/types";

export interface OxiDnsConfig {
  include?: string[];
  runtime?: Record<string, unknown>;
  api?: Record<string, unknown>;
  log?: Record<string, unknown>;
  plugins: OxiDnsPluginConfig[];
  [key: string]: unknown;
}

export interface OxiDnsPluginConfig {
  tag: string;
  type: string;
  args?: unknown;
}

export interface OxiDnsParseResult {
  config?: OxiDnsConfig;
  diagnostics: string[];
}

const emptyMetrics = { calls: 0, avgLatency: 0, errorRate: 0, qps: 0 };

export function parseOxiDnsYaml(text: string): OxiDnsParseResult {
  try {
    const document = parseDocument(text, { prettyErrors: true });
    const diagnostics = [
      ...document.errors.map((error) => error.message),
      ...document.warnings.map((warning) => warning.message),
    ];
    if (document.errors.length > 0) return { diagnostics };

    const value = document.toJSON();
    if (!isPlainRecord(value)) {
      return { diagnostics: ["配置文件必须是 YAML 对象"] };
    }

    const rawPlugins = value.plugins;
    if (rawPlugins !== undefined && !Array.isArray(rawPlugins)) {
      return { diagnostics: ["plugins 必须是数组"] };
    }

    const plugins = (Array.isArray(rawPlugins) ? rawPlugins : []).map(
      (plugin, index): OxiDnsPluginConfig => {
        if (!isPlainRecord(plugin)) {
          throw new Error(`plugins[${index}] 必须是对象`);
        }
        return {
          tag: String(plugin.tag ?? ""),
          type: String(plugin.type ?? ""),
          args: plugin.args,
        };
      },
    );

    return {
      config: { ...value, plugins } as OxiDnsConfig,
      diagnostics,
    };
  } catch (error) {
    return {
      diagnostics: [error instanceof Error ? error.message : "YAML 解析失败"],
    };
  }
}

export function stringifyOxiDnsConfig(config: OxiDnsConfig): string {
  return stringify(cleanUndefined(config), {
    indent: 2,
    lineWidth: 0,
    nullStr: "null",
  });
}

export function pluginsFromConfig(config: OxiDnsConfig): PluginInstance[] {
  return config.plugins.map((plugin) => {
    const definition = getPluginKindDefinition(plugin.type);
    const now = new Date().toISOString();
    return {
      id: plugin.tag || `${plugin.type}-${now}`,
      name: plugin.tag,
      type: definition?.type ?? inferPluginType(plugin.type),
      pluginKind: plugin.type,
      status: "running",
      enabled: true,
      pinned: false,
      config: uiConfigFromPluginArgs(plugin.type, plugin.args),
      metrics: { ...emptyMetrics },
      createdAt: now,
      updatedAt: now,
    };
  });
}

export function configFromPlugins(
  baseConfig: OxiDnsConfig,
  plugins: PluginInstance[],
): OxiDnsConfig {
  return {
    ...baseConfig,
    plugins: plugins.map((plugin) => {
      const args = pluginArgsFromUiConfig(plugin.pluginKind, plugin.config);
      return {
        tag: plugin.name,
        type: plugin.pluginKind,
        ...(isEmptyValue(args) ? {} : { args }),
      };
    }),
  };
}

export function pluginConfigToYaml(config: unknown): string {
  return stringify(cleanUndefined(config ?? {}), {
    indent: 2,
    lineWidth: 0,
    nullStr: "null",
  }).trimEnd();
}

export function pluginConfigFromYaml(input: string): {
  value?: Record<string, unknown>;
  error?: string;
} {
  const result = parseOxiDnsYaml(
    `plugins:\n  - tag: plugin\n    type: debug_print\n    args:\n${indentYaml(input || "{}", 6)}\n`,
  );
  if (result.diagnostics.length > 0 || !result.config) {
    return { error: result.diagnostics[0] ?? "YAML 解析失败" };
  }
  const args = result.config.plugins[0]?.args;
  if (!isPlainRecord(args)) return { error: "插件配置必须是 YAML 对象" };
  return { value: args };
}

export function uiConfigFromPluginArgs(
  pluginKind: string,
  args: unknown,
): Record<string, unknown> {
  const definition = getPluginKindDefinition(pluginKind);
  if (
    definition?.configSchema.length === 1 &&
    definition.configSchema[0].key === "args"
  ) {
    return { args: args ?? [] };
  }
  if (isPlainRecord(args)) return args;
  if (args === undefined || args === null) return {};
  return { args };
}

export function pluginArgsFromUiConfig(
  pluginKind: string,
  config: Record<string, unknown>,
): unknown {
  const definition = getPluginKindDefinition(pluginKind);
  if (
    definition?.configSchema.length === 1 &&
    definition.configSchema[0].key === "args"
  ) {
    return config.args;
  }
  return config;
}

export function createDefaultOxiDnsConfig(): OxiDnsConfig {
  return {
    log: { level: "info" },
    plugins: [],
  };
}

function inferPluginType(_pluginKind: string): PluginType {
  return "executor";
}

function cleanUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(cleanUndefined);
  if (!isPlainRecord(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key, cleanUndefined(entry)]),
  );
}

function isEmptyValue(value: unknown) {
  if (value === undefined || value === null) return true;
  if (Array.isArray(value)) return value.length === 0;
  return isPlainRecord(value) && Object.keys(value).length === 0;
}

function indentYaml(input: string, count: number) {
  const prefix = " ".repeat(count);
  return input
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
