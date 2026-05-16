/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { pluginConfigFromYaml, pluginConfigToYaml } from "@/lib/oxidns-config";

export interface YamlParseResult {
  value: unknown;
  error?: string;
}

export function stringifyPluginConfigYaml(value: unknown): string {
  return pluginConfigToYaml(value);
}

export function parsePluginConfigYaml(input: string): YamlParseResult {
  const result = pluginConfigFromYaml(input);
  return {
    value: result.value,
    error: result.error,
  };
}

export function stringifyArgsLevelPluginConfigYaml(
  value: unknown,
  alreadyArgsLevel = false,
): string {
  return stringifyPluginConfigYaml(alreadyArgsLevel ? value : { args: value });
}

export function parseArgsLevelPluginConfigYaml(
  input: string,
  alreadyArgsLevel = false,
): YamlParseResult {
  const parsed = parsePluginConfigYaml(input);
  if (parsed.error || alreadyArgsLevel) return parsed;

  if (
    parsed.value &&
    typeof parsed.value === "object" &&
    !Array.isArray(parsed.value) &&
    "args" in parsed.value
  ) {
    return {
      value: (parsed.value as Record<string, unknown>).args ?? {},
    };
  }

  return {
    value: undefined,
    error: "插件 YAML 必须包含 args 字段",
  };
}
