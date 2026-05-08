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
