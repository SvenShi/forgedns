/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

"use client";

import { useMemo, useState } from "react";
import { AlertCircle } from "lucide-react";
import { YamlEditor } from "@/components/config/yaml-editor";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ConfigField } from "@/lib/plugin-definitions";
import type { PluginInstance } from "@/lib/types";
import {
  parsePluginConfigYaml,
  stringifyPluginConfigYaml,
} from "@/lib/plugin-config-yaml";
import {
  createPluginConfigFormValues,
  PluginConfigFieldsEditor,
  serializePluginConfigValues,
} from "@/components/plugins/plugin-config-fields-editor";

interface PluginConfigModeEditorProps {
  fields: ConfigField[];
  plugins: PluginInstance[];
  values: Record<string, unknown>;
  onChange: (values: Record<string, unknown>) => void;
  readOnly?: boolean;
  defaultArrayObjectCollapsed?: boolean;
  fieldLabel?: string;
  yamlLabel?: string;
}

export function PluginConfigModeEditor({
  fields,
  plugins,
  values,
  onChange,
  readOnly = false,
  defaultArrayObjectCollapsed = false,
  fieldLabel = "字段",
  yamlLabel = "YAML",
}: PluginConfigModeEditorProps) {
  const [mode, setMode] = useState<"fields" | "yaml">("fields");
  const [yamlText, setYamlText] = useState(() =>
    stringifyPluginConfigYaml(values),
  );
  const [yamlError, setYamlError] = useState<string | null>(null);
  const schemaValues = useMemo(
    () => createPluginConfigFormValues(fields, values),
    [fields, values],
  );

  const handleModeChange = (nextMode: "fields" | "yaml") => {
    if (nextMode === "yaml") {
      setYamlText(stringifyPluginConfigYaml(values));
      setYamlError(null);
    }
    setMode(nextMode);
  };

  const handleFieldChange = (nextValues: Record<string, unknown>) => {
    onChange(serializePluginConfigValues(fields, nextValues));
  };

  const handleYamlChange = (nextYaml: string) => {
    setYamlText(nextYaml);
    if (readOnly) return;

    const parsed = parsePluginConfigYaml(nextYaml);
    if (parsed.error) {
      setYamlError(parsed.error);
      return;
    }

    if (
      parsed.value &&
      typeof parsed.value === "object" &&
      !Array.isArray(parsed.value)
    ) {
      setYamlError(null);
      onChange(parsed.value as Record<string, unknown>);
      return;
    }

    setYamlError("插件配置必须是 YAML 对象");
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Tabs value={mode} onValueChange={(value) => handleModeChange(value as typeof mode)}>
          <TabsList className="grid w-44 grid-cols-2">
            <TabsTrigger value="fields">{fieldLabel}</TabsTrigger>
            <TabsTrigger value="yaml">{yamlLabel}</TabsTrigger>
          </TabsList>
        </Tabs>
        {yamlError && mode === "yaml" && (
          <Badge variant="destructive" className="h-auto gap-1 whitespace-normal py-1">
            <AlertCircle className="h-3.5 w-3.5" />
            {yamlError}
          </Badge>
        )}
      </div>

      {mode === "fields" ? (
        <PluginConfigFieldsEditor
          fields={fields}
          plugins={plugins}
          values={schemaValues}
          onChange={handleFieldChange}
          defaultArrayObjectCollapsed={defaultArrayObjectCollapsed}
          readOnly={readOnly}
        />
      ) : (
        <YamlEditor
          value={yamlText}
          onChange={handleYamlChange}
          readOnly={readOnly}
          className="min-h-[260px]"
        />
      )}
    </div>
  );
}
