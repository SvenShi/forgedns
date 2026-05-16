/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

"use client";

import { useState } from "react";
import { AlertCircle } from "lucide-react";
import { YamlEditor } from "@/components/config/yaml-editor";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ConfigField } from "@/lib/plugin-definitions";
import type { PluginInstance } from "@/lib/types";
import {
  parseArgsLevelPluginConfigYaml,
  stringifyArgsLevelPluginConfigYaml,
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
  onValidityChange?: (valid: boolean) => void;
  readOnly?: boolean;
  defaultArrayObjectCollapsed?: boolean;
  fieldLabel?: string;
  yamlLabel?: string;
  pluginKind?: string;
  currentPluginName?: string;
}

export function PluginConfigModeEditor({
  fields,
  plugins,
  values,
  onChange,
  onValidityChange,
  readOnly = false,
  defaultArrayObjectCollapsed = false,
  fieldLabel = "字段",
  yamlLabel = "YAML",
  pluginKind,
  currentPluginName,
}: PluginConfigModeEditorProps) {
  const alreadyArgsLevel = isAlreadyArgsLevelSchema(fields);
  const [mode, setMode] = useState<"fields" | "yaml">("fields");
  const [yamlText, setYamlText] = useState(() =>
    stringifyArgsLevelPluginConfigYaml(values, alreadyArgsLevel),
  );
  const [yamlError, setYamlError] = useState<string | null>(null);
  const [fieldValues, setFieldValues] = useState(() =>
    createPluginConfigFormValues(fields, values),
  );

  const handleModeChange = (nextMode: "fields" | "yaml") => {
    if (nextMode === "yaml") {
      setYamlText(
        stringifyArgsLevelPluginConfigYaml(
          serializePluginConfigValues(fields, fieldValues),
          alreadyArgsLevel,
        ),
      );
      setYamlError(null);
      onValidityChange?.(true);
    }
    setMode(nextMode);
  };

  const handleFieldChange = (nextValues: Record<string, unknown>) => {
    setFieldValues(nextValues);
    onValidityChange?.(true);
    onChange(serializePluginConfigValues(fields, nextValues));
  };

  const handleYamlChange = (nextYaml: string) => {
    setYamlText(nextYaml);
    if (readOnly) return;

    const parsed = parseArgsLevelPluginConfigYaml(nextYaml, alreadyArgsLevel);
    if (parsed.error) {
      setYamlError(parsed.error);
      onValidityChange?.(false);
      return;
    }

    if (
      parsed.value &&
      typeof parsed.value === "object" &&
      !Array.isArray(parsed.value)
    ) {
      setYamlError(null);
      onValidityChange?.(true);
      const parsedValues = parsed.value as Record<string, unknown>;
      setFieldValues(createPluginConfigFormValues(fields, parsedValues));
      onChange(parsedValues);
      return;
    }

    setYamlError("插件配置必须是 YAML 对象");
    onValidityChange?.(false);
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Tabs
          value={mode}
          onValueChange={(value) => handleModeChange(value as typeof mode)}
        >
          <TabsList className="grid w-44 grid-cols-2">
            <TabsTrigger value="fields">{fieldLabel}</TabsTrigger>
            <TabsTrigger value="yaml">{yamlLabel}</TabsTrigger>
          </TabsList>
        </Tabs>
        {yamlError && mode === "yaml" && (
          <Badge
            variant="destructive"
            className="h-auto gap-1 whitespace-normal py-1"
          >
            <AlertCircle className="h-3.5 w-3.5" />
            {yamlError}
          </Badge>
        )}
      </div>

      {mode === "fields" ? (
        <PluginConfigFieldsEditor
          fields={fields}
          plugins={plugins}
          values={fieldValues}
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
          variant="plugin-args"
          plugins={plugins}
          pluginKind={pluginKind}
          fields={fields}
          currentPluginName={currentPluginName}
        />
      )}
    </div>
  );
}

function isAlreadyArgsLevelSchema(fields: ConfigField[]) {
  return fields.length === 1 && fields[0]?.key === "args";
}
