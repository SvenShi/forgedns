/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

"use client";

import { useState } from "react";
import { Pencil, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAppStore } from "@/lib/store";
import type {
  PluginComponentDefinition,
  PluginDetailComponentProps,
} from "@/components/plugins/types";
import { PluginDetailTemplate } from "@/components/plugins/plugin-detail-template";
import {
  SequenceComposer,
  parseSequenceRules,
} from "@/components/plugins/sequence-composer";

function SequenceDetail({ plugin, chartData, onClose }: PluginDetailComponentProps) {
  const updatePluginConfig = useAppStore((state) => state.updatePluginConfig);
  const plugins = useAppStore((state) => state.plugins);
  const [editing, setEditing] = useState(false);
  const [configValues, setConfigValues] = useState<Record<string, unknown>>(
    () => plugin.config,
  );

  const handleCancel = () => {
    setConfigValues(plugin.config);
    setEditing(false);
  };

  const handleSave = () => {
    updatePluginConfig(plugin.id, configValues);
    setEditing(false);
  };

  return (
    <PluginDetailTemplate
      plugin={plugin}
      chartData={chartData}
      onClose={onClose}
      summaryItems={[
        {
          label: "规则数",
          value: String(parseSequenceRules(plugin.config.args).length),
        },
      ]}
      configContent={
        <Card>
          <CardHeader className="grid grid-cols-[1fr_auto] items-center p-4 pb-2">
            <CardTitle className="text-sm">Sequence 编排</CardTitle>
            <div className="flex gap-2">
              {editing ? (
                <>
                  <Button variant="outline" size="sm" onClick={handleCancel}>
                    取消
                  </Button>
                  <Button size="sm" onClick={handleSave}>
                    <Save className="h-4 w-4" />
                    保存配置
                  </Button>
                </>
              ) : (
                <Button size="sm" onClick={() => setEditing(true)}>
                  <Pencil className="h-4 w-4" />
                  编辑配置
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <SequenceComposer
              value={configValues}
              onChange={setConfigValues}
              plugins={plugins}
              readOnly={!editing}
              currentSequenceName={plugin.name}
            />
          </CardContent>
        </Card>
      }
    />
  );
}

export const sequencePlugin: PluginComponentDefinition = {
  Detail: SequenceDetail,
};
