"use client";

import { useState } from "react";
import type React from "react";
import { SheetTitle } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Pencil, Pin, PinOff, Save, Trash2 } from "lucide-react";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import type { PluginDetailTemplateProps, PluginSummaryItem } from "./types";
import { pluginTypeColors, pluginTypeIcons } from "./display";
import { getPluginCatalogItem, renderPluginKindIcon } from "./catalog";
import { PluginConfigModeEditor } from "./plugin-config-mode-editor";
import { PluginMetricsPanel } from "./plugin-metrics-panel";

export function PluginDetailTemplate({
  plugin,
  onClose,
  icon,
  summaryItems,
  configContent,
  metricsContent,
}: PluginDetailTemplateProps) {
  const {
    togglePluginPin,
    deletePlugin,
    updatePluginConfig,
    renamePlugin,
    saveConfig,
    isConfigSaving,
    plugins,
    dependencyGraph,
  } = useAppStore();
  const hasMetricSeries = useAppStore(
    (s) => (s.pluginMetrics[plugin.name]?.length ?? 0) > 0,
  );
  const definition = getPluginCatalogItem(plugin.pluginKind);
  const resolvedIcon =
    icon ??
    (definition
      ? renderPluginKindIcon(definition.icon, { className: "h-5 w-5" })
      : pluginTypeIcons[plugin.type]);
  const [configJson, setConfigJson] = useState(() =>
    JSON.stringify(plugin.config, null, 2),
  );
  const [configValues, setConfigValues] = useState<Record<string, unknown>>(
    () => (definition ? plugin.config : {}),
  );
  const [editingName, setEditingName] = useState(false);
  const [editingConfig, setEditingConfig] = useState(false);
  const [configValid, setConfigValid] = useState(true);
  const [newName, setNewName] = useState(plugin.name);

  const handleSaveConfig = async () => {
    if (!configValid) return;
    if (definition) {
      updatePluginConfig(plugin.id, configValues);
      try {
        await saveConfig();
        setEditingConfig(false);
      } catch {
        // Store-level error badge is shown in the full config editor.
      }
      return;
    }

    try {
      updatePluginConfig(plugin.id, JSON.parse(configJson));
      await saveConfig();
      setEditingConfig(false);
    } catch {
      // Invalid JSON. Validation UI can be added once backend config errors are wired in.
    }
  };

  const handleCancelConfigEdit = () => {
    setConfigJson(JSON.stringify(plugin.config, null, 2));
    setConfigValues(definition ? plugin.config : {});
    setConfigValid(true);
    setEditingConfig(false);
  };

  const handleSaveName = () => {
    if (newName.trim()) {
      renamePlugin(plugin.id, newName.trim());
      setEditingName(false);
    }
  };

  const resolvedSummaryItems = summaryItems ?? [];
  const hasStatsContent =
    metricsContent !== undefined &&
    metricsContent !== null &&
    metricsContent !== false;
  const visibleTabCount =
    1 + (hasStatsContent ? 1 : 0) + (hasMetricSeries ? 1 : 0);

  return (
    <div className="flex min-h-full flex-col">
      <header className="border-b bg-sidebar/70 px-5 py-5 pr-24">
        <div className="flex min-w-0 items-start gap-4">
          <div className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-primary/20 bg-primary/12 text-primary [&_svg]:size-5">
            {resolvedIcon}
          </div>
          <div className="min-w-0 flex-1 pt-0.5">
            {editingName ? (
              <div className="flex items-center gap-2">
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="h-9 font-mono text-lg"
                  onKeyDown={(e) => e.key === "Enter" && handleSaveName()}
                />
                <Button size="icon-sm" onClick={handleSaveName}>
                  <Save className="h-4 w-4" />
                </Button>
              </div>
            ) : (
              <SheetTitle
                className="cursor-pointer truncate font-mono text-xl font-semibold leading-none transition-colors hover:text-primary"
                onClick={() => setEditingName(true)}
              >
                {plugin.name}
              </SheetTitle>
            )}
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Badge
                variant="outline"
                className={cn("gap-1", pluginTypeColors[plugin.type])}
              >
                {PLUGIN_TYPE_LABELS[plugin.type]}
              </Badge>
              <Badge variant="outline" className="bg-background/70">
                {definition?.name ?? plugin.pluginKind}
              </Badge>
            </div>
            {definition?.description && (
              <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
                {definition.description}
              </p>
            )}
          </div>
        </div>

        {resolvedSummaryItems.length > 0 && (
          <div className="mt-5 grid grid-cols-3 gap-2">
            {resolvedSummaryItems.map((item) => (
              <SummaryItem key={item.label} item={item} />
            ))}
          </div>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => togglePluginPin(plugin.id)}
          >
            {plugin.pinned ? (
              <>
                <PinOff className="mr-1.5 h-4 w-4" />
                取消固定
              </>
            ) : (
              <>
                <Pin className="mr-1.5 h-4 w-4" />
                固定
              </>
            )}
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="text-destructive hover:text-destructive"
              >
                <Trash2 className="mr-1.5 h-4 w-4" />
                删除
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>确认删除</AlertDialogTitle>
                <AlertDialogDescription>
                  确定要删除插件 &ldquo;{plugin.name}&rdquo;
                  吗？此操作无法撤销。
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>取消</AlertDialogCancel>
                <AlertDialogAction
                  onClick={() => {
                    deletePlugin(plugin.id);
                    onClose();
                  }}
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  删除
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </header>

      <Tabs defaultValue="config" className="flex-1 px-5 py-5">
        <TabsList
          className={cn(
            "grid w-full",
            visibleTabCount === 1 && "grid-cols-1",
            visibleTabCount === 2 && "grid-cols-2",
            visibleTabCount === 3 && "grid-cols-3",
          )}
        >
          <TabsTrigger value="config">配置</TabsTrigger>
          {hasStatsContent && <TabsTrigger value="stats">统计</TabsTrigger>}
          {hasMetricSeries && <TabsTrigger value="metrics">指标</TabsTrigger>}
        </TabsList>

        <TabsContent value="config" className="mt-4 space-y-4">
          {configContent ?? (
            <Card>
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-sm">配置</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 p-4 pt-0">
                {definition ? (
                  <PluginConfigModeEditor
                    key={plugin.id}
                    fields={definition.configSchema}
                    plugins={plugins}
                    values={configValues}
                    onChange={setConfigValues}
                    onValidityChange={setConfigValid}
                    defaultArrayObjectCollapsed={!editingConfig}
                    readOnly={!editingConfig}
                    pluginKind={plugin.pluginKind}
                    currentPluginName={plugin.name}
                  />
                ) : (
                  <Textarea
                    value={configJson}
                    onChange={(event) => setConfigJson(event.target.value)}
                    className="min-h-[220px] font-mono text-sm"
                    disabled={!editingConfig}
                  />
                )}
                <div className="flex justify-end gap-2">
                  {editingConfig ? (
                    <>
                      <Button
                        key="cancel-config-edit"
                        variant="outline"
                        onClick={handleCancelConfigEdit}
                      >
                        取消
                      </Button>
                      <Button
                        key="save-config-edit"
                        onClick={handleSaveConfig}
                        disabled={!configValid || isConfigSaving}
                      >
                        <Save className="mr-1.5 h-4 w-4" />
                        {isConfigSaving ? "保存中" : "保存配置"}
                      </Button>
                    </>
                  ) : (
                    <Button
                      key="start-config-edit"
                      onClick={() => setEditingConfig(true)}
                    >
                      <Pencil className="mr-1.5 h-4 w-4" />
                      编辑配置
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
          <DependencySection
            tag={plugin.name}
            dependencyGraph={dependencyGraph}
          />
        </TabsContent>

        {hasStatsContent && (
          <TabsContent value="stats" className="mt-4 space-y-4">
            {metricsContent}
          </TabsContent>
        )}

        {hasMetricSeries && (
          <TabsContent value="metrics" className="mt-4 space-y-4">
            <PluginMetricsPanel tag={plugin.name} />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

function DependencySection({
  tag,
  dependencyGraph,
}: {
  tag: string;
  dependencyGraph: ReturnType<typeof useAppStore.getState>["dependencyGraph"];
}) {
  if (!dependencyGraph) return null;
  const initIndex = dependencyGraph.init_order.indexOf(tag);
  const upstream = dependencyGraph.edges.filter(
    (edge) => edge.source_tag === tag,
  );
  const downstream = dependencyGraph.edges.filter(
    (edge) => edge.target_tag === tag,
  );

  return (
    <Card>
      <CardHeader className="p-4 pb-2">
        <CardTitle className="text-sm">依赖关系</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3 p-4 pt-0 text-sm sm:grid-cols-3">
        <SummaryItem
          item={{
            label: "初始化序号",
            value: initIndex >= 0 ? String(initIndex + 1) : "-",
          }}
        />
        <SummaryItem
          item={{ label: "依赖插件", value: String(upstream.length) }}
        />
        <SummaryItem
          item={{ label: "被引用", value: String(downstream.length) }}
        />
        <div className="space-y-1 sm:col-span-3">
          {[...upstream, ...downstream].length ? (
            [...upstream, ...downstream].map((edge) => (
              <div
                key={`${edge.source_tag}-${edge.target_tag}-${edge.field}`}
                className="truncate rounded-md border px-2 py-1 font-mono text-xs text-muted-foreground"
              >
                {edge.source_tag}.{edge.field} -&gt; {edge.target_tag}
              </div>
            ))
          ) : (
            <div className="rounded-md border border-dashed px-3 py-2 text-muted-foreground">
              暂无依赖边
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function SummaryItem({ item }: { item: PluginSummaryItem }) {
  return (
    <div className="rounded-lg border border-border/70 bg-background/70 px-3 py-2">
      <div className="text-xs text-muted-foreground">{item.label}</div>
      <div className="mt-1 truncate font-mono text-sm font-semibold">
        {item.value}
      </div>
    </div>
  );
}
