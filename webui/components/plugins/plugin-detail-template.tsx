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
import {
  Pencil,
  Pin,
  PinOff,
  Power,
  PowerOff,
  RefreshCw,
  Save,
  Trash2,
} from "lucide-react";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import type { PluginDetailTemplateProps, PluginSummaryItem } from "./types";
import { pluginTypeColors, pluginTypeIcons } from "./display";
import { getPluginCatalogItem, renderPluginKindIcon } from "./catalog";
import {
  createPluginConfigFormValues,
  PluginConfigFieldsEditor,
  serializePluginConfigValues,
} from "./plugin-config-fields-editor";

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
    togglePluginEnabled,
    deletePlugin,
    updatePluginConfig,
    renamePlugin,
    plugins,
  } = useAppStore();
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
    () =>
      definition
        ? createPluginConfigFormValues(definition.configSchema, plugin.config)
        : {},
  );
  const [editingName, setEditingName] = useState(false);
  const [editingConfig, setEditingConfig] = useState(false);
  const [newName, setNewName] = useState(plugin.name);

  const handleSaveConfig = () => {
    if (definition) {
      updatePluginConfig(
        plugin.id,
        serializePluginConfigValues(definition.configSchema, configValues),
      );
      setEditingConfig(false);
      return;
    }

    try {
      updatePluginConfig(plugin.id, JSON.parse(configJson));
      setEditingConfig(false);
    } catch {
      // Invalid JSON. Validation UI can be added once backend config errors are wired in.
    }
  };

  const handleCancelConfigEdit = () => {
    setConfigJson(JSON.stringify(plugin.config, null, 2));
    setConfigValues(
      definition
        ? createPluginConfigFormValues(definition.configSchema, plugin.config)
        : {},
    );
    setEditingConfig(false);
  };

  const handleSaveName = () => {
    if (newName.trim()) {
      renamePlugin(plugin.id, newName.trim());
      setEditingName(false);
    }
  };

  const resolvedSummaryItems = summaryItems ?? [];

  return (
    <div className="flex min-h-full flex-col">
      <header className="border-b bg-sidebar/70 px-5 py-5 pr-14">
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
          <Button
            variant="outline"
            size="sm"
            onClick={() => togglePluginEnabled(plugin.id)}
          >
            {plugin.enabled ? (
              <>
                <PowerOff className="mr-1.5 h-4 w-4" />
                禁用
              </>
            ) : (
              <>
                <Power className="mr-1.5 h-4 w-4" />
                启用
              </>
            )}
          </Button>
          <Button variant="outline" size="sm">
            <RefreshCw className="mr-1.5 h-4 w-4" />
            重载
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
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="config">配置</TabsTrigger>
          <TabsTrigger value="metrics">统计</TabsTrigger>
        </TabsList>

        <TabsContent value="config" className="mt-4 space-y-4">
          {configContent ?? (
            <Card>
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-sm">配置</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 p-4 pt-0">
                {definition ? (
                  <PluginConfigFieldsEditor
                    fields={definition.configSchema}
                    plugins={plugins}
                    values={configValues}
                    onChange={setConfigValues}
                    defaultArrayObjectCollapsed={!editingConfig}
                    readOnly={!editingConfig}
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
                      <Button key="save-config-edit" onClick={handleSaveConfig}>
                        <Save className="mr-1.5 h-4 w-4" />
                        保存配置
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
        </TabsContent>

        <TabsContent value="metrics" className="mt-4 space-y-4">
          {metricsContent ?? (
            <Card>
              <CardContent className="p-6 text-sm text-muted-foreground">
                此插件没有可展示的统计信息。
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
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
