"use client";

import { useState, useMemo } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import {
  Plus,
  Server,
  Cog,
  Filter,
  Database,
  ArrowLeft,
  Search,
} from "lucide-react";
import { useAppStore } from "@/lib/store";
import type { PluginType } from "@/lib/types";
import { PLUGIN_TYPE_LABELS, PLUGIN_TYPE_DESCRIPTIONS } from "@/lib/types";
import {
  getPluginCatalogItemsByType,
  getPluginKindIconComponent,
  type PluginCatalogItem,
} from "@/components/plugins/catalog";
import {
  createDefaultPluginConfigValues,
  isPluginConfigFormValid,
} from "@/components/plugins/plugin-config-fields-editor";
import { PluginConfigModeEditor } from "@/components/plugins/plugin-config-mode-editor";
import { SequenceComposer } from "@/components/plugins/sequence-composer";

const typeIcons: Record<PluginType, React.ReactNode> = {
  server: <Server className="h-4 w-4" />,
  executor: <Cog className="h-4 w-4" />,
  matcher: <Filter className="h-4 w-4" />,
  provider: <Database className="h-4 w-4" />,
};

interface CreatePluginDialogProps {
  defaultType?: PluginType;
  supportedPluginKinds?: string[];
}

export function CreatePluginDialog({
  defaultType,
  supportedPluginKinds,
}: CreatePluginDialogProps) {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<PluginType>(
    defaultType || "server",
  );
  const [selectedKind, setSelectedKind] = useState<PluginCatalogItem | null>(
    null,
  );
  const [instanceName, setInstanceName] = useState("");
  const [search, setSearch] = useState("");
  const [configValues, setConfigValues] = useState<Record<string, unknown>>({});
  const addPlugin = useAppStore((s) => s.addPlugin);
  const plugins = useAppStore((s) => s.plugins);

  const pluginsByType = useMemo(() => {
    const supported = supportedPluginKinds?.length
      ? new Set(supportedPluginKinds)
      : null;
    const normalizedSearch = search.trim().toLowerCase();
    const byType = (type: PluginType) => {
      const plugins = getPluginCatalogItemsByType(type);
      const supportedPlugins = supported
        ? plugins.filter((plugin) => supported.has(plugin.kind))
        : plugins;

      if (!normalizedSearch) return supportedPlugins;

      return supportedPlugins.filter((plugin) => {
        const configText = plugin.configSchema
          .map(
            (field) => `${field.key} ${field.label} ${field.description ?? ""}`,
          )
          .join(" ");
        const searchableText = [
          plugin.kind,
          plugin.name,
          plugin.description,
          PLUGIN_TYPE_LABELS[plugin.type],
          configText,
        ]
          .join(" ")
          .toLowerCase();

        return searchableText.includes(normalizedSearch);
      });
    };

    return {
      server: byType("server"),
      executor: byType("executor"),
      matcher: byType("matcher"),
      provider: byType("provider"),
    };
  }, [search, supportedPluginKinds]);

  const handleSelectKind = (kind: PluginCatalogItem) => {
    setSelectedKind(kind);
    setConfigValues(createDefaultPluginConfigValues(kind.configSchema));
    setInstanceName("");
  };

  const handleBack = () => {
    setSelectedKind(null);
    setConfigValues({});
    setInstanceName("");
  };

  const handleCreate = () => {
    if (!selectedKind || !instanceName.trim()) return;

    const processedConfig = configValues;

    addPlugin({
      name: instanceName.trim(),
      type: selectedKind.type,
      pluginKind: selectedKind.kind,
      status: "stopped",
      enabled: false,
      pinned: false,
      config: processedConfig,
    });

    handleClose();
  };

  const handleClose = () => {
    setOpen(false);
    setSelectedKind(null);
    setConfigValues({});
    setInstanceName("");
    setSearch("");
    setActiveTab(defaultType || "server");
  };

  const isValid = () => {
    if (!selectedKind || !instanceName.trim()) return false;
    return isPluginConfigFormValid(selectedKind.configSchema, configValues);
  };

  const renderPluginKindCard = (kind: PluginCatalogItem) => {
    const IconComponent = getPluginKindIconComponent(kind.icon);
    return (
      <button
        key={kind.kind}
        onClick={() => handleSelectKind(kind)}
        className="flex items-start gap-3 p-3 rounded-lg border border-border bg-card hover:bg-accent/50 hover:border-primary/50 transition-colors text-left w-full"
      >
        <div className="p-2 rounded-md bg-primary/10 text-primary shrink-0">
          <IconComponent className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="font-medium text-sm">{kind.name}</div>
          <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
            {kind.description}
          </div>
        </div>
      </button>
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        if (!isOpen && isSequenceFullscreenOpen()) return;
        if (!isOpen) handleClose();
        else setOpen(true);
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-1.5" />
          新建插件
        </Button>
      </DialogTrigger>
      <DialogContent
        className="w-[calc(100vw-2rem)] sm:!max-w-[920px] lg:!max-w-[1080px] max-h-[90vh] p-4 gap-0 overflow-hidden"
        onPointerDownOutside={(event) => {
          if (isSequenceFullscreenEvent(event)) event.preventDefault();
        }}
        onInteractOutside={(event) => {
          if (isSequenceFullscreenEvent(event)) event.preventDefault();
        }}
      >
        {!selectedKind ? (
          <>
            <DialogHeader className="px-6 pt-6 pb-4">
              <DialogTitle>添加插件</DialogTitle>
              <DialogDescription>选择要添加的插件类型</DialogDescription>
            </DialogHeader>
            <Tabs
              value={activeTab}
              onValueChange={(v) => setActiveTab(v as PluginType)}
              className="flex-1"
            >
              <div className="px-6">
                <TabsList className="w-full grid grid-cols-4">
                  {(Object.keys(PLUGIN_TYPE_LABELS) as PluginType[]).map(
                    (type) => (
                      <TabsTrigger key={type} value={type} className="gap-1.5">
                        {typeIcons[type]}
                        <span className="hidden sm:inline">
                          {PLUGIN_TYPE_LABELS[type]}
                        </span>
                      </TabsTrigger>
                    ),
                  )}
                </TabsList>
              </div>
              <div className="px-6 py-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="搜索插件名称、类型或配置项"
                    className="pl-9"
                  />
                </div>
              </div>
              <div className="px-6 pb-2">
                <p className="text-xs text-muted-foreground">
                  {PLUGIN_TYPE_DESCRIPTIONS[activeTab]}
                </p>
              </div>
              <ScrollArea className="h-[min(560px,calc(90vh-180px))] px-6">
                {(Object.keys(PLUGIN_TYPE_LABELS) as PluginType[]).map(
                  (type) => (
                    <TabsContent
                      key={type}
                      value={type}
                      className="mt-0 grid gap-3 pb-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4"
                    >
                      {pluginsByType[type].length > 0 ? (
                        pluginsByType[type].map(renderPluginKindCard)
                      ) : (
                        <div className="col-span-full rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
                          没有匹配的插件
                        </div>
                      )}
                    </TabsContent>
                  ),
                )}
              </ScrollArea>
            </Tabs>
          </>
        ) : (
          <>
            <DialogHeader className="px-6 pt-6 pb-4 border-b">
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={handleBack}
                >
                  <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                  <DialogTitle className="flex items-center gap-2">
                    配置 {selectedKind.name}
                    <Badge variant="secondary" className="font-normal">
                      {PLUGIN_TYPE_LABELS[selectedKind.type]}
                    </Badge>
                  </DialogTitle>
                  <DialogDescription className="mt-1">
                    {selectedKind.description}
                  </DialogDescription>
                </div>
              </div>
            </DialogHeader>
            <ScrollArea className="h-[min(600px,calc(90vh-180px))] px-5 py-4">
              <div className="px-1">
                <FieldGroup>
                  <Field>
                    <FieldLabel>
                      实例名称 <span className="text-destructive">*</span>
                    </FieldLabel>
                    <Input
                      value={instanceName}
                      onChange={(e) => setInstanceName(e.target.value)}
                      placeholder={`例如: ${selectedKind.kind}_main`}
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      建议使用小写字母、数字和下划线
                    </p>
                  </Field>

                  <div className="border-t pt-4 mt-2">
                    <h4 className="text-sm font-medium mb-3">插件配置</h4>
                    {selectedKind.kind === "sequence" ? (
                      <SequenceComposer
                        value={configValues}
                        onChange={setConfigValues}
                        plugins={plugins}
                        currentSequenceName={instanceName.trim() || undefined}
                      />
                    ) : (
                      <PluginConfigModeEditor
                        fields={selectedKind.configSchema}
                        plugins={plugins}
                        values={configValues}
                        onChange={setConfigValues}
                      />
                    )}
                  </div>
                </FieldGroup>
              </div>
            </ScrollArea>
            <DialogFooter className="px-6 py-4 border-t">
              <Button variant="outline" onClick={handleBack}>
                返回
              </Button>
              <Button onClick={handleCreate} disabled={!isValid()}>
                创建插件
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function isSequenceFullscreenEvent(event: Event) {
  const target = event.target;
  return (
    target instanceof Element &&
    Boolean(target.closest("[data-sequence-fullscreen='true']"))
  );
}

function isSequenceFullscreenOpen() {
  return Boolean(document.querySelector("[data-sequence-fullscreen='true']"));
}
