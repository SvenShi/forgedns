"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AppHeader } from "@/components/shell/app-header";
import { PluginCard } from "@/components/plugins/plugin-card";
import { CreatePluginDialog } from "@/components/plugins/create-plugin-dialog";
import { useAppStore } from "@/lib/store";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Search, LayoutGrid, List, Pin } from "lucide-react";
import type { PluginType } from "@/lib/types";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  getPluginCatalogItem,
  renderPluginKindIcon,
} from "@/components/plugins/catalog";
import {
  pluginTypeColors,
  pluginTypeIcons,
} from "@/components/plugins/display";

export default function PluginsPage() {
  return (
    <Suspense fallback={<PluginsPageFallback />}>
      <PluginsPageContent />
    </Suspense>
  );
}

function PluginsPageContent() {
  const searchParams = useSearchParams();
  const initialType = searchParams.get("type") as PluginType | null;
  const [activeTab, setActiveTab] = useState<PluginType | "all">(
    initialType || "all",
  );
  const [viewMode, setViewMode] = useState<"grid" | "table">("grid");
  const [search, setSearch] = useState("");

  const plugins = useAppStore((s) => s.plugins);
  const { setSelectedPlugin, setDetailOpen } = useAppStore();

  const filteredPlugins = plugins.filter((p) => {
    const definition = getPluginCatalogItem(p.pluginKind);
    const normalizedSearch = search.toLowerCase();
    const matchesType = activeTab === "all" || p.type === activeTab;
    const matchesSearch =
      p.name.toLowerCase().includes(normalizedSearch) ||
      p.pluginKind.toLowerCase().includes(normalizedSearch) ||
      (definition?.name.toLowerCase().includes(normalizedSearch) ?? false) ||
      (definition?.description.toLowerCase().includes(normalizedSearch) ??
        false);
    return matchesType && matchesSearch;
  });

  const pluginsByType = {
    server: plugins.filter((p) => p.type === "server"),
    executor: plugins.filter((p) => p.type === "executor"),
    matcher: plugins.filter((p) => p.type === "matcher"),
    provider: plugins.filter((p) => p.type === "provider"),
  };

  const handleRowClick = (plugin: (typeof plugins)[0]) => {
    setSelectedPlugin(plugin);
    setDetailOpen(true);
  };

  return (
    <>
      <AppHeader title="插件中心" />
      <main className="flex-1 overflow-auto p-6">
        <div className="space-y-6">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3 flex-1 min-w-[200px] max-w-md">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="搜索插件名称或类型..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center border rounded-md">
                <Button
                  variant={viewMode === "grid" ? "secondary" : "ghost"}
                  size="sm"
                  className="rounded-r-none"
                  onClick={() => setViewMode("grid")}
                >
                  <LayoutGrid className="h-4 w-4" />
                </Button>
                <Button
                  variant={viewMode === "table" ? "secondary" : "ghost"}
                  size="sm"
                  className="rounded-l-none"
                  onClick={() => setViewMode("table")}
                >
                  <List className="h-4 w-4" />
                </Button>
              </div>
              <CreatePluginDialog
                defaultType={activeTab !== "all" ? activeTab : undefined}
              />
            </div>
          </div>

          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as PluginType | "all")}
          >
            <TabsList>
              <TabsTrigger value="all">
                全部
                <Badge variant="secondary" className="ml-1.5 text-xs">
                  {plugins.length}
                </Badge>
              </TabsTrigger>
              {(Object.keys(pluginsByType) as PluginType[]).map((type) => (
                <TabsTrigger key={type} value={type} className="gap-1.5">
                  {pluginTypeIcons[type]}
                  {PLUGIN_TYPE_LABELS[type]}
                  <Badge variant="secondary" className="ml-1 text-xs">
                    {pluginsByType[type].length}
                  </Badge>
                </TabsTrigger>
              ))}
            </TabsList>

            <TabsContent value={activeTab} className="mt-6">
              {viewMode === "grid" ? (
                <div className="grid items-stretch gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {filteredPlugins.map((plugin) => (
                    <PluginCard key={plugin.id} plugin={plugin} />
                  ))}
                </div>
              ) : (
                <div className="border rounded-lg overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>名称</TableHead>
                        <TableHead>类型</TableHead>
                        <TableHead>插件</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredPlugins.map((plugin) => (
                        <TableRow
                          key={plugin.id}
                          className="cursor-pointer"
                          onClick={() => handleRowClick(plugin)}
                        >
                          <TableCell className="font-mono font-medium">
                            <div className="flex items-center gap-2">
                              {plugin.name}
                              {plugin.pinned && (
                                <Pin className="h-3 w-3 text-primary" />
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={cn(
                                "gap-1",
                                pluginTypeColors[plugin.type],
                              )}
                            >
                              {pluginTypeIcons[plugin.type]}
                              {PLUGIN_TYPE_LABELS[plugin.type]}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <PluginKindBadge pluginKind={plugin.pluginKind} />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}

              {filteredPlugins.length === 0 && (
                <div className="border border-dashed rounded-lg p-12 text-center text-muted-foreground">
                  <p>没有找到匹配的插件</p>
                  {search && (
                    <p className="text-sm mt-1">
                      尝试调整搜索条件或
                      <button
                        onClick={() => setSearch("")}
                        className="text-primary hover:underline ml-1"
                      >
                        清除搜索
                      </button>
                    </p>
                  )}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </>
  );
}

function PluginsPageFallback() {
  return (
    <>
      <AppHeader title="插件中心" />
      <main className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border border-dashed p-12 text-center text-sm text-muted-foreground">
          正在加载插件中心...
        </div>
      </main>
    </>
  );
}

function PluginKindBadge({ pluginKind }: { pluginKind: string }) {
  const definition = getPluginCatalogItem(pluginKind);

  return (
    <Badge variant="outline" className="gap-1.5">
      {definition &&
        renderPluginKindIcon(definition.icon, { className: "h-3 w-3" })}
      {definition?.name ?? pluginKind}
    </Badge>
  );
}
