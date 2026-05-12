"use client";

import { Suspense, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "next/navigation";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { AppHeader } from "@/components/shell/app-header";
import { PluginCard } from "@/components/plugins/plugin-card";
import { CreatePluginDialog } from "@/components/plugins/create-plugin-dialog";
import { useAppStore } from "@/lib/store";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Search, LayoutGrid, List, Pin, GitBranch } from "lucide-react";
import type { PluginInstance, PluginType } from "@/lib/types";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import type {
  DependencyGraphEdge,
  DependencyGraphNode,
  DependencyGraphReport,
  SequenceFlowExpression,
  SequenceFlowReport,
} from "@/lib/oxidns-api";
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
  const [viewMode, setViewMode] = useState<"grid" | "table" | "topology">(
    "grid",
  );
  const [search, setSearch] = useState("");

  const plugins = useAppStore((s) => s.plugins);
  const dependencyGraph = useAppStore((s) => s.dependencyGraph);
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
                <Button
                  variant={viewMode === "topology" ? "secondary" : "ghost"}
                  size="sm"
                  className="rounded-l-none"
                  onClick={() => setViewMode("topology")}
                >
                  <GitBranch className="h-4 w-4" />
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
            {viewMode !== "topology" && (
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
            )}

            <TabsContent
              value={activeTab}
              className={viewMode === "topology" ? "mt-0" : "mt-6"}
            >
              {viewMode === "grid" ? (
                <div className="grid items-stretch gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {filteredPlugins.map((plugin) => (
                    <PluginCard key={plugin.id} plugin={plugin} />
                  ))}
                </div>
              ) : viewMode === "table" ? (
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
              ) : (
                <TopologyView
                  plugins={plugins}
                  dependencyGraph={dependencyGraph}
                  onSelect={handleRowClick}
                />
              )}

              {viewMode !== "topology" && filteredPlugins.length === 0 && (
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

function TopologyView({
  plugins,
  dependencyGraph,
  onSelect,
}: {
  plugins: PluginInstance[];
  dependencyGraph: DependencyGraphReport | null;
  onSelect: (plugin: PluginInstance) => void;
}) {
  const [selectedRoot, setSelectedRoot] = useState<string | null>(null);

  const topology = useMemo(() => {
    if (!dependencyGraph) return null;
    return buildTopologyModel(dependencyGraph, plugins);
  }, [dependencyGraph, plugins]);

  if (!dependencyGraph) {
    return (
      <div className="rounded-lg border border-dashed p-12 text-center text-sm text-muted-foreground">
        暂无依赖图，请先读取并校验配置。
      </div>
    );
  }

  if (!topology) return null;

  const activeRoot =
    topology.roots.find((root) => root.tag === selectedRoot)?.tag ??
    topology.roots[0]?.tag;
  const visibleTags = activeRoot
    ? (topology.reachableByRoot.get(activeRoot) ?? new Set([activeRoot]))
    : new Set<string>();
  const layout = layoutTopology(topology, activeRoot, visibleTags);

  const nodes: Node[] = layout.nodes.map(({ node, x, y, isRoot }) => ({
    id: node.tag,
    type: "topologyPlugin",
    position: { x, y },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: (
        topology.sequenceFlowsByTag.has(node.tag) ? (
          <SequenceFlowNode
            node={node}
            flow={topology.sequenceFlowsByTag.get(node.tag)!}
            isRoot={isRoot}
            plugin={plugins.find((item) => item.name === node.tag)}
            onSelect={onSelect}
          />
        ) : (
          <TopologyNodeButton
            node={node}
            isRoot={isRoot}
            plugin={plugins.find((item) => item.name === node.tag)}
            onSelect={onSelect}
          />
        )
      ),
    },
    draggable: false,
  }));

  const edges: Edge[] = topology.edges
    .filter(
      (edge) =>
        visibleTags.has(edge.source_tag) && visibleTags.has(edge.target_tag),
    )
    .map((edge, index) => ({
      id: `${edge.source_tag}-${edge.target_tag}-${index}`,
      source: edge.source_tag,
      target: edge.target_tag,
      label: formatDependencyEdgeLabel(edge),
      type: "smoothstep",
      labelBgPadding: [6, 3],
      labelBgBorderRadius: 4,
      style: { strokeWidth: 1.5 },
      className: "text-muted-foreground",
    }));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-card/50 p-2">
        {topology.roots.map((root) => (
          <Button
            key={root.tag}
            variant={activeRoot === root.tag ? "secondary" : "ghost"}
            size="sm"
            className="h-8 gap-1.5"
            onClick={() => setSelectedRoot(root.tag)}
          >
            {renderTopologyPluginIcon(root)}
            <span className="max-w-44 truncate font-mono">{root.tag}</span>
            <Badge variant="outline" className="ml-0.5 text-xs">
              {topology.reachableByRoot.get(root.tag)?.size ?? 1}
            </Badge>
          </Button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>入口插件按未被其它插件引用的根节点识别</span>
        <span>·</span>
        <span>{visibleTags.size} 个插件</span>
        <span>·</span>
        <span>
          {
            topology.edges.filter(
              (edge) =>
                visibleTags.has(edge.source_tag) &&
                visibleTags.has(edge.target_tag),
            ).length
          }{" "}
          条依赖
        </span>
      </div>

      <div className="h-[640px] rounded-lg border bg-muted/20">
        <ReactFlow
          key={activeRoot ?? "empty"}
          nodes={nodes}
          edges={edges}
          nodeTypes={topologyNodeTypes}
          fitView
          nodesDraggable={false}
        >
          <Background gap={18} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}

interface TopologyModel {
  allTags: Set<string>;
  nodesByTag: Map<string, TopologyGraphNode>;
  edges: TopologyGraphEdge[];
  edgesBySource: Map<string, TopologyGraphEdge[]>;
  edgesByTarget: Map<string, TopologyGraphEdge[]>;
  roots: TopologyGraphNode[];
  reachableByRoot: Map<string, Set<string>>;
  initIndex: Map<string, number>;
  visitIndex: Map<string, number>;
  sequenceFlowsByTag: Map<string, SequenceFlowReport>;
}

type TopologyGraphNode = DependencyGraphNode;

type TopologyGraphEdge = DependencyGraphEdge;

function buildTopologyModel(
  graph: DependencyGraphReport,
  plugins: PluginInstance[],
): TopologyModel {
  void plugins;
  const allTags = new Set(graph.nodes.map((node) => node.tag));
  const nodesByTag = new Map(graph.nodes.map((node) => [node.tag, node]));
  const referencedTags = new Set(graph.edges.map((edge) => edge.target_tag));
  const initIndex = new Map(graph.init_order.map((tag, index) => [tag, index]));
  const edgesBySource = new Map<string, TopologyGraphEdge[]>();
  const edgesByTarget = new Map<string, TopologyGraphEdge[]>();

  for (const edge of graph.edges) {
    if (!allTags.has(edge.source_tag) || !allTags.has(edge.target_tag)) continue;
    const edges = edgesBySource.get(edge.source_tag) ?? [];
    edges.push(edge);
    edgesBySource.set(edge.source_tag, edges);

    const incomingEdges = edgesByTarget.get(edge.target_tag) ?? [];
    incomingEdges.push(edge);
    edgesByTarget.set(edge.target_tag, incomingEdges);
  }

  for (const edges of edgesBySource.values()) {
    edges.sort((a, b) => {
      const fieldOrder = compareDependencyField(a.field, b.field);
      if (fieldOrder !== 0) return fieldOrder;
      return compareByInitOrder(a.target_tag, b.target_tag, initIndex);
    });
  }

  const roots = graph.nodes
    .filter((node) => !referencedTags.has(node.tag))
    .sort((a, b) => compareByInitOrder(a.tag, b.tag, initIndex));
  const fallbackRoots =
    roots.length > 0
      ? roots
      : graph.nodes
          .slice()
          .sort((a, b) => compareByInitOrder(a.tag, b.tag, initIndex));
  const reachableByRoot = new Map<string, Set<string>>();

  for (const root of fallbackRoots) {
    reachableByRoot.set(root.tag, collectReachableTags(root.tag, edgesBySource));
  }
  const visitIndex = buildVisitIndex(fallbackRoots, edgesBySource);

  const sequenceFlowsByTag = new Map(
    (graph.sequence_flows ?? []).map((flow) => [flow.tag, flow]),
  );

  return {
    allTags,
    nodesByTag,
    edges: graph.edges,
    edgesBySource,
    edgesByTarget,
    roots: fallbackRoots,
    reachableByRoot,
    initIndex,
    visitIndex,
    sequenceFlowsByTag,
  };
}

function buildVisitIndex(
  roots: TopologyGraphNode[],
  edgesBySource: Map<string, TopologyGraphEdge[]>,
) {
  const visitIndex = new Map<string, number>();
  const stack = roots
    .slice()
    .reverse()
    .map((root) => root.tag);
  let index = 0;

  while (stack.length > 0) {
    const tag = stack.pop();
    if (!tag || visitIndex.has(tag)) continue;
    visitIndex.set(tag, index);
    index += 1;

    for (const edge of (edgesBySource.get(tag) ?? []).slice().reverse()) {
      stack.push(edge.target_tag);
    }
  }

  return visitIndex;
}

function collectReachableTags(
  rootTag: string,
  edgesBySource: Map<string, TopologyGraphEdge[]>,
) {
  const visited = new Set<string>();
  const stack = [rootTag];

  while (stack.length > 0) {
    const tag = stack.pop();
    if (!tag || visited.has(tag)) continue;
    visited.add(tag);

    for (const edge of edgesBySource.get(tag) ?? []) {
      stack.push(edge.target_tag);
    }
  }

  return visited;
}

function layoutTopology(
  topology: TopologyModel,
  activeRoot: string | undefined,
  visibleTags: Set<string>,
) {
  const xGap = 460;
  const yGap = 180;
  const minYGap = 140;
  const roots = topology.roots.filter((root) => root.tag === activeRoot);

  const rootTags = new Set(roots.map((root) => root.tag));
  const depthByTag = new Map<string, number>();
  const stack = roots.map((root) => ({ tag: root.tag, depth: 0 }));

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || !visibleTags.has(current.tag)) continue;
    const previousDepth = depthByTag.get(current.tag);
    if (previousDepth !== undefined && previousDepth >= current.depth) continue;
    depthByTag.set(current.tag, current.depth);

    for (const edge of topology.edgesBySource.get(current.tag) ?? []) {
      stack.push({ tag: edge.target_tag, depth: current.depth + 1 });
    }
  }

  for (const tag of visibleTags) {
    if (!depthByTag.has(tag)) depthByTag.set(tag, 0);
  }

  const tags = Array.from(visibleTags).sort((a, b) => {
    const depthOrder = (depthByTag.get(a) ?? 0) - (depthByTag.get(b) ?? 0);
    if (depthOrder !== 0) return depthOrder;
    const visitOrder =
      (topology.visitIndex.get(a) ?? Number.MAX_SAFE_INTEGER) -
      (topology.visitIndex.get(b) ?? Number.MAX_SAFE_INTEGER);
    if (visitOrder !== 0) return visitOrder;
    return compareByInitOrder(a, b, topology.initIndex);
  });
  const yByTag = new Map<string, number>();
  const occupiedByDepth = new Map<number, number[]>();

  roots.forEach((root, index) => {
    yByTag.set(root.tag, index * yGap);
    occupiedByDepth.set(0, [...(occupiedByDepth.get(0) ?? []), index * yGap]);
  });

  for (const tag of tags) {
    if (yByTag.has(tag)) continue;
    const depth = depthByTag.get(tag) ?? 0;
    const parentYs = (topology.edgesByTarget.get(tag) ?? [])
      .filter((edge) => visibleTags.has(edge.source_tag))
      .map((edge) => yByTag.get(edge.source_tag))
      .filter((y): y is number => y !== undefined);
    const fallbackIndex = occupiedByDepth.get(depth)?.length ?? 0;
    const desiredY =
      parentYs.length > 0
        ? parentYs.reduce((sum, y) => sum + y, 0) / parentYs.length
        : fallbackIndex * yGap;
    const y = resolveAvailableY(
      desiredY,
      occupiedByDepth.get(depth) ?? [],
      minYGap,
    );
    yByTag.set(tag, y);
    occupiedByDepth.set(depth, [...(occupiedByDepth.get(depth) ?? []), y]);
  }

  return {
    nodes: tags.flatMap((tag) => {
      const node = topology.nodesByTag.get(tag);
      if (!node) return [];
      const depth = depthByTag.get(tag) ?? 0;
      return [
        {
          node,
          x: depth * xGap,
          y: yByTag.get(tag) ?? 0,
          isRoot: rootTags.has(tag),
        },
      ];
    }),
  };
}

function resolveAvailableY(desiredY: number, occupied: number[], minGap: number) {
  let y = desiredY;
  while (occupied.some((used) => Math.abs(used - y) < minGap)) {
    y += minGap;
  }
  return y;
}

function compareByInitOrder(
  a: string,
  b: string,
  initIndex: Map<string, number>,
) {
  const left = initIndex.get(a) ?? Number.MAX_SAFE_INTEGER;
  const right = initIndex.get(b) ?? Number.MAX_SAFE_INTEGER;
  if (left !== right) return left - right;
  return a.localeCompare(b);
}

function compareDependencyField(a: string, b: string) {
  const left = tokenizeDependencyField(a);
  const right = tokenizeDependencyField(b);
  const length = Math.max(left.length, right.length);

  for (let index = 0; index < length; index += 1) {
    const leftToken = left[index];
    const rightToken = right[index];
    if (leftToken === undefined) return -1;
    if (rightToken === undefined) return 1;
    if (typeof leftToken === "number" && typeof rightToken === "number") {
      if (leftToken !== rightToken) return leftToken - rightToken;
      continue;
    }
    const order = String(leftToken).localeCompare(String(rightToken));
    if (order !== 0) return order;
  }

  return a.localeCompare(b);
}

function tokenizeDependencyField(field: string) {
  return Array.from(field.matchAll(/[A-Za-z0-9_]+|\[(\d+)\]/g)).map((match) =>
    match[1] === undefined ? match[0] : Number(match[1]),
  );
}

function formatDependencyEdgeLabel(edge: DependencyGraphEdge) {
  return edge.field
    .replace(/^args\[(\d+)\]\.matches\[(\d+)\]/, "#$1 match[$2]")
    .replace(/^args\[(\d+)\]\.exec/, "#$1 exec")
    .replace(" -> quick_setup", " -> quick");
}

function SequenceFlowNode({
  node,
  flow,
  isRoot,
  plugin,
  onSelect,
}: {
  node: TopologyGraphNode;
  flow: SequenceFlowReport;
  isRoot: boolean;
  plugin?: PluginInstance;
  onSelect: (plugin: PluginInstance) => void;
}) {
  return (
    <div
      role={plugin ? "button" : undefined}
      tabIndex={plugin ? 0 : undefined}
      className={cn(
        "w-[25rem] cursor-pointer rounded-md border px-3 py-2 text-left shadow-sm transition-colors hover:border-primary",
        topologyKindSurfaceColors(node.kind),
      )}
      onClick={() => {
        if (plugin) onSelect(plugin);
      }}
      onKeyDown={(event) => {
        if (!plugin || (event.key !== "Enter" && event.key !== " ")) return;
        event.preventDefault();
        onSelect(plugin);
      }}
    >
      <div className="flex items-center gap-2">
        <span className={cn("shrink-0", topologyKindTextColor(node.kind))}>
          {renderTopologyPluginIcon(node)}
        </span>
        <div className="min-w-0 flex-1 truncate font-mono text-sm font-medium">
          {node.tag}
        </div>
        {isRoot && (
          <Badge variant="outline" className="border-primary bg-background text-primary">
            入口
          </Badge>
        )}
        <Badge variant="outline" className={topologyKindBadgeColors(node.kind)}>
          sequence
        </Badge>
      </div>

      <div className="mt-2 max-h-72 space-y-2 overflow-auto pr-1">
        {flow.rules.map((rule, index) => (
          <div key={rule.index} className="rounded-md border bg-background p-2">
            <div className="mb-1 flex items-center gap-2 text-[11px] text-muted-foreground">
              <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-foreground">
                #{rule.index}
              </span>
              {index > 0 && <span>未命中上一条则继续</span>}
            </div>
            <div className="grid gap-2">
              <div className="flex min-w-0 items-start gap-2">
                <span className="mt-0.5 w-10 shrink-0 text-[11px] font-medium text-muted-foreground">
                  IF
                </span>
                <div className="flex min-w-0 flex-wrap gap-1">
                  {rule.matches.length === 0 ? (
                    <Badge variant="secondary" className="bg-muted">
                      always
                    </Badge>
                  ) : (
                    rule.matches.map((expression) => (
                      <SequenceExpressionChip
                        key={`${expression.field}-${expression.raw}`}
                        expression={expression}
                      />
                    ))
                  )}
                </div>
              </div>
              <div className="flex min-w-0 items-start gap-2">
                <span className="mt-0.5 w-10 shrink-0 text-[11px] font-medium text-muted-foreground">
                  THEN
                </span>
                <div className="flex min-w-0 flex-wrap gap-1">
                  {rule.exec ? (
                    <SequenceExpressionChip expression={rule.exec} />
                  ) : (
                    <Badge variant="secondary" className="bg-muted">
                      no exec
                    </Badge>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SequenceExpressionChip({
  expression,
}: {
  expression: SequenceFlowExpression;
}) {
  const label = sequenceExpressionLabel(expression);
  const detail = sequenceExpressionDetail(expression);

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className={cn(
            "max-w-56 truncate rounded-md border bg-background px-1.5 py-0.5 text-left font-mono text-[11px] hover:border-primary",
            expression.kind === "quick_setup" && "border-amber-400 text-amber-700",
            expression.kind === "builtin" && "border-primary/40 text-primary",
          )}
          onClick={(event) => event.stopPropagation()}
        >
          {label}
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-80 text-xs" align="start">
        <div className="space-y-2">
          <div className="font-medium">{label}</div>
          <div className="grid grid-cols-[4.5rem_1fr] gap-x-2 gap-y-1">
            <span className="text-muted-foreground">字段</span>
            <span className="font-mono">{expression.field}</span>
            <span className="text-muted-foreground">类型</span>
            <span>{expression.kind}</span>
            {detail.map(([key, value]) => (
              <span key={key} className="contents">
                <span className="text-muted-foreground">{key}</span>
                <span className="font-mono">{value}</span>
              </span>
            ))}
          </div>
          <pre className="max-h-40 overflow-auto rounded-md bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
            {expression.raw}
          </pre>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function sequenceExpressionLabel(expression: SequenceFlowExpression) {
  const not = expression.inverted ? "NOT " : "";
  if (expression.kind === "quick_setup") {
    const pluginType = expression.plugin_type ?? "quick";
    const param = expression.param ? ` ${compactText(expression.param, 28)}` : "";
    return `${not}quick_setup(${pluginType})${param}`;
  }
  if (expression.kind === "builtin") {
    const param = expression.param ? ` ${compactText(expression.param, 28)}` : "";
    return `${expression.builtin ?? "builtin"}${param}`;
  }
  if (expression.target_tag) return `${not}$${expression.target_tag}`;
  return `${not}${compactText(expression.raw, 36)}`;
}

function sequenceExpressionDetail(expression: SequenceFlowExpression) {
  const detail: Array<[string, string]> = [];
  if (expression.target_tag) detail.push(["目标", expression.target_tag]);
  if (expression.plugin_type) detail.push(["插件", expression.plugin_type]);
  if (expression.param) detail.push(["参数", expression.param]);
  if (expression.builtin) detail.push(["内建", expression.builtin]);
  if (expression.inverted) detail.push(["取反", "true"]);
  return detail;
}

function compactText(value: string, maxLength: number) {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}

function TopologyNodeButton({
  node,
  isRoot,
  plugin,
  onSelect,
}: {
  node: TopologyGraphNode;
  isRoot: boolean;
  plugin?: PluginInstance;
  onSelect: (plugin: PluginInstance) => void;
}) {
  return (
    <div
      role={plugin ? "button" : undefined}
      tabIndex={plugin ? 0 : undefined}
      className={cn(
        "w-56 rounded-md border px-3 py-2 text-left shadow-sm transition-colors",
        plugin && "cursor-pointer hover:border-primary",
        topologyKindSurfaceColors(node.kind),
      )}
      onClick={() => {
        if (plugin) onSelect(plugin);
      }}
      onKeyDown={(event) => {
        if (!plugin || (event.key !== "Enter" && event.key !== " ")) return;
        event.preventDefault();
        onSelect(plugin);
      }}
    >
      <div className="flex items-center gap-2">
        <span className={cn("shrink-0", topologyKindTextColor(node.kind))}>
          {renderTopologyPluginIcon(node)}
        </span>
        <div className="min-w-0 flex-1 truncate font-mono text-sm font-medium">
          {node.tag}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {isRoot && (
          <Badge variant="outline" className="border-primary bg-background text-primary">
            入口
          </Badge>
        )}
        <Badge variant="outline" className={topologyKindBadgeColors(node.kind)}>
          {node.kind}
        </Badge>
        <Badge variant="secondary" className="bg-background">
          {node.plugin_type}
        </Badge>
      </div>
    </div>
  );
}

const topologyNodeTypes = {
  topologyPlugin: TopologyPluginNode,
};

function TopologyPluginNode({ data }: NodeProps<Node<{ label: ReactNode }>>) {
  return (
    <div className="relative">
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2 !w-2 !border-border !bg-background"
      />
      {data.label}
      <Handle
        type="source"
        position={Position.Right}
        className="!h-2 !w-2 !border-border !bg-background"
      />
    </div>
  );
}

function renderTopologyPluginIcon(node: DependencyGraphNode) {
  const definition = getPluginCatalogItem(node.plugin_type);
  if (definition) {
    return renderPluginKindIcon(definition.icon, { className: "h-4 w-4" });
  }
  return renderTopologyKindIcon(node.kind);
}

function renderTopologyKindIcon(kind: string) {
  return isPluginType(kind) ? pluginTypeIcons[kind] : <GitBranch className="h-4 w-4" />;
}

function isPluginType(kind: string): kind is PluginType {
  return ["server", "executor", "matcher", "provider"].includes(kind);
}

function topologyKindSurfaceColors(kind: string) {
  switch (kind) {
    case "server":
      return "border-emerald-400 bg-emerald-50 text-emerald-950 dark:border-emerald-500 dark:bg-emerald-950 dark:text-emerald-50";
    case "executor":
      return "border-sky-400 bg-sky-50 text-sky-950 dark:border-sky-500 dark:bg-sky-950 dark:text-sky-50";
    case "matcher":
      return "border-amber-400 bg-amber-50 text-amber-950 dark:border-amber-500 dark:bg-amber-950 dark:text-amber-50";
    case "provider":
      return "border-indigo-400 bg-indigo-50 text-indigo-950 dark:border-indigo-500 dark:bg-indigo-950 dark:text-indigo-50";
    default:
      return "border-border bg-background";
  }
}

function topologyKindTextColor(kind: string) {
  switch (kind) {
    case "server":
      return "text-emerald-700 dark:text-emerald-300";
    case "executor":
      return "text-sky-700 dark:text-sky-300";
    case "matcher":
      return "text-amber-700 dark:text-amber-300";
    case "provider":
      return "text-indigo-700 dark:text-indigo-300";
    default:
      return "text-muted-foreground";
  }
}

function topologyKindBadgeColors(kind: string) {
  switch (kind) {
    case "server":
      return "border-emerald-500 bg-white text-emerald-700 dark:bg-emerald-950 dark:text-emerald-200";
    case "executor":
      return "border-sky-500 bg-white text-sky-700 dark:bg-sky-950 dark:text-sky-200";
    case "matcher":
      return "border-amber-500 bg-white text-amber-700 dark:bg-amber-950 dark:text-amber-200";
    case "provider":
      return "border-indigo-500 bg-white text-indigo-700 dark:bg-indigo-950 dark:text-indigo-200";
    default:
      return "border-border bg-background text-muted-foreground";
  }
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
