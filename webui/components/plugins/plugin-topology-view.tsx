"use client";

import { useMemo, useState, type ReactNode } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Panel,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ArrowRight, CornerDownRight, GitBranch } from "lucide-react";
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
  pluginKindAccentBgClass,
  pluginKindAccentHex,
  pluginKindBadgeOutlineClass,
  pluginKindIconBgClass,
  pluginTypeAccentHex,
  pluginTypeIcons,
} from "@/components/plugins/display";

// ─── Types ───────────────────────────────────────────────────────────────────

interface TopologyModel {
  allTags: Set<string>;
  nodesByTag: Map<string, DependencyGraphNode>;
  edges: DependencyGraphEdge[];
  edgesBySource: Map<string, DependencyGraphEdge[]>;
  edgesByTarget: Map<string, DependencyGraphEdge[]>;
  roots: DependencyGraphNode[];
  // Reachability computed on the FULL edge graph (used only for fallback)
  reachableByRoot: Map<string, Set<string>>;
  // Reachability computed on the filtered graph (inlined edges removed).
  // Use this to determine which nodes to actually render.
  filteredReachableByRoot: Map<string, Set<string>>;
  initIndex: Map<string, number>;
  visitIndex: Map<string, number>;
  sequenceFlowsByTag: Map<string, SequenceFlowReport>;
  // Tags rendered inline inside sequence rule rows, not as standalone graph nodes
  inlinedTags: Set<string>;
}

interface TopologyLayout {
  nodes: Array<{
    node: DependencyGraphNode;
    x: number;
    y: number;
    isRoot: boolean;
  }>;
  // Depth (0-based column index) of every laid-out node. Edges use this to
  // detect back/cycle edges and render them as a direct curved line instead
  // of trying to route them through the orthogonal grid.
  depthByTag: Map<string, number>;
}

// ─── Edge semantic classification ────────────────────────────────────────────

// Edge colour palette is derived from the plugin-type accent palette so the
// dependency-graph wires read as a natural extension of the plugin colours:
//   match edges  → matcher accent (amber)  — these target matcher plugins
//   exec edges   → executor accent (sky)   — these target executor/sequence
//   structural   → neutral slate           — generic args.entry, provider deps
//   cycle (back) → destructive red         — emphasises a config problem
const EDGE_COLOR_MATCH = pluginTypeAccentHex.matcher; // amber-500
const EDGE_COLOR_EXEC = pluginTypeAccentHex.executor; // sky-500
const EDGE_COLOR_STRUCTURAL = "#64748b"; // slate-500
const EDGE_COLOR_CYCLE = "#ef4444"; // red-500

function classifyEdge(field: string): "match" | "exec" | "structural" {
  if (/\.matches\[/.test(field)) return "match";
  if (/\.exec$/.test(field)) return "exec";
  return "structural";
}

function getEdgeStyle(field: string) {
  const kind = classifyEdge(field);
  if (kind === "match") {
    return {
      style: { stroke: EDGE_COLOR_MATCH, strokeDasharray: "5 3", strokeWidth: 1.6 },
      markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_COLOR_MATCH, width: 12, height: 12 },
      labelStyle: { fill: EDGE_COLOR_MATCH, fontSize: 10, fontFamily: "monospace", fontWeight: 600 },
    };
  }
  if (kind === "exec") {
    return {
      style: { stroke: EDGE_COLOR_EXEC, strokeWidth: 2.2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_COLOR_EXEC, width: 14, height: 14 },
      labelStyle: { fill: EDGE_COLOR_EXEC, fontSize: 10, fontFamily: "monospace", fontWeight: 600 },
    };
  }
  return {
    style: { stroke: EDGE_COLOR_STRUCTURAL, strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_COLOR_STRUCTURAL, width: 10, height: 10 },
    labelStyle: { fill: EDGE_COLOR_STRUCTURAL, fontSize: 10, fontFamily: "monospace" },
  };
}

// Style override for back / cycle edges. We deliberately switch to a straight
// line so the user can see exactly which two plugins form the cycle without
// the orthogonal router trying to route around the rest of the graph.
function cycleEdgeStyle() {
  return {
    style: {
      stroke: EDGE_COLOR_CYCLE,
      strokeWidth: 2,
      strokeDasharray: "6 3",
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: EDGE_COLOR_CYCLE,
      width: 14,
      height: 14,
    },
    labelStyle: {
      fill: EDGE_COLOR_CYCLE,
      fontSize: 10,
      fontFamily: "monospace",
      fontWeight: 700,
    },
  };
}

// Pull the rule index out of a sequence-edge field like "args[3].exec" or
// "args[2].matches[1]". Returns null for non-sequence fields (e.g. "args.entry").
function ruleIndexFromField(field: string): number | null {
  const match = field.match(/^args\[(\d+)\]/);
  return match ? Number(match[1]) : null;
}

// ─── Visual helpers ───────────────────────────────────────────────────────────
//
// All plugin-kind colour mappings live in `components/plugins/display.tsx` so
// the topology view, plugin cards, table view, and detail sheet all draw
// from the same palette. The aliases below keep the call sites short.

const kindAccentColor = pluginKindAccentHex;
const kindIconBgClass = pluginKindIconBgClass;
const kindBadgeClass = pluginKindBadgeOutlineClass;
const kindAccentBgClass = pluginKindAccentBgClass;

// ─── Main TopologyView ────────────────────────────────────────────────────────

export function TopologyView({
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
    return buildTopologyModel(dependencyGraph);
  }, [dependencyGraph]);

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
  // filteredReachableByRoot excludes nodes only reachable via inlined paths,
  // so floating "orphan" nodes (e.g. raw providers) never appear in the graph.
  const visibleTags =
    topology.filteredReachableByRoot.get(activeRoot ?? "") ??
    new Set<string>();
  const layout = layoutTopology(topology, activeRoot, visibleTags);

  const nodes: Node[] = layout.nodes.map(({ node, x, y, isRoot }) => ({
    id: node.tag,
    type: "topologyPlugin",
    position: { x, y },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: topology.sequenceFlowsByTag.has(node.tag) ? (
        <SequenceFlowNode
          node={node}
          flow={topology.sequenceFlowsByTag.get(node.tag)!}
          nodesByTag={topology.nodesByTag}
          inlinedTags={topology.inlinedTags}
          sequenceFlowsByTag={topology.sequenceFlowsByTag}
          plugins={plugins}
          isRoot={isRoot}
          onSelect={onSelect}
        />
      ) : (
        <TopologyNodeCard
          node={node}
          isRoot={isRoot}
          plugin={plugins.find((p) => p.name === node.tag)}
          onSelect={onSelect}
        />
      ),
    },
    draggable: false,
  }));

  const edges: Edge[] = topology.edges
    .filter(
      (edge) =>
        !topology.inlinedTags.has(edge.source_tag) &&
        !topology.inlinedTags.has(edge.target_tag) &&
        visibleTags.has(edge.source_tag) &&
        visibleTags.has(edge.target_tag),
    )
    .map((edge, index) => {
      // Back/cycle edge detection: edges that don't go strictly left → right
      // (source depth >= target depth) are rendered as a direct line so the
      // dependency cycle is visually obvious instead of being routed around
      // the layout by the orthogonal smoothstep router.
      const sourceDepth = layout.depthByTag.get(edge.source_tag) ?? 0;
      const targetDepth = layout.depthByTag.get(edge.target_tag) ?? 0;
      const isCycle = sourceDepth >= targetDepth;

      const { style, markerEnd, labelStyle } = isCycle
        ? cycleEdgeStyle()
        : getEdgeStyle(edge.field);

      // For sequence sources, anchor the edge on the specific rule row
      // (handle id `rule-N`) so it's obvious which #N → target the line means.
      // Falls back to the default node-level right handle when the source is
      // not a sequence or the rule's exec is not a sequence call.
      const ruleIdx = ruleIndexFromField(edge.field);
      const sourceHandle =
        topology.sequenceFlowsByTag.has(edge.source_tag) &&
        ruleIdx !== null &&
        topology.sequenceFlowsByTag.has(edge.target_tag) &&
        /\.exec$/.test(edge.field)
          ? `rule-${ruleIdx}`
          : undefined;

      return {
        id: `${edge.source_tag}-${edge.target_tag}-${index}`,
        source: edge.source_tag,
        target: edge.target_tag,
        sourceHandle,
        label: isCycle
          ? `循环 · ${formatDependencyEdgeLabel(edge)}`
          : formatDependencyEdgeLabel(edge),
        type: isCycle ? "straight" : "smoothstep",
        animated: isCycle,
        style,
        markerEnd,
        labelStyle,
        labelBgPadding: [4, 2] as [number, number],
        labelBgBorderRadius: 3,
        labelBgStyle: { fillOpacity: 0.9 },
        zIndex: isCycle ? 10 : 0,
      };
    });

  const graphNodeCount = visibleTags.size;
  // Inlined count = full reachable - filtered reachable for this root
  const fullReachable = topology.reachableByRoot.get(activeRoot ?? "") ?? new Set<string>();
  const inlinedCount = [...fullReachable].filter((t) => topology.inlinedTags.has(t)).length;

  return (
    <div className="space-y-3">
      <RootSelector
        roots={topology.roots}
        activeRoot={activeRoot}
        filteredReachableByRoot={topology.filteredReachableByRoot}
        onSelect={setSelectedRoot}
      />

      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span>{graphNodeCount} 个图节点</span>
        <span className="text-border">·</span>
        <span>{inlinedCount} 个内嵌插件</span>
        <span className="text-border">·</span>
        <span>{topology.sequenceFlowsByTag.size} 个 sequence</span>
      </div>

      <div className="h-[660px] overflow-hidden rounded-xl border bg-muted/10 shadow-sm">
        <ReactFlow
          key={activeRoot ?? "empty"}
          nodes={nodes}
          edges={edges}
          nodeTypes={topologyNodeTypes}
          fitView
          fitViewOptions={{ padding: 0.12 }}
          nodesDraggable={false}
          minZoom={0.2}
          maxZoom={2}
        >
          <Background gap={20} size={1} className="opacity-30" />
          <Controls showInteractive={false} />
          <Panel position="bottom-left">
            <TopologyLegend />
          </Panel>
        </ReactFlow>
      </div>
    </div>
  );
}

// ─── Root selector ────────────────────────────────────────────────────────────

function RootSelector({
  roots,
  activeRoot,
  filteredReachableByRoot,
  onSelect,
}: {
  roots: DependencyGraphNode[];
  activeRoot: string | undefined;
  filteredReachableByRoot: Map<string, Set<string>>;
  onSelect: (tag: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-card/60 px-3 py-2">
      <span className="shrink-0 text-[11px] font-medium text-muted-foreground">
        入口节点
      </span>
      <div className="flex flex-wrap gap-1.5">
        {roots.map((root) => {
          const isActive = activeRoot === root.tag;
          const count = filteredReachableByRoot.get(root.tag)?.size ?? 1;
          return (
            <button
              key={root.tag}
              type="button"
              onClick={() => onSelect(root.tag)}
              className={cn(
                "flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs transition-all",
                isActive
                  ? "border-primary bg-primary/10 text-primary font-medium shadow-sm"
                  : "border-border bg-background hover:border-primary/50 hover:bg-muted/50 text-foreground",
              )}
            >
              <span
                className="shrink-0"
                style={{ color: kindAccentColor(root.kind) }}
              >
                {renderTopologyPluginIcon(root)}
              </span>
              <span className="max-w-36 truncate font-mono">{root.tag}</span>
              <span
                className={cn(
                  "ml-0.5 rounded-full px-1.5 py-px text-[10px] font-medium",
                  isActive
                    ? "bg-primary/20 text-primary"
                    : "bg-muted text-muted-foreground",
                )}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ─── Legend panel ─────────────────────────────────────────────────────────────

function TopologyLegend() {
  return (
    <div className="rounded-lg border bg-card/90 p-2.5 text-[11px] shadow-sm backdrop-blur-sm">
      <div className="mb-1.5 font-semibold text-muted-foreground">图例</div>

      {/* Node types — any plugin kind may appear as a standalone graph node
          depending on how the config is structured. Don't conflate
          server ↔ entry; the `入口` badge is rendered inline on root nodes. */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-1">
        {(
          [
            { kind: "server", label: "Server" },
            { kind: "executor", label: "Executor" },
            { kind: "matcher", label: "Matcher" },
            { kind: "provider", label: "Provider" },
          ] as const
        ).map(({ kind, label }) => (
          <div key={kind} className="flex items-center gap-1.5">
            <div className={cn("h-2.5 w-2.5 rounded-sm", kindAccentBgClass(kind))} />
            <span className="text-foreground">{label}</span>
          </div>
        ))}
      </div>

      {/* Inline card types */}
      <div className="mt-2 space-y-1 border-t pt-2">
        <div className="flex items-center gap-1.5">
          <div className="h-4 w-10 rounded border border-amber-300/80 bg-amber-50/80 dark:border-amber-700/60 dark:bg-amber-950/50" />
          <span className="text-muted-foreground">匹配条件</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-4 w-10 rounded border border-sky-300/80 bg-sky-50/80 dark:border-sky-700/60 dark:bg-sky-950/50" />
          <span className="text-muted-foreground">执行目标</span>
        </div>
      </div>

      {/* Edge types */}
      <div className="mt-2 space-y-1 border-t pt-2">
        <div className="flex items-center gap-1.5">
          <svg width="22" height="8" className="shrink-0">
            <line
              x1="0"
              y1="4"
              x2="18"
              y2="4"
              stroke={EDGE_COLOR_EXEC}
              strokeWidth="2.2"
            />
          </svg>
          <span className="text-muted-foreground">sequence 调用</span>
        </div>
        <div className="flex items-center gap-1.5">
          <svg width="22" height="8" className="shrink-0">
            <line
              x1="0"
              y1="4"
              x2="18"
              y2="4"
              stroke={EDGE_COLOR_STRUCTURAL}
              strokeWidth="1.5"
            />
          </svg>
          <span className="text-muted-foreground">结构依赖</span>
        </div>
        <div className="flex items-center gap-1.5">
          <svg width="22" height="8" className="shrink-0">
            <line
              x1="0"
              y1="4"
              x2="18"
              y2="4"
              stroke={EDGE_COLOR_CYCLE}
              strokeWidth="2"
              strokeDasharray="4 2"
            />
          </svg>
          <span className="text-muted-foreground">循环依赖</span>
        </div>
      </div>
    </div>
  );
}

// ─── Sequence flow node ───────────────────────────────────────────────────────

function SequenceFlowNode({
  node,
  flow,
  nodesByTag,
  inlinedTags,
  sequenceFlowsByTag,
  plugins,
  isRoot,
  onSelect,
}: {
  node: DependencyGraphNode;
  flow: SequenceFlowReport;
  nodesByTag: Map<string, DependencyGraphNode>;
  inlinedTags: Set<string>;
  sequenceFlowsByTag: Map<string, SequenceFlowReport>;
  plugins: PluginInstance[];
  isRoot: boolean;
  onSelect: (plugin: PluginInstance) => void;
}) {
  const seqPlugin = plugins.find((p) => p.name === node.tag);
  const accent = kindAccentColor(node.kind);
  const iconBg = kindIconBgClass(node.kind);

  // A rule needs a dedicated right-edge handle when its exec hops out to
  // another sequence node (i.e. another card on the canvas). For exec values
  // that get inlined as a card inside the row, no external edge is drawn so
  // we don't need a per-row handle.
  const ruleHasOutgoingSequenceCall = (rule: SequenceFlowReport["rules"][number]) => {
    const target = rule.exec?.target_tag;
    if (!target) return false;
    return sequenceFlowsByTag.has(target) && !inlinedTags.has(target);
  };

  return (
    <div
      role={seqPlugin ? "button" : undefined}
      tabIndex={seqPlugin ? 0 : undefined}
      className="relative w-[30rem] overflow-hidden rounded-lg border bg-card shadow-sm transition-shadow hover:shadow-md"
      style={{ borderLeftColor: accent, borderLeftWidth: 4 }}
      onClick={() => {
        if (seqPlugin) onSelect(seqPlugin);
      }}
      onKeyDown={(event) => {
        if (!seqPlugin || (event.key !== "Enter" && event.key !== " ")) return;
        event.preventDefault();
        onSelect(seqPlugin);
      }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-2 px-3 py-2.5"
        style={{ backgroundColor: `${accent}10` }}
      >
        <span className={cn("shrink-0 rounded-full p-1", iconBg)}>
          {renderTopologyPluginIcon(node)}
        </span>
        <div className="min-w-0 flex-1 truncate font-mono text-sm font-semibold">
          {node.tag}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {isRoot && (
            <Badge
              variant="outline"
              className="border-primary px-1.5 py-0 text-[10px] text-primary"
            >
              入口
            </Badge>
          )}
          <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
            序列 {flow.rules.length} 条
          </Badge>
        </div>
      </div>

      {/* Rules — only vertical scrolling, never horizontal (the rule grid
          can be forced wider than the card by long exec chips otherwise) */}
      <div className="max-h-80 overflow-x-hidden overflow-y-auto border-t">
        {flow.rules.map((rule, idx) => {
          const hasSeqCall = ruleHasOutgoingSequenceCall(rule);
          return (
            <div
              key={rule.index}
              className={cn(
                // 1fr · auto · 1fr keeps the arrow column anchored at the
                // horizontal centre of the row regardless of how wide the
                // match / exec chips are — so arrows line up vertically
                // across every rule.
                "relative grid grid-cols-[2.25rem_1fr_auto_1fr] items-center gap-2 px-3 py-2 transition-colors last:border-b-0",
                idx < flow.rules.length - 1 && "border-b border-dashed",
                idx % 2 === 1 && "bg-muted/15",
                "hover:bg-muted/30",
              )}
            >
              {/* Index column */}
              <div className="flex flex-col items-center gap-0.5">
                <span
                  className={cn(
                    "rounded px-1.5 py-px text-center font-mono text-[10px] font-semibold",
                    hasSeqCall
                      ? "bg-sky-100 text-sky-700 dark:bg-sky-900/60 dark:text-sky-200"
                      : "bg-muted text-muted-foreground",
                  )}
                >
                  #{rule.index}
                </span>
                {idx > 0 && idx < flow.rules.length - 1 && (
                  <span className="text-[10px] leading-none text-muted-foreground/40">
                    ↓
                  </span>
                )}
              </div>

              {/* Matches (IF column) */}
              <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                {rule.matches.length === 0 ? (
                  <span className="rounded bg-muted/60 px-1.5 py-0.5 text-[10px] italic text-muted-foreground">
                    always
                  </span>
                ) : (
                  rule.matches.map((expression) => {
                    const key = `${expression.field}-${expression.raw}`;
                    // Direct plugin ref → inline card
                    if (
                      expression.target_tag &&
                      inlinedTags.has(expression.target_tag)
                    ) {
                      return (
                        <InlinePluginCard
                          key={key}
                          tag={expression.target_tag}
                          node={nodesByTag.get(expression.target_tag)}
                          inverted={expression.inverted}
                          context="match"
                          plugin={plugins.find(
                            (p) => p.name === expression.target_tag,
                          )}
                          onSelect={onSelect}
                        />
                      );
                    }
                    // quick_setup with $param ref → composite card
                    const qsTag = quickSetupParamTag(expression);
                    if (qsTag && inlinedTags.has(qsTag)) {
                      return (
                        <QuickSetupInlineCard
                          key={key}
                          expression={expression}
                          tag={qsTag}
                          node={nodesByTag.get(qsTag)}
                          context="match"
                          plugin={plugins.find((p) => p.name === qsTag)}
                          onSelect={onSelect}
                        />
                      );
                    }
                    return (
                      <SequenceExpressionChip key={key} expression={expression} />
                    );
                  })
                )}
              </div>

              {/* Arrow — colored when this rule fires an outgoing sequence call */}
              <ArrowRight
                className={cn(
                  "h-3.5 w-3.5 shrink-0",
                  hasSeqCall
                    ? "text-sky-500 dark:text-sky-400"
                    : "text-muted-foreground/40",
                )}
              />

              {/* Exec (THEN column) — min-w-0 plus the grid track being `auto`
                  means an extra-wide chip clips to ellipsis instead of
                  forcing the whole row to overflow the card */}
              <div className="flex min-w-0 items-center overflow-hidden">
                {renderExecExpression(
                  rule.exec,
                  inlinedTags,
                  sequenceFlowsByTag,
                  nodesByTag,
                  plugins,
                  onSelect,
                )}
              </div>

              {/* Per-rule source handle. Anchors any exec → other-sequence edge
                  to this row so the user can read which `#N exec` line goes
                  where. Without this, edges from different rules would fall
                  back to the default node-level handle and pile up on top of
                  each other on the right edge of the card.

                  Styling notes for visual continuity with the edge wire:
                  • SOLID sky fill (no white center) so the line — which is
                    the same sky-500 colour — visually extrudes out of the
                    dot rather than starting from a white gap.
                  • `right: 0` plus `translateY(-50%)` places the dot's right
                    edge AT the card's inner right edge, so the wire emerges
                    at the dot's surface with no whitespace gap. The card's
                    `overflow-hidden` still clips anything past the edge —
                    no transform-X means the whole dot stays inside. */}
              {hasSeqCall && (
                <Handle
                  type="source"
                  position={Position.Right}
                  id={`rule-${rule.index}`}
                  className="!h-2.5 !w-2.5 !rounded-full !border-0 !bg-sky-500"
                  style={{ right: 0, transform: "translateY(-50%)" }}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Invert mark (the bang `!` shown when a match expression is negated) ──────
//
// Replaces the older `NOT` text badge. A small rose-tinted square with a single
// `!` character. Reused everywhere a negated match needs to be visualised, and
// kept consistent with the `InvertCheckbox` button in `sequence-composer.tsx`.
export function InvertMark() {
  return (
    <span
      aria-label="取反"
      className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded border border-rose-400 bg-rose-100 font-mono text-[11px] font-bold leading-none text-rose-600 dark:border-rose-600 dark:bg-rose-950 dark:text-rose-400"
    >
      !
    </span>
  );
}

// ─── Inline plugin card ───────────────────────────────────────────────────────

export function InlinePluginCard({
  tag,
  node,
  inverted,
  context,
  plugin,
  onSelect,
}: {
  tag: string;
  node: DependencyGraphNode | undefined;
  inverted: boolean;
  context: "match" | "exec";
  plugin?: PluginInstance;
  onSelect: (plugin: PluginInstance) => void;
}) {
  const iconNode = node ?? { tag, kind: context === "match" ? "matcher" : "executor", plugin_type: "" };

  return (
    <div
      role={plugin ? "button" : undefined}
      tabIndex={plugin ? 0 : undefined}
      className={cn(
        "flex cursor-default items-center gap-1.5 rounded border px-2 py-1 transition-colors",
        plugin && "cursor-pointer",
        context === "match"
          ? "border-amber-200/80 bg-amber-50/70 hover:border-amber-400/70 dark:border-amber-800/40 dark:bg-amber-950/40"
          : "border-sky-200/80 bg-sky-50/70 hover:border-sky-400/70 dark:border-sky-800/40 dark:bg-sky-950/40",
      )}
      onClick={(e) => {
        e.stopPropagation();
        if (plugin) onSelect(plugin);
      }}
      onKeyDown={(e) => {
        if (!plugin || (e.key !== "Enter" && e.key !== " ")) return;
        e.preventDefault();
        e.stopPropagation();
        onSelect(plugin);
      }}
    >
      {inverted && <InvertMark />}
      <span
        className={cn(
          "shrink-0 rounded-full p-0.5",
          kindIconBgClass(node?.kind ?? iconNode.kind),
        )}
      >
        {renderTopologyPluginIcon(iconNode)}
      </span>
      <div className="min-w-0">
        <div className="max-w-[8rem] truncate font-mono text-[10px] font-medium leading-tight">
          {tag}
        </div>
        {node?.plugin_type && (
          <div className="text-[9px] leading-tight text-muted-foreground">
            {node.plugin_type}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Quick-setup composite inline card ────────────────────────────────────────

export function QuickSetupInlineCard({
  expression,
  tag,
  node,
  context,
  plugin,
  onSelect,
}: {
  expression: SequenceFlowExpression;
  tag: string;
  node: DependencyGraphNode | undefined;
  context: "match" | "exec";
  plugin?: PluginInstance;
  onSelect: (plugin: PluginInstance) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      {/* Invert mark always comes first, before the type badge */}
      {expression.inverted && <InvertMark />}
      {/* quick_setup type label */}
      <span
        className={cn(
          "shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] font-semibold",
          context === "match"
            ? "bg-amber-100/80 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300"
            : "bg-sky-100/80 text-sky-700 dark:bg-sky-900/50 dark:text-sky-300",
        )}
      >
        {expression.plugin_type ?? "qs"}
      </span>
      {/* Referenced plugin card — inverted already shown above */}
      <InlinePluginCard
        tag={tag}
        node={node}
        inverted={false}
        context={context}
        plugin={plugin}
        onSelect={onSelect}
      />
    </div>
  );
}

// ─── Sequence call chip (exec → another sequence) ─────────────────────────────

export function SequenceCallChip({
  tag,
  ruleCount,
  plugin,
  onSelect,
}: {
  tag: string;
  ruleCount: number;
  plugin?: PluginInstance;
  onSelect: (plugin: PluginInstance) => void;
}) {
  return (
    <div
      role={plugin ? "button" : undefined}
      tabIndex={plugin ? 0 : undefined}
      className={cn(
        "flex items-center gap-1.5 rounded border px-2 py-1 transition-colors",
        "border-sky-300/80 bg-sky-50/70 dark:border-sky-700/60 dark:bg-sky-950/40",
        plugin && "cursor-pointer hover:border-sky-500 dark:hover:border-sky-500",
      )}
      onClick={(e) => {
        e.stopPropagation();
        if (plugin) onSelect(plugin);
      }}
      onKeyDown={(e) => {
        if (!plugin || (e.key !== "Enter" && e.key !== " ")) return;
        e.preventDefault();
        e.stopPropagation();
        onSelect(plugin);
      }}
    >
      <CornerDownRight className="h-3 w-3 shrink-0 text-sky-600 dark:text-sky-400" />
      <span className="max-w-[8rem] truncate font-mono text-[10px] font-medium text-sky-700 dark:text-sky-300">
        {tag}
      </span>
      <span className="shrink-0 rounded bg-sky-100/80 px-1 py-px text-[9px] text-sky-600 dark:bg-sky-900/50 dark:text-sky-400">
        {ruleCount}条
      </span>
    </div>
  );
}

// ─── Exec expression renderer ─────────────────────────────────────────────────

function renderExecExpression(
  exec: SequenceFlowExpression | undefined,
  inlinedTags: Set<string>,
  sequenceFlowsByTag: Map<string, SequenceFlowReport>,
  nodesByTag: Map<string, DependencyGraphNode>,
  plugins: PluginInstance[],
  onSelect: (plugin: PluginInstance) => void,
) {
  if (!exec) {
    return <span className="text-[11px] text-muted-foreground">—</span>;
  }

  // Direct plugin reference that is inlined
  if (exec.target_tag && inlinedTags.has(exec.target_tag)) {
    return (
      <InlinePluginCard
        tag={exec.target_tag}
        node={nodesByTag.get(exec.target_tag)}
        inverted={false}
        context="exec"
        plugin={plugins.find((p) => p.name === exec.target_tag)}
        onSelect={onSelect}
      />
    );
  }

  // Reference to another sequence — show sequence call chip
  if (exec.target_tag && sequenceFlowsByTag.has(exec.target_tag)) {
    const targetFlow = sequenceFlowsByTag.get(exec.target_tag)!;
    return (
      <SequenceCallChip
        tag={exec.target_tag}
        ruleCount={targetFlow.rules.length}
        plugin={plugins.find((p) => p.name === exec.target_tag)}
        onSelect={onSelect}
      />
    );
  }

  // quick_setup with $param reference that is inlined
  const qsTag = quickSetupParamTag(exec);
  if (qsTag && inlinedTags.has(qsTag)) {
    return (
      <QuickSetupInlineCard
        expression={exec}
        tag={qsTag}
        node={nodesByTag.get(qsTag)}
        context="exec"
        plugin={plugins.find((p) => p.name === qsTag)}
        onSelect={onSelect}
      />
    );
  }

  return <SequenceExpressionChip expression={exec} />;
}

// ─── Regular plugin node ──────────────────────────────────────────────────────

function TopologyNodeCard({
  node,
  isRoot,
  plugin,
  onSelect,
}: {
  node: DependencyGraphNode;
  isRoot: boolean;
  plugin?: PluginInstance;
  onSelect: (plugin: PluginInstance) => void;
}) {
  const accent = kindAccentColor(node.kind);
  const iconBg = kindIconBgClass(node.kind);
  const badgeCls = kindBadgeClass(node.kind);

  return (
    <div
      role={plugin ? "button" : undefined}
      tabIndex={plugin ? 0 : undefined}
      className={cn(
        "relative w-52 overflow-hidden rounded-md border bg-card shadow-sm transition-all",
        plugin && "cursor-pointer hover:shadow-md",
      )}
      style={{ borderLeftColor: accent, borderLeftWidth: 3 }}
      onClick={() => {
        if (plugin) onSelect(plugin);
      }}
      onKeyDown={(event) => {
        if (!plugin || (event.key !== "Enter" && event.key !== " ")) return;
        event.preventDefault();
        onSelect(plugin);
      }}
    >
      <div className="px-3 py-2.5">
        <div className="flex items-center gap-2">
          <span className={cn("shrink-0 rounded-full p-1", iconBg)}>
            {renderTopologyPluginIcon(node)}
          </span>
          <div className="min-w-0 flex-1 truncate font-mono text-sm font-medium">
            {node.tag}
          </div>
          {isRoot && (
            <Badge
              variant="outline"
              className="shrink-0 border-primary px-1.5 py-0 text-[10px] text-primary"
            >
              入口
            </Badge>
          )}
        </div>
        <div className="mt-2 flex flex-wrap gap-1">
          <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", badgeCls)}>
            {PLUGIN_TYPE_LABELS[node.kind as PluginType] ?? node.kind}
          </Badge>
          <Badge variant="secondary" className="bg-muted/60 px-1.5 py-0 text-[10px] text-muted-foreground">
            {node.plugin_type}
          </Badge>
        </div>
      </div>
    </div>
  );
}

// ─── Expression chip ──────────────────────────────────────────────────────────

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
            "max-w-48 truncate rounded border bg-background px-1.5 py-0.5 text-left font-mono text-[10px] transition-colors hover:border-primary",
            expression.kind === "quick_setup" &&
              "border-amber-300 text-amber-700 dark:border-amber-700 dark:text-amber-300",
            expression.kind === "builtin" &&
              "border-primary/40 text-primary",
            expression.kind === "plugin" &&
              "border-border text-foreground",
          )}
          onClick={(event) => event.stopPropagation()}
        >
          {label}
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-72 text-xs" align="start">
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
          <pre className="max-h-32 overflow-auto rounded bg-muted p-2 font-mono text-[10px] whitespace-pre-wrap">
            {expression.raw}
          </pre>
        </div>
      </PopoverContent>
    </Popover>
  );
}

// ─── ReactFlow node wrapper ───────────────────────────────────────────────────

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

// ─── Topology model ───────────────────────────────────────────────────────────

function buildTopologyModel(graph: DependencyGraphReport): TopologyModel {
  const allTags = new Set(graph.nodes.map((node) => node.tag));
  const nodesByTag = new Map(graph.nodes.map((node) => [node.tag, node]));
  const referencedTags = new Set(graph.edges.map((edge) => edge.target_tag));
  const initIndex = new Map(
    graph.init_order.map((tag, index) => [tag, index]),
  );
  const edgesBySource = new Map<string, DependencyGraphEdge[]>();
  const edgesByTarget = new Map<string, DependencyGraphEdge[]>();

  for (const edge of graph.edges) {
    if (!allTags.has(edge.source_tag) || !allTags.has(edge.target_tag))
      continue;

    const outEdges = edgesBySource.get(edge.source_tag) ?? [];
    outEdges.push(edge);
    edgesBySource.set(edge.source_tag, outEdges);

    const inEdges = edgesByTarget.get(edge.target_tag) ?? [];
    inEdges.push(edge);
    edgesByTarget.set(edge.target_tag, inEdges);
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
    reachableByRoot.set(
      root.tag,
      collectReachableTags(root.tag, edgesBySource),
    );
  }

  const visitIndex = buildVisitIndex(fallbackRoots, edgesBySource);
  const sequenceFlowsByTag = new Map(
    (graph.sequence_flows ?? []).map((flow) => [flow.tag, flow]),
  );

  // Compute which tags are rendered inline inside sequence rule rows.
  // A tag is inlined when it appears as a target in any sequence expression
  // and is not itself a sequence (sequences stay as graph nodes).
  const seqReferencedTags = new Set<string>();
  for (const flow of graph.sequence_flows ?? []) {
    for (const rule of flow.rules) {
      for (const expr of rule.matches) {
        if (expr.target_tag) seqReferencedTags.add(expr.target_tag);
        // quick_setup with "$tag" param also references a plugin
        const qsMatchTag = quickSetupParamTag(expr);
        if (qsMatchTag) seqReferencedTags.add(qsMatchTag);
      }
      if (rule.exec?.target_tag) seqReferencedTags.add(rule.exec.target_tag);
      const qsExecTag = rule.exec ? quickSetupParamTag(rule.exec) : undefined;
      if (qsExecTag) seqReferencedTags.add(qsExecTag);
    }
  }
  const inlinedTags = new Set(
    [...seqReferencedTags].filter((t) => !sequenceFlowsByTag.has(t)),
  );

  // Transitively inline nodes whose every graph-level parent is already inlined.
  // This prevents "orphaned" structural dependencies (e.g. geosite_cn_raw) from
  // appearing as disconnected floating nodes after their direct parent is inlined.
  let changed = true;
  while (changed) {
    changed = false;
    for (const [tag] of nodesByTag) {
      if (inlinedTags.has(tag) || sequenceFlowsByTag.has(tag)) continue;
      const parents = edgesByTarget.get(tag) ?? [];
      if (parents.length > 0 && parents.every((e) => inlinedTags.has(e.source_tag))) {
        inlinedTags.add(tag);
        changed = true;
      }
    }
  }

  // Reachability on the filtered graph: skip edges that touch inlined tags so
  // nodes only reachable through inlined paths are not shown as graph nodes.
  const filteredReachableByRoot = new Map<string, Set<string>>();
  for (const root of fallbackRoots) {
    const visited = new Set<string>();
    const stack = [root.tag];
    while (stack.length > 0) {
      const tag = stack.pop()!;
      if (visited.has(tag) || inlinedTags.has(tag)) continue;
      visited.add(tag);
      for (const edge of edgesBySource.get(tag) ?? []) {
        if (!inlinedTags.has(edge.target_tag)) stack.push(edge.target_tag);
      }
    }
    filteredReachableByRoot.set(root.tag, visited);
  }

  return {
    allTags,
    nodesByTag,
    edges: graph.edges,
    edgesBySource,
    edgesByTarget,
    roots: fallbackRoots,
    reachableByRoot,
    filteredReachableByRoot,
    initIndex,
    visitIndex,
    sequenceFlowsByTag,
    inlinedTags,
  };
}

function buildVisitIndex(
  roots: DependencyGraphNode[],
  edgesBySource: Map<string, DependencyGraphEdge[]>,
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
  edgesBySource: Map<string, DependencyGraphEdge[]>,
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

// ─── Layout ───────────────────────────────────────────────────────────────────

// top/bottom range of a placed node in ReactFlow coordinate space (top-left origin)
interface PlacedNode {
  top: number;
  bottom: number;
}

// Estimate the rendered height of a node so the layout can reserve the right space.
// ReactFlow position.y is the TOP-LEFT corner, so heights must match the actual DOM.
function estimateNodeHeight(
  tag: string,
  sequenceFlowsByTag: Map<string, SequenceFlowReport>,
): number {
  const flow = sequenceFlowsByTag.get(tag);
  if (!flow) return 96; // regular card node
  // header ≈ 58px  +  rule rows capped by max-h-80 (320px)  +  16px bottom buffer
  return 58 + Math.min(flow.rules.length * 58, 320) + 16;
}

function layoutTopology(
  topology: TopologyModel,
  activeRoot: string | undefined,
  visibleTags: Set<string>,
): TopologyLayout {
  // Sequence nodes are w-[30rem] = 480px wide; xGap must exceed that by enough
  // to leave visible wire space between columns. 600px gives ~120px clearance.
  const xGap = 600;
  // Minimum vertical gap (px) between the bottom edge of one node and the top of the next
  const yGap = 36;

  const roots = topology.roots.filter((root) => root.tag === activeRoot);
  const rootTags = new Set(roots.map((root) => root.tag));
  const depthByTag = new Map<string, number>();
  const stack = roots.map((root) => ({ tag: root.tag, depth: 0 }));
  // Guard against cycles: each directed edge is followed at most once in BFS.
  // Without this, a back edge can keep re-deepening both endpoints and the
  // loop runs forever.
  const visitedEdges = new Set<string>();

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || !visibleTags.has(current.tag)) continue;
    const previousDepth = depthByTag.get(current.tag);
    if (previousDepth !== undefined && previousDepth >= current.depth) continue;
    depthByTag.set(current.tag, current.depth);
    for (const edge of topology.edgesBySource.get(current.tag) ?? []) {
      const edgeKey = `${edge.source_tag}|${edge.target_tag}|${edge.field}`;
      if (visitedEdges.has(edgeKey)) continue;
      visitedEdges.add(edgeKey);
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

  // yByTag stores the TOP-LEFT y coordinate for each node (matches ReactFlow position.y)
  const yByTag = new Map<string, number>();
  // Per-depth column: list of [top, bottom] ranges of already-placed nodes
  const occupiedByDepth = new Map<number, PlacedNode[]>();

  roots.forEach((root) => {
    const h = estimateNodeHeight(root.tag, topology.sequenceFlowsByTag);
    const col = occupiedByDepth.get(0) ?? [];
    const top =
      col.length > 0
        ? (col[col.length - 1]?.bottom ?? 0) + yGap
        : 0;
    yByTag.set(root.tag, top);
    col.push({ top, bottom: top + h });
    occupiedByDepth.set(0, col);
  });

  for (const tag of tags) {
    if (yByTag.has(tag)) continue;

    const depth = depthByTag.get(tag) ?? 0;
    const h = estimateNodeHeight(tag, topology.sequenceFlowsByTag);
    const col = occupiedByDepth.get(depth) ?? [];

    // Desired top = center on parent's visual center, minus half this node's height
    const parentCenters = (topology.edgesByTarget.get(tag) ?? [])
      .filter((e) => visibleTags.has(e.source_tag))
      .map((e) => {
        const py = yByTag.get(e.source_tag);
        const ph = estimateNodeHeight(e.source_tag, topology.sequenceFlowsByTag);
        return py !== undefined ? py + ph / 2 : undefined;
      })
      .filter((c): c is number => c !== undefined);

    const desiredCenter =
      parentCenters.length > 0
        ? parentCenters.reduce((s, c) => s + c, 0) / parentCenters.length
        : col.length > 0
          ? (col[col.length - 1]?.bottom ?? 0) + yGap + h / 2
          : h / 2;

    const desiredTop = desiredCenter - h / 2;
    const top = resolveAvailableY(desiredTop, h, col, yGap);

    yByTag.set(tag, top);
    col.push({ top, bottom: top + h });
    occupiedByDepth.set(depth, col);
  }

  // Second pass: re-center root nodes on their visible children so the
  // connecting edges are horizontal instead of angled.
  for (const root of roots) {
    const rootH = estimateNodeHeight(root.tag, topology.sequenceFlowsByTag);
    const childCenters = (topology.edgesBySource.get(root.tag) ?? [])
      .filter((e) => visibleTags.has(e.target_tag))
      .map((e) => {
        const cy = yByTag.get(e.target_tag) ?? 0;
        const ch = estimateNodeHeight(e.target_tag, topology.sequenceFlowsByTag);
        return cy + ch / 2;
      });
    if (childCenters.length === 0) continue;
    const avgCenter =
      childCenters.reduce((s, c) => s + c, 0) / childCenters.length;
    yByTag.set(root.tag, avgCenter - rootH / 2);
  }

  return {
    nodes: tags.flatMap((tag) => {
      const node = topology.nodesByTag.get(tag);
      if (!node) return [];
      return [
        {
          node,
          x: (depthByTag.get(tag) ?? 0) * xGap,
          y: yByTag.get(tag) ?? 0,
          isRoot: rootTags.has(tag),
        },
      ];
    }),
    depthByTag,
  };
}

// Find the first conflict in the column and push the new node below it.
// Repeats until no overlap remains.
function resolveAvailableY(
  desiredTop: number,
  nodeHeight: number,
  occupied: PlacedNode[],
  gap: number,
): number {
  let top = desiredTop;
  for (let iter = 0; iter < 500; iter++) {
    const bottom = top + nodeHeight;
    const conflict = occupied.find(
      (o) => top < o.bottom + gap && bottom > o.top - gap,
    );
    if (!conflict) return top;
    top = conflict.bottom + gap;
  }
  return top;
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

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

function renderTopologyPluginIcon(node: DependencyGraphNode) {
  const definition = getPluginCatalogItem(node.plugin_type);
  if (definition) {
    return renderPluginKindIcon(definition.icon, { className: "h-3.5 w-3.5" });
  }
  return isPluginType(node.kind) ? (
    pluginTypeIcons[node.kind]
  ) : (
    <GitBranch className="h-3.5 w-3.5" />
  );
}

function isPluginType(kind: string): kind is PluginType {
  return ["server", "executor", "matcher", "provider"].includes(kind);
}

function sequenceExpressionLabel(expression: SequenceFlowExpression) {
  // Plain-text label; the rose `!` badge is rendered separately by InvertMark.
  // We still prefix `!` here so when the label is shown as standalone text
  // (e.g. inside a Popover detail panel) the negation is visible.
  const not = expression.inverted ? "!" : "";
  if (expression.kind === "quick_setup") {
    const pluginType = expression.plugin_type ?? "quick";
    const param = expression.param
      ? ` ${compactText(expression.param, 24)}`
      : "";
    return `${not}quick(${pluginType})${param}`;
  }
  if (expression.kind === "builtin") {
    const param = expression.param
      ? ` ${compactText(expression.param, 24)}`
      : "";
    return `${expression.builtin ?? "builtin"}${param}`;
  }
  if (expression.target_tag) return `${not}$${expression.target_tag}`;
  return `${not}${compactText(expression.raw, 32)}`;
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
  return value.length > maxLength
    ? `${value.slice(0, maxLength - 1)}…`
    : value;
}

// Returns the plugin tag referenced by a quick_setup "$tag" param, or undefined.
function quickSetupParamTag(
  expr: SequenceFlowExpression,
): string | undefined {
  if (expr.kind === "quick_setup" && expr.param?.startsWith("$")) {
    return expr.param.slice(1);
  }
  return undefined;
}
