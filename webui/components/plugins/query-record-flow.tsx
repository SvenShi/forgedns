"use client";

import { useMemo, type ReactNode } from "react";
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
import {
  AlertTriangle,
  Check,
  Circle,
  CornerDownRight,
  GitBranch,
  Play,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import type { PluginInstance } from "@/lib/types";
import type {
  DependencyGraphReport,
  QueryRecordDetail,
  QueryRecorderStep,
  SequenceFlowExpression,
  SequenceFlowReport,
  SequenceFlowRule,
} from "@/lib/oxidns-api";
import { cn } from "@/lib/utils";
import {
  pluginKindAccentHex,
  pluginKindBadgeOutlineClass,
  pluginKindIconBgClass,
  pluginTypeAccentHex,
} from "@/components/plugins/display";

type MatchStatus = "matched" | "not_matched" | "unevaluated";
type ActionStatus =
  | "not_executed"
  | "entered"
  | "next"
  | "stop"
  | "return"
  | "error";

interface RuntimeIndexes {
  matchers: Map<string, QueryRecorderStep[]>;
  actions: Map<string, QueryRecorderStep[]>;
  stepsBySequence: Map<string, QueryRecorderStep[]>;
}

interface SequenceRuntime {
  flow: SequenceFlowReport;
  steps: QueryRecorderStep[];
  firstEventIndex: number;
}

interface SequenceEdge {
  source: string;
  target: string;
  ruleIndex: number;
  label: string;
}

type FlowModel =
  | { mode: "empty" }
  | {
      mode: "fallback";
      reason: string;
      steps: QueryRecorderStep[];
    }
  | {
      mode: "flow";
      sequences: SequenceRuntime[];
      edges: SequenceEdge[];
      runtime: RuntimeIndexes;
      pluginByTag: Map<string, PluginInstance>;
    };

interface QuerySequenceNodeData extends Record<string, unknown> {
  sequence: SequenceRuntime;
  runtime: RuntimeIndexes;
  pluginByTag: Map<string, PluginInstance>;
  outgoingRuleIndexes: Set<number>;
}

interface QueryStepNodeData extends Record<string, unknown> {
  step: QueryRecorderStep;
}

type QuerySequenceFlowNode = Node<QuerySequenceNodeData, "querySequence">;
type QueryStepFlowNode = Node<QueryStepNodeData, "queryStep">;

const QUERY_EDGE_COLOR = pluginTypeAccentHex.executor;
const QUERY_MATCH_COLOR = pluginTypeAccentHex.matcher;

const queryRecordNodeTypes = {
  querySequence: QuerySequenceNode,
  queryStep: QueryStepNode,
};

export function QueryRecordFlowCanvas({
  record,
  dependencyGraph,
  plugins,
}: {
  record: QueryRecordDetail;
  dependencyGraph: DependencyGraphReport | null;
  plugins: PluginInstance[];
}) {
  const model = useMemo(
    () => buildFlowModel(record, dependencyGraph, plugins),
    [dependencyGraph, plugins, record],
  );

  if (model.mode === "empty") {
    return (
      <div className="flex min-h-36 items-center justify-center rounded-md border border-dashed bg-muted/10 px-4 text-center text-sm text-muted-foreground">
        本条记录没有 sequence 路径事件。
      </div>
    );
  }

  const nodes: Node[] =
    model.mode === "flow"
      ? buildSequenceNodes(model)
      : buildFallbackNodes(model);
  const edges: Edge[] =
    model.mode === "flow"
      ? buildSequenceEdges(model)
      : buildFallbackEdges(model);

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {model.mode === "flow" ? (
          <>
            <span className="rounded-full border bg-muted/30 px-2 py-0.5">
              {model.sequences.length} 个 sequence
            </span>
            <span className="rounded-full border bg-muted/30 px-2 py-0.5">
              {record.steps.length} 个事件
            </span>
          </>
        ) : (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-300/70 bg-amber-500/10 px-2 py-0.5 text-amber-700 dark:text-amber-300">
            <AlertTriangle className="h-3 w-3" />
            {model.reason}
          </span>
        )}
        <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-700 dark:text-emerald-300">
          命中
        </span>
        <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-rose-700 dark:text-rose-300">
          未命中
        </span>
        <span className="rounded-full border bg-muted/30 px-2 py-0.5">
          未评估
        </span>
      </div>

      <div className="h-[520px] overflow-hidden rounded-md border bg-muted/10">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={queryRecordNodeTypes}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.2}
          maxZoom={2}
          nodesDraggable={false}
        >
          <Background gap={20} size={1} className="opacity-30" />
          <Controls showInteractive={false} />
          <Panel position="bottom-left">
            <QueryRecordFlowLegend fallback={model.mode === "fallback"} />
          </Panel>
        </ReactFlow>
      </div>
    </div>
  );
}

function buildFlowModel(
  record: QueryRecordDetail,
  dependencyGraph: DependencyGraphReport | null,
  plugins: PluginInstance[],
): FlowModel {
  const steps = record.steps ?? [];
  if (steps.length === 0) return { mode: "empty" };

  const runtime = buildRuntimeIndexes(steps);
  const pluginByTag = new Map(plugins.map((plugin) => [plugin.name, plugin]));
  const flowByTag = new Map(
    (dependencyGraph?.sequence_flows ?? []).map((flow) => [flow.tag, flow]),
  );

  if (!dependencyGraph || flowByTag.size === 0) {
    return {
      mode: "fallback",
      reason: "配置拓扑不可用，已按事件顺序降级显示",
      steps,
    };
  }

  const sequenceTags = orderedSequenceTags(steps);
  const missing = sequenceTags.filter((tag) => !flowByTag.has(tag));
  if (missing.length > 0) {
    return {
      mode: "fallback",
      reason: `缺少 sequence 配置：${missing.join(", ")}`,
      steps,
    };
  }

  const sequences = sequenceTags.map((tag) => {
    const sequenceSteps = runtime.stepsBySequence.get(tag) ?? [];
    return {
      flow: flowByTag.get(tag)!,
      steps: sequenceSteps,
      firstEventIndex: sequenceSteps[0]?.event_index ?? 0,
    };
  });

  const sequenceSet = new Set(sequenceTags);
  const edges: SequenceEdge[] = [];
  for (const sequence of sequences) {
    for (const rule of sequence.flow.rules) {
      const target = targetSequenceTag(rule.exec, flowByTag, sequenceSet);
      if (!target) continue;
      edges.push({
        source: sequence.flow.tag,
        target,
        ruleIndex: rule.index,
        label: `#${rule.index} ${sequenceActionLabel(rule.exec)}`,
      });
    }
  }

  return {
    mode: "flow",
    sequences,
    edges,
    runtime,
    pluginByTag,
  };
}

function buildRuntimeIndexes(steps: QueryRecorderStep[]): RuntimeIndexes {
  const matchers = new Map<string, QueryRecorderStep[]>();
  const actions = new Map<string, QueryRecorderStep[]>();
  const stepsBySequence = new Map<string, QueryRecorderStep[]>();

  for (const step of steps) {
    pushMapValue(stepsBySequence, step.sequence_tag, step);
    if (typeof step.node_index !== "number" || !step.tag) continue;

    if (step.kind === "matcher") {
      pushMapValue(
        matchers,
        matcherKey(step.sequence_tag, step.node_index, step.tag),
        step,
      );
    }

    if (step.kind === "executor" || step.kind === "builtin") {
      pushMapValue(
        actions,
        actionKey(step.sequence_tag, step.node_index, step.kind, step.tag),
        step,
      );
    }
  }

  for (const entries of [
    ...matchers.values(),
    ...actions.values(),
    ...stepsBySequence.values(),
  ]) {
    entries.sort((a, b) => a.event_index - b.event_index);
  }

  return { matchers, actions, stepsBySequence };
}

function buildSequenceNodes(model: Extract<FlowModel, { mode: "flow" }>) {
  const outgoingBySequence = new Map<string, Set<number>>();
  for (const edge of model.edges) {
    const indexes = outgoingBySequence.get(edge.source) ?? new Set<number>();
    indexes.add(edge.ruleIndex);
    outgoingBySequence.set(edge.source, indexes);
  }

  return model.sequences.map<QuerySequenceFlowNode>((sequence, index) => ({
    id: sequence.flow.tag,
    type: "querySequence",
    position: {
      x: index * 660,
      y: index % 2 === 0 ? 0 : 56,
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    draggable: false,
    data: {
      sequence,
      runtime: model.runtime,
      pluginByTag: model.pluginByTag,
      outgoingRuleIndexes:
        outgoingBySequence.get(sequence.flow.tag) ?? new Set(),
    },
  }));
}

function buildSequenceEdges(model: Extract<FlowModel, { mode: "flow" }>) {
  return model.edges.map<Edge>((edge, index) => ({
    id: `${edge.source}-${edge.target}-${edge.ruleIndex}-${index}`,
    source: edge.source,
    target: edge.target,
    sourceHandle: `rule-${edge.ruleIndex}`,
    type: "smoothstep",
    label: edge.label,
    style: { stroke: QUERY_EDGE_COLOR, strokeWidth: 2.2 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: QUERY_EDGE_COLOR,
      width: 14,
      height: 14,
    },
    labelStyle: {
      fill: QUERY_EDGE_COLOR,
      fontSize: 10,
      fontFamily: "monospace",
      fontWeight: 700,
    },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 3,
  }));
}

function buildFallbackNodes(model: Extract<FlowModel, { mode: "fallback" }>) {
  return model.steps.map<QueryStepFlowNode>((step, index) => ({
    id: `step:${step.event_index}`,
    type: "queryStep",
    position: { x: 0, y: index * 116 },
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
    draggable: false,
    data: { step },
  }));
}

function buildFallbackEdges(model: Extract<FlowModel, { mode: "fallback" }>) {
  return model.steps.slice(1).map<Edge>((step, index) => ({
    id: `step-edge:${model.steps[index].event_index}-${step.event_index}`,
    source: `step:${model.steps[index].event_index}`,
    target: `step:${step.event_index}`,
    type: "smoothstep",
    style: { stroke: QUERY_EDGE_COLOR, strokeWidth: 1.8 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: QUERY_EDGE_COLOR,
      width: 12,
      height: 12,
    },
  }));
}

function QuerySequenceNode({ data }: NodeProps<QuerySequenceFlowNode>) {
  const { sequence, runtime, pluginByTag, outgoingRuleIndexes } = data;
  const flow = sequence.flow;
  const accent = pluginKindAccentHex("executor");
  const eventRange = eventRangeLabel(sequence.steps);

  return (
    <div
      className="relative w-[34rem] overflow-hidden rounded-lg border bg-card shadow-sm"
      style={{ borderLeftColor: accent, borderLeftWidth: 4 }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-border !bg-background"
      />
      <div
        className="flex items-center gap-2 px-3 py-2.5"
        style={{ backgroundColor: `${accent}12` }}
      >
        <span
          className={cn(
            "shrink-0 rounded-full p-1",
            pluginKindIconBgClass("executor"),
          )}
        >
          <GitBranch className="h-3.5 w-3.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-sm font-semibold">
            {flow.tag}
          </div>
          <div className="truncate font-mono text-[10px] text-muted-foreground">
            events {eventRange}
          </div>
        </div>
        <Badge variant="secondary" className="shrink-0 px-1.5 py-0 text-[10px]">
          {flow.rules.length} 条规则
        </Badge>
      </div>

      <div className="max-h-[390px] overflow-x-hidden overflow-y-auto border-t">
        {flow.rules.map((rule, index) => (
          <SequenceRuleRow
            key={rule.index}
            sequenceTag={flow.tag}
            rule={rule}
            ruleOffset={index}
            isLast={index === flow.rules.length - 1}
            runtime={runtime}
            pluginByTag={pluginByTag}
            hasOutgoingSequence={outgoingRuleIndexes.has(rule.index)}
          />
        ))}
      </div>
    </div>
  );
}

function SequenceRuleRow({
  sequenceTag,
  rule,
  ruleOffset,
  isLast,
  runtime,
  pluginByTag,
  hasOutgoingSequence,
}: {
  sequenceTag: string;
  rule: SequenceFlowRule;
  ruleOffset: number;
  isLast: boolean;
  runtime: RuntimeIndexes;
  pluginByTag: Map<string, PluginInstance>;
  hasOutgoingSequence: boolean;
}) {
  const matchStatuses = rule.matches.map((expression, matchIndex) =>
    getMatchStatus(sequenceTag, rule.index, matchIndex, expression, runtime),
  );
  const actionStatus = getActionStatus(
    sequenceTag,
    rule.index,
    rule.exec,
    runtime,
  );
  const missed = matchStatuses.some(
    (status) => status.status === "not_matched",
  );
  const ran = actionStatus.status !== "not_executed";

  return (
    <div
      className={cn(
        "relative grid grid-cols-[2.35rem_minmax(0,1fr)_1rem_minmax(9rem,0.78fr)] items-center gap-2 px-3 py-2 transition-colors",
        !isLast && "border-b border-dashed",
        ruleOffset % 2 === 1 && "bg-muted/15",
        missed && "bg-rose-500/5",
        ran && !missed && "bg-sky-500/5",
      )}
    >
      <div className="flex flex-col items-center gap-0.5">
        <span
          className={cn(
            "rounded px-1.5 py-px text-center font-mono text-[10px] font-semibold",
            ran
              ? "bg-sky-100 text-sky-700 dark:bg-sky-900/60 dark:text-sky-200"
              : missed
                ? "bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-300"
                : "bg-muted text-muted-foreground",
          )}
        >
          #{rule.index}
        </span>
      </div>

      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {rule.matches.length === 0 ? (
          <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-700 dark:text-emerald-300">
            always
          </span>
        ) : (
          rule.matches.map((expression, matchIndex) => (
            <MatcherStatusChip
              key={`${expression.field}-${expression.raw}-${matchIndex}`}
              sequenceTag={sequenceTag}
              ruleIndex={rule.index}
              matchIndex={matchIndex}
              expression={expression}
              runtime={runtime}
              pluginByTag={pluginByTag}
            />
          ))
        )}
      </div>

      <CornerDownRight
        className={cn(
          "h-3.5 w-3.5 shrink-0",
          ran ? "text-sky-500" : "text-muted-foreground/40",
        )}
      />

      <div className="flex min-w-0 items-center overflow-hidden">
        <ActionStatusChip
          sequenceTag={sequenceTag}
          ruleIndex={rule.index}
          expression={rule.exec}
          runtime={runtime}
          pluginByTag={pluginByTag}
        />
      </div>

      {hasOutgoingSequence && (
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
}

function MatcherStatusChip({
  sequenceTag,
  ruleIndex,
  matchIndex,
  expression,
  runtime,
  pluginByTag,
}: {
  sequenceTag: string;
  ruleIndex: number;
  matchIndex: number;
  expression: SequenceFlowExpression;
  runtime: RuntimeIndexes;
  pluginByTag: Map<string, PluginInstance>;
}) {
  const result = getMatchStatus(
    sequenceTag,
    ruleIndex,
    matchIndex,
    expression,
    runtime,
  );
  const plugin =
    result.runtimeTag === undefined
      ? undefined
      : pluginByTag.get(result.runtimeTag);

  return (
    <StatusPopover
      title={sequenceExpressionLabel(expression)}
      events={result.events}
      fallback={`字段 ${expression.field}`}
    >
      <span
        className={cn(
          "inline-flex max-w-[12rem] items-center gap-1.5 rounded border px-2 py-1 text-left text-[10px] transition-colors",
          matchStatusClass(result.status),
        )}
      >
        {expression.inverted && <InvertMark />}
        {matchStatusIcon(result.status)}
        <span className="min-w-0 flex-1 truncate font-mono">
          {sequenceExpressionLabel(expression)}
        </span>
        {plugin && (
          <span
            className={cn(
              "shrink-0 rounded px-1 py-px text-[9px]",
              pluginKindBadgeOutlineClass(plugin.type),
            )}
          >
            {plugin.pluginKind}
          </span>
        )}
        <StatusSuffix
          events={result.events}
          label={matchStatusLabel(result.status)}
        />
      </span>
    </StatusPopover>
  );
}

function ActionStatusChip({
  sequenceTag,
  ruleIndex,
  expression,
  runtime,
  pluginByTag,
}: {
  sequenceTag: string;
  ruleIndex: number;
  expression: SequenceFlowExpression | undefined;
  runtime: RuntimeIndexes;
  pluginByTag: Map<string, PluginInstance>;
}) {
  const result = getActionStatus(sequenceTag, ruleIndex, expression, runtime);
  const plugin =
    result.runtimeTag === undefined
      ? undefined
      : pluginByTag.get(result.runtimeTag);

  return (
    <StatusPopover
      title={sequenceActionLabel(expression)}
      events={result.events}
      fallback={expression ? `字段 ${expression.field}` : "该规则没有 exec"}
    >
      <span
        className={cn(
          "inline-flex max-w-full items-center gap-1.5 rounded border px-2 py-1 text-left text-[10px] transition-colors",
          actionStatusClass(result.status),
        )}
      >
        {actionStatusIcon(result.status)}
        <span className="min-w-0 flex-1 truncate font-mono">
          {sequenceActionLabel(expression)}
        </span>
        {plugin && (
          <span
            className={cn(
              "shrink-0 rounded px-1 py-px text-[9px]",
              pluginKindBadgeOutlineClass(plugin.type),
            )}
          >
            {plugin.pluginKind}
          </span>
        )}
        <StatusSuffix
          events={result.events}
          label={actionStatusLabel(result.status)}
        />
      </span>
    </StatusPopover>
  );
}

function StatusPopover({
  title,
  events,
  fallback,
  children,
}: {
  title: string;
  events: QueryRecorderStep[];
  fallback: string;
  children: ReactNode;
}) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="nodrag nopan min-w-0"
          onClick={(event) => event.stopPropagation()}
        >
          {children}
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-80 text-xs" align="start">
        <div className="space-y-2">
          <div className="font-medium">{title}</div>
          <div className="font-mono text-[10px] text-muted-foreground">
            {fallback}
          </div>
          {events.length > 0 ? (
            <div className="max-h-44 space-y-1 overflow-auto">
              {events.map((event) => (
                <div
                  key={event.event_index}
                  className="grid grid-cols-[3rem_1fr_auto] gap-2 rounded border bg-muted/20 px-2 py-1 font-mono text-[10px]"
                >
                  <span className="text-muted-foreground">
                    #{event.event_index}
                  </span>
                  <span className="min-w-0 truncate">
                    {event.sequence_tag}
                    {typeof event.node_index === "number"
                      ? ` / ${event.node_index}`
                      : ""}
                  </span>
                  <span>{event.outcome}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded border border-dashed bg-muted/10 px-2 py-3 text-muted-foreground">
              本次查询没有记录到这个节点的运行事件。
            </div>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function StatusSuffix({
  events,
  label,
}: {
  events: QueryRecorderStep[];
  label: string;
}) {
  return (
    <span className="inline-flex shrink-0 items-center gap-1">
      <span className="rounded bg-background/70 px-1 py-px text-[9px]">
        {label}
      </span>
      {events.length > 1 && (
        <span className="rounded bg-background/70 px-1 py-px font-mono text-[9px]">
          x{events.length}
        </span>
      )}
    </span>
  );
}

function QueryStepNode({ data }: NodeProps<QueryStepFlowNode>) {
  const step = data.step;
  return (
    <div className="relative w-72 rounded-md border bg-card px-3 py-2 shadow-sm">
      <Handle
        type="target"
        position={Position.Top}
        className="!h-2 !w-2 !border-border !bg-background"
      />
      <div className="flex min-w-0 items-center justify-between gap-2">
        <span className="font-mono text-xs text-muted-foreground">
          #{step.event_index}
        </span>
        <Badge variant="outline" className="font-mono text-[10px]">
          {step.outcome}
        </Badge>
      </div>
      <div className="mt-1 min-w-0 truncate font-mono text-xs">
        {step.sequence_tag}
        {typeof step.node_index === "number" ? ` / ${step.node_index}` : ""}
      </div>
      <div className="mt-2 flex min-w-0 items-center gap-1.5">
        <span
          className={cn(
            "rounded px-1.5 py-0.5 font-mono text-[10px]",
            step.kind === "matcher"
              ? "bg-amber-500/10 text-amber-700 dark:text-amber-300"
              : "bg-sky-500/10 text-sky-700 dark:text-sky-300",
          )}
        >
          {step.kind}
        </span>
        <span className="min-w-0 truncate font-mono text-[10px] text-muted-foreground">
          {step.tag ?? "-"}
        </span>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        className="!h-2 !w-2 !border-border !bg-background"
      />
    </div>
  );
}

function QueryRecordFlowLegend({ fallback }: { fallback: boolean }) {
  return (
    <div className="rounded-md border bg-card/90 p-2 text-[11px] shadow-sm backdrop-blur-sm">
      <div className="mb-1.5 font-semibold text-muted-foreground">图例</div>
      <div className="space-y-1">
        <LegendLine color={QUERY_MATCH_COLOR} label="matcher 判断" dashed />
        <LegendLine color={QUERY_EDGE_COLOR} label="sequence 跳转" />
        {fallback && (
          <div className="flex items-center gap-1.5 text-muted-foreground">
            <AlertTriangle className="h-3 w-3 text-amber-500" />
            原始事件顺序
          </div>
        )}
      </div>
    </div>
  );
}

function LegendLine({
  color,
  label,
  dashed,
}: {
  color: string;
  label: string;
  dashed?: boolean;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <svg width="24" height="8" className="shrink-0">
        <line
          x1="0"
          y1="4"
          x2="20"
          y2="4"
          stroke={color}
          strokeWidth="2"
          strokeDasharray={dashed ? "4 2" : undefined}
        />
      </svg>
      <span className="text-muted-foreground">{label}</span>
    </div>
  );
}

function getMatchStatus(
  sequenceTag: string,
  ruleIndex: number,
  matchIndex: number,
  expression: SequenceFlowExpression,
  runtime: RuntimeIndexes,
) {
  const runtimeTag = matcherRuntimeTag(
    sequenceTag,
    ruleIndex,
    matchIndex,
    expression,
  );
  const events = runtimeTag
    ? (runtime.matchers.get(matcherKey(sequenceTag, ruleIndex, runtimeTag)) ??
      [])
    : [];
  const last = events[events.length - 1];
  const status: MatchStatus =
    last?.outcome === "matched"
      ? "matched"
      : last?.outcome === "not_matched"
        ? "not_matched"
        : "unevaluated";
  return { status, events, runtimeTag };
}

function getActionStatus(
  sequenceTag: string,
  ruleIndex: number,
  expression: SequenceFlowExpression | undefined,
  runtime: RuntimeIndexes,
) {
  const target = actionRuntimeTarget(sequenceTag, ruleIndex, expression);
  const events = target
    ? (runtime.actions.get(
        actionKey(sequenceTag, ruleIndex, target.kind, target.tag),
      ) ?? [])
    : [];
  return {
    status: reduceActionStatus(events),
    events,
    runtimeTag: target?.tag,
  };
}

function reduceActionStatus(events: QueryRecorderStep[]): ActionStatus {
  if (events.length === 0) return "not_executed";
  if (events.some((event) => event.outcome === "error")) return "error";
  if (events.some((event) => event.outcome === "stop")) return "stop";
  if (events.some((event) => event.outcome === "return")) return "return";
  if (events.some((event) => event.outcome === "next")) return "next";
  if (events.some((event) => event.outcome === "entered")) return "entered";
  return "not_executed";
}

function matcherRuntimeTag(
  sequenceTag: string,
  ruleIndex: number,
  matchIndex: number,
  expression: SequenceFlowExpression,
) {
  if (expression.target_tag) return expression.target_tag;
  if (expression.kind === "quick_setup" && expression.plugin_type) {
    return `@qs:match:${sequenceTag}:${ruleIndex}:${matchIndex}:${expression.plugin_type}`;
  }
  return undefined;
}

function actionRuntimeTarget(
  sequenceTag: string,
  ruleIndex: number,
  expression: SequenceFlowExpression | undefined,
) {
  if (!expression) return undefined;
  if (expression.kind === "builtin" && expression.builtin) {
    return { kind: "builtin", tag: expression.builtin };
  }
  if (expression.target_tag) {
    return { kind: "executor", tag: expression.target_tag };
  }
  if (expression.kind === "quick_setup" && expression.plugin_type) {
    return {
      kind: "executor",
      tag: `@qs:exec:${sequenceTag}:${ruleIndex}:${expression.plugin_type}`,
    };
  }
  return undefined;
}

function targetSequenceTag(
  expression: SequenceFlowExpression | undefined,
  flowByTag: Map<string, SequenceFlowReport>,
  visibleSequences: Set<string>,
) {
  if (!expression?.target_tag || !visibleSequences.has(expression.target_tag)) {
    return undefined;
  }
  if (expression.kind === "builtin") {
    return expression.builtin === "jump" || expression.builtin === "goto"
      ? expression.target_tag
      : undefined;
  }
  return flowByTag.has(expression.target_tag)
    ? expression.target_tag
    : undefined;
}

function orderedSequenceTags(steps: QueryRecorderStep[]) {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const step of steps
    .slice()
    .sort((a, b) => a.event_index - b.event_index)) {
    if (seen.has(step.sequence_tag)) continue;
    seen.add(step.sequence_tag);
    tags.push(step.sequence_tag);
  }
  return tags;
}

function matcherKey(sequenceTag: string, ruleIndex: number, tag: string) {
  return `${sequenceTag}|${ruleIndex}|${tag}`;
}

function actionKey(
  sequenceTag: string,
  ruleIndex: number,
  kind: string,
  tag: string,
) {
  return `${sequenceTag}|${ruleIndex}|${kind}|${tag}`;
}

function pushMapValue<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const values = map.get(key) ?? [];
  values.push(value);
  map.set(key, values);
}

function sequenceExpressionLabel(expression: SequenceFlowExpression) {
  const not = expression.inverted ? "!" : "";
  if (expression.kind === "quick_setup") {
    const param = expression.param
      ? ` ${compactText(expression.param, 18)}`
      : "";
    return `${not}quick(${expression.plugin_type ?? "?"})${param}`;
  }
  if (expression.target_tag) return `${not}$${expression.target_tag}`;
  return `${not}${compactText(expression.raw, 26)}`;
}

function sequenceActionLabel(expression: SequenceFlowExpression | undefined) {
  if (!expression) return "无 exec";
  if (expression.kind === "builtin") {
    const param = expression.param
      ? ` ${compactText(expression.param, 18)}`
      : "";
    return `${expression.builtin ?? "builtin"}${param}`;
  }
  return sequenceExpressionLabel(expression);
}

function compactText(value: string, maxLength: number) {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}

function eventRangeLabel(steps: QueryRecorderStep[]) {
  if (steps.length === 0) return "-";
  const first = steps[0]?.event_index;
  const last = steps[steps.length - 1]?.event_index;
  return first === last ? `#${first}` : `#${first}-#${last}`;
}

function InvertMark() {
  return (
    <span
      aria-label="取反"
      className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded border border-rose-400 bg-rose-100 font-mono text-[11px] font-bold leading-none text-rose-600 dark:border-rose-600 dark:bg-rose-950 dark:text-rose-400"
    >
      !
    </span>
  );
}

function matchStatusIcon(status: MatchStatus) {
  if (status === "matched") return <Check className="h-3 w-3 shrink-0" />;
  if (status === "not_matched") return <X className="h-3 w-3 shrink-0" />;
  return <Circle className="h-3 w-3 shrink-0" />;
}

function actionStatusIcon(status: ActionStatus) {
  if (status === "error") return <AlertTriangle className="h-3 w-3 shrink-0" />;
  if (status === "not_executed") return <Circle className="h-3 w-3 shrink-0" />;
  return <Play className="h-3 w-3 shrink-0" />;
}

function matchStatusLabel(status: MatchStatus) {
  if (status === "matched") return "命中";
  if (status === "not_matched") return "未命中";
  return "未评估";
}

function actionStatusLabel(status: ActionStatus) {
  switch (status) {
    case "entered":
      return "已进入";
    case "next":
      return "继续";
    case "stop":
      return "停止";
    case "return":
      return "返回";
    case "error":
      return "错误";
    default:
      return "未执行";
  }
}

function matchStatusClass(status: MatchStatus) {
  if (status === "matched") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 hover:border-emerald-500/60 dark:text-emerald-300";
  }
  if (status === "not_matched") {
    return "border-rose-500/30 bg-rose-500/10 text-rose-700 hover:border-rose-500/60 dark:text-rose-300";
  }
  return "border-border bg-muted/30 text-muted-foreground hover:border-primary/40";
}

function actionStatusClass(status: ActionStatus) {
  if (status === "error") {
    return "border-destructive/40 bg-destructive/10 text-destructive hover:border-destructive/70";
  }
  if (status === "stop" || status === "return") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 hover:border-emerald-500/60 dark:text-emerald-300";
  }
  if (status === "next" || status === "entered") {
    return "border-sky-500/30 bg-sky-500/10 text-sky-700 hover:border-sky-500/60 dark:text-sky-300";
  }
  return "border-border bg-muted/30 text-muted-foreground hover:border-primary/40";
}
