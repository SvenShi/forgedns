/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

"use client";

import {
  useMemo,
  useState,
  type ReactNode,
  type SyntheticEvent,
} from "react";
import { createPortal } from "react-dom";
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
import {
  ArrowDown,
  ArrowRight,
  GitBranch,
  Maximize2,
  Minimize2,
  Minus,
  Plus,
  Save,
  Search,
  Trash2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { YamlEditor } from "@/components/config/yaml-editor";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  getPluginCatalogItem,
  getPluginCatalogItemsByType,
  renderPluginKindIcon,
  type PluginCatalogItem,
} from "@/components/plugins/catalog";
import {
  createDefaultPluginConfigValues,
  PluginConfigFieldsEditor,
  serializePluginConfigValues,
} from "@/components/plugins/plugin-config-fields-editor";
import { useAppStore } from "@/lib/store";
import type { PluginInstance, PluginType } from "@/lib/types";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import {
  parsePluginConfigYaml,
  stringifyPluginConfigYaml,
} from "@/lib/plugin-config-yaml";

type ConditionMode = "reference" | "text";
type ActionMode = "reference" | "control" | "text";
type ControlKind = "accept" | "return" | "reject" | "mark" | "jump" | "goto";

type SequenceFlowNode =
  | Node<RuleNodeData, "rule">
  | Node<PreviewNodeData, "preview">;

interface RuleNodeData extends Record<string, unknown> {
  rule: SequenceRule;
  index: number;
  total: number;
  plugins: PluginInstance[];
  sequenceTags: string[];
  readOnly: boolean;
  currentSequenceName?: string;
  visitedSequences: Set<string>;
  onChange: (patch: Partial<SequenceRule>) => void;
  onMove: (offset: number) => void;
  onDelete: () => void;
}

interface PreviewNodeData extends Record<string, unknown> {
  action: SequenceAction;
  plugins: PluginInstance[];
  currentSequenceName?: string;
  visitedSequences: Set<string>;
}

interface SequenceCondition {
  id: string;
  mode: ConditionMode;
  value: string;
  invert: boolean;
}

interface SequenceAction {
  mode: ActionMode;
  value: string;
  control: ControlKind;
}

interface SequenceRule {
  id: string;
  matches: SequenceCondition[];
  action: SequenceAction;
}

interface SequenceComposerProps {
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  plugins: PluginInstance[];
  readOnly?: boolean;
  currentSequenceName?: string;
}

interface SequenceCanvasProps {
  rules: SequenceRule[];
  plugins: PluginInstance[];
  sequenceTags: string[];
  readOnly: boolean;
  currentSequenceName?: string;
  fullHeight?: boolean;
  onAddRule: () => void;
  onUpdateRule: (ruleId: string, patch: Partial<SequenceRule>) => void;
  onMoveRule: (index: number, offset: number) => void;
  onDeleteRule: (ruleId: string) => void;
}

const conditionModeLabels: Record<ConditionMode, string> = {
  reference: "引用",
  text: "文本",
};

const actionModeLabels: Record<ActionMode, string> = {
  reference: "引用",
  control: "控制流",
  text: "文本",
};

const controlLabels: Record<ControlKind, string> = {
  accept: "accept",
  return: "return",
  reject: "reject",
  mark: "mark",
  jump: "jump",
  goto: "goto",
};

const builtinControls: ControlKind[] = [
  "accept",
  "return",
  "reject",
  "mark",
  "jump",
  "goto",
];

const flowNodeTypes = {
  rule: SequenceRuleFlowNode,
  preview: SequencePreviewFlowNode,
};

const sequenceNodeInteractionClass =
  "sequence-flow-interactive nodrag nopan nowheel";

export function SequenceComposer({
  value,
  onChange,
  plugins,
  readOnly = false,
  currentSequenceName,
}: SequenceComposerProps) {
  const [view, setView] = useState<"visual" | "yaml">("visual");
  const [expanded, setExpanded] = useState(false);
  const [yamlText, setYamlText] = useState(() =>
    stringifyPluginConfigYaml(value),
  );
  const [yamlError, setYamlError] = useState<string | null>(null);
  const rules = useMemo(() => parseSequenceRules(value.args), [value.args]);
  const sequenceTags = plugins
    .filter((plugin) => plugin.type === "executor" && plugin.pluginKind === "sequence")
    .map((plugin) => plugin.name);

  const updateRules = (nextRules: SequenceRule[]) => {
    onChange({ ...value, args: serializeSequenceRules(nextRules) });
  };

  const addRule = () => {
    updateRules([...rules, createEmptyRule()]);
  };

  const updateRule = (ruleId: string, patch: Partial<SequenceRule>) => {
    updateRules(
      rules.map((rule) =>
        rule.id === ruleId
          ? {
              ...rule,
              ...patch,
            }
          : rule,
      ),
    );
  };

  const moveRule = (index: number, offset: number) => {
    const nextIndex = index + offset;
    if (nextIndex < 0 || nextIndex >= rules.length) return;
    const nextRules = [...rules];
    const [rule] = nextRules.splice(index, 1);
    nextRules.splice(nextIndex, 0, rule);
    updateRules(nextRules);
  };

  const deleteRule = (ruleId: string) => {
    updateRules(rules.filter((rule) => rule.id !== ruleId));
  };

  const handleViewChange = (nextView: "visual" | "yaml") => {
    if (nextView === "yaml") {
      setYamlText(stringifyPluginConfigYaml(value));
      setYamlError(null);
    }
    setView(nextView);
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

    setYamlError("sequence 配置必须是 YAML 对象");
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Tabs
          value={view}
          onValueChange={(next) => handleViewChange(next as typeof view)}
        >
          <TabsList className="grid w-44 max-w-full grid-cols-2">
            <TabsTrigger value="visual">画布</TabsTrigger>
            <TabsTrigger value="yaml">YAML</TabsTrigger>
          </TabsList>
        </Tabs>
        {view === "yaml" && yamlError && (
          <Badge variant="destructive" className="h-auto gap-1 whitespace-normal py-1">
            {yamlError}
          </Badge>
        )}
        {!readOnly && view === "visual" && (
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setExpanded(true)}
            >
              <Maximize2 className="h-4 w-4" />
              全屏
            </Button>
            <Button type="button" size="sm" onClick={addRule}>
              <Plus className="h-4 w-4" />
              新增规则
            </Button>
          </div>
        )}
        {readOnly && view === "visual" && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setExpanded(true)}
          >
            <Maximize2 className="h-4 w-4" />
            全屏
          </Button>
        )}
      </div>

      {view === "visual" && (
        <>
          <SequenceCanvas
            rules={rules}
            plugins={plugins}
            sequenceTags={sequenceTags}
            readOnly={readOnly}
            currentSequenceName={currentSequenceName}
            onAddRule={addRule}
            onUpdateRule={updateRule}
            onMoveRule={moveRule}
            onDeleteRule={deleteRule}
          />
          {expanded &&
            typeof document !== "undefined" &&
            createPortal(
              <SequenceExpandedCanvas
                rules={rules}
                plugins={plugins}
                sequenceTags={sequenceTags}
                readOnly={readOnly}
                currentSequenceName={currentSequenceName}
                onClose={() => setExpanded(false)}
                onAddRule={addRule}
                onUpdateRule={updateRule}
                onMoveRule={moveRule}
                onDeleteRule={deleteRule}
              />
              ,
              document.body,
            )}
        </>
      )}

      {view === "yaml" && (
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

function SequenceExpandedCanvas({
  rules,
  plugins,
  sequenceTags,
  readOnly,
  currentSequenceName,
  onClose,
  onAddRule,
  onUpdateRule,
  onMoveRule,
  onDeleteRule,
}: {
  rules: SequenceRule[];
  plugins: PluginInstance[];
  sequenceTags: string[];
  readOnly: boolean;
  currentSequenceName?: string;
  onClose: () => void;
  onAddRule: () => void;
  onUpdateRule: (ruleId: string, patch: Partial<SequenceRule>) => void;
  onMoveRule: (index: number, offset: number) => void;
  onDeleteRule: (ruleId: string) => void;
}) {
  return (
    <div
      data-sequence-fullscreen="true"
      className="pointer-events-auto fixed inset-0 z-[1000] flex h-dvh w-screen flex-col overflow-hidden bg-background"
      onPointerDownCapture={(event) => event.stopPropagation()}
      onKeyDownCapture={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          onClose();
        }
      }}
    >
      <div className="flex min-h-14 items-center justify-between gap-3 border-b bg-sidebar/80 px-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium">
            <GitBranch className="h-4 w-4 text-primary" />
            <span>Sequence 编排画布</span>
            <Badge variant="secondary" className="font-mono">
              {rules.length} rules
            </Badge>
          </div>
          <div className="mt-0.5 text-xs text-muted-foreground">
            全屏编辑只影响视图，保存仍使用当前插件配置按钮。
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {!readOnly && (
            <Button type="button" size="sm" onClick={onAddRule}>
              <Plus className="h-4 w-4" />
              新增规则
            </Button>
          )}
          <Button type="button" variant="outline" size="sm" onClick={onClose}>
            <Minimize2 className="h-4 w-4" />
            退出全屏
          </Button>
        </div>
      </div>
      <div className="min-h-0 flex-1 p-4">
        <SequenceCanvas
          rules={rules}
          plugins={plugins}
          sequenceTags={sequenceTags}
          readOnly={readOnly}
          currentSequenceName={currentSequenceName}
          fullHeight
          onAddRule={onAddRule}
          onUpdateRule={onUpdateRule}
          onMoveRule={onMoveRule}
          onDeleteRule={onDeleteRule}
        />
      </div>
    </div>
  );
}

function SequenceCanvas({
  rules,
  plugins,
  sequenceTags,
  readOnly,
  currentSequenceName,
  fullHeight = false,
  onAddRule,
  onUpdateRule,
  onMoveRule,
  onDeleteRule,
}: SequenceCanvasProps) {
  if (rules.length === 0) {
    return (
      <div
        className={
          fullHeight
            ? "flex h-full flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center"
            : "rounded-lg border border-dashed p-8 text-center"
        }
      >
        <GitBranch className="mx-auto h-8 w-8 text-muted-foreground" />
        <div className="mt-3 text-sm font-medium">暂无规则</div>
        <p className="mt-1 text-xs text-muted-foreground">
          sequence 至少需要一条规则，通常从 cache、matcher 或 forward 开始。
        </p>
        {!readOnly && (
          <Button type="button" className="mt-4" onClick={onAddRule}>
            <Plus className="h-4 w-4" />
            新增第一条规则
          </Button>
        )}
      </div>
    );
  }

  const { nodes, edges } = buildSequenceFlow({
    rules,
    plugins,
    sequenceTags,
    readOnly,
    currentSequenceName,
    onUpdateRule,
    onMoveRule,
    onDeleteRule,
  });

  return (
    <div
      className={
        fullHeight
          ? "sequence-flow h-full min-h-0 rounded-lg border bg-muted/20"
          : "sequence-flow h-[520px] rounded-lg border bg-muted/20"
      }
    >
      <ReactFlow<SequenceFlowNode, Edge>
        nodes={nodes}
        edges={edges}
        nodeTypes={flowNodeTypes}
        fitView
        fitViewOptions={{ padding: 0.16 }}
        minZoom={0.35}
        maxZoom={1.8}
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        elementsSelectable={false}
        noDragClassName="sequence-flow-interactive"
        noPanClassName="sequence-flow-interactive"
        noWheelClassName="sequence-flow-interactive"
        panOnDrag={[1]}
        zoomOnScroll
        zoomOnPinch
        zoomOnDoubleClick={false}
        preventScrolling
      >
        <Background gap={18} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function buildSequenceFlow({
  rules,
  plugins,
  sequenceTags,
  readOnly,
  currentSequenceName,
  onUpdateRule,
  onMoveRule,
  onDeleteRule,
}: {
  rules: SequenceRule[];
  plugins: PluginInstance[];
  sequenceTags: string[];
  readOnly: boolean;
  currentSequenceName?: string;
  onUpdateRule: (ruleId: string, patch: Partial<SequenceRule>) => void;
  onMoveRule: (index: number, offset: number) => void;
  onDeleteRule: (ruleId: string) => void;
}): { nodes: SequenceFlowNode[]; edges: Edge[] } {
  const nodes: SequenceFlowNode[] = [];
  const edges: Edge[] = [];
  const baseVisited = currentSequenceName
    ? new Set([currentSequenceName])
    : new Set<string>();

  rules.forEach((rule, index) => {
    const ruleId = `rule-${rule.id}`;
    nodes.push({
      id: ruleId,
      type: "rule",
      position: { x: 0, y: index * 260 },
      data: {
        rule,
        index,
        total: rules.length,
        plugins,
        sequenceTags,
        readOnly,
        currentSequenceName,
        visitedSequences: baseVisited,
        onChange: (patch) => onUpdateRule(rule.id, patch),
        onMove: (offset) => onMoveRule(index, offset),
        onDelete: () => onDeleteRule(rule.id),
      },
      draggable: false,
      selectable: false,
      focusable: false,
    });

    if (index < rules.length - 1) {
      edges.push({
        id: `seq-${rule.id}-${rules[index + 1].id}`,
        source: ruleId,
        target: `rule-${rules[index + 1].id}`,
        type: "smoothstep",
        animated: false,
        style: { strokeWidth: 2 },
      });
    }

    const target = getSequenceControlTarget(rule.action);
    if (target) {
      const previewId = `preview-${rule.id}-${target}`;
      nodes.push({
        id: previewId,
        type: "preview",
        position: { x: 900, y: index * 260 },
        data: {
          action: rule.action,
          plugins,
          currentSequenceName,
          visitedSequences: baseVisited,
        },
        draggable: false,
        selectable: false,
        focusable: false,
      });
      edges.push({
        id: `branch-${rule.id}-${target}`,
        source: ruleId,
        target: previewId,
        type: "smoothstep",
        animated: rule.action.control === "goto",
        style: {
          stroke: rule.action.control === "goto" ? "var(--destructive)" : "var(--primary)",
          strokeWidth: 2,
        },
      });
    }
  });

  return { nodes, edges };
}

function SequenceRuleFlowNode({ data }: NodeProps<Node<RuleNodeData, "rule">>) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <InteractiveNodeFrame>
        <SequenceRuleNode {...data} />
      </InteractiveNodeFrame>
      <Handle type="source" position={Position.Bottom} id="next" />
      <Handle type="source" position={Position.Right} id="branch" />
    </>
  );
}

function SequencePreviewFlowNode({
  data,
}: NodeProps<Node<PreviewNodeData, "preview">>) {
  return (
    <>
      <Handle type="target" position={Position.Left} />
      <InteractiveNodeFrame>
        <SequenceReferencePreview {...data} />
      </InteractiveNodeFrame>
    </>
  );
}

function InteractiveNodeFrame({ children }: { children: ReactNode }) {
  return (
    <div
      className={sequenceNodeInteractionClass}
      onWheel={stopCanvasEvent}
    >
      {children}
    </div>
  );
}

function stopCanvasEvent(event: SyntheticEvent) {
  event.stopPropagation();
}

function InlineSelect({
  value,
  options,
  disabled,
  onChange,
}: {
  value: string;
  options: Array<{ value: string; label: string }>;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      className="h-8 min-w-0 rounded-lg border border-input bg-background px-2 text-sm outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

function SequenceRuleNode({
  rule,
  index,
  total,
  plugins,
  sequenceTags,
  readOnly,
  onChange,
  onMove,
  onDelete,
}: {
  rule: SequenceRule;
  index: number;
  total: number;
  plugins: PluginInstance[];
  sequenceTags: string[];
  readOnly: boolean;
  onChange: (patch: Partial<SequenceRule>) => void;
  onMove: (offset: number) => void;
  onDelete: () => void;
}) {
  const addCondition = () => {
    onChange({ matches: [...rule.matches, createEmptyCondition()] });
  };

  const updateCondition = (
    conditionId: string,
    patch: Partial<SequenceCondition>,
  ) => {
    onChange({
      matches: rule.matches.map((condition) =>
        condition.id === conditionId ? { ...condition, ...patch } : condition,
      ),
    });
  };

  const deleteCondition = (conditionId: string) => {
    onChange({
      matches: rule.matches.filter((condition) => condition.id !== conditionId),
    });
  };

  return (
    <div className="nodrag nopan nowheel">
      <Card className="w-[760px] rounded-lg bg-background py-0 shadow-sm">
        <CardHeader className="grid grid-cols-[1fr_auto] items-center gap-2 border-b px-3 py-2">
          <div className="flex min-w-0 items-center gap-2">
            <Badge variant="secondary" className="font-mono">
              #{index + 1}
            </Badge>
            <CardTitle className="truncate text-sm">
              {summarizeRule(rule)}
            </CardTitle>
          </div>
          {!readOnly && (
            <div className="flex items-center gap-1">
              <Button
                type="button"
                variant="outline"
                size="icon-sm"
                disabled={index === 0}
                onClick={() => onMove(-1)}
                aria-label="上移规则"
              >
                <ArrowDown className="h-4 w-4 rotate-180" />
              </Button>
              <Button
                type="button"
                variant="outline"
                size="icon-sm"
                disabled={index === total - 1}
                onClick={() => onMove(1)}
                aria-label="下移规则"
              >
                <ArrowDown className="h-4 w-4" />
              </Button>
              <Button
                type="button"
                variant="outline"
                size="icon-sm"
                onClick={onDelete}
                aria-label="删除规则"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          )}
        </CardHeader>
        <CardContent className="grid gap-3 p-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <div className="text-xs font-medium text-muted-foreground">
                匹配条件
              </div>
              {!readOnly && (
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  onClick={addCondition}
                >
                  <Plus className="h-3.5 w-3.5" />
                  条件
                </Button>
              )}
            </div>
            {rule.matches.length > 0 ? (
              <div className="space-y-2">
                {rule.matches.map((condition) => (
                  <ConditionEditor
                    key={condition.id}
                    condition={condition}
                    plugins={plugins}
                    readOnly={readOnly}
                    onChange={(patch) => updateCondition(condition.id, patch)}
                    onDelete={() => deleteCondition(condition.id)}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-md border border-dashed px-3 py-4 text-center text-xs text-muted-foreground">
                无条件，始终命中
              </div>
            )}
          </div>

          <div className="hidden items-center px-1 text-muted-foreground lg:flex">
            <ArrowRight className="h-5 w-5" />
          </div>

          <div className="space-y-2">
            <div className="text-xs font-medium text-muted-foreground">
              执行动作
            </div>
            <ActionEditor
              action={rule.action}
              plugins={plugins}
              sequenceTags={sequenceTags}
              readOnly={readOnly}
              onChange={(action) => onChange({ action })}
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ConditionEditor({
  condition,
  plugins,
  readOnly,
  onChange,
  onDelete,
}: {
  condition: SequenceCondition;
  plugins: PluginInstance[];
  readOnly: boolean;
  onChange: (patch: Partial<SequenceCondition>) => void;
  onDelete: () => void;
}) {
  return (
    <div className="rounded-md border bg-muted/20 p-2">
      <div className="grid gap-2 sm:grid-cols-[7.5rem_1fr_auto]">
        <InlineSelect
          value={condition.mode}
          onChange={(mode) =>
            onChange({
              mode: mode as ConditionMode,
              value: condition.value || defaultConditionValue(mode as ConditionMode),
            })
          }
          disabled={readOnly}
          options={Object.entries(conditionModeLabels).map(([value, label]) => ({
            value,
            label,
          }))}
        />
        {condition.mode === "reference" ? (
          <ReferenceCreatePicker
            plugins={plugins}
            value={stripReferencePrefix(condition.value)}
            referenceTypes={["matcher"]}
            disabled={readOnly}
            placeholder="选择 matcher"
            onChange={(tag) => onChange({ value: `$${tag}` })}
          />
        ) : (
          <Input
            value={condition.value}
            onChange={(event) => onChange({ value: event.target.value })}
            placeholder="has_resp / qname domain:example.com"
            className="h-8 font-mono text-xs"
            disabled={readOnly}
          />
        )}
        {!readOnly && (
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={onDelete}
            aria-label="删除条件"
          >
            <Minus className="h-4 w-4" />
          </Button>
        )}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <Switch
          checked={condition.invert}
          disabled={readOnly}
          onCheckedChange={(invert) => onChange({ invert })}
        />
        <span className="text-xs text-muted-foreground">取反</span>
      </div>
    </div>
  );
}

function SequenceReferencePreview({
  action,
  plugins,
  currentSequenceName,
  visitedSequences,
}: {
  action: SequenceAction;
  plugins: PluginInstance[];
  currentSequenceName?: string;
  visitedSequences: Set<string>;
}) {
  const target = getSequenceControlTarget(action);
  if (!target) return null;

  const isSelfReference = Boolean(currentSequenceName && target === currentSequenceName);
  const isVisited = visitedSequences.has(target);
  const targetPlugin = plugins.find(
    (plugin) =>
      plugin.name === target &&
      plugin.type === "executor" &&
      plugin.pluginKind === "sequence",
  );

  if (isSelfReference || isVisited) {
    return (
      <div className="w-[360px] rounded-lg border border-dashed bg-background/90 px-3 py-2 text-xs text-muted-foreground shadow-sm">
        {action.control} 指向{" "}
        <span className="font-mono text-foreground">{target}</span>
        ，已用指向标记表示，避免循环展开。
      </div>
    );
  }

  if (!targetPlugin) {
    return (
      <div className="w-[360px] rounded-lg border border-dashed bg-background/90 px-3 py-2 text-xs text-muted-foreground shadow-sm">
        {action.control} 目标{" "}
        <span className="font-mono text-foreground">{target}</span> 尚未创建。
      </div>
    );
  }

  const targetRules = parseSequenceRules(targetPlugin.config.args);

  return (
      <div className="w-max rounded-lg border border-dashed bg-background/95 p-3 shadow-sm">
        <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
          <GitBranch className="h-3.5 w-3.5 text-primary" />
          <span>
            {action.control} 到{" "}
            <span className="font-mono text-foreground">{target}</span>{" "}
            的只读执行链
          </span>
        </div>
        <div className="space-y-3">
          {targetRules.length > 0 ? (
            targetRules.map((rule, index) => (
              <SequenceRuleNode
                key={`${target}-${rule.id}`}
                rule={rule}
                index={index}
                total={targetRules.length}
                plugins={plugins}
                sequenceTags={[]}
                readOnly
                onChange={() => undefined}
                onMove={() => undefined}
                onDelete={() => undefined}
              />
            ))
          ) : (
            <div className="rounded-md border border-dashed px-3 py-4 text-center text-xs text-muted-foreground">
              目标 sequence 暂无规则
            </div>
          )}
        </div>
    </div>
  );
}

function ActionEditor({
  action,
  plugins,
  sequenceTags,
  readOnly,
  onChange,
}: {
  action: SequenceAction;
  plugins: PluginInstance[];
  sequenceTags: string[];
  readOnly: boolean;
  onChange: (action: SequenceAction) => void;
}) {
  const controlArg = getControlArg(action);

  const updateMode = (mode: ActionMode) => {
    if (mode === "control") {
      onChange({
        mode,
        value: action.control,
        control: action.control,
      });
      return;
    }

    onChange({
      mode,
      value: action.value || defaultActionValue(mode),
      control: "accept",
    });
  };

  const updateControl = (control: ControlKind) => {
    onChange({
      mode: "control",
      control,
      value: control === "accept" || control === "return" ? control : `${control} `,
    });
  };

  return (
    <div className="rounded-md border bg-muted/20 p-2">
      <div className="grid gap-2 sm:grid-cols-[7.5rem_1fr]">
        <InlineSelect
          value={action.mode}
          onChange={(mode) => updateMode(mode as ActionMode)}
          disabled={readOnly}
          options={Object.entries(actionModeLabels).map(([value, label]) => ({
            value,
            label,
          }))}
        />

        {action.mode === "reference" && (
          <ReferenceCreatePicker
            plugins={plugins}
            value={stripReferencePrefix(action.value)}
            referenceTypes={["executor"]}
            disabled={readOnly}
            placeholder="选择 executor"
            onChange={(tag) =>
              onChange({ mode: "reference", value: `$${tag}`, control: action.control })
            }
          />
        )}

        {action.mode === "text" && (
          <Input
            value={action.value}
            onChange={(event) =>
              onChange({ ...action, value: event.target.value })
            }
            placeholder="forward 1.1.1.1 / ttl 300 / debug_print hit"
            className="h-8 font-mono text-xs"
            disabled={readOnly}
          />
        )}

        {action.mode === "control" && (
          <div className="grid gap-2 sm:grid-cols-[8rem_1fr]">
            <InlineSelect
              value={action.control}
              onChange={(control) => updateControl(control as ControlKind)}
              disabled={readOnly}
              options={builtinControls.map((control) => ({
                value: control,
                label: controlLabels[control],
              }))}
            />
            {action.control === "accept" || action.control === "return" ? (
              <div className="flex h-8 items-center rounded-md border bg-background px-2 font-mono text-xs text-muted-foreground">
                {action.control}
              </div>
            ) : action.control === "jump" || action.control === "goto" ? (
              <SequenceTargetInput
                value={controlArg}
                sequenceTags={sequenceTags}
                disabled={readOnly}
                onChange={(target) =>
                  onChange({
                    mode: "control",
                    control: action.control,
                    value: `${action.control} ${target}`.trim(),
                  })
                }
              />
            ) : (
              <Input
                value={controlArg}
                onChange={(event) =>
                  onChange({
                    mode: "control",
                    control: action.control,
                    value: `${action.control} ${event.target.value}`.trim(),
                  })
                }
                placeholder={action.control === "reject" ? "3" : "1,2,3"}
                className="h-8 font-mono text-xs"
                disabled={readOnly}
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SequenceTargetInput({
  value,
  sequenceTags,
  disabled,
  onChange,
}: {
  value: string;
  sequenceTags: string[];
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <>
      <Input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="seq_tag"
        className="h-8 font-mono text-xs"
        disabled={disabled}
        list="sequence-targets"
      />
      <datalist id="sequence-targets">
        {sequenceTags.map((tag) => (
          <option key={tag} value={tag} />
        ))}
      </datalist>
    </>
  );
}

function ReferenceCreatePicker({
  plugins,
  value,
  referenceTypes,
  disabled,
  placeholder,
  onChange,
}: {
  plugins: PluginInstance[];
  value: string;
  referenceTypes: PluginType[];
  disabled: boolean;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const normalizedSearch = search.trim().toLowerCase();
  const selectedPlugin = plugins.find((plugin) => plugin.name === value);
  const filteredPlugins = plugins.filter((plugin) => {
    if (!referenceTypes.includes(plugin.type)) return false;
    if (!normalizedSearch) return true;
    const definition = getPluginCatalogItem(plugin.pluginKind);
    return [
      plugin.name,
      plugin.pluginKind,
      plugin.type,
      definition?.name,
      definition?.description,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(normalizedSearch);
  });

  return (
    <>
      <Popover open={open && !disabled} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            type="button"
            variant="outline"
            className="h-8 min-w-0 justify-between bg-background font-normal"
            disabled={disabled}
          >
            {selectedPlugin ? (
              <span className="flex min-w-0 items-center gap-2">
                {renderPluginKindIcon(
                  getPluginCatalogItem(selectedPlugin.pluginKind)?.icon ?? "Database",
                  { className: "h-4 w-4 shrink-0 text-primary" },
                )}
                <span className="truncate font-mono text-xs">
                  {selectedPlugin.name}
                </span>
              </span>
            ) : value ? (
              <span className="truncate font-mono text-xs">{value}</span>
            ) : (
              <span className="text-xs text-muted-foreground">{placeholder}</span>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent
          align="start"
          className="z-[1100] w-[26rem] max-w-[calc(100vw-3rem)] p-2"
        >
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索插件 tag、类型或说明"
              className="h-8 pl-9"
            />
          </div>
          <div className="mt-2 max-h-64 space-y-1 overflow-y-auto">
            {filteredPlugins.map((plugin) => (
              <button
                key={plugin.id}
                type="button"
                className="flex w-full items-center gap-2 rounded-md border bg-background p-2 text-left hover:bg-accent"
                onClick={() => {
                  onChange(plugin.name);
                  setOpen(false);
                  setSearch("");
                }}
              >
                {renderPluginKindIcon(
                  getPluginCatalogItem(plugin.pluginKind)?.icon ?? "Database",
                  { className: "h-4 w-4 shrink-0 text-primary" },
                )}
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-xs">
                    {plugin.name}
                  </span>
                  <span className="block truncate text-[0.7rem] text-muted-foreground">
                    {PLUGIN_TYPE_LABELS[plugin.type]} · {getPluginCatalogItem(plugin.pluginKind)?.name ?? plugin.pluginKind}
                  </span>
                </span>
              </button>
            ))}
            {filteredPlugins.length === 0 && (
              <div className="rounded-md border border-dashed p-3 text-center text-xs text-muted-foreground">
                没有匹配的插件
              </div>
            )}
          </div>
          <div className="mt-2 border-t pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-full"
              onClick={() => {
                setCreateOpen(true);
                setOpen(false);
              }}
            >
              <Plus className="h-4 w-4" />
              快速创建{referenceTypes.includes("matcher") ? " Matcher" : " Executor"}
            </Button>
          </div>
        </PopoverContent>
      </Popover>
      <QuickCreatePluginDialog
        key={`${referenceTypes[0]}-${search.trim()}`}
        open={createOpen}
        onOpenChange={setCreateOpen}
        pluginType={referenceTypes[0]}
        defaultName={search.trim()}
        onCreated={onChange}
      />
    </>
  );
}

function QuickCreatePluginDialog({
  open,
  onOpenChange,
  pluginType,
  defaultName,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pluginType: PluginType;
  defaultName: string;
  onCreated: (tag: string) => void;
}) {
  const addPlugin = useAppStore((state) => state.addPlugin);
  const plugins = useAppStore((state) => state.plugins);
  const catalogItems = getPluginCatalogItemsByType(pluginType);
  const [selectedKind, setSelectedKind] = useState<PluginCatalogItem | null>(
    catalogItems[0] ?? null,
  );
  const [instanceName, setInstanceName] = useState(defaultName);
  const [configValues, setConfigValues] = useState<Record<string, unknown>>(
    () =>
      catalogItems[0]
        ? createDefaultPluginConfigValues(catalogItems[0].configSchema)
        : {},
  );

  const handleKindChange = (kind: string) => {
    const nextKind = catalogItems.find((item) => item.kind === kind) ?? null;
    setSelectedKind(nextKind);
    setConfigValues(
      nextKind ? createDefaultPluginConfigValues(nextKind.configSchema) : {},
    );
  };

  const handleCreate = () => {
    const tag = instanceName.trim();
    if (!selectedKind || !tag) return;
    addPlugin({
      name: tag,
      type: selectedKind.type,
      pluginKind: selectedKind.kind,
      status: "stopped",
      enabled: false,
      pinned: false,
      config: serializePluginConfigValues(selectedKind.configSchema, configValues),
    });
    onCreated(tag);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[calc(100vw-2rem)] sm:!max-w-[760px]">
        <DialogHeader>
          <DialogTitle>快速创建插件</DialogTitle>
          <DialogDescription>
            创建后会立即回填到当前 sequence 规则中。
          </DialogDescription>
        </DialogHeader>
        <div className="grid max-h-[70vh] gap-4 overflow-y-auto pr-1">
          <FieldGroup>
            <Field>
              <FieldLabel>插件类型</FieldLabel>
              <Select
                value={selectedKind?.kind ?? ""}
                onValueChange={handleKindChange}
              >
                <SelectTrigger>
                  <SelectValue placeholder="选择插件类型" />
                </SelectTrigger>
                <SelectContent>
                  {catalogItems.map((item) => (
                    <SelectItem key={item.kind} value={item.kind}>
                      {item.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel>实例名称</FieldLabel>
              <Input
                value={instanceName}
                onChange={(event) => setInstanceName(event.target.value)}
                placeholder={`${selectedKind?.kind ?? pluginType}_main`}
                className="font-mono"
              />
            </Field>
            {selectedKind && (
              <Field>
                <FieldLabel>插件配置</FieldLabel>
                <PluginConfigFieldsEditor
                  fields={selectedKind.configSchema}
                  plugins={plugins}
                  values={configValues}
                  onChange={setConfigValues}
                />
              </Field>
            )}
          </FieldGroup>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={handleCreate} disabled={!selectedKind || !instanceName.trim()}>
            <Save className="h-4 w-4" />
            创建并引用
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function parseSequenceRules(value: unknown): SequenceRule[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => {
    const record: Record<string, unknown> =
      entry && typeof entry === "object" && !Array.isArray(entry)
        ? (entry as Record<string, unknown>)
        : { exec: entry };
    return {
      id: createItemId(),
      matches: parseMatches(record.matches),
      action: parseAction(record.exec),
    };
  });
}

export function serializeSequenceRules(rules: SequenceRule[]) {
  return rules
    .map((rule) => {
      const entry: Record<string, unknown> = {};
      const matches = serializeMatches(rule.matches);
      const exec = serializeAction(rule.action);
      if (matches !== undefined) entry.matches = matches;
      if (exec) entry.exec = exec;
      return entry;
    })
    .filter((entry) => Object.keys(entry).length > 0);
}

function parseMatches(value: unknown): SequenceCondition[] {
  const entries = Array.isArray(value)
    ? value
    : typeof value === "string" && value.trim()
      ? [value]
      : [];

  return entries
    .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
    .filter(Boolean)
    .map(parseCondition);
}

function parseCondition(value: string): SequenceCondition {
  const inverted = value.startsWith("!");
  const withoutInvert = inverted ? value.slice(1) : value;
  if (withoutInvert.startsWith("$")) {
    return {
      id: createItemId(),
      mode: "reference",
      value: withoutInvert,
      invert: inverted,
    };
  }
  return {
    id: createItemId(),
    mode: "text",
    value: withoutInvert,
    invert: inverted,
  };
}

function parseAction(value: unknown): SequenceAction {
  const text = typeof value === "string" ? value.trim() : "";
  const control = inferControlKind(text);
  if (text.startsWith("$")) {
    return { mode: "reference", value: text, control: "accept" };
  }
  if (control) {
    return { mode: "control", value: text, control };
  }
  if (text) {
    return {
      mode: "text",
      value: text,
      control: "accept",
    };
  }
  return { mode: "text", value: "", control: "accept" };
}

function serializeMatches(matches: SequenceCondition[]) {
  const serialized = matches
    .map((condition) => {
      const value = condition.value.trim();
      if (!value) return "";
      if (condition.mode === "reference") {
        const tag = stripReferencePrefix(value);
        return `${condition.invert ? "!" : ""}$${tag}`;
      }
      return `${condition.invert ? "!" : ""}${value}`;
    })
    .filter(Boolean);

  if (serialized.length === 0) return undefined;
  if (serialized.length === 1) return serialized[0];
  return serialized;
}

function serializeAction(action: SequenceAction) {
  if (action.mode === "reference") {
    const tag = stripReferencePrefix(action.value);
    return tag ? `$${tag}` : "";
  }
  if (action.mode === "control") {
    const arg = getControlArg(action);
    if (action.control === "accept" || action.control === "return") {
      return action.control;
    }
    return `${action.control} ${arg}`.trim();
  }
  return action.value.trim();
}

function createEmptyRule(): SequenceRule {
  return {
    id: createItemId(),
    matches: [],
    action: { mode: "control", value: "accept", control: "accept" },
  };
}

function createEmptyCondition(): SequenceCondition {
  return {
    id: createItemId(),
    mode: "text",
    value: "has_resp",
    invert: false,
  };
}

function defaultConditionValue(mode: ConditionMode) {
  if (mode === "reference") return "$has_resp";
  return "has_resp";
}

function defaultActionValue(mode: ActionMode) {
  if (mode === "reference") return "$forward_main";
  if (mode === "text") return "accept";
  return "accept";
}

function inferControlKind(value: string): ControlKind | null {
  const head = value.trim().split(/\s+/)[0];
  return builtinControls.includes(head as ControlKind) ? (head as ControlKind) : null;
}

function getControlArg(action: SequenceAction) {
  const expectedHead = `${action.control} `;
  if (action.value.startsWith(expectedHead)) return action.value.slice(expectedHead.length);
  if (action.value === action.control) return "";
  return action.value.trim().split(/\s+/).slice(1).join(" ");
}

function getSequenceControlTarget(action: SequenceAction) {
  if (
    action.mode !== "control" ||
    (action.control !== "jump" && action.control !== "goto")
  ) {
    return "";
  }

  return getControlArg(action).trim();
}

function stripReferencePrefix(value: unknown) {
  const text = typeof value === "string" ? value.trim() : "";
  const withoutInvert = text.startsWith("!") ? text.slice(1) : text;
  return withoutInvert.startsWith("$") ? withoutInvert.slice(1) : withoutInvert;
}

function summarizeRule(rule: SequenceRule) {
  const matches =
    rule.matches.length === 0
      ? "always"
      : rule.matches.map((condition) => serializeMatches([condition])).join(" && ");
  const action = serializeAction(rule.action) || "未配置动作";
  return `${matches} -> ${action}`;
}

function createItemId() {
  return `seq_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}
