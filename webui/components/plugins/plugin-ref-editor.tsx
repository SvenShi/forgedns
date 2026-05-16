/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

"use client";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  getPluginCatalogItem,
  getPluginCatalogItemsByType,
} from "@/components/plugins/catalog";
import { PluginReferencePicker } from "@/components/plugins/plugin-reference-picker";
import type { PluginInstance, PluginType } from "@/lib/types";
import { cn } from "@/lib/utils";

// ─── InlineSelect ─────────────────────────────────────────────────────────────

export function InlineSelect({
  value,
  options,
  disabled,
  onChange,
  placeholder,
  className,
}: {
  value: string;
  options: Array<{ value: string; label: string }>;
  disabled: boolean;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <Select value={value} onValueChange={onChange} disabled={disabled}>
      <SelectTrigger
        className={`h-8 min-w-0 bg-background ${className ?? ""}`}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent className="z-[1200]">
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

// ─── QuickSetupRow ────────────────────────────────────────────────────────────
//
// Renders the two-column quick_setup form: plugin-kind select + param input
// (or PluginReferencePicker when paramReferenceTypes is set). Used in both the
// sequence composer and the cron composer for inline plugin invocations.

export function QuickSetupRow({
  type,
  value,
  plugins,
  readOnly,
  onChange,
}: {
  type: PluginType;
  value: string;
  plugins: PluginInstance[];
  readOnly: boolean;
  onChange: (next: string) => void;
}) {
  const { pluginType, param } = parseQuickSetupValue(value);
  const catalog = getPluginCatalogItemsByType(type).filter(
    (item) => item.quickSetup,
  );
  const activeDef = getPluginCatalogItem(pluginType);
  const paramRefTypes = activeDef?.quickSetup?.paramReferenceTypes ?? [];
  const paramPlaceholder =
    activeDef?.quickSetup?.paramPlaceholder ?? "参数 (可选)";
  const accent = type === "matcher" ? "amber" : "sky";

  return (
    <div className="flex min-w-0 items-center gap-1.5">
      <span
        className={cn(
          "shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold",
          accent === "amber"
            ? "bg-amber-100/80 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300"
            : "bg-sky-100/80 text-sky-700 dark:bg-sky-900/50 dark:text-sky-300",
        )}
      >
        qs
      </span>
      <InlineSelect
        value={pluginType}
        onChange={(nextKind) => onChange(formatQuickSetupValue(nextKind, param))}
        disabled={readOnly}
        className="w-[9rem] shrink-0"
        options={catalog.map((item) => ({
          value: item.kind,
          label: item.kind,
        }))}
      />
      <div className="min-w-0 flex-1">
        {paramRefTypes.length > 0 ? (
          <PluginReferencePicker
            plugins={plugins}
            value={stripReferencePrefix(param)}
            referenceTypes={paramRefTypes}
            disabled={readOnly}
            placeholder={paramPlaceholder}
            allowCreate
            onChange={(tag) =>
              onChange(formatQuickSetupValue(pluginType, `$${tag}`))
            }
          />
        ) : (
          <Input
            value={param}
            onChange={(event) =>
              onChange(formatQuickSetupValue(pluginType, event.target.value))
            }
            placeholder={paramPlaceholder}
            className="h-8 w-full font-mono text-xs"
            disabled={readOnly}
          />
        )}
      </div>
    </div>
  );
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/** Returns true when `value` starts with a plugin kind that has quickSetup. */
export function isQuickSetupValue(value: string, type: PluginType): boolean {
  const head = value.trim().split(/\s+/)[0];
  if (!head) return false;
  const def = getPluginCatalogItem(head);
  return Boolean(def && def.type === type && def.quickSetup);
}

export interface QuickSetupParts {
  pluginType: string;
  param: string;
}

export function parseQuickSetupValue(value: string): QuickSetupParts {
  const trimmed = value.trim();
  const firstSpace = trimmed.search(/\s/);
  if (firstSpace === -1) return { pluginType: trimmed, param: "" };
  return {
    pluginType: trimmed.slice(0, firstSpace),
    param: trimmed.slice(firstSpace + 1).trim(),
  };
}

export function formatQuickSetupValue(pluginType: string, param: string): string {
  return param.trim() ? `${pluginType} ${param.trim()}` : pluginType;
}

/** Returns the kind of the first plugin of `type` that has quickSetup defined. */
export function firstQuickSetupKind(type: PluginType): string {
  return (
    getPluginCatalogItemsByType(type).find((item) => item.quickSetup)?.kind ??
    ""
  );
}

/** Strips leading `!` (invert) and `$` (reference prefix) from a raw value. */
export function stripReferencePrefix(value: unknown): string {
  const text = typeof value === "string" ? value.trim() : "";
  const withoutInvert = text.startsWith("!") ? text.slice(1) : text;
  return withoutInvert.startsWith("$") ? withoutInvert.slice(1) : withoutInvert;
}

/** Creates a random unique ID for newly added items. */
export function createItemId(): string {
  return `item_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

/** Creates a deterministic ID for items parsed from a serialised config. */
export function createStableItemId(scope: string, index: number): string {
  return `${scope}_${index}`;
}
