"use client";

import { useState } from "react";
import {
  Rocket,
  History,
  AlertCircle,
  MoreHorizontal,
  GitCompare,
  Undo2,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAppStore } from "@/lib/store";
import { useAuthStore } from "@/lib/auth-store";
import type { ConfigSnapshot } from "@/lib/config-history";
import { ConfigDiffDialog } from "@/components/config/config-diff-dialog";

export type SyncState =
  | "in-sync"
  | "not-applied"
  | "applying"
  | "apply-failed"
  | "error";

export interface ConfigSyncStatus {
  state: SyncState;
  label: string;
  tone: "neutral" | "warning" | "destructive";
  head: ConfigSnapshot | undefined;
  /** Snapshot of the config that is currently running on the backend. */
  lastGood: ConfigSnapshot | undefined;
}

// Single source of truth for "is the on-disk config in sync with what's
// running" — shared by the global header control and the editor so the two
// never disagree.
export function useConfigSyncStatus(): ConfigSyncStatus {
  const configHistory = useAppStore((s) => s.configHistory);
  const configError = useAppStore((s) => s.configError);
  const configVersion = useAppStore((s) => s.configVersion);
  const runningVersion = useAppStore((s) => s.runningVersion);
  const isApplying = useAppStore((s) => s.isApplying);

  // Snapshot of the config currently on disk (what 应用 would push live).
  const current = configHistory.find((s) => s.version === configVersion);
  // Snapshot of what the backend is actually running right now. applyStatus
  // is a sticky per-entry flag (an old "applied" never clears), so we resolve
  // the running config by runningVersion — not by find(applied).
  const lastGood =
    configHistory.find((s) => s.version === runningVersion) ??
    configHistory.find((s) => s.applyStatus === "applied");

  let state: SyncState = "in-sync";
  let tone: ConfigSyncStatus["tone"] = "neutral";
  let label = "配置已同步";

  if (isApplying) {
    state = "applying";
    label = "正在应用配置…";
  } else if (configError) {
    state = "error";
    tone = "destructive";
    label = "配置有错误，无法应用；可在菜单中恢复有效版本";
  } else if (
    configVersion &&
    runningVersion &&
    configVersion === runningVersion
  ) {
    // On-disk config == what's running → nothing to apply.
    state = "in-sync";
  } else if (configVersion && current?.applyStatus === "apply-failed") {
    state = "apply-failed";
    tone = "destructive";
    label = `应用失败：${current.applyError ?? "热重载未成功"}`;
  } else if (configVersion) {
    state = "not-applied";
    tone = "warning";
    label = "有未应用的配置改动，点击应用";
  }

  return { state, label, tone, head: current, lastGood };
}

const PILL_TONE: Record<"warning" | "destructive", string> = {
  warning:
    "border-yellow-500/40 bg-yellow-500/10 text-yellow-700 hover:bg-yellow-500/20 hover:text-yellow-700 dark:text-yellow-300 dark:hover:text-yellow-300",
  destructive:
    "border-destructive/40 bg-destructive/10 text-destructive hover:bg-destructive/20 hover:text-destructive",
};

// One shared, mode-agnostic config-sync control for the global AppHeader.
// In-sync it is near-invisible (a calm history icon + overflow menu); when
// there are pending / failed / invalid changes it becomes a prominent
// amber/red pill so the operator never misses an unapplied change.
export function ConfigSyncControl() {
  const isConnected = useAuthStore((s) => s.isConnected);
  const applyConfig = useAppStore((s) => s.applyConfig);
  const restoreSnapshot = useAppStore((s) => s.restoreSnapshot);
  const saveConfig = useAppStore((s) => s.saveConfig);
  const setHistoryOpen = useAppStore((s) => s.setHistoryOpen);
  const configText = useAppStore((s) => s.configText);
  const configVersion = useAppStore((s) => s.configVersion);
  const { state, label, tone, lastGood } = useConfigSyncStatus();

  const [diffOpen, setDiffOpen] = useState(false);

  if (!isConnected) return null;

  const handleApply = async () => {
    try {
      await applyConfig();
    } catch {
      // Surfaced via the snapshot status (red pill + label).
    }
  };

  // "Discard pending change, go back to the running config." Loads the
  // running config into the buffer AND writes it to disk, so disk == running
  // and the sync status returns to in-sync (pill clears) — without needing a
  // reload, since the running config is already what's live.
  const handleRevertToRunning = async () => {
    if (!lastGood) return;
    restoreSnapshot(lastGood.id);
    try {
      await saveConfig();
    } catch {
      // Validation/save failure is surfaced via configError (error pill).
    }
  };

  const canDiff = Boolean(lastGood && lastGood.content !== configText);
  const canRestore = Boolean(
    lastGood && lastGood.version !== configVersion,
  );

  const pillClass = tone === "neutral" ? "" : PILL_TONE[tone];

  const primary =
    state === "in-sync" ? (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon-sm"
            className="rounded-md"
            onClick={() => setHistoryOpen(true)}
          >
            <History className="h-4 w-4" />
            <span className="sr-only">配置历史</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent>配置历史（已同步）</TooltipContent>
      </Tooltip>
    ) : state === "applying" ? (
      <Button
        variant="outline"
        size="sm"
        className="h-7 gap-1.5 rounded-md px-2.5"
        disabled
      >
        <Spinner className="h-3.5 w-3.5" />
        应用中
      </Button>
    ) : (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className={`h-7 gap-1.5 rounded-md px-2.5 ${pillClass}`}
            onClick={handleApply}
            disabled={state === "error"}
          >
            {state === "not-applied" ? (
              <Rocket className="h-3.5 w-3.5" />
            ) : (
              <AlertCircle className="h-3.5 w-3.5" />
            )}
            {state === "not-applied"
              ? "应用更改"
              : state === "apply-failed"
                ? "应用失败·重试"
                : "配置有误"}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{label}</TooltipContent>
      </Tooltip>
    );

  return (
    <>
      <div className="flex items-center gap-1">
        {primary}
        <DropdownMenu>
          <Tooltip>
            <TooltipTrigger asChild>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="rounded-md"
                >
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">配置操作</span>
                </Button>
              </DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent>配置操作</TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuItem
              disabled={!canDiff}
              onClick={() => setDiffOpen(true)}
            >
              <GitCompare className="h-4 w-4" />
              查看差异
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setHistoryOpen(true)}>
              <History className="h-4 w-4" />
              配置历史
            </DropdownMenuItem>
            {canRestore && lastGood && (
              <DropdownMenuItem onClick={handleRevertToRunning}>
                <Undo2 className="h-4 w-4" />
                放弃改动·恢复运行版
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              disabled={state === "applying" || state === "error"}
              onClick={handleApply}
            >
              <RefreshCw className="h-4 w-4" />
              重载当前配置
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {lastGood && (
        <ConfigDiffDialog
          open={diffOpen}
          onOpenChange={setDiffOpen}
          original={lastGood.content}
          modified={configText}
          originalTitle="正在运行"
          modifiedTitle="待应用（当前配置）"
        />
      )}
    </>
  );
}
