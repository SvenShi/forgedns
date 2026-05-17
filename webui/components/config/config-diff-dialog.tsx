"use client";

import { DiffEditor, type DiffOnMount } from "@monaco-editor/react";
import { useTheme } from "next-themes";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { registerOxiDnsYamlLanguage } from "@/lib/oxidns-yaml-monaco";

type MonacoApi = Parameters<DiffOnMount>[1];

interface ConfigDiffDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Left side — the selected historical snapshot. */
  original: string;
  /** Right side — the current editor content. */
  modified: string;
  originalTitle?: string;
  modifiedTitle?: string;
}

export function ConfigDiffDialog({
  open,
  onOpenChange,
  original,
  modified,
  originalTitle = "历史快照",
  modifiedTitle = "当前编辑器",
}: ConfigDiffDialogProps) {
  const { resolvedTheme } = useTheme();
  const theme =
    resolvedTheme === "light" ? "oxidns-yaml-light" : "oxidns-yaml-dark";

  const handleBeforeMount = (monaco: MonacoApi) => {
    registerOxiDnsYamlLanguage(monaco);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex h-[min(80vh,720px)] max-w-[min(1100px,calc(100vw-3rem))] flex-col gap-3 sm:max-w-[min(1100px,calc(100vw-3rem))]">
        <DialogHeader>
          <DialogTitle>配置差异对比</DialogTitle>
          <DialogDescription>
            左：{originalTitle} · 右：{modifiedTitle}
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 overflow-hidden rounded-md border bg-muted/30 font-mono text-sm">
          <DiffEditor
            height="100%"
            language="yaml"
            theme={theme}
            original={original}
            modified={modified}
            beforeMount={handleBeforeMount}
            options={{
              readOnly: true,
              renderSideBySide: true,
              automaticLayout: true,
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              wordWrap: "on",
              fontSize: 13,
              lineHeight: 22,
              fontFamily:
                "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace",
              renderOverviewRuler: false,
            }}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
