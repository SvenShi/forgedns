"use client";

import { useMemo, useState } from "react";
import { Copy, Check, Server, Zap, Filter, Database } from "lucide-react";
import { pluginKindDefinitions } from "@/lib/plugin-definitions";
import type { PluginType } from "@/lib/types";

interface PluginEntry {
  tag: string;
  kind: string;
  category: PluginType | "unknown";
  line: number;
}

const kindToCategory = new Map<string, PluginType>(
  pluginKindDefinitions.map((d) => [d.kind, d.type]),
);

const CATEGORY_ORDER: (PluginType | "unknown")[] = [
  "server",
  "executor",
  "matcher",
  "provider",
];

const CATEGORY_LABELS: Record<PluginType | "unknown", string> = {
  server: "服务器",
  executor: "执行器",
  matcher: "匹配器",
  provider: "数据源",
  unknown: "未知",
};

const CATEGORY_ICONS: Record<PluginType | "unknown", React.ReactNode> = {
  server: <Server className="h-3 w-3" />,
  executor: <Zap className="h-3 w-3" />,
  matcher: <Filter className="h-3 w-3" />,
  provider: <Database className="h-3 w-3" />,
  unknown: null,
};

function parsePluginsFromYaml(text: string): PluginEntry[] {
  const lines = text.split("\n");
  const results: PluginEntry[] = [];

  let inPlugins = false;
  let itemIndent = -1;
  let current: { tag?: string; kind?: string; line?: number } | null = null;

  const flush = () => {
    if (current?.tag && current.line != null) {
      const kind = current.kind ?? "";
      results.push({
        tag: current.tag,
        kind,
        category: kindToCategory.get(kind) ?? "unknown",
        line: current.line,
      });
    }
    current = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trimStart();
    const indent = raw.length - trimmed.length;

    if (!trimmed || trimmed.startsWith("#")) continue;

    if (!inPlugins) {
      if (indent === 0 && /^plugins\s*:/.test(trimmed)) {
        inPlugins = true;
      }
      continue;
    }

    // Back to a top-level key — plugins section ended
    if (indent === 0 && !trimmed.startsWith("- ")) {
      break;
    }

    if (trimmed.startsWith("- ")) {
      flush();
      current = { line: i + 1 };
      itemIndent = indent;
      const rest = trimmed.slice(2).trim();
      const tagM = rest.match(/^tag\s*:\s*(.+)/);
      if (tagM) current.tag = tagM[1].trim();
      const typeM = rest.match(/^type\s*:\s*(.+)/);
      if (typeM) current.kind = typeM[1].trim();
    } else if (current && indent > itemIndent) {
      const tagM = trimmed.match(/^tag\s*:\s*(.+)/);
      if (tagM) current.tag = tagM[1].trim();
      const typeM = trimmed.match(/^type\s*:\s*(.+)/);
      if (typeM) current.kind = typeM[1].trim();
    }
  }

  flush();
  return results;
}

interface PluginIndexPanelProps {
  yamlText: string;
  onJumpToLine?: (line: number) => void;
}

export function PluginIndexPanel({
  yamlText,
  onJumpToLine,
}: PluginIndexPanelProps) {
  const [copiedTag, setCopiedTag] = useState<string | null>(null);

  const entries = useMemo(() => parsePluginsFromYaml(yamlText), [yamlText]);

  const grouped = useMemo(() => {
    const map = new Map<PluginType | "unknown", PluginEntry[]>();
    for (const entry of entries) {
      const list = map.get(entry.category) ?? [];
      list.push(entry);
      map.set(entry.category, list);
    }
    return map;
  }, [entries]);

  const handleCopy = (tag: string, e: React.MouseEvent) => {
    e.stopPropagation();
    void navigator.clipboard.writeText(`$${tag}`).then(() => {
      setCopiedTag(tag);
      setTimeout(() => setCopiedTag(null), 1500);
    });
  };

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-16 text-xs text-muted-foreground">
        暂无插件
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {CATEGORY_ORDER.map((cat) => {
        const items = grouped.get(cat);
        if (!items?.length) return null;
        return (
          <div key={cat}>
            <div className="flex items-center gap-1.5 mb-1 px-1">
              <span className="text-muted-foreground/70">
                {CATEGORY_ICONS[cat]}
              </span>
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                {CATEGORY_LABELS[cat]}
              </span>
              <span className="ml-auto text-xs tabular-nums text-muted-foreground/50">
                {items.length}
              </span>
            </div>
            <div className="space-y-0.5">
              {items.map((entry) => (
                <div
                  key={entry.tag}
                  className="group flex items-center gap-1 rounded px-1.5 py-1 cursor-pointer hover:bg-muted/60 transition-colors"
                  onClick={() => onJumpToLine?.(entry.line)}
                >
                  <span className="flex-1 truncate text-xs font-mono text-foreground/90">
                    {entry.tag}
                  </span>
                  <button
                    className="hidden group-hover:flex items-center p-0.5 rounded text-muted-foreground hover:text-foreground transition-colors flex-shrink-0"
                    onClick={(e) => handleCopy(entry.tag, e)}
                    title={`复制 $${entry.tag}`}
                  >
                    {copiedTag === entry.tag ? (
                      <Check className="h-3 w-3 text-primary" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </button>
                  <span className="text-xs text-muted-foreground/40 font-mono flex-shrink-0">
                    {entry.kind}
                  </span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
