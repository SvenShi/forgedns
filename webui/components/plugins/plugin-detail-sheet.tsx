"use client";

import { useState } from "react";
import { Maximize2, Minimize2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetClose, SheetContent } from "@/components/ui/sheet";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import { DefaultPluginDetail } from "@/components/plugins/default-plugin-detail";
import { getPluginComponentDefinition } from "@/components/plugins/registry";
import type { PluginMetricPoint } from "@/components/plugins/types";

const generateChartData = (): PluginMetricPoint[] =>
  Array.from({ length: 24 }, (_, i) => ({
    time: `${i}:00`,
    qps: Math.floor(Math.random() * 1000) + 500,
    latency: Math.random() * 10 + 1,
  }));

export function PluginDetailSheet() {
  const { selectedPlugin, detailOpen, setDetailOpen } = useAppStore();
  const [chartData] = useState(generateChartData);
  const [expandedPluginId, setExpandedPluginId] = useState<string | null>(null);

  if (!selectedPlugin) return null;

  const expanded = expandedPluginId === selectedPlugin.id;

  const DetailComponent =
    getPluginComponentDefinition(selectedPlugin)?.Detail ?? DefaultPluginDetail;

  const handleOpenChange = (open: boolean) => {
    if (!open && isSequenceFullscreenOpen()) return;
    if (!open) setExpandedPluginId(null);
    setDetailOpen(open);
  };

  return (
    <Sheet open={detailOpen} onOpenChange={handleOpenChange}>
      <SheetContent
        overlayClassName="bg-background/45 backdrop-blur-[1px]"
        showCloseButton={false}
        className={cn(
          "gap-0 overflow-y-auto bg-background p-0 shadow-2xl data-[side=right]:!max-w-none data-[side=right]:!w-full",
          expanded
            ? "data-[side=right]:!inset-0 data-[side=right]:!h-svh data-[side=right]:!border-l-0 sm:data-[side=right]:!w-full"
            : "sm:data-[side=right]:!w-[min(920px,calc(100vw-3rem))]",
        )}
        onPointerDownOutside={(event) => {
          if (isSequenceFullscreenEvent(event)) event.preventDefault();
        }}
        onInteractOutside={(event) => {
          if (isSequenceFullscreenEvent(event)) event.preventDefault();
        }}
      >
        <div className="absolute right-3 top-3 z-20 flex items-center gap-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() =>
                  setExpandedPluginId((current) =>
                    current === selectedPlugin.id ? null : selectedPlugin.id,
                  )
                }
              >
                {expanded ? (
                  <Minimize2 className="h-4 w-4" />
                ) : (
                  <Maximize2 className="h-4 w-4" />
                )}
                <span className="sr-only">
                  {expanded ? "还原详情宽度" : "放大详情"}
                </span>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">
              {expanded ? "还原" : "放大"}
            </TooltipContent>
          </Tooltip>
          <SheetClose asChild>
            <Button variant="ghost" size="icon-sm">
              <X className="h-4 w-4" />
              <span className="sr-only">关闭详情</span>
            </Button>
          </SheetClose>
        </div>
        <DetailComponent
          key={selectedPlugin.id}
          plugin={selectedPlugin}
          chartData={chartData}
          onClose={() => setDetailOpen(false)}
        />
      </SheetContent>
    </Sheet>
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
