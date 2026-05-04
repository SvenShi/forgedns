"use client";

import { useState } from "react";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { useAppStore } from "@/lib/store";
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

  if (!selectedPlugin) return null;

  const DetailComponent =
    getPluginComponentDefinition(selectedPlugin)?.Detail ?? DefaultPluginDetail;

  const handleOpenChange = (open: boolean) => {
    if (!open && isSequenceFullscreenOpen()) return;
    setDetailOpen(open);
  };

  return (
    <Sheet open={detailOpen} onOpenChange={handleOpenChange}>
      <SheetContent
        overlayClassName="bg-background/45 backdrop-blur-[1px]"
        className="gap-0 overflow-y-auto bg-background p-0 shadow-2xl data-[side=right]:!w-full data-[side=right]:!max-w-none sm:data-[side=right]:!w-[min(920px,calc(100vw-3rem))]"
        onPointerDownOutside={(event) => {
          if (isSequenceFullscreenEvent(event)) event.preventDefault();
        }}
        onInteractOutside={(event) => {
          if (isSequenceFullscreenEvent(event)) event.preventDefault();
        }}
      >
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
