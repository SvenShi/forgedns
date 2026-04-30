"use client";

import type { PluginInstance } from "@/lib/types";
import { DefaultPluginCard } from "@/components/plugins/default-plugin-card";
import { getPluginComponentDefinition } from "@/components/plugins/registry";

interface PluginCardProps {
  plugin: PluginInstance;
  compact?: boolean;
}

export function PluginCard({ plugin, compact = false }: PluginCardProps) {
  const CardComponent =
    getPluginComponentDefinition(plugin)?.Card ?? DefaultPluginCard;

  return <CardComponent plugin={plugin} compact={compact} />;
}
