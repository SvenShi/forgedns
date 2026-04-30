"use client";

import type { PluginDetailComponentProps } from "./types";
import { PluginDetailTemplate } from "./plugin-detail-template";

export function DefaultPluginDetail(props: PluginDetailComponentProps) {
  return <PluginDetailTemplate {...props} />;
}
