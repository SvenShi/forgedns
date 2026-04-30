"use client";

import { create } from "zustand";
import type { PluginInstance } from "./types";
import { mockPlugins, mockSystemMetrics, mockSystemInfo } from "./mock-data";

interface AppState {
  plugins: PluginInstance[];
  systemMetrics: typeof mockSystemMetrics;
  systemInfo: typeof mockSystemInfo;
  selectedPlugin: PluginInstance | null;
  detailOpen: boolean;
  editorMode: boolean;
  isRestarting: boolean;
  yamlConfig: string;

  setSelectedPlugin: (plugin: PluginInstance | null) => void;
  setDetailOpen: (open: boolean) => void;
  setEditorMode: (mode: boolean) => void;
  setYamlConfig: (config: string) => void;
  restartService: () => Promise<void>;
  togglePluginPin: (id: string) => void;
  togglePluginEnabled: (id: string) => void;
  updatePluginConfig: (id: string, config: Record<string, unknown>) => void;
  deletePlugin: (id: string) => void;
  addPlugin: (
    plugin: Omit<PluginInstance, "id" | "createdAt" | "updatedAt" | "metrics">,
  ) => void;
  renamePlugin: (id: string, name: string) => void;
}

const defaultYamlConfig = `# ForgeDNS Configuration
plugins:
  - tag: seq_main
    type: sequence
    args:
      - exec: "$cache_main"
      - matches: "has_resp"
        exec: "accept"
      - matches: "!has_resp"
        exec: "$forward_main"
  - tag: udp_in
    type: udp_server
    args:
      entry: "seq_main"
      listen: "0.0.0.0:53"
  - tag: cache_main
    type: cache
    args:
      size: 8192
      short_circuit: false
  - tag: forward_main
    type: forward
    args:
      upstreams:
        - tag: "cloudflare"
          addr: "udp://1.1.1.1:53"
          timeout: 3s
`;

export const useAppStore = create<AppState>((set) => ({
  plugins: mockPlugins,
  systemMetrics: mockSystemMetrics,
  systemInfo: mockSystemInfo,
  selectedPlugin: null,
  detailOpen: false,
  editorMode: false,
  isRestarting: false,
  yamlConfig: defaultYamlConfig,

  setSelectedPlugin: (plugin) => set({ selectedPlugin: plugin }),
  setDetailOpen: (open) => set({ detailOpen: open }),
  setEditorMode: (mode) => set({ editorMode: mode }),
  setYamlConfig: (config) => set({ yamlConfig: config }),
  restartService: async () => {
    set({ isRestarting: true });
    // Simulate restart delay
    await new Promise((resolve) => setTimeout(resolve, 2000));
    set({ isRestarting: false });
  },

  togglePluginPin: (id) =>
    set((state) => ({
      plugins: state.plugins.map((p) =>
        p.id === id ? { ...p, pinned: !p.pinned } : p,
      ),
      selectedPlugin:
        state.selectedPlugin?.id === id
          ? { ...state.selectedPlugin, pinned: !state.selectedPlugin.pinned }
          : state.selectedPlugin,
    })),

  togglePluginEnabled: (id) =>
    set((state) => ({
      plugins: state.plugins.map((p) =>
        p.id === id
          ? {
              ...p,
              enabled: !p.enabled,
              status: !p.enabled ? "running" : "stopped",
            }
          : p,
      ),
      selectedPlugin:
        state.selectedPlugin?.id === id
          ? {
              ...state.selectedPlugin,
              enabled: !state.selectedPlugin.enabled,
              status: !state.selectedPlugin.enabled ? "running" : "stopped",
            }
          : state.selectedPlugin,
    })),

  updatePluginConfig: (id, config) =>
    set((state) => ({
      plugins: state.plugins.map((p) =>
        p.id === id ? { ...p, config, updatedAt: new Date().toISOString() } : p,
      ),
      selectedPlugin:
        state.selectedPlugin?.id === id
          ? {
              ...state.selectedPlugin,
              config,
              updatedAt: new Date().toISOString(),
            }
          : state.selectedPlugin,
    })),

  deletePlugin: (id) =>
    set((state) => ({
      plugins: state.plugins.filter((p) => p.id !== id),
      selectedPlugin:
        state.selectedPlugin?.id === id ? null : state.selectedPlugin,
      detailOpen: state.selectedPlugin?.id === id ? false : state.detailOpen,
    })),

  addPlugin: (plugin) =>
    set((state) => ({
      plugins: [
        ...state.plugins,
        {
          ...plugin,
          id: String(Date.now()),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          metrics: { calls: 0, avgLatency: 0, errorRate: 0, qps: 0 },
        },
      ],
    })),

  renamePlugin: (id, name) =>
    set((state) => ({
      plugins: state.plugins.map((p) =>
        p.id === id ? { ...p, name, updatedAt: new Date().toISOString() } : p,
      ),
      selectedPlugin:
        state.selectedPlugin?.id === id
          ? {
              ...state.selectedPlugin,
              name,
              updatedAt: new Date().toISOString(),
            }
          : state.selectedPlugin,
    })),
}));
