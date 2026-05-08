"use client";

import { create } from "zustand";
import type { PluginInstance } from "./types";
import { mockPlugins, mockSystemMetrics, mockSystemInfo } from "./mock-data";
import {
  configFromPlugins,
  createDefaultOxiDnsConfig,
  parseOxiDnsYaml,
  pluginsFromConfig,
  stringifyOxiDnsConfig,
  type OxiDnsConfig,
} from "./oxidns-config";
import {
  apiHeaders,
  apiUrl,
  fetchConfigFile,
  saveConfigFile,
  type ConfigFileResponse,
} from "./oxidns-api";

type StoreSet = (
  partial: Partial<AppState> | ((state: AppState) => Partial<AppState>),
) => void;

interface AppState {
  plugins: PluginInstance[];
  systemMetrics: typeof mockSystemMetrics;
  systemInfo: typeof mockSystemInfo;
  selectedPlugin: PluginInstance | null;
  detailOpen: boolean;
  editorMode: boolean;
  isRestarting: boolean;
  isConfigLoading: boolean;
  isConfigSaving: boolean;
  configModel: OxiDnsConfig;
  configText: string;
  configVersion: string | null;
  configPath: string;
  configError: string | null;
  yamlConfig: string;

  setSelectedPlugin: (plugin: PluginInstance | null) => void;
  setDetailOpen: (open: boolean) => void;
  setEditorMode: (mode: boolean) => void;
  setYamlConfig: (config: string) => void;
  loadConfig: () => Promise<void>;
  saveConfig: (options?: { reload?: boolean }) => Promise<void>;
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

const initialConfigModel = configFromPlugins(
  createDefaultOxiDnsConfig(),
  mockPlugins,
);
const initialConfigText = stringifyOxiDnsConfig(initialConfigModel);

export const useAppStore = create<AppState>((set, get) => ({
  plugins: mockPlugins,
  systemMetrics: mockSystemMetrics,
  systemInfo: mockSystemInfo,
  selectedPlugin: null,
  detailOpen: false,
  editorMode: false,
  isRestarting: false,
  isConfigLoading: false,
  isConfigSaving: false,
  configModel: initialConfigModel,
  configText: initialConfigText,
  configVersion: null,
  configPath: "/etc/oxidns/config.yaml",
  configError: null,
  yamlConfig: initialConfigText,

  setSelectedPlugin: (plugin) => set({ selectedPlugin: plugin }),
  setDetailOpen: (open) => set({ detailOpen: open }),
  setEditorMode: (mode) => set({ editorMode: mode }),
  setYamlConfig: (config) => {
    const parsed = parseOxiDnsYaml(config);
    if (!parsed.config) {
      set({
        configText: config,
        yamlConfig: config,
        configError: parsed.diagnostics[0] ?? "配置解析失败",
      });
      return;
    }

    const plugins = pluginsFromConfig(parsed.config);
    set({
      configModel: parsed.config,
      configText: config,
      yamlConfig: config,
      plugins,
      selectedPlugin: syncSelectedPlugin(get().selectedPlugin, plugins),
      configError: parsed.diagnostics[0] ?? null,
    });
  },

  loadConfig: async () => {
    set({ isConfigLoading: true, configError: null });
    try {
      const response = await fetchConfigFile();
      applyConfigFileResponse(response, set);
    } catch (error) {
      set({
        configError:
          error instanceof Error ? error.message : "读取配置文件失败",
      });
    } finally {
      set({ isConfigLoading: false });
    }
  },

  saveConfig: async (options) => {
    const state = get();
    if (state.configError) throw new Error(state.configError);

    set({ isConfigSaving: true, configError: null });
    try {
      const response = await saveConfigFile({
        content: state.configText,
        baseVersion: state.configVersion,
        validate: true,
        reload: options?.reload ?? false,
      });
      set({
        configVersion: response.version,
        configPath: response.path,
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "保存配置文件失败";
      set({ configError: message });
      throw error;
    } finally {
      set({ isConfigSaving: false });
    }
  },

  restartService: async () => {
    set({ isRestarting: true });
    try {
      const response = await fetch(apiUrl("/reload"), {
        method: "POST",
        headers: apiHeaders(),
      });
      if (!response.ok) throw new Error(await response.text());
    } finally {
      set({ isRestarting: false });
    }
  },

  togglePluginPin: (id) =>
    set((state) => {
      const plugins = state.plugins.map((p) =>
        p.id === id ? { ...p, pinned: !p.pinned } : p,
      );
      return {
        plugins,
        selectedPlugin: syncSelectedPlugin(state.selectedPlugin, plugins),
      };
    }),

  togglePluginEnabled: (id) =>
    set((state) => {
      const plugins: PluginInstance[] = state.plugins.map((p) =>
        p.id === id
          ? {
              ...p,
              enabled: !p.enabled,
              status: !p.enabled ? "running" : "stopped",
            }
          : p,
      );
      return {
        plugins,
        selectedPlugin: syncSelectedPlugin(state.selectedPlugin, plugins),
      };
    }),

  updatePluginConfig: (id, config) =>
    set((state) =>
      syncPluginsToConfig(state, (plugins) =>
        plugins.map((p) =>
          p.id === id
            ? { ...p, config, updatedAt: new Date().toISOString() }
            : p,
        ),
      ),
    ),

  deletePlugin: (id) =>
    set((state) => {
      const next = syncPluginsToConfig(state, (plugins) =>
        plugins.filter((p) => p.id !== id),
      );
      return {
        ...next,
        selectedPlugin:
          state.selectedPlugin?.id === id ? null : next.selectedPlugin,
        detailOpen: state.selectedPlugin?.id === id ? false : state.detailOpen,
      };
    }),

  addPlugin: (plugin) =>
    set((state) =>
      syncPluginsToConfig(state, (plugins) => [
        ...plugins,
        {
          ...plugin,
          id: plugin.name,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          metrics: { calls: 0, avgLatency: 0, errorRate: 0, qps: 0 },
        },
      ]),
    ),

  renamePlugin: (id, name) =>
    set((state) =>
      syncPluginsToConfig(state, (plugins) =>
        plugins.map((p) =>
          p.id === id
            ? {
                ...p,
                id: name,
                name,
                updatedAt: new Date().toISOString(),
              }
            : p,
        ),
      ),
    ),
}));

function applyConfigFileResponse(response: ConfigFileResponse, set: StoreSet) {
  const parsed = parseOxiDnsYaml(response.content);
  if (!parsed.config) {
    set({
      configText: response.content,
      yamlConfig: response.content,
      configVersion: response.version,
      configPath: response.path,
      configError: parsed.diagnostics[0] ?? "配置解析失败",
    });
    return;
  }

  set({
    configModel: parsed.config,
    configText: response.content,
    yamlConfig: response.content,
    configVersion: response.version,
    configPath: response.path,
    plugins: pluginsFromConfig(parsed.config),
    configError: parsed.diagnostics[0] ?? null,
  });
}

function syncPluginsToConfig(
  state: AppState,
  update: (plugins: PluginInstance[]) => PluginInstance[],
) {
  const plugins = update(state.plugins);
  const configModel = configFromPlugins(state.configModel, plugins);
  const configText = stringifyOxiDnsConfig(configModel);
  return {
    plugins,
    configModel,
    configText,
    yamlConfig: configText,
    selectedPlugin: syncSelectedPlugin(state.selectedPlugin, plugins),
    configError: null,
  };
}

function syncSelectedPlugin(
  selectedPlugin: PluginInstance | null,
  plugins: PluginInstance[],
) {
  if (!selectedPlugin) return null;
  return plugins.find((plugin) => plugin.id === selectedPlugin.id) ?? null;
}
