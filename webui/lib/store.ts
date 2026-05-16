"use client";

import { create } from "zustand";
import type { PluginInstance } from "./types";
import {
  configFromPlugins,
  createDefaultOxiDnsConfig,
  parseOxiDnsYaml,
  pluginsFromConfig,
  stringifyOxiDnsConfig,
  type OxiDnsConfig,
} from "./oxidns-config";
import {
  fetchControl,
  fetchConfigFile,
  fetchHealth,
  fetchReloadStatus,
  fetchSystem,
  requestReload,
  saveConfigFile,
  validateConfigText,
  type ConfigFileResponse,
  type ConfigValidateResponse,
  type ControlResponse,
  type DependencyGraphReport,
  type HealthResponse,
  type ReloadSnapshot,
  type SystemResponse,
} from "./oxidns-api";

type StoreSet = (
  partial: Partial<AppState> | ((state: AppState) => Partial<AppState>),
) => void;

interface AppState {
  plugins: PluginInstance[];
  health: HealthResponse | null;
  control: ControlResponse | null;
  system: SystemResponse | null;
  reloadStatus: ReloadSnapshot | null;
  dependencyGraph: DependencyGraphReport | null;
  configDiagnostics: string[];
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
  refreshRuntimeState: () => Promise<void>;
  validateCurrentConfig: () => Promise<void>;
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

const initialConfigModel = createDefaultOxiDnsConfig();
const initialConfigText = stringifyOxiDnsConfig(initialConfigModel);

export const useAppStore = create<AppState>((set, get) => ({
  plugins: [],
  health: null,
  control: null,
  system: null,
  reloadStatus: null,
  dependencyGraph: null,
  configDiagnostics: [],
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
        configDiagnostics: parsed.diagnostics,
      });
      return;
    }

    const plugins = restorePinnedState(pluginsFromConfig(parsed.config));
    set({
      configModel: parsed.config,
      configText: config,
      yamlConfig: config,
      plugins,
      selectedPlugin: syncSelectedPlugin(get().selectedPlugin, plugins),
      configError: parsed.diagnostics[0] ?? null,
      configDiagnostics: parsed.diagnostics,
    });
  },

  loadConfig: async () => {
    set({ isConfigLoading: true, configError: null });
    try {
      const response = await fetchConfigFile();
      applyConfigFileResponse(response, set);
      await get().validateCurrentConfig();
      await get().refreshRuntimeState();
    } catch (error) {
      set({
        configError:
          error instanceof Error ? error.message : "读取配置文件失败",
      });
    } finally {
      set({ isConfigLoading: false });
    }
  },

  refreshRuntimeState: async () => {
    const results = await Promise.allSettled([
      fetchHealth(),
      fetchControl(),
      fetchSystem(),
      fetchReloadStatus(),
    ]);
    const [health, control, system, reloadStatus] = results;
    set({
      health: health.status === "fulfilled" ? health.value : get().health,
      control: control.status === "fulfilled" ? control.value : get().control,
      system: system.status === "fulfilled" ? system.value : get().system,
      reloadStatus:
        reloadStatus.status === "fulfilled"
          ? reloadStatus.value
          : get().reloadStatus,
    });
  },

  validateCurrentConfig: async () => {
    const state = get();
    if (state.configError) return;
    try {
      const response = await validateConfigText(state.configText);
      applyConfigValidationResponse(response, set);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "配置校验失败";
      set({
        configError: message,
        configDiagnostics: [message],
        dependencyGraph: null,
      });
      throw error;
    }
  },

  saveConfig: async (options) => {
    const state = get();
    if (state.configError) throw new Error(state.configError);

    set({ isConfigSaving: true, configError: null });
    try {
      const validation = await validateConfigText(state.configText);
      applyConfigValidationResponse(validation, set);
      const response = await saveConfigFile({
        content: state.configText,
        baseVersion: state.configVersion,
        validate: true,
        reload: options?.reload ?? false,
      });
      set({
        configVersion: response.version,
        configPath: response.path,
        reloadStatus: response.reload ?? get().reloadStatus,
      });
      await get().refreshRuntimeState();
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
      await requestReload();
      await get().refreshRuntimeState();
    } finally {
      set({ isRestarting: false });
    }
  },

  togglePluginPin: (id) =>
    set((state) => {
      const plugins = state.plugins.map((p) =>
        p.id === id ? { ...p, pinned: !p.pinned } : p,
      );
      savePinnedIds(new Set(plugins.filter((p) => p.pinned).map((p) => p.id)));
      return {
        plugins,
        selectedPlugin: syncSelectedPlugin(state.selectedPlugin, plugins),
      };
    }),

  togglePluginEnabled: (id) =>
    set((state) => {
      void id;
      const plugins: PluginInstance[] = state.plugins.map((p) => p);
      return { plugins };
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
      configDiagnostics: parsed.diagnostics,
    });
    return;
  }

  set({
    configModel: parsed.config,
    configText: response.content,
    yamlConfig: response.content,
    configVersion: response.version,
    configPath: response.path,
    plugins: restorePinnedState(pluginsFromConfig(parsed.config)),
    configError: parsed.diagnostics[0] ?? null,
    configDiagnostics: parsed.diagnostics,
  });
}

function applyConfigValidationResponse(
  response: ConfigValidateResponse,
  set: StoreSet,
) {
  set({
    dependencyGraph: response.dependency_graph,
    configDiagnostics: [],
    configError: null,
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
    configDiagnostics: [],
  };
}

function syncSelectedPlugin(
  selectedPlugin: PluginInstance | null,
  plugins: PluginInstance[],
) {
  if (!selectedPlugin) return null;
  return plugins.find((plugin) => plugin.id === selectedPlugin.id) ?? null;
}

const PINNED_PLUGINS_KEY = "oxidns:pinned-plugins";

function loadPinnedIds(): Set<string> {
  try {
    const stored = localStorage.getItem(PINNED_PLUGINS_KEY);
    return stored ? new Set(JSON.parse(stored) as string[]) : new Set();
  } catch {
    return new Set();
  }
}

function savePinnedIds(ids: Set<string>): void {
  try {
    localStorage.setItem(PINNED_PLUGINS_KEY, JSON.stringify([...ids]));
  } catch {}
}

function restorePinnedState(plugins: PluginInstance[]): PluginInstance[] {
  const pinnedIds = loadPinnedIds();
  if (pinnedIds.size === 0) return plugins;
  return plugins.map((p) => ({ ...p, pinned: pinnedIds.has(p.id) }));
}
