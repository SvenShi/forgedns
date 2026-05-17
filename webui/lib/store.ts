"use client";

import { create } from "zustand";
import type { PluginInstance } from "./types";
import {
  configFromPlugins,
  createDefaultOxiDnsConfig,
  parseOxiDnsYaml,
  pluginsFromConfig,
  serializePluginsPreserving,
  stringifyOxiDnsConfig,
  type OxiDnsConfig,
} from "./oxidns-config";
import {
  fetchControl,
  fetchConfigFile,
  fetchHealth,
  fetchPrometheusMetrics,
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
import {
  parsePrometheusMetrics,
  type PluginMetricsMap,
} from "./metrics";
import {
  annotateApply,
  clearSnapshots,
  deleteSnapshot,
  getScopeKey,
  listSnapshots,
  recordSnapshot,
  type ConfigSnapshot,
} from "./config-history";

type StoreSet = (
  partial: Partial<AppState> | ((state: AppState) => Partial<AppState>),
) => void;

interface AppState {
  plugins: PluginInstance[];
  health: HealthResponse | null;
  control: ControlResponse | null;
  system: SystemResponse | null;
  reloadStatus: ReloadSnapshot | null;
  pluginMetrics: PluginMetricsMap;
  dependencyGraph: DependencyGraphReport | null;
  configDiagnostics: string[];
  configHistory: ConfigSnapshot[];
  selectedPlugin: PluginInstance | null;
  detailOpen: boolean;
  editorMode: boolean;
  historyOpen: boolean;
  isConfigLoading: boolean;
  isConfigSaving: boolean;
  isApplying: boolean;
  configModel: OxiDnsConfig;
  configText: string;
  configVersion: string | null;
  /** Version the backend is actually running now (proxy: last loaded/applied). */
  runningVersion: string | null;
  configPath: string;
  configError: string | null;
  yamlConfig: string;

  setSelectedPlugin: (plugin: PluginInstance | null) => void;
  setDetailOpen: (open: boolean) => void;
  setEditorMode: (mode: boolean) => void;
  setHistoryOpen: (open: boolean) => void;
  setYamlConfig: (config: string) => void;
  loadConfig: () => Promise<void>;
  refreshRuntimeState: () => Promise<void>;
  refreshMetrics: () => Promise<void>;
  validateCurrentConfig: () => Promise<void>;
  saveConfig: () => Promise<void>;
  applyConfig: () => Promise<void>;
  restoreSnapshot: (id: string) => void;
  rollbackToSnapshot: (id: string) => Promise<void>;
  deleteConfigSnapshot: (id: string) => void;
  clearConfigHistory: () => void;
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
  pluginMetrics: {},
  dependencyGraph: null,
  configDiagnostics: [],
  configHistory: [],
  selectedPlugin: null,
  detailOpen: false,
  editorMode: false,
  historyOpen: false,
  isConfigLoading: false,
  isConfigSaving: false,
  isApplying: false,
  configModel: initialConfigModel,
  configText: initialConfigText,
  configVersion: null,
  runningVersion: null,
  configPath: "/etc/oxidns/config.yaml",
  configError: null,
  yamlConfig: initialConfigText,

  setSelectedPlugin: (plugin) => set({ selectedPlugin: plugin }),
  setDetailOpen: (open) => set({ detailOpen: open }),
  setEditorMode: (mode) => set({ editorMode: mode }),
  setHistoryOpen: (open) => set({ historyOpen: open }),
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
      const scope = getScopeKey(response.path);
      recordSnapshot(scope, {
        content: response.content,
        version: response.version,
        source: "server",
        pluginCount: pluginCountOf(response.content),
        applyStatus: "applied",
      });
      // The backend is running exactly what it just served us from disk.
      set({
        configHistory: listSnapshots(scope),
        runningVersion: response.version,
      });
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
    const nextReload =
      reloadStatus.status === "fulfilled"
        ? reloadStatus.value
        : get().reloadStatus;
    set({
      health: health.status === "fulfilled" ? health.value : get().health,
      control: control.status === "fulfilled" ? control.value : get().control,
      system: system.status === "fulfilled" ? system.value : get().system,
      reloadStatus: nextReload,
      // The backend authoritatively reports what config it is running; prefer
      // it over the load-time disk-version guess so the "未应用" state
      // survives page reloads. Falls back to the prior value for older
      // backends that don't report running_version.
      ...(nextReload?.running_version
        ? { runningVersion: nextReload.running_version }
        : {}),
    });
    await get().refreshMetrics();
  },

  refreshMetrics: async () => {
    try {
      const text = await fetchPrometheusMetrics();
      set({ pluginMetrics: parsePrometheusMetrics(text).byTag });
    } catch {
      // Metrics are best-effort observability; keep the last snapshot on
      // transient errors (e.g. API hub torn down during reload).
    }
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

  // Save only. Hot-reload is a separate explicit step (applyConfig) so the
  // disk write and the running-config swap are never coupled.
  saveConfig: async () => {
    const state = get();
    if (state.configError) throw new Error(state.configError);

    set({ isConfigSaving: true, configError: null });
    try {
      const validation = await validateConfigText(state.configText);
      applyConfigValidationResponse(validation, set);
      const content = state.configText;
      const response = await saveConfigFile({
        content,
        baseVersion: state.configVersion,
        validate: true,
        reload: false,
      });
      const scope = getScopeKey(response.path);
      recordSnapshot(scope, {
        content,
        version: response.version,
        source: "save",
        pluginCount: pluginCountOf(content),
        applyStatus: "not-applied",
      });
      set({
        configVersion: response.version,
        configPath: response.path,
        reloadStatus: response.reload ?? get().reloadStatus,
        configHistory: listSnapshots(scope),
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

  // Trigger a backend hot-reload of the on-disk config and wait for the
  // outcome. The backend already rolls the running pipeline back to the
  // previous in-memory config if assembly fails (src/app.rs handle_reload),
  // so a failed apply leaves the service running on the old config; we only
  // surface that state and annotate the snapshot.
  applyConfig: async () => {
    const before = get();
    const scope = getScopeKey(before.configPath);
    const version = before.configVersion;
    set({ isApplying: true });
    try {
      let baseline: number | undefined;
      try {
        baseline = (await fetchReloadStatus()).last_completed_ms;
      } catch {
        baseline = undefined;
      }

      let snapshot: ReloadSnapshot;
      try {
        await requestReload();
        snapshot = await pollReload(baseline);
      } catch (error) {
        // requestReload / polling threw (reload busy, network, API torn down
        // and never recovered) — surface it as a failed apply instead of a
        // silent no-op so the pill turns red rather than staying unchanged.
        const message =
          error instanceof Error
            ? error.message
            : "应用失败：无法触发热重载";
        if (version) {
          annotateApply(scope, version, "apply-failed", message);
          set({ configHistory: listSnapshots(scope) });
        }
        throw new Error(message);
      }

      set({ reloadStatus: snapshot });
      const failed =
        snapshot.status === "failed" || Boolean(snapshot.last_error);
      if (version) {
        annotateApply(
          scope,
          version,
          failed ? "apply-failed" : "applied",
          snapshot.last_error,
        );
        set({
          configHistory: listSnapshots(scope),
          // On success the backend is now running this config. Prefer the
          // authoritative version it reports; fall back to the applied one.
          ...(failed
            ? {}
            : { runningVersion: snapshot.running_version ?? version }),
        });
      }
      await get().refreshRuntimeState();
      if (failed) {
        throw new Error(snapshot.last_error || "应用失败：热重载未成功");
      }
    } finally {
      set({ isApplying: false });
    }
  },

  // Load a historical snapshot back into the editor only. It is NOT persisted
  // or applied — the operator still goes through 保存 → 应用, so a rollback
  // also produces its own history entry.
  restoreSnapshot: (id) => {
    const entry = get().configHistory.find((s) => s.id === id);
    if (!entry) return;
    get().setYamlConfig(entry.content);
  },

  // One-click rollback usable in BOTH console and editor mode: load the
  // snapshot, persist it to disk, then hot-reload so it becomes live. This is
  // the path users actually want from history; the old "load into buffer
  // only" was a dead end in console mode (no visible 保存 button there).
  rollbackToSnapshot: async (id) => {
    const entry = get().configHistory.find((s) => s.id === id);
    if (!entry) return;
    get().setYamlConfig(entry.content);
    await get().saveConfig();
    await get().applyConfig();
  },

  deleteConfigSnapshot: (id) => {
    const scope = getScopeKey(get().configPath);
    deleteSnapshot(scope, id);
    set({ configHistory: listSnapshots(scope) });
  },

  clearConfigHistory: () => {
    const scope = getScopeKey(get().configPath);
    clearSnapshots(scope);
    set({ configHistory: [] });
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
    set((state) => {
      const tag = state.plugins.find((p) => p.id === id)?.name;
      return syncPluginsToConfig(
        state,
        (plugins) =>
          plugins.map((p) =>
            p.id === id
              ? { ...p, config, updatedAt: new Date().toISOString() }
              : p,
          ),
        tag ? [tag] : [],
      );
    }),

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
    set((state) => {
      const oldTag = state.plugins.find((p) => p.id === id)?.name;
      return syncPluginsToConfig(
        state,
        (plugins) =>
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
        oldTag ? [oldTag, name] : [name],
      );
    }),
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
  changedTags: string[] = [],
) {
  const plugins = update(state.plugins);
  const configModel = configFromPlugins(state.configModel, plugins);
  // Preserve comments/blank lines: only the explicitly changed tags are
  // regenerated; every other plugin keeps its original YAML node verbatim.
  const configText = serializePluginsPreserving(
    state.configText,
    configModel,
    new Set(changedTags),
  );
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

function pluginCountOf(text: string): number {
  return parseOxiDnsYaml(text).config?.plugins.length ?? 0;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Poll the reload status until the backend settles on a new completion.
// During reassembly the API hub is briefly torn down, so transient fetch
// errors are expected and ignored. We treat the reload as done once it is
// no longer pending/in-progress AND a new completion timestamp appeared
// (distinct from the pre-reload baseline), or it explicitly failed.
async function pollReload(
  baselineCompleted?: number,
): Promise<ReloadSnapshot> {
  const maxAttempts = 40; // ~30s at 750ms intervals
  let last: ReloadSnapshot | null = null;
  for (let i = 0; i < maxAttempts; i += 1) {
    await delay(750);
    try {
      last = await fetchReloadStatus();
    } catch {
      continue;
    }
    const settled = !last.pending && !last.in_progress;
    const advanced =
      last.last_completed_ms !== undefined &&
      last.last_completed_ms !== baselineCompleted;
    if (settled && (advanced || last.status === "failed")) return last;
  }
  return last ?? { status: "unknown", pending: false, in_progress: false };
}
