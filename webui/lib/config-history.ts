"use client";

// Client-only config snapshot history. Persisted in localStorage and scoped
// per OxiDNS instance (server URL + config path) so multiple backends do not
// share history. The backend stores nothing; history lives on the device.
//
// Snapshots store the *raw* YAML text on purpose: serde_yaml_ng round-trips
// are lossy (comments / key order), so anything we want to faithfully restore
// must keep the original text rather than a re-serialized model.

import { useAuthStore } from "./auth-store";

export type ApplyStatus =
  | "not-applied"
  | "applying"
  | "applied"
  | "apply-failed";

export interface ConfigSnapshot {
  id: string;
  createdAt: number;
  content: string;
  version: string;
  source: "server" | "save";
  pluginCount: number;
  size: number;
  applyStatus: ApplyStatus;
  applyError?: string;
  appliedAt?: number;
}

export interface RecordSnapshotInput {
  content: string;
  version: string;
  source: ConfigSnapshot["source"];
  pluginCount: number;
  applyStatus: ApplyStatus;
}

const KEY_PREFIX = "oxidns:config-history:";
const MAX_ENTRIES = 30;

export function getScopeKey(configPath: string): string {
  let serverUrl = "";
  try {
    serverUrl = useAuthStore.getState().serverConfig.url.trim();
  } catch {
    serverUrl = "";
  }
  return `${serverUrl}|${configPath}`;
}

function storageKey(scope: string) {
  return `${KEY_PREFIX}${scope}`;
}

// One entry per version (= per content hash), keeping the most recent
// occurrence, newest first. Live status (运行中 / 待应用) is derived at render
// time from runningVersion / configVersion, NOT from a frozen per-entry
// applyStatus, so an old version never gets stuck looking "applied".
function dedupeByVersion(list: ConfigSnapshot[]): ConfigSnapshot[] {
  const newest = new Map<string, ConfigSnapshot>();
  for (const s of list) {
    const cur = newest.get(s.version);
    if (!cur || s.createdAt > cur.createdAt) newest.set(s.version, s);
  }
  return [...newest.values()].sort((a, b) => b.createdAt - a.createdAt);
}

export function listSnapshots(scope: string): ConfigSnapshot[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(storageKey(scope));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as ConfigSnapshot[];
    return Array.isArray(parsed) ? dedupeByVersion(parsed) : [];
  } catch {
    return [];
  }
}

function persist(scope: string, list: ConfigSnapshot[]): ConfigSnapshot[] {
  if (typeof window === "undefined") return list;
  try {
    window.localStorage.setItem(storageKey(scope), JSON.stringify(list));
  } catch {
    // Quota exceeded or storage disabled — degrade silently. The returned
    // list is still used for in-memory state this session.
  }
  return list;
}

function trim(list: ConfigSnapshot[]): ConfigSnapshot[] {
  if (list.length <= MAX_ENTRIES) return list;
  const kept = list.slice(0, MAX_ENTRIES);
  if (kept.some((s) => s.applyStatus === "applied")) return kept;
  // Always keep the most recent known-good config as a rollback anchor even
  // when it would otherwise age out of the window.
  const lastGood = list.find((s) => s.applyStatus === "applied");
  if (!lastGood) return kept;
  return [...kept.slice(0, MAX_ENTRIES - 1), lastGood];
}

export function recordSnapshot(
  scope: string,
  input: RecordSnapshotInput,
): ConfigSnapshot[] {
  // Upsert by version: a re-save of identical content is still a real event,
  // so drop any prior entry for this version and re-add it fresh at the head
  // (newest timestamp) instead of silently skipping it.
  const list = listSnapshots(scope).filter(
    (s) => s.version !== input.version,
  );
  const createdAt = Date.now();
  const entry: ConfigSnapshot = {
    id: `${createdAt}-${input.version.slice(0, 8)}`,
    createdAt,
    content: input.content,
    version: input.version,
    source: input.source,
    pluginCount: input.pluginCount,
    size: input.content.length,
    applyStatus: input.applyStatus,
    appliedAt: input.applyStatus === "applied" ? createdAt : undefined,
  };
  return persist(scope, trim([entry, ...list]));
}

export function annotateApply(
  scope: string,
  version: string,
  status: ApplyStatus,
  error?: string,
): ConfigSnapshot[] {
  let done = false;
  const next = listSnapshots(scope).map((s) => {
    if (done || s.version !== version) return s;
    done = true;
    return {
      ...s,
      applyStatus: status,
      applyError: status === "apply-failed" ? error : undefined,
      appliedAt: status === "applied" ? Date.now() : s.appliedAt,
    };
  });
  return persist(scope, next);
}

export function deleteSnapshot(scope: string, id: string): ConfigSnapshot[] {
  return persist(
    scope,
    listSnapshots(scope).filter((s) => s.id !== id),
  );
}

export function clearSnapshots(scope: string): ConfigSnapshot[] {
  if (typeof window !== "undefined") {
    try {
      window.localStorage.removeItem(storageKey(scope));
    } catch {
      // ignore
    }
  }
  return [];
}
