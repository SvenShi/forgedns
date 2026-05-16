"use client";

import { useAuthStore } from "./auth-store";

export interface ConfigFileResponse {
  ok: boolean;
  path: string;
  format: "yaml";
  content: string;
  version: string;
  updated_at_ms?: number;
}

export interface SaveConfigOptions {
  content: string;
  baseVersion?: string | null;
  validate?: boolean;
  reload?: boolean;
}

export interface SaveConfigResponse {
  ok: boolean;
  path: string;
  format: "yaml";
  version: string;
  updated_at_ms?: number;
  plugin_count: number;
  init_order: string[];
  dependency_graph?: DependencyGraphReport;
  reload?: ReloadSnapshot;
  message: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  uptime_ms: number;
  checks: {
    api: string;
    plugin_init: string;
    server_startup: string;
  };
  plugins: {
    total: number;
    servers: number;
  };
}

export interface ReloadSnapshot {
  status: string;
  pending: boolean;
  in_progress: boolean;
  last_started_ms?: number;
  last_completed_ms?: number;
  last_success_ms?: number;
  last_error?: string;
}

export interface ControlResponse {
  status: string;
  uptime_ms: number;
  config_path: string;
  shutdown_requested: boolean;
  reload: ReloadSnapshot;
}

export interface SystemResponse {
  ok: boolean;
  version: string;
  os: string;
  arch: string;
  uptime_ms: number;
  config_path: string;
  api_enabled: boolean;
  reload: ReloadSnapshot;
}

export interface DependencyGraphNode {
  tag: string;
  plugin_type: string;
  kind: string;
}

export interface DependencyGraphEdge {
  source_tag: string;
  field: string;
  target_tag: string;
  expected_kind: string;
  expected_plugin_type?: string;
}

export interface SequenceFlowExpression {
  field: string;
  raw: string;
  kind: "plugin" | "quick_setup" | "builtin" | "invalid";
  target_tag?: string;
  plugin_type?: string;
  param?: string;
  inverted: boolean;
  builtin?: string;
}

export interface SequenceFlowRule {
  index: number;
  matches: SequenceFlowExpression[];
  exec?: SequenceFlowExpression;
}

export interface SequenceFlowReport {
  tag: string;
  rules: SequenceFlowRule[];
}

export interface DependencyGraphReport {
  nodes: DependencyGraphNode[];
  edges: DependencyGraphEdge[];
  init_order: string[];
  sequence_flows?: SequenceFlowReport[];
}

export interface ConfigValidateResponse {
  ok: boolean;
  source: "file" | "body";
  path?: string;
  plugin_count: number;
  dependency_graph: DependencyGraphReport;
  message: string;
}

export interface ConfigDiagnostic {
  message: string;
  severity: "error" | "warning" | "info";
  line: number;
  column: number;
  end_line: number;
  end_column: number;
}

export class ConfigValidationError extends Error {
  diagnostics: string[];
  diagnosticDetails: ConfigDiagnostic[];

  constructor(
    message: string,
    diagnostics: string[] = [message],
    diagnosticDetails: ConfigDiagnostic[] = [],
  ) {
    super(message);
    this.name = "ConfigValidationError";
    this.diagnostics = diagnostics;
    this.diagnosticDetails = diagnosticDetails;
  }
}

export interface CacheEntryRow {
  id: string;
  domain: string;
  record_type: string;
  dns_class: string;
  rcode: string;
  answer_count: number;
  ttl: number;
  remaining_ttl: number;
  fresh: boolean;
  stale: boolean;
  cache_time_ms: number;
  expire_at_ms: number;
  last_access_ms: number;
  do_bit: boolean;
  cd_bit: boolean;
  ecs_scope?: {
    family: number;
    source_prefix: number;
    scope_prefix: number;
    network_hex: string;
  };
}

export interface CacheEntriesResponse {
  ok: boolean;
  entries: CacheEntryRow[];
  next_cursor?: string;
  total_entries: number;
}

export interface QueryQuestion {
  name: string;
  qtype: string;
  qclass: string;
}

export interface QueryRecordPayload {
  name: string;
  class: string;
  ttl: number;
  rr_type: string;
  payload_kind: string;
  payload_text: string;
  payload: unknown;
}

export interface QueryRecorderStep {
  event_index: number;
  sequence_tag: string;
  node_index?: number;
  kind: string;
  tag?: string;
  outcome: string;
}

export interface QueryRecordRow {
  id: number;
  created_at_ms: number;
  elapsed_ms: number;
  request_id: number;
  client_ip: string;
  questions_json: QueryQuestion[];
  error?: string;
  has_response: boolean;
  rcode?: string;
  answer_count: number;
  authority_count: number;
  additional_count: number;
  answers_json: QueryRecordPayload[];
  authorities_json: QueryRecordPayload[];
  additionals_json: QueryRecordPayload[];
  signature_json: QueryRecordPayload[];
  [key: string]: unknown;
}

export interface QueryRecordDetail extends QueryRecordRow {
  steps: QueryRecorderStep[];
}

export interface QueryRecordsResponse {
  ok: boolean;
  next_cursor?: string;
  records: QueryRecordRow[];
}

export interface QueryRecordDetailResponse {
  ok: boolean;
  record: QueryRecordDetail;
}

export async function fetchConfigFile(): Promise<ConfigFileResponse> {
  const response = await fetch(apiUrl("/config"), {
    method: "GET",
    headers: apiHeaders(),
  });
  return readJsonResponse<ConfigFileResponse>(response);
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(apiUrl("/health"), {
    method: "GET",
    headers: apiHeaders(),
  });
  return readJsonResponse<HealthResponse>(response);
}

export async function fetchControl(): Promise<ControlResponse> {
  const response = await fetch(apiUrl("/control"), {
    method: "GET",
    headers: apiHeaders(),
  });
  return readJsonResponse<ControlResponse>(response);
}

export async function fetchSystem(): Promise<SystemResponse> {
  const response = await fetch(apiUrl("/system"), {
    method: "GET",
    headers: apiHeaders(),
  });
  return readJsonResponse<SystemResponse>(response);
}

export async function fetchReloadStatus(): Promise<ReloadSnapshot> {
  const response = await fetch(apiUrl("/reload/status"), {
    method: "GET",
    headers: apiHeaders(),
  });
  return readJsonResponse<ReloadSnapshot>(response);
}

export async function validateConfigText(
  content: string,
): Promise<ConfigValidateResponse> {
  const response = await fetch(apiUrl("/config/validate"), {
    method: "POST",
    headers: {
      ...apiHeaders(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ format: "yaml", content }),
  });
  return readJsonResponse<ConfigValidateResponse>(response);
}

export async function saveConfigFile({
  content,
  baseVersion,
  validate = true,
  reload = false,
}: SaveConfigOptions): Promise<SaveConfigResponse> {
  const response = await fetch(apiUrl("/config"), {
    method: "PUT",
    headers: {
      ...apiHeaders(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      format: "yaml",
      content,
      base_version: baseVersion ?? undefined,
      validate,
      reload,
    }),
  });
  return readJsonResponse<SaveConfigResponse>(response);
}

export async function requestReload(): Promise<void> {
  const response = await fetch(apiUrl("/reload"), {
    method: "POST",
    headers: apiHeaders(),
  });
  await readJsonResponse<unknown>(response);
}

export async function fetchCacheEntries(
  tag: string,
  options: { limit?: number; cursor?: string } = {},
): Promise<CacheEntriesResponse> {
  const params = new URLSearchParams();
  if (options.limit) params.set("limit", String(options.limit));
  if (options.cursor) params.set("cursor", options.cursor);
  const suffix = params.toString() ? `?${params.toString()}` : "";
  const response = await fetch(
    apiUrl(`/plugins/${encodeURIComponent(tag)}/entries${suffix}`),
    { method: "GET", headers: apiHeaders() },
  );
  return readJsonResponse<CacheEntriesResponse>(response);
}

export async function deleteCacheEntry(tag: string, id: string): Promise<void> {
  const response = await fetch(
    apiUrl(`/plugins/${encodeURIComponent(tag)}/entries/${encodeURIComponent(id)}`),
    { method: "DELETE", headers: apiHeaders() },
  );
  await readJsonResponse<unknown>(response);
}

export async function flushCache(tag: string): Promise<void> {
  const response = await fetch(apiUrl(`/plugins/${encodeURIComponent(tag)}/flush`), {
    method: "GET",
    headers: apiHeaders(),
  });
  await readJsonResponse<unknown>(response);
}

export async function fetchQueryRecords(
  tag: string,
  options: { limit?: number; cursor?: string; sinceMs?: number; untilMs?: number } = {},
): Promise<QueryRecordsResponse> {
  const params = new URLSearchParams();
  if (options.limit) params.set("limit", String(options.limit));
  if (options.cursor) params.set("cursor", options.cursor);
  if (options.sinceMs) params.set("since_ms", String(options.sinceMs));
  if (options.untilMs) params.set("until_ms", String(options.untilMs));
  const suffix = params.toString() ? `?${params.toString()}` : "";
  const response = await fetch(
    apiUrl(`/plugins/${encodeURIComponent(tag)}/records${suffix}`),
    { method: "GET", headers: apiHeaders() },
  );
  return readJsonResponse<QueryRecordsResponse>(response);
}

export async function fetchQueryRecordDetail(
  tag: string,
  id: number,
): Promise<QueryRecordDetailResponse> {
  const response = await fetch(
    apiUrl(`/plugins/${encodeURIComponent(tag)}/records/${id}`),
    { method: "GET", headers: apiHeaders() },
  );
  return readJsonResponse<QueryRecordDetailResponse>(response);
}

export function apiUrl(path: string) {
  const baseUrl = useAuthStore.getState().serverConfig.url.trim();
  return `${baseUrl.replace(/\/$/, "")}${path}`;
}

export function apiHeaders() {
  const { serverConfig } = useAuthStore.getState();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (serverConfig.requiresAuth && serverConfig.username) {
    headers.Authorization = `Basic ${btoa(`${serverConfig.username}:${serverConfig.password}`)}`;
  }
  return headers;
}

async function readJsonResponse<T>(response: Response): Promise<T> {
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const message =
      body && typeof body.message === "string"
        ? body.message
        : `HTTP ${response.status}`;
    if (
      body &&
      Array.isArray(body.diagnostics) &&
      body.diagnostics.every((item: unknown) => typeof item === "string")
    ) {
      throw new ConfigValidationError(
        message,
        body.diagnostics,
        Array.isArray(body.diagnostic_details)
          ? (body.diagnostic_details as ConfigDiagnostic[])
          : [],
      );
    }
    throw new Error(message);
  }
  return body as T;
}
