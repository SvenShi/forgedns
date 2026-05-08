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
  message: string;
}

export async function fetchConfigFile(): Promise<ConfigFileResponse> {
  const response = await fetch(apiUrl("/config"), {
    method: "GET",
    headers: apiHeaders(),
  });
  return readJsonResponse<ConfigFileResponse>(response);
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
    throw new Error(message);
  }
  return body as T;
}
