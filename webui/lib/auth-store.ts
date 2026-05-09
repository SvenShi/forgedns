"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface ServerConfig {
  url: string;
  requiresAuth: boolean;
  username: string;
  password: string;
}

export interface AuthState {
  serverConfig: ServerConfig;
  isAuthenticated: boolean;
  isConnected: boolean;
  isConnecting: boolean;
  connectionError: string | null;
  user: { username: string } | null;

  setServerConfig: (config: ServerConfig) => void;
  connect: (username?: string, password?: string) => Promise<boolean>;
  disconnect: () => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      serverConfig: {
        url: "http://localhost:8080",
        requiresAuth: false,
        username: "",
        password: "",
      },
      isAuthenticated: false,
      isConnected: false,
      isConnecting: false,
      connectionError: null,
      user: null,

      setServerConfig: (config) => set({ serverConfig: config }),

      connect: async (username?: string, password?: string) => {
        set({ isConnecting: true, connectionError: null });

        const { serverConfig } = get();
        const authUsername = username ?? serverConfig.username ?? "";
        const authPassword = password ?? serverConfig.password ?? "";

        try {
          const url = serverConfig.url.trim();
          if (!url) {
            throw new Error("服务地址不能为空");
          }
          const headers: Record<string, string> = { Accept: "application/json" };
          if (serverConfig.requiresAuth) {
            if (!authUsername || !authPassword) {
              throw new Error("请输入用户名和密码");
            }
            headers.Authorization = `Basic ${btoa(`${authUsername}:${authPassword}`)}`;
          }
          const response = await fetch(`${url.replace(/\/$/, "")}/health`, {
            method: "GET",
            headers,
          });
          if (!response.ok) {
            throw new Error(
              response.status === 401
                ? "用户名或密码错误"
                : `连接失败：HTTP ${response.status}`,
            );
          }
          set({
            isConnected: true,
            isAuthenticated: true,
            isConnecting: false,
            user: serverConfig.requiresAuth ? { username: authUsername } : null,
          });
          return true;
        } catch (error) {
          set({
            isConnecting: false,
            connectionError:
              error instanceof Error ? error.message : "连接失败",
          });
          return false;
        }
      },

      disconnect: () => {
        set({
          isConnected: false,
          isAuthenticated: false,
          user: null,
          connectionError: null,
        });
      },

      logout: () => {
        set({
          isConnected: false,
          isAuthenticated: false,
          user: null,
          connectionError: null,
        });
      },
    }),
    {
      name: "oxidns-auth",
      partialize: (state) => ({
        serverConfig: state.serverConfig,
      }),
    },
  ),
);
