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
  isHydrated: boolean;
  connectionError: string | null;

  setServerConfig: (config: ServerConfig) => void;
  connect: (config?: ServerConfig) => Promise<boolean>;
  markHydrated: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      serverConfig: {
        url: "/api",
        requiresAuth: false,
        username: "",
        password: "",
      },
      isAuthenticated: false,
      isConnected: false,
      isConnecting: false,
      isHydrated: false,
      connectionError: null,

      setServerConfig: (config) =>
        set((state) => ({
          serverConfig: config,
          ...(isSameServerConfig(state.serverConfig, config)
            ? {}
            : {
                isAuthenticated: false,
                isConnected: false,
                connectionError: null,
              }),
        })),

      connect: async (config?: ServerConfig) => {
        set({ isConnecting: true, connectionError: null });

        const serverConfig = config ?? get().serverConfig;

        try {
          const url = serverConfig.url.trim();
          if (!url) {
            throw new Error("服务地址不能为空");
          }
          const headers: Record<string, string> = { Accept: "application/json" };
          if (serverConfig.requiresAuth) {
            if (!serverConfig.username || !serverConfig.password) {
              throw new Error("请输入用户名和密码");
            }
            headers.Authorization = `Basic ${btoa(`${serverConfig.username}:${serverConfig.password}`)}`;
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
            serverConfig,
            isConnected: true,
            isAuthenticated: true,
            isConnecting: false,
          });
          return true;
        } catch (error) {
          set({
            isConnected: false,
            isAuthenticated: false,
            isConnecting: false,
            connectionError:
              error instanceof Error ? error.message : "连接失败",
          });
          return false;
        }
      },

      markHydrated: () => set({ isHydrated: true }),
    }),
    {
      name: "oxidns-auth",
      partialize: (state) => ({
        serverConfig: state.serverConfig,
        isAuthenticated: state.isAuthenticated,
        isConnected: state.isConnected,
      }),
      onRehydrateStorage: () => (state) => {
        state?.markHydrated();
      },
    },
  ),
);

function isSameServerConfig(left: ServerConfig, right: ServerConfig) {
  return (
    left.url === right.url &&
    left.requiresAuth === right.requiresAuth &&
    left.username === right.username &&
    left.password === right.password
  );
}
