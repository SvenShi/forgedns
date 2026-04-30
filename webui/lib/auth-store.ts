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
          // Simulate connection attempt
          await new Promise((resolve) => setTimeout(resolve, 1500));

          // Simulate connection logic
          // In real app, this would make an API call to the backend
          const url = serverConfig.url.trim();
          if (!url) {
            throw new Error("服务地址不能为空");
          }

          if (serverConfig.requiresAuth) {
            if (!authUsername || !authPassword) {
              throw new Error("请输入用户名和密码");
            }
            // Simulate auth check - in real app, call API
            if (authUsername === "admin" && authPassword === "admin") {
              set({
                isConnected: true,
                isAuthenticated: true,
                isConnecting: false,
                user: { username: authUsername },
              });
              return true;
            } else {
              throw new Error("用户名或密码错误");
            }
          } else {
            set({
              isConnected: true,
              isAuthenticated: true,
              isConnecting: false,
              user: null,
            });
            return true;
          }
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
      name: "forgedns-auth",
      partialize: (state) => ({
        serverConfig: state.serverConfig,
      }),
    },
  ),
);
