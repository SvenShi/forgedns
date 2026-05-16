"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/shell/app-sidebar";
import { PluginDetailSheet } from "@/components/plugins/plugin-detail-sheet";
import { ConfigEditorView } from "@/components/config/config-editor-view";
import { useAppStore } from "@/lib/store";
import { useAuthStore } from "@/lib/auth-store";
import { AppHeader } from "@/components/shell/app-header";
import { ConnectionRequired } from "@/components/shell/connection-required";
import { TooltipProvider } from "@/components/ui/tooltip";

export default function ConsoleLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const editorMode = useAppStore((s) => s.editorMode);
  const loadConfig = useAppStore((s) => s.loadConfig);
  const isConnected = useAuthStore((s) => s.isConnected);
  const isAuthHydrated = useAuthStore((s) => s.isHydrated);
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const sidebarStateBeforeEditor = useRef(sidebarOpen);
  const previousEditorMode = useRef(editorMode);
  const canUseBackendPages =
    !isAuthHydrated || isConnected || pathname === "/settings";

  useEffect(() => {
    if (isConnected) void loadConfig();
  }, [isConnected, loadConfig]);

  useEffect(() => {
    const el = document.documentElement;
    if (editorMode) {
      el.style.overflow = "hidden";
    } else {
      el.style.overflow = "";
    }
    return () => { el.style.overflow = ""; };
  }, [editorMode]);

  useEffect(() => {
    if (!previousEditorMode.current && editorMode) {
      sidebarStateBeforeEditor.current = sidebarOpen;
      setSidebarOpen(false);
    }

    if (previousEditorMode.current && !editorMode) {
      setSidebarOpen(sidebarStateBeforeEditor.current);
    }

    previousEditorMode.current = editorMode;
  }, [editorMode, sidebarOpen]);

  return (
    <TooltipProvider>
      <SidebarProvider
        open={editorMode ? false : sidebarOpen}
        onOpenChange={(open) => {
          if (!editorMode) {
            setSidebarOpen(open);
          }
        }}
      >
        <AppSidebar />
        <SidebarInset className={`flex flex-col${editorMode ? " overflow-hidden" : ""}`}>
          {editorMode ? (
            <div className="h-svh flex flex-col overflow-hidden">
              <AppHeader title="配置编辑器" />
              {!isAuthHydrated || isConnected ? (
                <ConfigEditorView />
              ) : (
                <ConnectionRequired />
              )}
            </div>
          ) : canUseBackendPages ? (
            children
          ) : (
            <>
              <AppHeader title="连接后台服务" />
              <ConnectionRequired />
            </>
          )}
        </SidebarInset>
        <PluginDetailSheet />
      </SidebarProvider>
    </TooltipProvider>
  );
}
