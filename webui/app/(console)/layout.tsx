"use client";

import { useEffect, useRef, useState } from "react";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/shell/app-sidebar";
import { PluginDetailSheet } from "@/components/plugins/plugin-detail-sheet";
import { ConfigEditorView } from "@/components/config/config-editor-view";
import { useAppStore } from "@/lib/store";
import { AppHeader } from "@/components/shell/app-header";
import { TooltipProvider } from "@/components/ui/tooltip";

export default function ConsoleLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const editorMode = useAppStore((s) => s.editorMode);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const sidebarStateBeforeEditor = useRef(sidebarOpen);
  const previousEditorMode = useRef(editorMode);

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
        <SidebarInset className="flex flex-col">
          {editorMode ? (
            <>
              <AppHeader title="配置编辑器" />
              <ConfigEditorView />
            </>
          ) : (
            children
          )}
        </SidebarInset>
        <PluginDetailSheet />
      </SidebarProvider>
    </TooltipProvider>
  );
}
