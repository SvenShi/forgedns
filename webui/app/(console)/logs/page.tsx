"use client";

import { useEffect } from "react";
import { AppHeader } from "@/components/shell/app-header";
import { LogViewer } from "@/components/logs/log-viewer";

export default function LogsPage() {
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, []);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <AppHeader title="运行日志" />
      <div className="flex min-h-0 flex-1">
        <LogViewer />
      </div>
    </div>
  );
}
