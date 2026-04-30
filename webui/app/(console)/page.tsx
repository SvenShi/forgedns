"use client";

import { AppHeader } from "@/components/shell/app-header";
import { SystemMetrics } from "@/components/dashboard/system-metrics";
import { PluginCard } from "@/components/plugins/plugin-card";
import { useAppStore } from "@/lib/store";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

export default function DashboardPage() {
  const plugins = useAppStore((s) => s.plugins);
  const pinnedPlugins = plugins.filter((p) => p.pinned);

  return (
    <>
      <AppHeader title="仪表盘" />
      <main className="flex-1 overflow-auto p-6">
        <div className="space-y-8">
          <section>
            <h2 className="text-lg font-semibold mb-4">系统概览</h2>
            <SystemMetrics />
          </section>

          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">
                固定的插件
                <span className="text-muted-foreground font-normal ml-2 text-sm">
                  ({pinnedPlugins.length})
                </span>
              </h2>
              <Button variant="ghost" size="sm" asChild>
                <Link href="/plugins">
                  查看全部
                  <ArrowRight className="h-4 w-4 ml-1" />
                </Link>
              </Button>
            </div>
            {pinnedPlugins.length > 0 ? (
              <div className="grid items-stretch gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {pinnedPlugins.map((plugin) => (
                  <PluginCard key={plugin.id} plugin={plugin} />
                ))}
              </div>
            ) : (
              <div className="border border-dashed rounded-lg p-8 text-center text-muted-foreground">
                <p>还没有固定的插件</p>
                <p className="text-sm mt-1">
                  在插件中心点击插件卡片的菜单，选择&ldquo;固定到仪表盘&rdquo;
                </p>
              </div>
            )}
          </section>
        </div>
      </main>
    </>
  );
}
