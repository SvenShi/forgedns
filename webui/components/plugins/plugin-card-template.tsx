"use client";

import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  MoreVertical,
  Pin,
  PinOff,
  Power,
  PowerOff,
  Trash2,
} from "lucide-react";
import { PLUGIN_TYPE_LABELS } from "@/lib/types";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import type { PluginCardTemplateProps } from "./types";
import { pluginTypeColors, pluginTypeIcons } from "./display";
import { getPluginCatalogItem, renderPluginKindIcon } from "./catalog";

export function PluginCardTemplate({
  plugin,
  compact = false,
  icon,
  primaryMetric,
  children,
}: PluginCardTemplateProps) {
  const {
    setSelectedPlugin,
    setDetailOpen,
    togglePluginPin,
    togglePluginEnabled,
    deletePlugin,
  } = useAppStore();
  const definition = getPluginCatalogItem(plugin.pluginKind);
  const resolvedIcon =
    icon ??
    (definition
      ? renderPluginKindIcon(definition.icon, {
          className: "h-4 w-4 text-primary",
        })
      : null);

  const handleClick = () => {
    setSelectedPlugin(plugin);
    setDetailOpen(true);
  };

  return (
    <Card
      className={cn(
        "flex h-full min-h-[9.25rem] cursor-pointer flex-col transition-all hover:border-primary/50 hover:shadow-md",
        plugin.pinned && "border-primary/30",
        !plugin.enabled && "opacity-60",
      )}
      onClick={handleClick}
    >
      <CardHeader className="flex flex-row items-start justify-between gap-2 px-3 pb-2 pt-1">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {resolvedIcon}
            <span className="truncate font-mono text-sm font-medium">
              {plugin.name}
            </span>
            {plugin.pinned && (
              <Pin className="h-3 w-3 flex-shrink-0 text-primary" />
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <Badge
              variant="outline"
              className={cn("gap-1 text-xs", pluginTypeColors[plugin.type])}
            >
              {pluginTypeIcons[plugin.type]}
              {PLUGIN_TYPE_LABELS[plugin.type]}
            </Badge>
            <Badge variant="outline" className="text-xs">
              {definition?.name ?? plugin.pluginKind}
            </Badge>
          </div>
          {definition?.description && !compact && !children && (
            <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">
              {definition.description}
            </p>
          )}
        </div>
        <div className="flex shrink-0 items-start gap-1">
          {primaryMetric && (
            <div className="mr-1 rounded-md bg-muted/35 px-2 py-1.5 text-right">
              <div className="font-mono text-lg font-semibold leading-none">
                {primaryMetric.value}
              </div>
              <div className="mt-1 text-[10px] text-muted-foreground">
                {primaryMetric.label}
              </div>
            </div>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 flex-shrink-0"
              >
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              onClick={(e) => e.stopPropagation()}
            >
              <DropdownMenuItem onClick={() => togglePluginPin(plugin.id)}>
                {plugin.pinned ? (
                  <>
                    <PinOff className="mr-2 h-4 w-4" />
                    取消固定
                  </>
                ) : (
                  <>
                    <Pin className="mr-2 h-4 w-4" />
                    固定到仪表盘
                  </>
                )}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => togglePluginEnabled(plugin.id)}>
                {plugin.enabled ? (
                  <>
                    <PowerOff className="mr-2 h-4 w-4" />
                    禁用
                  </>
                ) : (
                  <>
                    <Power className="mr-2 h-4 w-4" />
                    启用
                  </>
                )}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => deletePlugin(plugin.id)}
                className="text-destructive focus:text-destructive"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                删除
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      {children && (
        <CardContent className="px-3 pb-1 pt-0">
          <div className="min-h-[4.75rem] rounded-md bg-muted/25 px-2.5 py-2">
            {children}
          </div>
        </CardContent>
      )}
    </Card>
  );
}
