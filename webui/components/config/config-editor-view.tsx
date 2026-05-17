"use client";

import { useAppStore } from "@/lib/store";
import { YamlEditor, type YamlEditorHandle } from "@/components/config/yaml-editor";
import { PluginIndexPanel } from "@/components/config/plugin-index-panel";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Save,
  RotateCcw,
  FileCode2,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Spinner } from "@/components/ui/spinner";

export function ConfigEditorView() {
  const yamlConfig = useAppStore((s) => s.configText);
  const setYamlConfig = useAppStore((s) => s.setYamlConfig);
  const saveConfig = useAppStore((s) => s.saveConfig);
  const isConfigLoading = useAppStore((s) => s.isConfigLoading);
  const isConfigSaving = useAppStore((s) => s.isConfigSaving);
  const configError = useAppStore((s) => s.configError);
  const configPath = useAppStore((s) => s.configPath);
  const configVersion = useAppStore((s) => s.configVersion);
  const plugins = useAppStore((s) => s.plugins);

  const yamlEditorRef = useRef<YamlEditorHandle>(null);
  const [originalConfig, setOriginalConfig] = useState(yamlConfig);
  const [saveStatus, setSaveStatus] = useState<"idle" | "success" | "error">(
    "idle",
  );
  const [isMac, setIsMac] = useState(false);

  const hasChanges = yamlConfig !== originalConfig;
  const modKey = isMac ? "⌘" : "Ctrl";

  useEffect(() => {
    const mac =
      typeof navigator !== "undefined" &&
      /mac|iphone|ipad|ipod/i.test(
        navigator.platform || navigator.userAgent,
      );
    const timer = window.setTimeout(() => setIsMac(mac), 0);
    return () => window.clearTimeout(timer);
  }, []);

  // Config is loaded once on connect by the console layout. Do NOT reload
  // here on mount — switching into editor mode must not refetch and clobber
  // local state (apply-failed status, runningVersion, unsaved edits).

  // Resync the dirty-tracking baseline only when the persisted config
  // changes (after load or save) — NOT on every keystroke, otherwise
  // hasChanges collapses immediately and 保存 stays disabled.
  useEffect(() => {
    if (!configVersion) return;
    const timer = window.setTimeout(
      () => setOriginalConfig(useAppStore.getState().configText),
      0,
    );
    return () => window.clearTimeout(timer);
  }, [configVersion]);

  const handleSave = async () => {
    setSaveStatus("idle");
    try {
      await saveConfig();
      setOriginalConfig(yamlConfig);
      setSaveStatus("success");
      setTimeout(() => setSaveStatus("idle"), 3000);
    } catch {
      setSaveStatus("error");
    }
  };

  const handleReset = () => {
    setYamlConfig(originalConfig);
    setSaveStatus("idle");
  };

  const busy = isConfigSaving;

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <FileCode2 className="h-5 w-5 text-muted-foreground" />
          <div>
            <h2 className="text-lg font-semibold">配置文件编辑器</h2>
            <p className="text-sm text-muted-foreground">{configPath}</p>
          </div>
          {hasChanges && (
            <Badge
              variant="outline"
              className="bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/30"
            >
              未保存
            </Badge>
          )}
          {saveStatus === "success" && (
            <Badge
              variant="outline"
              className="bg-primary/10 text-primary border-primary/30"
            >
              <CheckCircle2 className="h-3 w-3 mr-1" />
              已保存
            </Badge>
          )}
          {saveStatus === "error" && (
            <Badge variant="destructive">
              <AlertCircle className="h-3 w-3 mr-1" />
              保存失败
            </Badge>
          )}
          {configError && (
            <Badge variant="destructive" className="max-w-md truncate">
              <AlertCircle className="h-3 w-3 mr-1" />
              {configError}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleReset}
            disabled={!hasChanges || busy}
          >
            <RotateCcw className="h-4 w-4 mr-1.5" />
            重置
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleSave}
            disabled={!hasChanges || busy || Boolean(configError)}
          >
            {isConfigSaving ? (
              <Spinner className="h-4 w-4 mr-1.5" />
            ) : (
              <Save className="h-4 w-4 mr-1.5" />
            )}
            保存
          </Button>
        </div>
      </div>

      <div className="flex-1 min-h-0 p-6 flex flex-col">
        <div className="flex-1 min-h-0 flex gap-6">
          <div className="flex-1 min-w-0 min-h-0">
            <YamlEditor
              ref={yamlEditorRef}
              value={yamlConfig}
              onChange={setYamlConfig}
              onSave={() => {
                if (hasChanges && !busy && !configError) void handleSave();
              }}
              className="h-full"
              readOnly={isConfigLoading}
              variant="config"
              plugins={plugins}
            />
          </div>

          <Card className="w-80 flex-shrink-0 flex flex-col min-h-0">
            <CardHeader className="flex-shrink-0 pb-2">
              <CardTitle className="text-sm">插件索引</CardTitle>
              <CardDescription>点击跳转到定义行</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 min-h-0 overflow-y-auto pb-2 px-3">
              <PluginIndexPanel
                yamlText={yamlConfig}
                onJumpToLine={(line) => yamlEditorRef.current?.jumpToLine(line)}
              />
            </CardContent>
            <div className="border-t px-3 py-3 flex-shrink-0 space-y-2">
              <p className="text-xs text-muted-foreground font-medium mb-1.5">快捷键</p>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">缩进</span>
                <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">Tab</kbd>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">保存</span>
                <div className="flex gap-0.5">
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">{modKey}</kbd>
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">S</kbd>
                </div>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">撤销</span>
                <div className="flex gap-0.5">
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">{modKey}</kbd>
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">Z</kbd>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
