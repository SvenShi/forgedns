"use client";

import { useAppStore } from "@/lib/store";
import { YamlEditor } from "@/components/config/yaml-editor";
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
import { useEffect, useState } from "react";
import { Spinner } from "@/components/ui/spinner";
import { useAuthStore } from "@/lib/auth-store";

export function ConfigEditorView() {
  const yamlConfig = useAppStore((s) => s.configText);
  const setYamlConfig = useAppStore((s) => s.setYamlConfig);
  const loadConfig = useAppStore((s) => s.loadConfig);
  const saveConfig = useAppStore((s) => s.saveConfig);
  const isRestarting = useAppStore((s) => s.isRestarting);
  const isConfigLoading = useAppStore((s) => s.isConfigLoading);
  const isConfigSaving = useAppStore((s) => s.isConfigSaving);
  const configError = useAppStore((s) => s.configError);
  const configPath = useAppStore((s) => s.configPath);
  const configVersion = useAppStore((s) => s.configVersion);
  const dependencyGraph = useAppStore((s) => s.dependencyGraph);
  const isConnected = useAuthStore((s) => s.isConnected);

  const [originalConfig, setOriginalConfig] = useState(yamlConfig);
  const [saveStatus, setSaveStatus] = useState<"idle" | "success" | "error">(
    "idle",
  );

  const hasChanges = yamlConfig !== originalConfig;

  useEffect(() => {
    if (!isConnected) return;
    void loadConfig();
  }, [isConnected, loadConfig]);

  useEffect(() => {
    if (!configVersion) return;
    const timer = window.setTimeout(() => setOriginalConfig(yamlConfig), 0);
    return () => window.clearTimeout(timer);
  }, [configVersion, yamlConfig]);

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

  const handleSaveAndRestart = async () => {
    setSaveStatus("idle");
    try {
      await saveConfig({ reload: true });
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
            disabled={!hasChanges || isConfigSaving}
          >
            <RotateCcw className="h-4 w-4 mr-1.5" />
            重置
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleSave}
            disabled={!hasChanges || isConfigSaving || Boolean(configError)}
          >
            {isConfigSaving ? (
              <Spinner className="h-4 w-4 mr-1.5" />
            ) : (
              <Save className="h-4 w-4 mr-1.5" />
            )}
            保存
          </Button>
          <Button
            size="sm"
            onClick={handleSaveAndRestart}
            disabled={isConfigSaving || isRestarting || Boolean(configError)}
          >
            {isRestarting || isConfigSaving ? (
              <Spinner className="h-4 w-4 mr-1.5" />
            ) : (
              <Save className="h-4 w-4 mr-1.5" />
            )}
            保存并重启
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden p-6">
        <div className="h-full flex gap-6">
          <div className="flex-1 min-w-0">
            <YamlEditor
              value={yamlConfig}
              onChange={setYamlConfig}
              className="h-full"
              readOnly={isConfigLoading}
            />
          </div>

          <Card className="w-72 flex-shrink-0">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">快捷键</CardTitle>
              <CardDescription>编辑器操作说明</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">缩进</span>
                <kbd className="px-2 py-1 bg-muted rounded text-xs font-mono">
                  Tab
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">保存</span>
                <div className="flex gap-1">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs font-mono">
                    Ctrl
                  </kbd>
                  <kbd className="px-2 py-1 bg-muted rounded text-xs font-mono">
                    S
                  </kbd>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">撤销</span>
                <div className="flex gap-1">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs font-mono">
                    Ctrl
                  </kbd>
                  <kbd className="px-2 py-1 bg-muted rounded text-xs font-mono">
                    Z
                  </kbd>
                </div>
              </div>
            </CardContent>

            <CardHeader className="pb-3 pt-0">
              <CardTitle className="text-sm">配置结构</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-500" />
                <span className="text-muted-foreground">runtime</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  运行时
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-muted-foreground">api</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  管理 API
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-yellow-500" />
                <span className="text-muted-foreground">log</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  日志
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-purple-500" />
                <span className="text-muted-foreground">plugins</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {dependencyGraph?.nodes.length ?? 0}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-primary" />
                <span className="text-muted-foreground">init_order</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {dependencyGraph?.init_order.length ?? 0}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
