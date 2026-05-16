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
  const plugins = useAppStore((s) => s.plugins);
  const isConnected = useAuthStore((s) => s.isConnected);

  const yamlEditorRef = useRef<YamlEditorHandle>(null);
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

      <div className="flex-1 min-h-0 p-6 flex flex-col">
        <div className="flex-1 min-h-0 flex gap-6">
          <div className="flex-1 min-w-0 min-h-0">
            <YamlEditor
              ref={yamlEditorRef}
              value={yamlConfig}
              onChange={setYamlConfig}
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
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">Ctrl</kbd>
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">S</kbd>
                </div>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">撤销</span>
                <div className="flex gap-0.5">
                  <kbd className="px-1.5 py-0.5 bg-muted rounded font-mono text-xs">Ctrl</kbd>
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
