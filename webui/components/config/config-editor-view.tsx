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
import { useState } from "react";
import { Spinner } from "@/components/ui/spinner";

export function ConfigEditorView() {
  const yamlConfig = useAppStore((s) => s.yamlConfig);
  const setYamlConfig = useAppStore((s) => s.setYamlConfig);
  const restartService = useAppStore((s) => s.restartService);
  const isRestarting = useAppStore((s) => s.isRestarting);

  const [originalConfig] = useState(yamlConfig);
  const [isSaving, setIsSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"idle" | "success" | "error">(
    "idle",
  );

  const hasChanges = yamlConfig !== originalConfig;

  const handleSave = async () => {
    setIsSaving(true);
    setSaveStatus("idle");
    // Simulate save
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setIsSaving(false);
    setSaveStatus("success");
    setTimeout(() => setSaveStatus("idle"), 3000);
  };

  const handleSaveAndRestart = async () => {
    await handleSave();
    await restartService();
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
            <p className="text-sm text-muted-foreground">
              /etc/forgedns/config.yaml
            </p>
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
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleReset}
            disabled={!hasChanges || isSaving}
          >
            <RotateCcw className="h-4 w-4 mr-1.5" />
            重置
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleSave}
            disabled={!hasChanges || isSaving}
          >
            {isSaving ? (
              <Spinner className="h-4 w-4 mr-1.5" />
            ) : (
              <Save className="h-4 w-4 mr-1.5" />
            )}
            保存
          </Button>
          <Button
            size="sm"
            onClick={handleSaveAndRestart}
            disabled={isSaving || isRestarting}
          >
            {isRestarting ? (
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
                <span className="text-muted-foreground">servers</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  服务器
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-muted-foreground">executors</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  执行器
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-yellow-500" />
                <span className="text-muted-foreground">matchers</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  匹配器
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-purple-500" />
                <span className="text-muted-foreground">providers</span>
                <span className="ml-auto text-xs text-muted-foreground">
                  数据源
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
