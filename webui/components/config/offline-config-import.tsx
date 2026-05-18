"use client";

import { useRef, useState } from "react";
import { FileUp, ClipboardPaste, FileWarning, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { useAppStore } from "@/lib/store";

export function OfflineConfigImport() {
  const enterOfflineConfig = useAppStore((s) => s.enterOfflineConfig);
  const setEditorMode = useAppStore((s) => s.setEditorMode);
  const [text, setText] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    const content = await file.text();
    setText(content);
    setFileName(file.name);
  };

  const handleStart = () => {
    if (!text.trim()) return;
    enterOfflineConfig(text, fileName ?? undefined);
  };

  return (
    <main className="flex-1 overflow-auto p-6">
      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <ClipboardPaste className="h-5 w-5" />
            离线编辑配置文件
          </CardTitle>
          <CardDescription>
            当前未连接 OxiDNS 管理 API。可粘贴或上传 YAML
            配置文件在本地编辑，编辑结果仅保存在内存中，刷新页面即丢失，需手动下载或复制导出。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={text}
            onChange={(event) => {
              setText(event.target.value);
              setFileName(null);
            }}
            placeholder="在此粘贴 config.yaml 内容…"
            className="h-64 font-mono text-sm"
            spellCheck={false}
          />
          {fileName && (
            <p className="text-xs text-muted-foreground">
              已读取文件：<span className="font-mono">{fileName}</span>
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".yaml,.yml,text/yaml,application/x-yaml"
              className="hidden"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void handleFile(file);
                event.target.value = "";
              }}
            />
            <Button
              variant="outline"
              onClick={() => fileInputRef.current?.click()}
            >
              <FileUp className="h-4 w-4 mr-1.5" />
              上传文件
            </Button>
            <Button onClick={handleStart} disabled={!text.trim()}>
              <ClipboardPaste className="h-4 w-4 mr-1.5" />
              开始离线编辑
            </Button>
            <Button
              variant="ghost"
              className="ml-auto"
              onClick={() => setEditorMode(false)}
            >
              <LogOut className="h-4 w-4 mr-1.5" />
              退出
            </Button>
          </div>
          <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-700 dark:text-yellow-400">
            <FileWarning className="h-4 w-4 shrink-0" />
            <span>
              离线模式仅做客户端 YAML
              解析，不进行后台插件依赖校验；连接后台后可重新加载并应用配置。
            </span>
          </div>
        </CardContent>
      </Card>
    </main>
  );
}
