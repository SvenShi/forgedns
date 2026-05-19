"use client";

import Link from "next/link";
import { PlugZap, FileCode2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAppStore } from "@/lib/store";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function ConnectionRequired() {
  const setEditorMode = useAppStore((s) => s.setEditorMode);
  return (
    <main className="oxidns-dialog-scrollbar min-h-0 flex-1 overflow-auto p-6">
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <PlugZap className="h-5 w-5" />
            需要连接后台服务
          </CardTitle>
          <CardDescription>
            当前 WebUI 尚未连接 OxiDNS 管理 API，请先在系统配置中连接后台服务。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button asChild>
            <Link href="/settings">前往系统配置</Link>
          </Button>
          <Button variant="outline" onClick={() => setEditorMode(true)}>
            <FileCode2 className="h-4 w-4 mr-1.5" />
            离线编辑配置文件
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
