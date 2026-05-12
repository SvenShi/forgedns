"use client";

import Link from "next/link";
import { PlugZap } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function ConnectionRequired() {
  return (
    <main className="flex-1 overflow-auto p-6">
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
        <CardContent>
          <Button asChild>
            <Link href="/settings">前往系统配置</Link>
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
