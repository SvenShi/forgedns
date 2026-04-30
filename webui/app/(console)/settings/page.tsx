"use client";

import { useState } from "react";
import { AppHeader } from "@/components/shell/app-header";
import { useAppStore } from "@/lib/store";
import { useAuthStore } from "@/lib/auth-store";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import {
  Info,
  Download,
  Server,
  ShieldCheck,
  Cpu,
  FileText,
  RefreshCw,
  CheckCircle2,
  CircleAlert,
  PlugZap,
} from "lucide-react";

export default function SettingsPage() {
  const systemInfo = useAppStore((s) => s.systemInfo);
  const systemMetrics = useAppStore((s) => s.systemMetrics);
  const serverConfig = useAuthStore((s) => s.serverConfig);
  const setServerConfig = useAuthStore((s) => s.setServerConfig);
  const connect = useAuthStore((s) => s.connect);
  const disconnect = useAuthStore((s) => s.disconnect);
  const isConnected = useAuthStore((s) => s.isConnected);
  const isConnecting = useAuthStore((s) => s.isConnecting);
  const connectionError = useAuthStore((s) => s.connectionError);
  const user = useAuthStore((s) => s.user);

  const [backendUrl, setBackendUrl] = useState(serverConfig.url);
  const [requiresAuth, setRequiresAuth] = useState(serverConfig.requiresAuth);
  const [username, setUsername] = useState(serverConfig.username ?? "");
  const [password, setPassword] = useState(serverConfig.password ?? "");

  const hasUpdate = systemInfo.version !== systemInfo.latestVersion;
  const canConnect =
    backendUrl.trim().length > 0 &&
    (!requiresAuth || (username.trim().length > 0 && password.length > 0));

  const handleSaveConnection = () => {
    setServerConfig({
      url: backendUrl.trim(),
      requiresAuth,
      username: requiresAuth ? username.trim() : "",
      password: requiresAuth ? password : "",
    });
  };

  const handleConnect = async () => {
    handleSaveConnection();
    await connect(
      requiresAuth ? username.trim() : undefined,
      requiresAuth ? password : undefined,
    );
  };

  return (
    <>
      <AppHeader title="系统配置" />
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <PlugZap className="h-5 w-5" />
                    后台服务
                  </CardTitle>
                  <CardDescription className="mt-1.5">
                    配置 WebUI 连接的 ForgeDNS 管理服务地址和认证信息
                  </CardDescription>
                </div>
                <Badge
                  variant="outline"
                  className={
                    isConnected
                      ? "bg-primary/10 text-primary border-primary/30"
                      : "bg-muted text-muted-foreground"
                  }
                >
                  {isConnected ? "已连接" : "未连接"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <FieldGroup>
                <Field>
                  <FieldLabel>服务地址</FieldLabel>
                  <Input
                    value={backendUrl}
                    onChange={(event) => setBackendUrl(event.target.value)}
                    placeholder="http://localhost:8080"
                    className="font-mono"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    管理 API 的完整地址，例如 http://127.0.0.1:8080
                  </p>
                </Field>

                <Field
                  orientation="horizontal"
                  className="rounded-lg border p-3"
                >
                  <Switch
                    checked={requiresAuth}
                    onCheckedChange={setRequiresAuth}
                    aria-label="启用后台服务认证"
                  />
                  <FieldContent>
                    <FieldLabel className="w-full">
                      <ShieldCheck className="h-4 w-4" />
                      后台服务需要用户名密码
                    </FieldLabel>
                    <p className="text-sm text-muted-foreground">
                      启用后连接后台服务时会使用下方登录信息
                    </p>
                  </FieldContent>
                </Field>

                {requiresAuth && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field>
                      <FieldLabel>用户名</FieldLabel>
                      <Input
                        value={username}
                        onChange={(event) => setUsername(event.target.value)}
                        placeholder="admin"
                        autoComplete="username"
                      />
                    </Field>
                    <Field>
                      <FieldLabel>密码</FieldLabel>
                      <Input
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        type="password"
                        placeholder="请输入密码"
                        autoComplete="current-password"
                      />
                    </Field>
                  </div>
                )}
              </FieldGroup>

              {connectionError && (
                <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  <CircleAlert className="h-4 w-4" />
                  {connectionError}
                </div>
              )}

              <div className="flex flex-wrap items-center gap-2">
                <Button onClick={handleSaveConnection}>保存连接配置</Button>
                <Button
                  variant="outline"
                  onClick={handleConnect}
                  disabled={!canConnect || isConnecting}
                >
                  {isConnecting ? (
                    <RefreshCw className="h-4 w-4 mr-1.5 animate-spin" />
                  ) : (
                    <PlugZap className="h-4 w-4 mr-1.5" />
                  )}
                  {isConnecting ? "连接中" : "保存并连接"}
                </Button>
                {isConnected && (
                  <Button variant="ghost" onClick={disconnect}>
                    断开连接
                  </Button>
                )}
                {user && (
                  <span className="text-sm text-muted-foreground">
                    当前用户：
                    <span className="font-mono text-foreground">
                      {user.username}
                    </span>
                  </span>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Info className="h-5 w-5" />
                    服务信息
                  </CardTitle>
                  <CardDescription className="mt-1.5">
                    ForgeDNS 服务版本和更新状态
                  </CardDescription>
                </div>
                {hasUpdate && (
                  <Badge
                    variant="outline"
                    className="bg-primary/10 text-primary border-primary/30"
                  >
                    有新版本
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">当前版本</p>
                  <p className="font-mono text-lg">{systemInfo.version}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">最新版本</p>
                  <div className="flex items-center gap-2">
                    <p className="font-mono text-lg">
                      {systemInfo.latestVersion}
                    </p>
                    {!hasUpdate && (
                      <Badge
                        variant="outline"
                        className="bg-primary/10 text-primary"
                      >
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        已是最新
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
              {hasUpdate && (
                <Button>
                  <Download className="h-4 w-4 mr-1.5" />
                  下载更新
                </Button>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                运行参数
              </CardTitle>
              <CardDescription>调整服务运行时配置</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field>
                    <FieldLabel>工作线程数</FieldLabel>
                    <Input
                      type="number"
                      defaultValue={systemInfo.threads}
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      建议设置为 CPU 核心数
                    </p>
                  </Field>
                  <Field>
                    <FieldLabel>最大并发数</FieldLabel>
                    <Input
                      type="number"
                      defaultValue={systemInfo.maxConcurrency}
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      同时处理的最大请求数
                    </p>
                  </Field>
                </div>
              </FieldGroup>
              <div className="flex items-center gap-2 mt-4">
                <Button>保存配置</Button>
                <Button variant="outline">
                  <RefreshCw className="h-4 w-4 mr-1.5" />
                  重启服务
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                日志配置
              </CardTitle>
              <CardDescription>配置日志级别和滚动策略</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field>
                    <FieldLabel>日志级别</FieldLabel>
                    <Select defaultValue={systemInfo.logLevel}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="trace">Trace</SelectItem>
                        <SelectItem value="debug">Debug</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                        <SelectItem value="warn">Warn</SelectItem>
                        <SelectItem value="error">Error</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel>滚动策略</FieldLabel>
                    <Select defaultValue={systemInfo.logRolling}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="hourly">每小时</SelectItem>
                        <SelectItem value="daily">每天</SelectItem>
                        <SelectItem value="weekly">每周</SelectItem>
                        <SelectItem value="size">按大小 (100MB)</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                </div>
              </FieldGroup>
              <Button className="mt-4">保存配置</Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cpu className="h-5 w-5" />
                系统信息
              </CardTitle>
              <CardDescription>运行环境和资源使用情况</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">操作系统</p>
                  <p className="font-mono">{systemInfo.os}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">架构</p>
                  <p className="font-mono">{systemInfo.arch}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">CPU 使用率</p>
                  <p className="font-mono">
                    {systemMetrics.cpuUsage.toFixed(1)}%
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">内存使用</p>
                  <p className="font-mono">
                    {systemMetrics.memoryUsage} / {systemMetrics.memoryTotal} MB
                  </p>
                </div>
              </div>

              <Separator className="my-6" />

              <div className="space-y-3">
                <h4 className="text-sm font-medium">环境变量</h4>
                <div className="bg-muted/50 rounded-lg p-4 font-mono text-sm overflow-x-auto">
                  <div className="space-y-1.5 text-muted-foreground">
                    <p>
                      <span className="text-foreground">FORGEDNS_CONFIG</span>=
                      /etc/forgedns/config.yaml
                    </p>
                    <p>
                      <span className="text-foreground">FORGEDNS_DATA_DIR</span>
                      = /var/lib/forgedns
                    </p>
                    <p>
                      <span className="text-foreground">FORGEDNS_LOG_DIR</span>=
                      /var/log/forgedns
                    </p>
                    <p>
                      <span className="text-foreground">RUST_LOG</span>=
                      {systemInfo.logLevel}
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </>
  );
}
