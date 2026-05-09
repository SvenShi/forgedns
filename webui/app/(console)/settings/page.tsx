"use client";

import { useEffect, useState } from "react";
import { AppHeader } from "@/components/shell/app-header";
import { useAppStore } from "@/lib/store";
import { useAuthStore } from "@/lib/auth-store";
import { stringifyOxiDnsConfig, type OxiDnsConfig } from "@/lib/oxidns-config";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldContent, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { CheckCircle2, CircleAlert, FileCode2, PlugZap, RefreshCw, Server, Settings } from "lucide-react";

export default function SettingsPage() {
  const serverConfig = useAuthStore((s) => s.serverConfig);
  const setServerConfig = useAuthStore((s) => s.setServerConfig);
  const connect = useAuthStore((s) => s.connect);
  const disconnect = useAuthStore((s) => s.disconnect);
  const isConnected = useAuthStore((s) => s.isConnected);
  const isConnecting = useAuthStore((s) => s.isConnecting);
  const connectionError = useAuthStore((s) => s.connectionError);
  const user = useAuthStore((s) => s.user);

  const configModel = useAppStore((s) => s.configModel);
  const configPath = useAppStore((s) => s.configPath);
  const configVersion = useAppStore((s) => s.configVersion);
  const configError = useAppStore((s) => s.configError);
  const dependencyGraph = useAppStore((s) => s.dependencyGraph);
  const health = useAppStore((s) => s.health);
  const system = useAppStore((s) => s.system);
  const reloadStatus = useAppStore((s) => s.reloadStatus);
  const setYamlConfig = useAppStore((s) => s.setYamlConfig);
  const saveConfig = useAppStore((s) => s.saveConfig);
  const refreshRuntimeState = useAppStore((s) => s.refreshRuntimeState);
  const isConfigSaving = useAppStore((s) => s.isConfigSaving);

  const [backendUrl, setBackendUrl] = useState(serverConfig.url);
  const [requiresAuth, setRequiresAuth] = useState(serverConfig.requiresAuth);
  const [username, setUsername] = useState(serverConfig.username ?? "");
  const [password, setPassword] = useState(serverConfig.password ?? "");
  const [workerThreads, setWorkerThreads] = useState("");
  const [apiListen, setApiListen] = useState("");
  const [logLevel, setLogLevel] = useState("info");
  const [logFile, setLogFile] = useState("");
  const [rotationType, setRotationType] = useState("never");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const runtime = asRecord(configModel.runtime);
      const api = asRecord(configModel.api);
      const http = api.http;
      const log = asRecord(configModel.log);
      const rotation = asRecord(log.rotation);

      setWorkerThreads(String(runtime.worker_threads ?? ""));
      setApiListen(
        typeof http === "string" ? http : String(asRecord(http).listen ?? ""),
      );
      setLogLevel(String(log.level ?? "info"));
      setLogFile(String(log.file ?? ""));
      setRotationType(String(rotation.type ?? "never"));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [configModel]);

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
    const ok = await connect(
      requiresAuth ? username.trim() : undefined,
      requiresAuth ? password : undefined,
    );
    if (ok) await refreshRuntimeState();
  };

  const handleSaveTopLevelConfig = async (reload: boolean) => {
    const nextConfig: OxiDnsConfig = {
      ...configModel,
      runtime: {
        ...asRecord(configModel.runtime),
        ...(workerThreads.trim()
          ? { worker_threads: Number(workerThreads) }
          : { worker_threads: undefined }),
      },
      api: {
        ...asRecord(configModel.api),
        ...(apiListen.trim() ? { http: apiListen.trim() } : {}),
      },
      log: {
        ...asRecord(configModel.log),
        level: logLevel,
        ...(logFile.trim() ? { file: logFile.trim() } : { file: undefined }),
        rotation:
          rotationType === "never" ? { type: "never" } : { type: rotationType },
      },
    };
    setYamlConfig(stringifyOxiDnsConfig(nextConfig));
    await saveConfig({ reload });
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
                    配置 WebUI 连接的 OxiDNS 管理 API
                  </CardDescription>
                </div>
                <Badge variant="outline" className={isConnected ? "bg-primary/10 text-primary border-primary/30" : "bg-muted text-muted-foreground"}>
                  {isConnected ? "已连接" : "未连接"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <FieldGroup>
                <Field>
                  <FieldLabel>服务地址</FieldLabel>
                  <Input value={backendUrl} onChange={(event) => setBackendUrl(event.target.value)} placeholder="http://localhost:8080" className="font-mono" />
                </Field>
                <Field orientation="horizontal" className="rounded-lg border p-3">
                  <Switch checked={requiresAuth} onCheckedChange={setRequiresAuth} aria-label="启用后台服务认证" />
                  <FieldContent>
                    <FieldLabel className="w-full">需要用户名密码</FieldLabel>
                    <p className="text-sm text-muted-foreground">使用 Basic Auth 连接管理 API</p>
                  </FieldContent>
                </Field>
                {requiresAuth && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field>
                      <FieldLabel>用户名</FieldLabel>
                      <Input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
                    </Field>
                    <Field>
                      <FieldLabel>密码</FieldLabel>
                      <Input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" />
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
                <Button variant="outline" onClick={handleConnect} disabled={!canConnect || isConnecting}>
                  <PlugZap className="h-4 w-4 mr-1.5" />
                  {isConnecting ? "连接中" : "保存并连接"}
                </Button>
                {isConnected && <Button variant="ghost" onClick={disconnect}>断开连接</Button>}
                {user && <span className="text-sm text-muted-foreground">当前用户：<span className="font-mono text-foreground">{user.username}</span></span>}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                运行状态
              </CardTitle>
              <CardDescription>来自 /system、/health 和 /reload/status</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <InfoTile label="版本" value={system?.version ?? health?.version ?? "-"} />
              <InfoTile label="平台" value={system ? `${system.os}/${system.arch}` : "-"} />
              <InfoTile label="Health" value={health?.status ?? "-"} />
              <InfoTile label="Reload" value={reloadStatus?.status ?? "-"} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileCode2 className="h-5 w-5" />
                配置摘要
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <InfoTile label="配置文件" value={configPath} />
              <InfoTile label="版本" value={configVersion?.slice(0, 12) ?? "-"} />
              <InfoTile label="插件数" value={String(dependencyGraph?.nodes.length ?? configModel.plugins.length)} />
              <InfoTile label="初始化顺序" value={String(dependencyGraph?.init_order.length ?? 0)} />
              <div className="sm:col-span-2">
                <Badge variant={configError ? "destructive" : "outline"} className={configError ? "" : "bg-primary/10 text-primary"}>
                  {configError ? <CircleAlert className="h-3 w-3 mr-1" /> : <CheckCircle2 className="h-3 w-3 mr-1" />}
                  {configError ?? "配置校验通过"}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                顶层配置
              </CardTitle>
              <CardDescription>写回 runtime、api 和 log 顶层配置</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field>
                  <FieldLabel>runtime.worker_threads</FieldLabel>
                  <Input value={workerThreads} onChange={(event) => setWorkerThreads(event.target.value)} type="number" placeholder="留空使用系统默认" className="font-mono" />
                </Field>
                <Field>
                  <FieldLabel>api.http.listen</FieldLabel>
                  <Input value={apiListen} onChange={(event) => setApiListen(event.target.value)} placeholder="127.0.0.1:8080" className="font-mono" />
                </Field>
                <Field>
                  <FieldLabel>log.level</FieldLabel>
                  <Select value={logLevel} onValueChange={setLogLevel}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {["trace", "debug", "info", "warn", "error", "off"].map((level) => (
                        <SelectItem key={level} value={level}>{level}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field>
                  <FieldLabel>log.file</FieldLabel>
                  <Input value={logFile} onChange={(event) => setLogFile(event.target.value)} placeholder="留空输出到控制台" className="font-mono" />
                </Field>
                <Field>
                  <FieldLabel>log.rotation.type</FieldLabel>
                  <Select value={rotationType} onValueChange={setRotationType}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {["never", "minutely", "hourly", "daily", "weekly"].map((type) => (
                        <SelectItem key={type} value={type}>{type}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => handleSaveTopLevelConfig(false)} disabled={isConfigSaving}>
                  保存配置
                </Button>
                <Button variant="outline" onClick={() => handleSaveTopLevelConfig(true)} disabled={isConfigSaving}>
                  <RefreshCw className="h-4 w-4 mr-1.5" />
                  保存并重载
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </>
  );
}

function InfoTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-lg border px-3 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-mono text-sm font-semibold">{value}</div>
    </div>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
