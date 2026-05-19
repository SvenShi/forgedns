"use client";

import { useEffect, useState } from "react";
import { AppHeader } from "@/components/shell/app-header";
import { useAppStore } from "@/lib/store";
import { useAuthStore, type ServerConfig } from "@/lib/auth-store";
import { stringifyOxiDnsConfig, type OxiDnsConfig } from "@/lib/oxidns-config";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  CheckCircle2,
  CircleAlert,
  Cpu,
  FileCode2,
  Globe,
  PlugZap,
  RefreshCw,
  ScrollText,
  Server,
} from "lucide-react";

export default function SettingsPage() {
  const serverConfig = useAuthStore((s) => s.serverConfig);
  const setServerConfig = useAuthStore((s) => s.setServerConfig);
  const connect = useAuthStore((s) => s.connect);
  const isConnected = useAuthStore((s) => s.isConnected);
  const isConnecting = useAuthStore((s) => s.isConnecting);
  const connectionError = useAuthStore((s) => s.connectionError);

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
  const applyConfig = useAppStore((s) => s.applyConfig);
  const loadConfig = useAppStore((s) => s.loadConfig);
  const isConfigSaving = useAppStore((s) => s.isConfigSaving);
  const isApplying = useAppStore((s) => s.isApplying);

  const [backendUrl, setBackendUrl] = useState(serverConfig.url);
  const [requiresAuth, setRequiresAuth] = useState(serverConfig.requiresAuth);
  const [username, setUsername] = useState(serverConfig.username ?? "");
  const [password, setPassword] = useState(serverConfig.password ?? "");
  const [workerThreads, setWorkerThreads] = useState("");
  const [apiListen, setApiListen] = useState("");
  const [apiSslEnabled, setApiSslEnabled] = useState(false);
  const [apiSslCert, setApiSslCert] = useState("");
  const [apiSslKey, setApiSslKey] = useState("");
  const [apiSslClientCa, setApiSslClientCa] = useState("");
  const [apiSslRequireClientCert, setApiSslRequireClientCert] = useState(false);
  const [apiAuthEnabled, setApiAuthEnabled] = useState(false);
  const [apiAuthUsername, setApiAuthUsername] = useState("");
  const [apiAuthPassword, setApiAuthPassword] = useState("");
  const [apiCorsOrigins, setApiCorsOrigins] = useState("");
  const [apiWebuiEnabled, setApiWebuiEnabled] = useState(false);
  const [apiWebuiRoot, setApiWebuiRoot] = useState("");
  const [apiWebuiIndex, setApiWebuiIndex] = useState("");
  const [logLevel, setLogLevel] = useState("info");
  const [logFile, setLogFile] = useState("");
  const [rotationType, setRotationType] = useState("never");
  const [maxFiles, setMaxFiles] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const runtime = asRecord(configModel.runtime);
      const api = asRecord(configModel.api);
      const http = api.http;
      const httpObj =
        typeof http === "string" ? { listen: http } : asRecord(http);
      const ssl = asRecord(httpObj.ssl);
      const auth = asRecord(httpObj.auth);
      const cors = asRecord(httpObj.cors);
      const webui = asRecord(httpObj.webui);
      const log = asRecord(configModel.log);
      const rotation = asRecord(log.rotation);

      setWorkerThreads(String(runtime.worker_threads ?? ""));
      setApiListen(String(httpObj.listen ?? ""));
      setApiSslEnabled(Boolean(ssl.cert || ssl.key));
      setApiSslCert(String(ssl.cert ?? ""));
      setApiSslKey(String(ssl.key ?? ""));
      setApiSslClientCa(String(ssl.client_ca ?? ""));
      setApiSslRequireClientCert(Boolean(ssl.require_client_cert ?? false));
      setApiAuthEnabled(auth.type === "basic");
      setApiAuthUsername(String(auth.username ?? ""));
      setApiAuthPassword(String(auth.password ?? ""));
      const origins = Array.isArray(cors.allowed_origins)
        ? (cors.allowed_origins as string[])
        : [];
      setApiCorsOrigins(origins.join("\n"));
      setApiWebuiEnabled(Boolean(webui.root));
      setApiWebuiRoot(String(webui.root ?? ""));
      setApiWebuiIndex(String(webui.index ?? ""));
      setLogLevel(String(log.level ?? "info"));
      setLogFile(String(log.file ?? ""));
      setRotationType(String(rotation.type ?? "never"));
      setMaxFiles(rotation.max_files != null ? String(rotation.max_files) : "");
    }, 0);
    return () => window.clearTimeout(timer);
  }, [configModel]);

  const canConnect =
    backendUrl.trim().length > 0 &&
    (!requiresAuth || (username.trim().length > 0 && password.length > 0));

  const getConnectionConfig = (): ServerConfig => ({
    url: backendUrl.trim(),
    requiresAuth,
    username: requiresAuth ? username.trim() : "",
    password: requiresAuth ? password : "",
  });

  const handleSaveConnection = () => {
    setServerConfig(getConnectionConfig());
  };

  const handleConnect = async () => {
    const nextConfig = getConnectionConfig();
    setServerConfig(nextConfig);
    const ok = await connect(nextConfig);
    if (ok) await loadConfig();
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
        ...(apiListen.trim() ? { http: buildApiHttpConfig() } : {}),
      },
      log: {
        ...asRecord(configModel.log),
        level: logLevel,
        ...(logFile.trim() ? { file: logFile.trim() } : { file: undefined }),
        rotation:
          rotationType === "never"
            ? { type: "never" }
            : {
                type: rotationType,
                ...(maxFiles.trim() !== ""
                  ? { max_files: Number(maxFiles) }
                  : {}),
              },
      },
    };
    setYamlConfig(stringifyOxiDnsConfig(nextConfig));
    await saveConfig();
    if (reload) await applyConfig();
  };

  const buildApiHttpConfig = (): unknown => {
    const sslConfig =
      apiSslEnabled && apiSslCert.trim() && apiSslKey.trim()
        ? {
            cert: apiSslCert.trim(),
            key: apiSslKey.trim(),
            ...(apiSslClientCa.trim()
              ? { client_ca: apiSslClientCa.trim() }
              : {}),
            ...(apiSslRequireClientCert ? { require_client_cert: true } : {}),
          }
        : undefined;
    const authConfig = apiAuthEnabled
      ? {
          type: "basic",
          username: apiAuthUsername.trim(),
          password: apiAuthPassword,
        }
      : undefined;
    const corsOriginsList = apiCorsOrigins
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const corsConfig =
      corsOriginsList.length > 0
        ? { allowed_origins: corsOriginsList }
        : undefined;
    const webuiConfig =
      apiWebuiEnabled && apiWebuiRoot.trim()
        ? {
            root: apiWebuiRoot.trim(),
            ...(apiWebuiIndex.trim() ? { index: apiWebuiIndex.trim() } : {}),
          }
        : undefined;
    const hasDetail = sslConfig || authConfig || corsConfig || webuiConfig;
    if (!hasDetail) return apiListen.trim();
    return {
      listen: apiListen.trim(),
      ...(sslConfig ? { ssl: sslConfig } : {}),
      ...(authConfig ? { auth: authConfig } : {}),
      ...(corsConfig ? { cors: corsConfig } : {}),
      ...(webuiConfig ? { webui: webuiConfig } : {}),
    };
  };

  return (
    <>
      <AppHeader title="系统配置" />
      <main className="oxidns-dialog-scrollbar min-h-0 flex-1 overflow-auto p-6">
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
                    配置 WebUI 连接的 OxiDNS 管理 API，可使用 /api 或完整地址
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
              <div className="space-y-4">
                <Field>
                  <FieldLabel>服务地址</FieldLabel>
                  <Input
                    value={backendUrl}
                    onChange={(event) => setBackendUrl(event.target.value)}
                    placeholder="/api 或 http://localhost:8080"
                    className="font-mono"
                  />
                </Field>
                <div className="space-y-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="text-sm font-medium">需要用户名密码</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        使用 Basic Auth 连接管理 API
                      </p>
                    </div>
                    <Switch
                      checked={requiresAuth}
                      onCheckedChange={setRequiresAuth}
                      aria-label="启用后台服务认证"
                    />
                  </div>
                  {requiresAuth && (
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field>
                        <FieldLabel>用户名</FieldLabel>
                        <Input
                          value={username}
                          onChange={(event) => setUsername(event.target.value)}
                          autoComplete="username"
                        />
                      </Field>
                      <Field>
                        <FieldLabel>密码</FieldLabel>
                        <Input
                          value={password}
                          onChange={(event) => setPassword(event.target.value)}
                          type="password"
                          autoComplete="current-password"
                        />
                      </Field>
                    </div>
                  )}
                </div>
              </div>
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
                  <PlugZap className="h-4 w-4 mr-1.5" />
                  {isConnecting ? "连接中" : "保存并连接"}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                运行状态
              </CardTitle>
              <CardDescription>
                来自 /system、/health 和 /reload/status
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <InfoTile
                label="版本"
                value={system?.version ?? health?.version ?? "-"}
              />
              <InfoTile
                label="平台"
                value={system ? `${system.os}/${system.arch}` : "-"}
              />
              <InfoTile label="健康状态" value={health?.status ?? "-"} />
              <InfoTile label="重载状态" value={reloadStatus?.status ?? "-"} />
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
              <InfoTile
                label="版本"
                value={configVersion?.slice(0, 12) ?? "-"}
              />
              <InfoTile
                label="插件数"
                value={String(
                  dependencyGraph?.nodes.length ?? configModel.plugins.length,
                )}
              />
              <InfoTile
                label="初始化顺序"
                value={String(dependencyGraph?.init_order.length ?? 0)}
              />
              <div className="sm:col-span-2">
                <Badge
                  variant={configError ? "destructive" : "outline"}
                  className={configError ? "" : "bg-primary/10 text-primary"}
                >
                  {configError ? (
                    <CircleAlert className="h-3 w-3 mr-1" />
                  ) : (
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                  )}
                  {configError ?? "配置校验通过"}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cpu className="h-5 w-5" />
                运行时
              </CardTitle>
              <CardDescription>Tokio 运行时参数（runtime）</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <Field>
                <FieldLabel>Worker 线程数</FieldLabel>
                <p className="text-xs text-muted-foreground mb-2">
                  Tokio 多线程运行时的 worker
                  数，留空自动取系统可用并行度，不能为 0
                </p>
                <Input
                  value={workerThreads}
                  onChange={(event) => setWorkerThreads(event.target.value)}
                  type="number"
                  min={1}
                  placeholder="留空使用系统默认"
                  className="font-mono max-w-xs"
                />
              </Field>
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => handleSaveTopLevelConfig(false)}
                  disabled={isConfigSaving || isApplying || !isConnected}
                >
                  保存配置
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleSaveTopLevelConfig(true)}
                  disabled={isConfigSaving || isApplying || !isConnected}
                >
                  <RefreshCw className="h-4 w-4 mr-1.5" />
                  保存并应用
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                管理 API
              </CardTitle>
              <CardDescription>HTTP 管理接口配置（api.http）</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* 监听地址 */}
              <div className="space-y-2">
                <p className="text-sm font-medium">监听地址 (listen)</p>
                <p className="text-xs text-muted-foreground">
                  支持 <span className="font-mono">ip:port</span>、
                  <span className="font-mono">[ipv6]:port</span>、
                  <span className="font-mono">:port</span>；
                  <span className="font-mono">:port</span> 绑定为双栈{" "}
                  <span className="font-mono">[::]:port</span>，仅监听 IPv4 时写{" "}
                  <span className="font-mono">0.0.0.0:port</span>
                </p>
                <Input
                  value={apiListen}
                  onChange={(e) => setApiListen(e.target.value)}
                  placeholder=":9199"
                  className="font-mono"
                />
              </div>

              {/* TLS */}
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-medium">TLS / SSL</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      配置 HTTPS，cert 与 key 必须成对出现
                    </p>
                  </div>
                  <Switch
                    checked={apiSslEnabled}
                    onCheckedChange={setApiSslEnabled}
                    aria-label="启用 TLS"
                  />
                </div>
                {apiSslEnabled && (
                  <div className="space-y-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field>
                        <FieldLabel>证书文件路径 (cert)</FieldLabel>
                        <Input
                          value={apiSslCert}
                          onChange={(e) => setApiSslCert(e.target.value)}
                          placeholder="/etc/oxidns/api.crt"
                          className="font-mono"
                        />
                      </Field>
                      <Field>
                        <FieldLabel>私钥文件路径 (key)</FieldLabel>
                        <Input
                          value={apiSslKey}
                          onChange={(e) => setApiSslKey(e.target.value)}
                          placeholder="/etc/oxidns/api.key"
                          className="font-mono"
                        />
                      </Field>
                      <Field>
                        <FieldLabel>客户端 CA 证书 (client_ca)</FieldLabel>
                        <p className="text-xs text-muted-foreground mb-2">
                          可选，启用双向 TLS 时提供
                        </p>
                        <Input
                          value={apiSslClientCa}
                          onChange={(e) => setApiSslClientCa(e.target.value)}
                          placeholder="/etc/oxidns/client-ca.crt"
                          className="font-mono"
                        />
                      </Field>
                    </div>
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-sm font-medium">
                          要求客户端证书 (require_client_cert)
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          启用时必须提供 client_ca，客户端须携带受信任证书
                        </p>
                      </div>
                      <Switch
                        checked={apiSslRequireClientCert}
                        onCheckedChange={setApiSslRequireClientCert}
                        aria-label="要求客户端证书"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* 身份认证 */}
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-medium">身份认证 (auth)</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      当前支持 Basic Auth，客户端需在请求头中携带凭据
                    </p>
                  </div>
                  <Switch
                    checked={apiAuthEnabled}
                    onCheckedChange={setApiAuthEnabled}
                    aria-label="启用 Basic Auth"
                  />
                </div>
                {apiAuthEnabled && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field>
                      <FieldLabel>用户名 (username)</FieldLabel>
                      <Input
                        value={apiAuthUsername}
                        onChange={(e) => setApiAuthUsername(e.target.value)}
                        autoComplete="off"
                      />
                    </Field>
                    <Field>
                      <FieldLabel>密码 (password)</FieldLabel>
                      <Input
                        value={apiAuthPassword}
                        onChange={(e) => setApiAuthPassword(e.target.value)}
                        type="password"
                        autoComplete="new-password"
                      />
                    </Field>
                  </div>
                )}
              </div>

              {/* CORS */}
              <div className="space-y-2">
                <p className="text-sm font-medium">
                  跨域白名单 (cors.allowed_origins)
                </p>
                <p className="text-xs text-muted-foreground">
                  每行一个 Origin，如{" "}
                  <span className="font-mono">http://localhost:3000</span>； 写{" "}
                  <span className="font-mono">*</span> 允许任意
                  Origin（不可与浏览器凭据跨域同用）；
                  留空时根据监听地址自动推导
                </p>
                <Textarea
                  value={apiCorsOrigins}
                  onChange={(e) => setApiCorsOrigins(e.target.value)}
                  placeholder={
                    "http://localhost:3000\nhttps://console.example.com"
                  }
                  className="font-mono text-xs min-h-[80px] resize-y"
                  spellCheck={false}
                />
              </div>

              {/* WebUI 静态文件 */}
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-medium">
                      WebUI 静态文件 (webui)
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      启用后 WebUI 挂载在 <span className="font-mono">/</span>
                      ，管理 API 位于 <span className="font-mono">/api/*</span>
                    </p>
                  </div>
                  <Switch
                    checked={apiWebuiEnabled}
                    onCheckedChange={setApiWebuiEnabled}
                    aria-label="挂载 WebUI 静态文件"
                  />
                </div>
                {apiWebuiEnabled && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field>
                      <FieldLabel>静态文件目录 (root)</FieldLabel>
                      <Input
                        value={apiWebuiRoot}
                        onChange={(e) => setApiWebuiRoot(e.target.value)}
                        placeholder="/etc/oxidns/webui"
                        className="font-mono"
                      />
                    </Field>
                    <Field>
                      <FieldLabel>首页文件名 (index)</FieldLabel>
                      <Input
                        value={apiWebuiIndex}
                        onChange={(e) => setApiWebuiIndex(e.target.value)}
                        placeholder="index.html"
                        className="font-mono"
                      />
                    </Field>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => handleSaveTopLevelConfig(false)}
                  disabled={isConfigSaving || isApplying || !isConnected}
                >
                  保存配置
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleSaveTopLevelConfig(true)}
                  disabled={isConfigSaving || isApplying || !isConnected}
                >
                  <RefreshCw className="h-4 w-4 mr-1.5" />
                  保存并应用
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ScrollText className="h-5 w-5" />
                日志
              </CardTitle>
              <CardDescription>日志输出与轮转配置（log）</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field>
                  <FieldLabel>日志级别</FieldLabel>
                  <p className="text-xs text-muted-foreground mb-2">
                    控制输出的最低日志级别，默认{" "}
                    <span className="font-mono">info</span>
                  </p>
                  <Select value={logLevel} onValueChange={setLogLevel}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {["trace", "debug", "info", "warn", "error", "off"].map(
                        (level) => (
                          <SelectItem key={level} value={level}>
                            {level}
                          </SelectItem>
                        ),
                      )}
                    </SelectContent>
                  </Select>
                </Field>
                <Field>
                  <FieldLabel>日志文件路径</FieldLabel>
                  <p className="text-xs text-muted-foreground mb-2">
                    可选，留空仅输出到标准输出；配置后同时写入文件（纯文本，无颜色码）
                  </p>
                  <Input
                    value={logFile}
                    onChange={(event) => setLogFile(event.target.value)}
                    placeholder="留空输出到控制台"
                    className="font-mono"
                  />
                </Field>
                <Field>
                  <FieldLabel>日志轮转策略</FieldLabel>
                  <p className="text-xs text-muted-foreground mb-2">
                    按时间周期自动创建新日志文件，默认不轮转
                  </p>
                  <Select value={rotationType} onValueChange={setRotationType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="never">never — 不轮转</SelectItem>
                      <SelectItem value="minutely">
                        minutely — 按分钟
                      </SelectItem>
                      <SelectItem value="hourly">hourly — 按小时</SelectItem>
                      <SelectItem value="daily">daily — 按天</SelectItem>
                      <SelectItem value="weekly">weekly — 按周</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                {rotationType !== "never" && (
                  <Field>
                    <FieldLabel>最多保留历史文件数</FieldLabel>
                    <p className="text-xs text-muted-foreground mb-2">
                      <span className="font-mono">0</span>{" "}
                      或留空表示不自动删除旧文件
                    </p>
                    <Input
                      value={maxFiles}
                      onChange={(event) => setMaxFiles(event.target.value)}
                      type="number"
                      min={0}
                      placeholder="0（不限制）"
                      className="font-mono"
                    />
                  </Field>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => handleSaveTopLevelConfig(false)}
                  disabled={isConfigSaving || isApplying || !isConnected}
                >
                  保存配置
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleSaveTopLevelConfig(true)}
                  disabled={isConfigSaving || isApplying || !isConnected}
                >
                  <RefreshCw className="h-4 w-4 mr-1.5" />
                  保存并应用
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
      <div className="mt-1 truncate font-mono text-sm font-semibold">
        {value}
      </div>
    </div>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
