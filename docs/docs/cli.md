---
title: 命令行工具
sidebar_position: 3
---

本页介绍 ForgeDNS 当前所有实际支持的命令行工具。

当前主程序只有一个二进制：`forgedns`。

可用顶层命令如下：

- `start`
- `check`
- `export-dat`
- `service`

## 查看帮助

可先查看顶层帮助：

```bash
forgedns --help
```

查看某个子命令的帮助：

```bash
forgedns start --help
forgedns check --help
forgedns export-dat --help
forgedns service --help
```

## `start`

前台启动 ForgeDNS 服务。

典型用法：

```bash
forgedns start -c config.yaml
forgedns start -c config.yaml -l debug
forgedns start -c /etc/forgedns/config.yaml -d /etc/forgedns
```

参数说明：

- `-c, --config <PATH>`
  - 配置文件路径。
  - 默认值：`config.yaml`
- `-d, --working-dir <PATH>`
  - 启动前切换到指定工作目录。
- `-l, --log-level <LEVEL>`
  - 临时覆盖配置文件中的日志级别。
  - 支持：`off` `trace` `debug` `info` `warn` `error`

适用场景：

- 本地调试
- 前台运行
- 容器内直接启动

## `check`

静态检查配置文件是否有效，但不会真正启动 ForgeDNS。

典型用法：

```bash
forgedns check -c config.yaml
forgedns check -c /etc/forgedns/config.yaml
forgedns check -c config.yaml -d /etc/forgedns
```

参数说明：

- `-c, --config <PATH>`
  - 配置文件路径。
  - 默认值：`config.yaml`
- `-d, --working-dir <PATH>`
  - 校验前切换到指定工作目录。
  - 适合配置里使用相对路径时配合使用。

行为说明：

- 只做静态校验：
  - YAML 解析
  - 配置结构校验
  - 插件类型和依赖关系校验
- 不会初始化插件，不会绑定监听端口，也不会启动运行时。
- 校验成功时返回退出码 `0`，并输出简短成功信息。
- 校验失败时返回非零退出码，并输出具体错误原因。

## `export-dat`

从 `geosite.dat` 或 `geoip.dat` 中导出指定 selector 到文本规则文件。

这些导出的文本文件可直接给 `domain_set.files` 或 `ip_set.files` 使用。

典型用法：

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --selector cn \
  --selector geolocation-\!cn \
  --out-dir ./rules/exported
```

额外生成并集文件：

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --selector cn \
  --selector mastercard@cn \
  --out-dir ./rules/exported \
  --merged-file geosite_union.txt
```

导出 `geoip.dat`：

```bash
forgedns export-dat \
  --file ./rules/geoip.dat \
  --kind geoip \
  --selector cn \
  --out-dir ./rules/exported
```

不传 selector，直接导出整份 dat：

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --out-dir ./rules/exported
```

指定原始格式导出：

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --format original \
  --selector cn \
  --out-dir ./rules/exported
```

参数说明：

- `--file <PATH>`
  - `dat` 文件路径。
- `--kind <KIND>`
  - 指定 `dat` 类型。
  - 可选值：`auto` `geosite` `geoip`
  - 默认值：`auto`
- `--format <FORMAT>`
  - 指定文本导出格式。
  - 可选值：`forgedns` `original`
  - 默认值：`forgedns`
- `--selector <SELECTOR>`
  - 要导出的 selector。
  - 可重复传入多个，按输入顺序分别导出。
  - 不传时表示直接导出整份 dat。
- `--out-dir <DIR>`
  - 输出目录。
  - 不存在时会自动创建。
- `--merged-file <NAME>`
  - 可选。
  - 在输出目录中额外生成一个并集文件。
- `--overwrite`
  - 可选。
  - 允许覆盖已存在的目标文件。

行为说明：

- 默认按 selector 分别生成文件，例如 `cn.txt`、`geolocation-!cn.txt`。
- 不传 selector 时，会直接生成单个整表导出文件；默认文件名分别为 `geosite.txt` 或 `geoip.txt`。
- `geosite` 输出为 ForgeDNS 域名规则格式，例如 `full:`、`domain:`、`keyword:`、`regexp:`。
- `forgedns` 格式会在导出文件头加入注释行，例如 `# selector: cn`；不传 selector 时为 `# selector: all`。
- `geosite` 在 `original` 格式下会保留原始类型语义，输出如 `plain:`、`regex:`、`root_domain:`、`full:`。
- `geosite` 的 `original` 格式会按 code 分组输出；如果域名带 attribute，会追加在域名后面，例如 `@cn`、`@ads=1`。
- `geoip` 输出为 IP / CIDR 纯文本规则。
- `geoip` 的 `forgedns` 格式同样会加入 selector 注释行。
- `geoip` 的 `original` 格式会按 code 分组输出，组头形式为 `[code]`。
- `geosite` selector 支持 `code@attribute`，例如 `mastercard@cn`。
- 任一 selector 没有匹配结果时，命令会直接失败，不会静默跳过。

## `service`

管理系统服务安装与运行状态。

当前支持以下子命令：

- `service install`
- `service start`
- `service stop`
- `service uninstall`

### `service install`

安装系统服务定义，但不会立即启动。

```bash
sudo forgedns service install -d /etc/forgedns -c /etc/forgedns/config.yaml
```

参数说明：

- `-d, --working-dir <PATH>`
  - 服务工作目录。
  - 必须为绝对路径。
- `-c, --config <PATH>`
  - 服务启动时使用的配置文件路径。

### `service start`

启动已安装的系统服务。

```bash
sudo forgedns service start
```

### `service stop`

停止已安装的系统服务。

```bash
sudo forgedns service stop
```

### `service uninstall`

卸载已安装的系统服务。

```bash
sudo forgedns service uninstall
```

## 当前范围

当前 CLI 包含上述命令；本页即为当前实际行为的说明。
