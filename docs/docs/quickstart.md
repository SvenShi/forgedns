---
title: 快速开始
sidebar_position: 2
---

本页介绍 ForgeDNS 当前支持的几种安装方式，并给出最短可运行路径。

如果你只是想先跑起来，优先使用以下方式：

- Linux 服务器：优先使用 release 压缩包或 `.deb`
- 容器环境：优先使用 GHCR Docker 镜像
- 需要自行改代码或调试：使用 Cargo 从源码构建
- macOS / Windows：优先使用 release 压缩包

## 1. 从源码构建

适合需要调试、二次开发或暂时不依赖发行包的场景。

前提：

- 已安装稳定版 Rust 工具链
- 可用的 Cargo 构建环境

构建并运行：

```bash
git clone https://github.com/SvenShi/forgedns.git
cd forgedns

cargo build --release
./target/release/forgedns start -c config.yaml
```

调试运行：

```bash
cargo run -- -c config.yaml -l debug
```

配置检查：

```bash
./target/release/forgedns check -c config.yaml
```

## 2. 使用 GitHub Releases 二进制包

ForgeDNS 的 release 工作流会为多个平台生成独立二进制压缩包。压缩包内默认包含：

- `forgedns` 或 `forgedns.exe`
- `config.yaml`
- `LICENSE`

发布页地址：

- [https://github.com/SvenShi/forgedns/releases](https://github.com/SvenShi/forgedns/releases)

### 支持的压缩包目标

非 Windows 平台使用 `.tar.gz`：

- `forgedns-x86_64-unknown-linux-gnu.tar.gz`
- `forgedns-x86_64-unknown-linux-musl.tar.gz`
- `forgedns-aarch64-unknown-linux-gnu.tar.gz`
- `forgedns-aarch64-unknown-linux-musl.tar.gz`
- `forgedns-i686-unknown-linux-musl.tar.gz`
- `forgedns-arm-unknown-linux-musleabihf.tar.gz`
- `forgedns-x86_64-apple-darwin.tar.gz`
- `forgedns-aarch64-apple-darwin.tar.gz`
- `forgedns-x86_64-unknown-freebsd.tar.gz`

Windows 平台使用 `.zip`：

- `forgedns-x86_64-pc-windows-msvc.zip`
- `forgedns-i686-pc-windows-msvc.zip`
- `forgedns-aarch64-pc-windows-msvc.zip`

### Linux / macOS 安装示例

将下面的 `TAG` 替换为实际 release 标签，例如 `v0.1.0`。以 `x86_64-unknown-linux-gnu` 为例：

```bash
curl -L -o forgedns.tar.gz \
  https://github.com/SvenShi/forgedns/releases/download/TAG/forgedns-x86_64-unknown-linux-gnu.tar.gz

mkdir -p forgedns
tar -xzf forgedns.tar.gz -C forgedns
cd forgedns

chmod +x forgedns
./forgedns start -c config.yaml
```

如果你所在环境偏向静态链接部署，可优先选择 `*-linux-musl` 版本。

### Windows 安装示例

下载对应 `zip` 后解压，在 PowerShell 中运行：

```powershell
.\forgedns.exe start -c .\config.yaml
```

## 3. 使用 Debian 包安装

release 工作流当前会额外生成以下 Debian 包：

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

安装：

```bash
sudo dpkg -i forgedns_*_amd64.deb
```

或在 ARM64 Debian / Ubuntu 上：

```bash
sudo dpkg -i forgedns_*_arm64.deb
```

安装后默认文件位置：

- 二进制：`/usr/bin/forgedns`
- 配置：`/etc/forgedns/config.yaml`

项目也包含 systemd 打包配置，因此在 Debian 系发行版上适合直接作为系统服务部署。

验证：

```bash
forgedns check -c /etc/forgedns/config.yaml
sudo systemctl status forgedns
```

如果服务尚未启动，可执行：

```bash
sudo systemctl enable --now forgedns
```

## 4. 使用 Docker 镜像

仓库提供 GHCR 镜像发布流程，镜像仓库地址为：

- `ghcr.io/svenshi/forgedns`

当前 Docker 发布流程构建以下平台：

- `linux/amd64`
- `linux/arm64`
- `linux/arm/v7`

拉取并运行：

```bash
docker pull ghcr.io/svenshi/forgedns:TAG

docker run --rm \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 9088:9088/tcp \
  -v "$(pwd)/config.yaml:/etc/forgedns/config.yaml:ro" \
  ghcr.io/svenshi/forgedns:TAG
```

如果默认分支镜像已发布，也可以使用 `latest` 标签。

镜像默认启动命令等价于：

```bash
forgedns start -c /etc/forgedns/config.yaml
```

镜像内默认暴露：

- `53/udp`
- `53/tcp`
- `9088/tcp`

## 5. 选择建议

- 想最快验证功能：下载对应 release 压缩包
- 想以系统服务长期运行：优先使用 Debian 包
- 想在容器平台部署：使用 GHCR Docker 镜像
- 想参与开发或自行裁剪：从源码构建

## 6. 启动后下一步

启动完成后，建议继续阅读：

1. [配置总览](configuration.md)
2. [插件总览](plugin-reference/overview.md)
3. [常见策略场景](scenarios.md)
