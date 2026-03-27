---
title: Quick Start
sidebar_position: 2
---

This page covers the currently supported installation paths for ForgeDNS and the shortest way to get a runnable instance.

If you only want to get it running quickly, prefer:

- Linux servers: release archives or `.deb` packages
- Containerized environments: the GHCR Docker image
- Local development or debugging: build from source with Cargo
- macOS / Windows: release archives

## 1. Build From Source

This is the best fit when you want to debug, modify the code, or avoid waiting for packaged builds.

Requirements:

- A stable Rust toolchain
- A working Cargo build environment

Build and run:

```bash
git clone https://github.com/SvenShi/forgedns.git
cd forgedns

cargo build --release
./target/release/forgedns start -c config.yaml
```

Run with debug logging:

```bash
cargo run -- -c config.yaml -l debug
```

Validate configuration:

```bash
./target/release/forgedns check -c config.yaml
```

## 2. Install From GitHub Release Archives

The release workflow generates standalone binaries for multiple platforms. Each archive includes:

- `forgedns` or `forgedns.exe`
- `config.yaml`
- `LICENSE`

Release page:

- [https://github.com/SvenShi/forgedns/releases](https://github.com/SvenShi/forgedns/releases)

### Supported Archive Targets

Non-Windows targets use `.tar.gz`:

- `forgedns-x86_64-unknown-linux-gnu.tar.gz`
- `forgedns-x86_64-unknown-linux-musl.tar.gz`
- `forgedns-aarch64-unknown-linux-gnu.tar.gz`
- `forgedns-aarch64-unknown-linux-musl.tar.gz`
- `forgedns-i686-unknown-linux-musl.tar.gz`
- `forgedns-arm-unknown-linux-musleabihf.tar.gz`
- `forgedns-x86_64-apple-darwin.tar.gz`
- `forgedns-aarch64-apple-darwin.tar.gz`
- `forgedns-x86_64-unknown-freebsd.tar.gz`

Windows targets use `.zip`:

- `forgedns-x86_64-pc-windows-msvc.zip`
- `forgedns-i686-pc-windows-msvc.zip`
- `forgedns-aarch64-pc-windows-msvc.zip`

### Linux / macOS Example

Replace `TAG` below with the actual release tag, for example `v0.1.0`. Using `x86_64-unknown-linux-gnu` as an example:

```bash
curl -L -o forgedns.tar.gz \
  https://github.com/SvenShi/forgedns/releases/download/TAG/forgedns-x86_64-unknown-linux-gnu.tar.gz

mkdir -p forgedns
tar -xzf forgedns.tar.gz -C forgedns
cd forgedns

chmod +x forgedns
./forgedns start -c config.yaml
```

If you prefer a more self-contained static build on Linux, use a `*-linux-musl` archive.

### Windows Example

Download the matching `.zip`, extract it, then run:

```powershell
.\forgedns.exe start -c .\config.yaml
```

## 3. Install From Debian Packages

The release workflow currently builds `.deb` packages for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

Install on Debian / Ubuntu:

```bash
sudo dpkg -i forgedns_*_amd64.deb
```

Or on ARM64 Debian / Ubuntu:

```bash
sudo dpkg -i forgedns_*_arm64.deb
```

Default installed paths:

- Binary: `/usr/bin/forgedns`
- Config: `/etc/forgedns/config.yaml`

The project also ships systemd packaging metadata, so Debian-family systems are a good fit for service-based deployment.

Verify:

```bash
forgedns check -c /etc/forgedns/config.yaml
sudo systemctl status forgedns
```

If the service is not running yet:

```bash
sudo systemctl enable --now forgedns
```

## 4. Run With Docker

The repository publishes a GHCR image at:

- `ghcr.io/svenshi/forgedns`

The Docker workflow builds:

- `linux/amd64`
- `linux/arm64`
- `linux/arm/v7`

Pull and run:

```bash
docker pull ghcr.io/svenshi/forgedns:TAG

docker run --rm \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 9088:9088/tcp \
  -v "$(pwd)/config.yaml:/etc/forgedns/config.yaml:ro" \
  ghcr.io/svenshi/forgedns:TAG
```

If the default-branch image is published, you can also use the `latest` tag.

The image entrypoint effectively runs:

```bash
forgedns start -c /etc/forgedns/config.yaml
```

The container exposes:

- `53/udp`
- `53/tcp`
- `9088/tcp`

## 5. Which One Should You Use?

- Fastest evaluation path: download a release archive
- Long-running Linux service: prefer the Debian package
- Container platforms: use the GHCR Docker image
- Development or custom builds: compile from source

## 6. Next Reading

After the first successful start, continue with:

1. [Configuration Overview](configuration.md)
2. [Plugin Overview](plugin-reference/overview.md)
3. [Common Scenarios](scenarios.md)
