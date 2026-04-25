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

### How To Choose The Right Release Asset

If you are not sure which asset to download, use this mapping:

| System / Environment | Recommended release asset | Notes |
| --- | --- | --- |
| Linux x86_64 | `forgedns-x86_64-unknown-linux-musl.tar.gz` | Safer default for broad compatibility |
| Linux ARM64 | `forgedns-aarch64-unknown-linux-musl.tar.gz` | Safer default for broad compatibility |
| Debian / Ubuntu x86_64 service install | `*_amd64.deb` | Best fit for systemd-based deployment |
| Debian / Ubuntu ARM64 service install | `*_arm64.deb` | Best fit for systemd-based deployment |
| Alpine Linux x86_64 | `forgedns-x86_64-unknown-linux-musl.tar.gz` | Prefer musl on Alpine |
| Alpine Linux ARM64 | `forgedns-aarch64-unknown-linux-musl.tar.gz` | Static-friendly build |
| Confirmed glibc Linux requiring a dynamic build | `forgedns-x86_64-unknown-linux-gnu.tar.gz` / `forgedns-aarch64-unknown-linux-gnu.tar.gz` | Only choose this when the target environment is clearly compatible |
| 32-bit ARM Linux | `forgedns-arm-unknown-linux-musleabihf.tar.gz` | Fits some Raspberry Pi and older ARM boards |
| macOS Intel | `forgedns-x86_64-apple-darwin.tar.gz` | Intel Macs |
| macOS Apple Silicon | `forgedns-aarch64-apple-darwin.tar.gz` | M1 / M2 / M3 / M4 Macs |
| Windows x64 | `forgedns-x86_64-pc-windows-msvc.zip` | Most PCs |
| Windows 32-bit | `forgedns-i686-pc-windows-msvc.zip` | Only for 32-bit Windows |
| Windows ARM64 | `forgedns-aarch64-pc-windows-msvc.zip` | ARM-based Windows devices |
| FreeBSD x86_64 | `forgedns-x86_64-unknown-freebsd.tar.gz` | FreeBSD hosts |

If you still need to verify your platform, check it first:

```bash
uname -s
uname -m
```

Common output mapping:

- `Linux` + `x86_64`: default to `x86_64-unknown-linux-musl`; use `x86_64-unknown-linux-gnu` only when you explicitly need a glibc dynamic build
- `Linux` + `aarch64`: default to `aarch64-unknown-linux-musl`; use `aarch64-unknown-linux-gnu` only when you explicitly need a glibc dynamic build
- `Linux` + `armv7l`: use `arm-unknown-linux-musleabihf`
- `Darwin` + `x86_64`: use `x86_64-apple-darwin`
- `Darwin` + `arm64`: use `aarch64-apple-darwin`

On Windows PowerShell, run:

```powershell
[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
```

Map `X64`, `Arm64`, and `X86` to the `x86_64`, `aarch64`, and `i686` Windows assets respectively.

### Linux / macOS Example

Replace `TAG` below with the actual release tag, for example `v0.1.0`. The Linux example below uses `x86_64-unknown-linux-musl` as the default choice:

```bash
curl -L -o forgedns.tar.gz \
  https://github.com/SvenShi/forgedns/releases/download/TAG/forgedns-x86_64-unknown-linux-musl.tar.gz

mkdir -p forgedns
tar -xzf forgedns.tar.gz -C forgedns
cd forgedns

chmod +x forgedns
./forgedns start -c config.yaml
```

If you cannot guarantee the target machine's glibc compatibility, or you are running Alpine Linux, prefer a `*-linux-musl` archive instead of defaulting to `gnu`.

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

Verify service status:

```bash
sudo systemctl status forgedns
```

If the service is not running yet:

```bash
sudo systemctl enable --now forgedns
```

## 4. Run With Docker

The repository publishes a GHCR image at:

#### GitHub
- `ghcr.io/svenshi/forgedns`
#### Docker Hub
- `svenshi/forgedns`

The Docker workflow builds:

- `linux/amd64`
- `linux/arm64`

Pull and run:

```bash
docker pull svenshi/forgedns:latest

docker run --rm \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 9088:9088/tcp \
  -v "$(pwd)/config.yaml:/etc/forgedns/config.yaml:ro" \
  svenshi/forgedns:latest
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

### Docker Compose Example

If you prefer Compose for port mappings and config management, use this `docker-compose.yml`:

```yaml
services:
  forgedns:
    image: svenshi/forgedns:latest
    container_name: forgedns
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "9088:9088/tcp"
    volumes:
      - ./config.yaml:/etc/forgedns/config.yaml:ro
```

Start it with:

```bash
docker compose up -d
```

Follow logs with:

```bash
docker compose logs -f forgedns
```

## 5. Which One Should You Use?

- Fastest evaluation path: download a release archive
- Long-running Linux service: prefer the Debian package
- Container platforms: use the GHCR Docker or Docker Hub image
- Development or custom builds: compile from source

## 6. Next Reading

After the first successful start, continue with:

1. [Configuration Overview](configuration.md)
2. [Plugin Overview](plugin-reference/overview.md)
3. [Common Scenarios](scenarios.md)
