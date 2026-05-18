---
title: CLI Tools
sidebar_position: 3
---

This page explains the OxiDNS CLI by day-to-day task. For normal deployment, the most common flow is to run `check` first and then `start`.

OxiDNS ships a single executable: `oxidns`.

Available top-level commands:

- `start`
- `check`
- `export-dat`
- `service`
- `upgrade`

## Common Tasks

| Goal | Command |
| --- | --- |
| Validate a config | `oxidns check -c config.yaml` |
| Start in the foreground | `oxidns start -c config.yaml` |
| Temporarily enable debug logging | `oxidns start -c config.yaml -l debug` |
| Print the plugin dependency graph | `oxidns check -c config.yaml --graph` |
| Install as a system service | `sudo oxidns service install -d /etc/oxidns -c /etc/oxidns/config.yaml` |
| Check for a new release | `oxidns upgrade check` |
| Export rules from a dat file | `oxidns export-dat --file ./rules/geosite.dat --kind geosite --selector cn --out-dir ./rules/exported` |

## Help

Show top-level help:

```bash
oxidns --help
```

Show help for a specific subcommand:

```bash
oxidns start --help
oxidns check --help
oxidns export-dat --help
oxidns service --help
oxidns upgrade --help
```

## `start`

Starts OxiDNS in the foreground.

Typical usage:

```bash
oxidns start -c config.yaml
oxidns start -c config.yaml -l debug
oxidns start -c /etc/oxidns/config.yaml -d /etc/oxidns
```

Arguments:

- `-c, --config <PATH>`
  - Path to the configuration file.
  - Default: `config.yaml`
- `-d, --working-dir <PATH>`
  - Change to the specified working directory before startup.
- `-l, --log-level <LEVEL>`
  - Temporarily override the configured log level.
  - Supported values: `off` `trace` `debug` `info` `warn` `error`

Common use cases:

- Local debugging
- Foreground execution
- Direct container startup

## `check`

Statically validates a configuration file without starting OxiDNS.

Typical usage:

```bash
oxidns check -c config.yaml
oxidns check -c /etc/oxidns/config.yaml
oxidns check -c config.yaml -d /etc/oxidns
oxidns check -c config.yaml --graph
```

Arguments:

- `-c, --config <PATH>`
  - Path to the configuration file.
  - Default: `config.yaml`
- `-d, --working-dir <PATH>`
  - Change to the specified working directory before validation.
  - Useful when the config relies on relative paths.
- `--graph`
  - Print the plugin dependency graph after validation succeeds.

Behavior:

- Performs static validation only:
  - YAML parsing
  - schema-level config validation
  - plugin type and dependency validation
- Does not initialize plugins, bind listeners, or start the runtime.
- On success, exits with code `0` and prints a short success line.
- With `--graph`, it also prints a plain-text dependency graph in plugin initialization order.
- On failure, exits non-zero and prints the validation error.

## `export-dat`

Exports selected rules from `geosite.dat` or `geoip.dat` into text rule files.

These exported files can be referenced directly from `domain_set.files` or `ip_set.files`.

Typical usage:

```bash
oxidns export-dat \
  --file ./rules/geosite.dat \
  --selector cn \
  --selector geolocation-\!cn \
  --out-dir ./rules/exported
```

Generate an additional merged union file:

```bash
oxidns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --selector cn \
  --selector mastercard@cn \
  --out-dir ./rules/exported \
  --merged-file geosite_union.txt
```

Export from `geoip.dat`:

```bash
oxidns export-dat \
  --file ./rules/geoip.dat \
  --kind geoip \
  --selector cn \
  --out-dir ./rules/exported
```

Export the entire dat file without selectors:

```bash
oxidns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --out-dir ./rules/exported
```

Export using the original text format:

```bash
oxidns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --format original \
  --selector cn \
  --out-dir ./rules/exported
```

Arguments:

- `--file <PATH>`
  - Path to the source `dat` file.
- `--kind <KIND>`
  - Explicit `dat` kind.
  - Values: `auto` `geosite` `geoip`
  - Default: `auto`
- `--format <FORMAT>`
  - Output text format.
  - Values: `oxidns` `original`
  - Default: `oxidns`
- `--selector <SELECTOR>`
  - Selector to export.
  - Repeat the flag to export multiple selectors.
  - Omit it to export the entire dat file.
- `--out-dir <DIR>`
  - Output directory.
  - It is created automatically when missing.
- `--merged-file <NAME>`
  - Optional.
  - Writes one extra merged union file inside the output directory.
- `--overwrite`
  - Optional.
  - Allows replacing existing output files.

Behavior:

- By default, OxiDNS writes one file per selector, for example `cn.txt` or `geolocation-!cn.txt`.
- When no selector is provided, OxiDNS writes one full-export file named `geosite.txt` or `geoip.txt` by default.
- `geosite` exports OxiDNS domain rule expressions such as `full:`, `domain:`, `keyword:`, and `regexp:`.
- In `oxidns` format, exported files add a header comment such as `# selector: cn`; when no selector is provided, the header becomes `# selector: all`.
- In `original` format, `geosite` preserves the source type names and writes values such as `plain:`, `regex:`, `root_domain:`, and `full:`.
- In `original` format, `geosite` output is grouped by code, and domain attributes are appended after the domain text, for example `@cn` or `@ads=1`.
- `geoip` exports plain IP / CIDR lines.
- In `oxidns` format, `geoip` exports also include selector header comments.
- In `original` format, `geoip` output is grouped by code with section headers like `[code]`.
- `geosite` selectors support `code@attribute`, for example `mastercard@cn`.
- If any selector matches no rules, the command fails instead of silently skipping it.

## `service`

Manages system service installation and runtime state.

Supported subcommands:

- `service install`
- `service start`
- `service stop`
- `service uninstall`

### `service install`

Installs the service definition without starting it immediately.

```bash
sudo oxidns service install -d /etc/oxidns -c /etc/oxidns/config.yaml
```

Arguments:

- `-d, --working-dir <PATH>`
  - Service working directory.
  - Must be an absolute path.
- `-c, --config <PATH>`
  - Configuration path used by the installed service.

### `service start`

Starts the installed system service.

```bash
sudo oxidns service start
```

### `service stop`

Stops the installed system service.

```bash
sudo oxidns service stop
```

### `service uninstall`

Removes the installed system service.

```bash
sudo oxidns service uninstall
```

## `upgrade`

Checks, downloads, or applies OxiDNS upgrades from GitHub Releases.

Supported subcommands:

- `upgrade check`
- `upgrade download`
- `upgrade apply`

Common usage:

```bash
oxidns upgrade
oxidns upgrade --force
oxidns upgrade check
oxidns upgrade download --target latest
sudo oxidns upgrade apply --restart service
```

Common arguments:

- `--target <TAG|latest>`
  - Release tag or `latest`.
  - Default: `latest`
- `--repository <OWNER/REPO>`
  - GitHub repository.
  - Default: `svenshi/oxidns`
- `--asset <NAME|auto>`
  - Release asset name. `auto` selects the current platform archive.
  - Default: `auto`
- `--cache-dir <DIR>`
  - Directory for cached upgrade files.
  - Default: `./upgrade/cache`
- `--backup-dir <DIR>`
  - Directory for binary backups before `apply`.
  - Default: `./upgrade/backups`
- `--webui-dir <DIR>`
  - Directory where the WebUI static assets are installed during `apply`; keep it aligned with `api.http.webui.root`.
  - Default: `./webui`
- `--skip-webui`
  - For `apply`, skip the WebUI directory upgrade and replace only the binary.
- `--restart <none|service>`
  - Restart strategy after a successful `apply`.
  - Default: `none`
- `--allow-prerelease`
  - Allows prerelease releases.
- `--force`
  - For `apply`, continue downloading, verifying, and replacing even when the selected release is not newer than the current version.
- `--timeout <DURATION>`
  - HTTP timeout such as `30s` or `2m`.
- `--socks5 <ADDR>`
  - Optional SOCKS5 proxy.
- `--insecure-skip-verify`
  - Disables TLS certificate verification.

Behavior:

- `check` only queries the release and compares versions.
- `download` downloads the archive and verifies SHA256 with the GitHub release asset `digest` field.
- Omitting the subcommand defaults to `apply`.
- `apply` updates only when a newer version is available by default. `--force` forces the update.
- On Unix, `apply` unpacks the `.tar.gz`, backs up the current binary, and replaces it. Windows currently supports only `check` and `download`.
- By default, after replacing the binary `apply` backs up and installs the archive's `webui/` directory into `--webui-dir`; `--skip-webui` skips it, and an archive without `webui/` is skipped without affecting the binary upgrade.
- After a successful `apply`, the CLI asks whether to clean the cache and backup directories. The default answer is `Y`.

## Page Scope

This page covers the commands above. To confirm every argument supported by the local binary, run `oxidns <subcommand> --help`.
