---
title: CLI Tools
sidebar_position: 3
---

This page documents every CLI command currently supported by ForgeDNS.

ForgeDNS currently ships a single executable: `forgedns`.

Available top-level commands:

- `start`
- `check`
- `export-dat`
- `service`

## Help

Show top-level help:

```bash
forgedns --help
```

Show help for a specific subcommand:

```bash
forgedns start --help
forgedns check --help
forgedns export-dat --help
forgedns service --help
```

## `start`

Starts ForgeDNS in the foreground.

Typical usage:

```bash
forgedns start -c config.yaml
forgedns start -c config.yaml -l debug
forgedns start -c /etc/forgedns/config.yaml -d /etc/forgedns
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

Statically validates a configuration file without starting ForgeDNS.

Typical usage:

```bash
forgedns check -c config.yaml
forgedns check -c /etc/forgedns/config.yaml
forgedns check -c config.yaml -d /etc/forgedns
```

Arguments:

- `-c, --config <PATH>`
  - Path to the configuration file.
  - Default: `config.yaml`
- `-d, --working-dir <PATH>`
  - Change to the specified working directory before validation.
  - Useful when the config relies on relative paths.

Behavior:

- Performs static validation only:
  - YAML parsing
  - schema-level config validation
  - plugin type and dependency validation
- Does not initialize plugins, bind listeners, or start the runtime.
- On success, exits with code `0` and prints a short success line.
- On failure, exits non-zero and prints the validation error.

## `export-dat`

Exports selected rules from `geosite.dat` or `geoip.dat` into text rule files.

These exported files can be referenced directly from `domain_set.files` or `ip_set.files`.

Typical usage:

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --selector cn \
  --selector geolocation-\!cn \
  --out-dir ./rules/exported
```

Generate an additional merged union file:

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --selector cn \
  --selector mastercard@cn \
  --out-dir ./rules/exported \
  --merged-file geosite_union.txt
```

Export from `geoip.dat`:

```bash
forgedns export-dat \
  --file ./rules/geoip.dat \
  --kind geoip \
  --selector cn \
  --out-dir ./rules/exported
```

Export the entire dat file without selectors:

```bash
forgedns export-dat \
  --file ./rules/geosite.dat \
  --kind geosite \
  --out-dir ./rules/exported
```

Export using the original text format:

```bash
forgedns export-dat \
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
  - Values: `forgedns` `original`
  - Default: `forgedns`
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

- By default, ForgeDNS writes one file per selector, for example `cn.txt` or `geolocation-!cn.txt`.
- When no selector is provided, ForgeDNS writes one full-export file named `geosite.txt` or `geoip.txt` by default.
- `geosite` exports ForgeDNS domain rule expressions such as `full:`, `domain:`, `keyword:`, and `regexp:`.
- In `forgedns` format, exported files add a header comment such as `# selector: cn`; when no selector is provided, the header becomes `# selector: all`.
- In `original` format, `geosite` preserves the source type names and writes values such as `plain:`, `regex:`, `root_domain:`, and `full:`.
- In `original` format, `geosite` output is grouped by code, and domain attributes are appended after the domain text, for example `@cn` or `@ads=1`.
- `geoip` exports plain IP / CIDR lines.
- In `forgedns` format, `geoip` exports also include selector header comments.
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
sudo forgedns service install -d /etc/forgedns -c /etc/forgedns/config.yaml
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
sudo forgedns service start
```

### `service stop`

Stops the installed system service.

```bash
sudo forgedns service stop
```

### `service uninstall`

Removes the installed system service.

```bash
sudo forgedns service uninstall
```

## Current Scope

The CLI currently consists of the commands listed on this page, and this page is the source of truth for their behavior.
