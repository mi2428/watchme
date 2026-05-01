# WatchMe

WatchMe Agent exports OpenTelemetry metrics and traces from macOS.

## Commands

- `watchme agent`: all collectors.
- `watchme agent --collector.wifi`: Wi-Fi metrics, event traces, connectivity probes, and passive packet timing.
  - `watchme agent once --collector.wifi`: one-shot Wi-Fi metrics and connectivity trace export.
  - `watchme agent authorize-location`: request Location authorization for app-bundled Wi-Fi labels.
- `watchme agent --collector.system`: host CPU, memory, VM, disk, network, filesystem, and uptime/load metrics.
  - `watchme agent once --collector.system`: one-shot host system metrics export.
- `watchme agent --collector.self`: WatchMe process CPU, memory, thread, and open file descriptor metrics.
  - `watchme agent once --collector.self`: one-shot WatchMe process metrics export.
- `watchme --version`: embedded version, git revision, and build metadata.

## App bundle wrapper

Build `WatchMe.app` when Wi-Fi SSID/BSSID labels need macOS Location authorization:

```console
$ make app
$ scripts/watchme-app agent authorize-location
$ scripts/watchme-app agent
$ scripts/watchme-app agent once --collector.wifi
$ scripts/watchme-app agent once --collector.system
$ scripts/watchme-app agent once --collector.self
```

`scripts/watchme-app` runs `watchme agent` through the app bundle. The app bundle is required for Location-gated Wi-Fi identity labels; system and self metrics do not require Location authorization.

## Build metadata

`make build`, `make test`, and `make app` embed `watchme --version` metadata from git and the local Swift target.
Set `WATCHME_VERSION`, `WATCHME_GIT_DESCRIBE`, `WATCHME_GIT_COMMIT`, `WATCHME_GIT_COMMIT_DATE`, `WATCHME_BUILD_DATE`, `WATCHME_BUILD_HOST`, `WATCHME_BUILD_TARGET`, or `WATCHME_BUILD_PROFILE` to override the embedded values.

## OTLP delivery

WatchMe exports through OTLP/HTTP.
When a retryable OTLP request fails because the collector or network is unavailable, WatchMe stores the exact OTLP HTTP payload under `~/.watchme/otlp-spool`.
The next export first replays pending payloads oldest-first and removes each file only after the collector returns a 2xx response.

Set `WATCHME_OTLP_SPOOL_DIR` to override the spool directory.
