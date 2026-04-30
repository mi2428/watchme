# WatchMe

WatchMe Agent exports OpenTelemetry metrics and traces from macOS.

## Commands

- `watchme agent`: all collectors.
- `watchme agent --collector.wifi`: Wi-Fi metrics, event traces, active probes, and passive packet timing.
  - `watchme agent once --collector.wifi`: one-shot Wi-Fi metrics and active trace export.
  - `watchme agent authorize-location`: request Location authorization for app-bundled Wi-Fi labels.
- `watchme agent --collector.system`: CPU, memory, and disk metrics.
  - `watchme agent once --collector.system`: one-shot CPU, memory, and disk metrics export.

## App bundle wrapper

Build `WatchMe.app` when Wi-Fi SSID/BSSID labels need macOS Location authorization:

```console
$ make app
$ scripts/watchme-app agent authorize-location
$ scripts/watchme-app agent
$ scripts/watchme-app agent once --collector.wifi
$ scripts/watchme-app agent once --collector.system
```

`scripts/watchme-app` runs `watchme agent` through the app bundle. The app bundle is required for Location-gated Wi-Fi identity labels; system metrics do not require Location authorization.

## OTLP delivery

WatchMe exports through OTLP/HTTP.
When a retryable OTLP request fails because the collector or network is unavailable, WatchMe stores the exact OTLP HTTP payload under `~/.watchme/otlp-spool`.
The next export first replays pending payloads oldest-first and removes each file only after the collector returns a 2xx response.

Set `WATCHME_OTLP_SPOOL_DIR` to override the spool directory.
