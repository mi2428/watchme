# WatchMe

macOS observability agent that exports OpenTelemetry metrics and traces.

## Commands

- `watchme wifi`: Wi-Fi metrics, event traces, active probes, and passive packet timing.
  - `watchme wifi once`: one-shot Wi-Fi metrics and active trace export.
  - `watchme wifi authorize-only`: request Location authorization for app-bundled Wi-Fi labels.
- `watchme system`: CPU, memory, and disk metrics.
  - `watchme system once`: one-shot CPU, memory, and disk metrics export.

## App bundle wrapper

Build `WatchMe.app` when Wi-Fi SSID/BSSID labels need macOS Location authorization:

```console
$ make app
$ scripts/watchme-app wifi authorize-only
$ scripts/watchme-app wifi once
$ scripts/watchme-app system once
```

`scripts/watchme-app` supports both `wifi` and `system` commands. The app bundle is required for Location-gated Wi-Fi identity labels; system metrics do not require Location authorization.

## OTLP delivery

WatchMe exports through OTLP/HTTP.
When a retryable OTLP request fails because the collector or network is unavailable, WatchMe stores the exact OTLP HTTP payload under `~/.watchme/otlp-spool`.
The next export first replays pending payloads oldest-first and removes each file only after the collector returns a 2xx response.

Set `WATCHME_OTLP_SPOOL_DIR` to override the spool directory.
