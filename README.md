# WatchMe

macOS observability agent that exports OpenTelemetry metrics and traces.

## Commands

- `watchme wifi`: Wi-Fi metrics, event traces, active probes, and passive packet timing.
- `watchme system`: CPU, memory, and disk metrics.

## OTLP delivery

WatchMe exports through OTLP/HTTP.
When a retryable OTLP request fails because the collector or network is unavailable, WatchMe stores the exact OTLP HTTP payload under `~/.watchme/otlp-spool`.
The next export first replays pending payloads oldest-first and removes each file only after the collector returns a 2xx response.

Set `WATCHME_OTLP_SPOOL_DIR` to override the spool directory.
