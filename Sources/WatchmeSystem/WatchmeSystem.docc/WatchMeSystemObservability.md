# WatchMe system observability

@Metadata {
    @PageKind(article)
}

This document describes the current `watchme system` implementation.
It is meant to be checked against the source when instrumentation changes.

## Scope

`watchme system` turns macOS host CPU, memory, and disk counters into OpenTelemetry metrics exported through OTLP/HTTP.

The system module emits primary observations rather than quality scores or local interpretation.
It does not calculate CPU utilization percentages, memory pressure levels, disk saturation, energy impact, or health scores.
Those views can be built downstream from the exported counters and gauges.

## Runtime entry points

- **`watchme system`:** Long-running agent that exports CPU, memory, and disk metrics.
- **`watchme system once`:** One-shot metrics export.

### CLI options

- **`--collector.url`:** OTLP/HTTP collector base endpoint. WatchMe derives `/v1/metrics` and `/v1/traces` from this URL.
- **`--metrics.interval`:** System metric collection interval in seconds.
- **`--log.level`:** Structured log minimum level.

## OTLP delivery and local spool

`watchme system` uses the same OTLP/HTTP delivery path as `watchme wifi`.
When a retryable export fails because the collector or network is unavailable, WatchMe writes the exact OTLP HTTP payload to a local spool.
The default spool directory is `~/.watchme/otlp-spool`; set `WATCHME_OTLP_SPOOL_DIR` to override it.

Delivery behavior:

- Before sending a current OTLP request, WatchMe replays pending spool files oldest-first.
- A spooled payload is removed only after the collector returns a 2xx HTTP response.
- Retryable failures, such as connection failures, timeouts, HTTP 408, HTTP 429, or HTTP 5xx, leave the payload on disk.
- Non-retryable HTTP status responses, such as most HTTP 4xx responses, drop that payload so a bad request does not permanently block newer metrics.
- Recovery is attempted on the next metrics interval in long-running mode, or by a later `watchme system once`, `watchme wifi once`, or long-running agent execution.

## Collection points

| Area | Source file | API or mechanism | What it observes |
| --- | --- | --- | --- |
| CPU time | `Sources/WatchmeSystem/SystemMetrics.swift` | `host_processor_info` with `PROCESSOR_CPU_LOAD_INFO` | Aggregate user, system, idle, and nice CPU ticks converted to seconds. |
| Memory | `Sources/WatchmeSystem/SystemMetrics.swift` | `host_statistics64` with `HOST_VM_INFO64` | Free, active, inactive, wired, and compressed VM page counts converted to bytes. |
| Disk I/O | `Sources/WatchmeSystem/SystemMetrics.swift` | IOKit whole-media block storage `Statistics` property | Per-disk bytes read, bytes written, read operations, and write operations. |

## Metrics

Metrics are encoded as OTLP/HTTP JSON and exported to `<--collector.url>/v1/metrics`.
`MetricSample` gauges become OTel gauge datapoints.
`MetricSample` counters are emitted as cumulative monotonic OTel sum datapoints.
WatchMe keeps a per-series local total by adding source deltas; if a source counter decreases WatchMe treats it as a local source reset.

Metrics are exported:

- once immediately in `watchme system once`;
- at agent startup;
- every `--metrics.interval` seconds in agent mode.

| Metric | Labels | Source | Meaning |
| --- | --- | --- | --- |
| `watchme_system_cpu_time_seconds_total` | `mode` | `host_processor_info` | Aggregate CPU time in seconds for `user`, `system`, `idle`, and `nice`. |
| `watchme_system_memory_bytes` | `state` | `host_statistics64` | Memory bytes in `free`, `active`, `inactive`, `wired`, and `compressed` VM page states. |
| `watchme_system_disk_read_bytes_total` | `disk` | IOKit block storage statistics | Bytes read from the disk since the source counter started. |
| `watchme_system_disk_write_bytes_total` | `disk` | IOKit block storage statistics | Bytes written to the disk since the source counter started. |
| `watchme_system_disk_read_ops_total` | `disk` | IOKit block storage statistics | Disk read operations since the source counter started. |
| `watchme_system_disk_write_ops_total` | `disk` | IOKit block storage statistics | Disk write operations since the source counter started. |

## Operational checks

```console
$ watchme system once
$ watchme system --metrics.interval 5
```
