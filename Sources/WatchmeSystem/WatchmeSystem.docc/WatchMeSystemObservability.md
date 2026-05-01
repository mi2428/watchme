# System collector observability

@Metadata {
    @PageKind(article)
}

This document describes the current system collector implementation used by `watchme agent --collector.system`.
It is meant to be checked against the source when instrumentation changes.

## Scope

With `--collector.system`, WatchMe Agent turns macOS host CPU, memory, VM activity, disk, network interface, filesystem, and host basics into OpenTelemetry metrics exported through OTLP/HTTP.

The system module emits primary observations rather than quality scores or local interpretation.
It does not calculate CPU utilization percentages, memory pressure levels, disk saturation, energy impact, or health scores.
Those views can be built downstream from the exported counters and gauges.

## Runtime entry points

- **`./scripts/watchme agent --collector.system`:** Long-running WatchMe Agent execution that exports host system metrics.
- **`./scripts/watchme agent once --collector.system`:** One-shot metrics export.
- **`./scripts/watchme agent ...`:** Runs the same `watchme agent` command through the app-bundle wrapper for parity with app-bundled workflows. Location authorization is not required for system metrics.

### CLI options

- **`--otlp.url`:** OTLP/HTTP collector base endpoint. `watchme agent --collector.system` exports metrics to `/v1/metrics` under this URL. Default: `http://127.0.0.1:4318`.
- **`--system.metrics.interval`:** System metric collection interval in seconds. Default: `5`.
- **`--log.level`:** Structured log minimum level. Default: `debug`.

## OTLP delivery and local spool

The system collector uses the same OTLP/HTTP delivery path as the Wi-Fi collector used by `watchme agent --collector.wifi`.
When a retryable export fails because the collector or network is unavailable, WatchMe writes the exact OTLP HTTP payload to a local spool.
The default spool directory is `~/.watchme/otlp-spool`; set `WATCHME_OTLP_SPOOL_DIR` to override it.

Delivery behavior:

- Before sending a current OTLP request, WatchMe replays pending spool files oldest-first.
- A spooled payload is removed only after the collector returns a 2xx HTTP response.
- Retryable failures, such as connection failures, timeouts, HTTP 408, HTTP 429, or HTTP 5xx, leave the payload on disk.
- Non-retryable HTTP status responses, such as most HTTP 4xx responses, drop that payload so a bad request does not permanently block newer metrics.
- The local spool is bounded to 1000 pending files, 100 MiB, and seven days by default; one export replays at most 100 pending files.
- Recovery is attempted on the next metrics interval in long-running WatchMe Agent mode, or by a later `watchme agent once --collector.system`, `watchme agent once --collector.wifi`, or long-running WatchMe Agent execution.

## Collection points

| Area | Source file | API or mechanism | What it observes |
| --- | --- | --- | --- |
| CPU time | `Sources/WatchmeSystem/SystemMetrics.swift` | `host_processor_info` with `PROCESSOR_CPU_LOAD_INFO` | Aggregate user, system, idle, and nice CPU ticks converted to seconds. |
| Memory | `Sources/WatchmeSystem/SystemMetrics.swift` | `host_statistics64` with `HOST_VM_INFO64` | Free, active, inactive, wired, and compressed VM page counts converted to bytes. |
| VM activity | `Sources/WatchmeSystem/SystemMetrics.swift` | `host_statistics64` with `HOST_VM_INFO64` | Page-in/out, swap, compression, fault, purge, lookup, and related VM counters. |
| Disk I/O | `Sources/WatchmeSystem/SystemMetrics.swift` | IOKit whole-media block storage `Statistics` property | Per-disk bytes read, bytes written, read operations, and write operations. |
| Network I/O | `Sources/WatchmeSystem/SystemMetrics.swift` | `sysctl` route interface list with `NET_RT_IFLIST2` | Per-interface 64-bit byte, packet, error, and receive-drop counters. |
| Filesystem capacity | `Sources/WatchmeSystem/SystemMetrics.swift` | `getfsstat` | Local filesystem size, free, and available bytes. |
| Host basics | `Sources/WatchmeSystem/SystemMetrics.swift` | `ProcessInfo`, `getloadavg`, and `sysctlbyname` | System uptime, load averages, and CPU counts. |

## Metrics

Metrics are encoded as OTLP/HTTP JSON and exported to `<--otlp.url>/v1/metrics`.
`MetricSample` gauges become OTel gauge datapoints.
`MetricSample` counters are emitted as cumulative monotonic OTel sum datapoints.
WatchMe keeps a per-series local total by adding source deltas; if a source counter decreases WatchMe treats it as a local source reset.

Metrics are exported:

- once immediately in `watchme agent once --collector.system`;
- at WatchMe Agent startup;
- every `--system.metrics.interval` seconds in long-running WatchMe Agent mode.

| Metric | Labels | Source | Meaning |
| --- | --- | --- | --- |
| `watchme_system_cpu_time_seconds_total` | `mode` | `host_processor_info` | Aggregate CPU time in seconds for `user`, `system`, `idle`, and `nice`. |
| `watchme_system_memory_bytes` | `state` | `host_statistics64` | Memory bytes in `free`, `active`, `inactive`, `wired`, and `compressed` VM page states. |
| `watchme_system_vm_activity_total` | `event` | `host_statistics64` | VM activity counters such as `pagein`, `pageout`, `swapin`, `swapout`, `compression`, `decompression`, `fault`, `copy_on_write_fault`, and `purge`. |
| `watchme_system_disk_read_bytes_total` | `disk` | IOKit block storage statistics | Bytes read from the disk since the source counter started. |
| `watchme_system_disk_write_bytes_total` | `disk` | IOKit block storage statistics | Bytes written to the disk since the source counter started. |
| `watchme_system_disk_read_ops_total` | `disk` | IOKit block storage statistics | Disk read operations since the source counter started. |
| `watchme_system_disk_write_ops_total` | `disk` | IOKit block storage statistics | Disk write operations since the source counter started. |
| `watchme_system_network_bytes_total` | `interface`, `direction` | `NET_RT_IFLIST2` interface statistics | Bytes received or transmitted by interface. |
| `watchme_system_network_packets_total` | `interface`, `direction` | `NET_RT_IFLIST2` interface statistics | Packets received or transmitted by interface. |
| `watchme_system_network_errors_total` | `interface`, `direction` | `NET_RT_IFLIST2` interface statistics | Receive or transmit errors by interface. |
| `watchme_system_network_drops_total` | `interface`, `direction` | `NET_RT_IFLIST2` interface statistics | Receive drops by interface. macOS does not expose a matching transmit-drop field through this source. |
| `watchme_system_filesystem_bytes` | `mount`, `fstype`, `state` | `getfsstat` | Local filesystem `size`, `free`, and `available` bytes. Network, synthetic, and selected system support mounts are omitted. |
| `watchme_system_uptime_seconds` | none | `ProcessInfo.systemUptime` | System uptime in seconds. |
| `watchme_system_load_average` | `window` | `getloadavg` | Load average for `1m`, `5m`, and `15m` windows. |
| `watchme_system_cpu_count` | `kind` | `ProcessInfo` and `sysctlbyname` | Logical and physical CPU counts. |

## Operational checks

```console
$ ./scripts/watchme agent once --collector.system
$ ./scripts/watchme agent --collector.system --system.metrics.interval 5
$ make app
$ ./scripts/watchme agent once --collector.system
```
