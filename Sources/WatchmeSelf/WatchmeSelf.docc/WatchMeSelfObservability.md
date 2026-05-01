# Self collector observability

@Metadata {
    @PageKind(article)
}

This document describes the self collector implementation used by `watchme agent --collector.self`.
The self collector observes the WatchMe process itself, separate from host system metrics.

## Scope

With `--collector.self`, WatchMe Agent exports resource usage for the running WatchMe process through OTLP/HTTP.
This keeps agent overhead visible without mixing process-specific labels into the host-level `system` collector.

The self collector emits primary observations only.
It does not calculate health scores or overhead percentages; those can be derived downstream.

## Runtime entry points

- **`watchme agent --collector.self`:** Long-running WatchMe Agent execution that exports WatchMe process metrics.
- **`watchme agent once --collector.self`:** One-shot self metric export.

### CLI options

- **`--otlp.url`:** OTLP/HTTP collector base endpoint. `watchme agent --collector.self` exports metrics to `/v1/metrics` under this URL. Default: `http://127.0.0.1:4318`.
- **`--self.metrics.interval`:** Self metric collection interval in seconds. Default: `5`.
- **`--log.level`:** Structured log minimum level. Default: `debug`.

## Collection points

| Area | Source file | API or mechanism | What it observes |
| --- | --- | --- | --- |
| Process CPU time | `Sources/WatchmeSelf/SelfMetrics.swift` | `getrusage(RUSAGE_SELF)` | User and system CPU time consumed by the WatchMe process. |
| Process memory and threads | `Sources/WatchmeSelf/SelfMetrics.swift` | `proc_pidinfo(PROC_PIDTASKINFO)` | Resident memory, virtual memory, and thread count. |
| Open file descriptors | `Sources/WatchmeSelf/SelfMetrics.swift` | `proc_pidinfo(PROC_PIDLISTFDS)` | Count of currently open file descriptors. |

## Metrics

Metrics are encoded as OTLP/HTTP JSON and exported to `<--otlp.url>/v1/metrics`.
`MetricSample` gauges become OTel gauge datapoints.
`MetricSample` counters are emitted as cumulative monotonic OTel sum datapoints.

Metrics are exported:

- once immediately in `watchme agent once --collector.self`;
- at WatchMe Agent startup;
- every `--self.metrics.interval` seconds in long-running WatchMe Agent mode.

| Metric | Labels | Source | Meaning |
| --- | --- | --- | --- |
| `watchme_self_process_cpu_time_seconds_total` | `mode` | `getrusage` | WatchMe process CPU time in seconds for `user` and `system`. |
| `watchme_self_process_resident_memory_bytes` | none | `proc_pidinfo` | Resident memory used by the WatchMe process. |
| `watchme_self_process_virtual_memory_bytes` | none | `proc_pidinfo` | Virtual memory used by the WatchMe process. |
| `watchme_self_process_threads` | none | `proc_pidinfo` | Thread count in the WatchMe process. |
| `watchme_self_process_open_fds` | none | `proc_pidinfo` | Open file descriptor count in the WatchMe process. |

## Operational checks

```console
$ watchme agent once --collector.self
$ watchme agent --collector.self --self.metrics.interval 5
```
