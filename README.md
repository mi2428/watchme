# WatchMe

WatchMe is a macOS OpenTelemetry agent.
It observes host resources, the WatchMe process itself, and Wi-Fi connection behavior, then exports metrics and traces through OTLP/HTTP.

The goal is to keep primary evidence about what happened on a macOS client: resource usage, Wi-Fi association state, reachability, address acquisition, gateway behavior, and packet timing.
WatchMe avoids local quality scores where possible.
It reports values from macOS APIs, packet timestamps, and explicit Wi-Fi-bound probes so dashboards and alert rules can interpret them downstream.

## Getting Started

### Requirements

- macOS 13 or newer
- Swift 5.9 or newer
- An OTLP/HTTP receiver, such as OpenTelemetry Collector
- macOS Location permission when SSID/BSSID labels are required
- Permission to open `/dev/bpf*` when Wi-Fi passive packet timing is enabled

### Build And Authorize

Build `WatchMe.app` locally, then put the repository's `scripts` directory on `PATH`.
The `watchme` wrapper launches the app bundle through LaunchServices, which is required for Location-gated Wi-Fi identity fields such as SSID and BSSID.

```console
$ git clone git@github.com:mi2428/watchme.git
```

```console
$ make app
$ export PATH="$PWD/scripts:$PATH"
$ watchme --help
$ watchme agent authorize-location
```

To keep the wrapper available in new shells, add the checkout's `scripts` directory to your shell profile.

```console
$ echo 'export PATH="/path/to/watchme/scripts:$PATH"' >> ~/.zshrc
```

Do not run `.build/watchme-app/WatchMe.app/Contents/MacOS/watchme` directly when validating SSID/BSSID labels; direct execution can bypass the app bundle identity that macOS TCC uses for Location authorization.

### Run

Start all collectors:

```console
$ docker compose up -d
$ watchme agent --otlp.url http://127.0.0.1:4318
```

Run all collectors once and exit:

```console
$ watchme agent once
```

Run a single collector:

```console
$ watchme agent --collector.self
$ watchme agent --collector.system
$ watchme agent --collector.wifi
```

Common options:

```console
$ watchme agent --log.level info
$ watchme agent --system.metrics.interval 5
$ watchme agent --self.metrics.interval 5
$ watchme agent --wifi.metrics.interval 5
$ watchme agent --wifi.traces.interval 60
$ watchme agent --wifi.probe.bpf.enabled false
$ watchme agent --wifi.probe.internet.target www.cloudflare.com
```

## Observability

### Self Collector

The Self Collector observes the WatchMe process.
It keeps agent overhead visible without mixing process-specific measurements into host-level system metrics.

Examples:

```console
$ watchme agent --collector.self
$ watchme agent once --collector.self
```

Metrics:

| Metric | Description |
| --- | --- |
| `watchme_self_process_cpu_time_seconds_total` | User and system CPU time consumed by the WatchMe process. |
| `watchme_self_process_resident_memory_bytes` | Resident memory used by the WatchMe process. |
| `watchme_self_process_virtual_memory_bytes` | Virtual memory used by the WatchMe process. |
| `watchme_self_process_threads` | Thread count in the WatchMe process. |
| `watchme_self_process_open_fds` | Open file descriptor count in the WatchMe process. |

The Self Collector does not currently emit traces.

### System Collector

The System Collector observes the macOS host.
It exports primary CPU, memory, VM, disk, network interface, filesystem, uptime, load average, and CPU count measurements.
It does not calculate derived values such as CPU utilization, memory pressure scores, disk saturation, or health scores; those can be built downstream.

Examples:

```console
$ watchme agent --collector.system
$ watchme agent once --collector.system
```

Metrics:

| Metric | Description |
| --- | --- |
| `watchme_system_cpu_time_seconds_total` | CPU time for `user`, `system`, `idle`, and `nice` modes. |
| `watchme_system_memory_bytes` | Memory bytes for `free`, `active`, `inactive`, `wired`, and `compressed` VM states. |
| `watchme_system_vm_activity_total` | VM activity counters such as page-in/out, swap, faults, compression, and purge. |
| `watchme_system_disk_read_bytes_total` / `watchme_system_disk_write_bytes_total` | Disk read and write bytes. |
| `watchme_system_disk_read_ops_total` / `watchme_system_disk_write_ops_total` | Disk read and write operations. |
| `watchme_system_network_bytes_total` | Network bytes by interface and direction. |
| `watchme_system_network_packets_total` | Network packets by interface and direction. |
| `watchme_system_network_errors_total` | Network errors by interface and direction. |
| `watchme_system_network_drops_total` | Receive drops by interface. |
| `watchme_system_filesystem_bytes` | Filesystem size, free, and available bytes by mount and filesystem type. |
| `watchme_system_uptime_seconds` | System uptime in seconds. |
| `watchme_system_load_average` | 1m, 5m, and 15m load averages. |
| `watchme_system_cpu_count` | Logical and physical CPU counts. |

The System Collector does not currently emit traces.

### Wi-Fi Collector

The Wi-Fi Collector observes Wi-Fi state and reachability using CoreWLAN, SystemConfiguration, BPF, and active probes bound to the Wi-Fi interface.
It connects SSID/BSSID identity, RSSI, noise, channel, PHY/security state, IP addressing, first-hop gateway behavior, internet reachability, DHCP/ARP/NDP timing, and active probe timing.

Examples:

```console
$ watchme agent --collector.wifi
$ watchme agent once --collector.wifi
```

Main metrics:

| Metric | Description |
| --- | --- |
| `watchme_wifi_rssi_dbm` | Received signal strength. |
| `watchme_wifi_noise_dbm` | Noise floor. |
| `watchme_wifi_tx_rate_mbps` | Current transmit rate. |
| `watchme_wifi_channel_number` / `watchme_wifi_channel_width_mhz` | Current channel number and channel width. |
| `watchme_wifi_transmit_power_mw` | Current Wi-Fi transmit power. |
| `watchme_wifi_power_on` / `watchme_wifi_service_active` / `watchme_wifi_associated` | Interface power, service state, and association state. |
| `watchme_wifi_info` | Info metric carrying identity status, SSID/BSSID labels, channel band, PHY mode, security, and related categorical state. |
| `watchme_wifi_corewlan_event_total` | CoreWLAN event callback counts. |
| `watchme_wifi_snapshot_change_total` | Counts of observed Wi-Fi snapshot field changes. |
| `watchme_wifi_bpf_packets_received_total` / `watchme_wifi_bpf_packets_dropped_total` | BPF descriptor packet receive and drop counters. |
| `watchme_wifi_probe_internet_path_*` | End-to-end internet path probe summary across DNS, ICMP, TCP, and HTTP checks. |
| `watchme_wifi_probe_internet_dns_*` | DNS A/AAAA probes through Wi-Fi resolvers. |
| `watchme_wifi_probe_internet_icmp_*` | Wi-Fi-bound internet ICMP echo probes. |
| `watchme_wifi_probe_internet_tcp_*` | TCP/80 connect probes. |
| `watchme_wifi_probe_internet_http_*` | Plain HTTP HEAD request-to-first-response probes. |
| `watchme_wifi_probe_gateway_icmp_*` | First-hop gateway ICMP burst probes. |
| `watchme_wifi_probe_gateway_resolution_*` | Gateway ARP or NDP resolution probes. |

Main traces and spans:

| Trace or span | Description |
| --- | --- |
| `wifi.connectivity` | Connectivity trace emitted at startup, on the periodic trace timer, and in one-shot mode. |
| `wifi.join` | Trace emitted after Wi-Fi association or IPv4 acquisition. |
| `wifi.roam` | Trace emitted for roam-like BSSID changes. |
| `wifi.disconnect` | Trace emitted when Wi-Fi disconnects. |
| `wifi.power.changed` / `wifi.link.changed` / `wifi.network.*` | Event traces derived from CoreWLAN and SystemConfiguration changes. |
| `wifi.network.attachment` | Trace built from DHCP, router solicitation/advertisement, or address-acquisition packet windows. |
| `phase.connectivity_check` | Connectivity check phase inside Wi-Fi traces. |
| `probe.gateway.path.*` | First-hop gateway reachability spans, including ARP/NDP and ICMP behavior. |
| `probe.internet.*` | Internet DNS, ICMP, TCP connect, and HTTP probe spans. |
| `packet.*` | BPF-correlated packet timing spans for DHCPv4, ARP, ICMPv6, DNS, ICMP, TCP, and HTTP packets. |

If SSID/BSSID labels are `unknown`, grant Location permission to `WatchMe.app` and run through the `watchme` wrapper.
If BPF is unavailable in your environment, disable passive packet timing with `--wifi.probe.bpf.enabled false`.

### OTLP Delivery

WatchMe exports metrics and traces through OTLP/HTTP.
The default base URL is `http://127.0.0.1:4318`.

When a retryable export fails, WatchMe stores the exact OTLP HTTP payload under `~/.watchme/otlp-spool`.
The next export replays pending payloads oldest-first and removes a payload only after the collector returns a 2xx response.

The spool is bounded by default to 1000 files, 100 MiB, seven days of age, and 100 replayed files per export.
Set `WATCHME_OTLP_SPOOL_DIR` to override the spool directory.

## Development

Use `make help` to list quality, build, app-bundle, documentation, and release targets.

```console
$ make

Development
  build                       Build the WatchMe executable
  app                         Build WatchMe.app for Location authorization
  fmt                         Format and modernize Swift sources
  lint                        Run Swift formatting and lint checks
  test                        Run unit tests
  doc                         Generate DocC documentation; set PREVIEW=1 to serve a local preview
  quality                     Format, lint, and test
  clean                       Remove local build artifacts

Distribution
  dmg                         Build an installable DMG into dist/
  release                     Build a DMG locally and publish it to GitHub Releases. Requires TAG=vX.Y.Z
  releae                      Alias for release

Help
  help                        Show this help message

Variables:
  TAG                         Release tag for make release, for example vX.Y.Z
  GIT_REMOTE                  Release git remote, defaults to origin
  GH_REPO                     GitHub repo override for release, for example owner/repo
  CONFIG                      SwiftPM build configuration, defaults to debug
  DMG_CONFIG                  SwiftPM build configuration for DMGs, defaults to release
  DOC_OUTPUT                  DocC output directory, defaults to .build/docc
  DOC_TARGET                  DocC target, defaults to WatchmeWiFi
  PREVIEW                     Set to 1 to preview DocC documentation, defaults to 0
  SWIFT                       Swift executable, defaults to swift
  WATCHME_VERSION             Embedded package version, defaults to f4d8947-dirty
  WATCHME_BUNDLE_VERSION      App bundle version, defaults to 0.0.0
  SWIFTFORMAT                 SwiftFormat executable, defaults to swiftformat
  SWIFTLINT                   SwiftLint executable, defaults to swiftlint

Examples:
  make dmg TAG=vX.Y.Z         Build an installable DMG
  make release TAG=vX.Y.Z     Publish the DMG to GitHub Releases
```

### Documentation

Generate DocC documentation with the Makefile:

```text
$ make doc DOC_TARGET=WatchmeWiFi DOC_OUTPUT=.build/docc/WatchmeWiFi
```

Serve a local DocC preview:

```text
$ make doc DOC_TARGET=WatchmeWiFi PREVIEW=1
```

Use the SwiftPM DocC plugin directly:

```text
$ swift package \
    --allow-writing-to-directory .build/docc/WatchmeWiFi \
    generate-documentation \
    --target WatchmeWiFi \
    --output-path .build/docc/WatchmeWiFi

$ swift package --disable-sandbox preview-documentation --target WatchmeWiFi
```

Replace `WatchmeWiFi` with `WatchmeSelf`, `WatchmeSystem`, or `WatchmeAgent` to build or preview another target.
