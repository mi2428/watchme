# WatchMe Wi-Fi observability

@Metadata {
    @PageKind(article)
}

This document describes the current `watchme wifi` implementation.
It is meant to be checked against the source when instrumentation changes.

### Table of contents

- [Scope](#scope)
- [Runtime entry points](#runtime-entry-points)
  - [CLI options](#cli-options)
- [Collection points](#collection-points)
- [Snapshot model](#snapshot-model)
- [Metrics](#metrics)
- [Trace lifecycle](#trace-lifecycle)
  - [Trace triggers](#trace-triggers)
- [Emitted spans](#emitted-spans)
  - [Root span](#root-span)
  - [Active validation spans](#active-validation-spans)
  - [Packet-window phase span](#packet-window-phase-span)
  - [DHCPv4 packet spans](#dhcpv4-packet-spans)
  - [ICMPv6 packet spans](#icmpv6-packet-spans)
- [Passive packet store behavior](#passive-packet-store-behavior)
- [BPF details](#bpf-details)
- [Active probe details](#active-probe-details)
- [Event classification](#event-classification)
- [Currently unused span helper](#currently-unused-span-helper)
- [Operational checks](#operational-checks)

## Scope

`watchme wifi` turns macOS Wi-Fi state into two observability signal families:

- Prometheus text-format metrics pushed to Pushgateway.
- OpenTelemetry traces exported through OTLP/HTTP.

The Wi-Fi module does not shell out to `ifconfig`, `networksetup`, `airport`, `curl`, or other CLI tools.
Collection is implemented with macOS APIs and file descriptors inside the process.

## Runtime entry points

- **`watchme wifi`:** Long-running agent that starts metrics, active trace, CoreWLAN/SystemConfiguration event monitors, and BPF packet monitor.
- **`watchme wifi once`:** One-shot metrics push and one active trace.
- **`watchme wifi authorize-only`:** Requests Core Location authorization so CoreWLAN can return SSID/BSSID.
- **`scripts/watchme-app wifi ...`:** Runs the `.app` bundle through LaunchServices so macOS TCC applies the app's Location grant; use this path when SSID/BSSID are required.

For SSID/BSSID labels on modern macOS, build and authorize the app bundle:

```console
$ make app
$ scripts/watchme-app wifi authorize-only
$ scripts/watchme-app wifi once
```

Running `.build/watchme-app/WatchMe.app/Contents/MacOS/watchme` directly can still behave like a plain CLI process for TCC and may return `unknown` for SSID/BSSID.

### CLI options

The options below apply to `watchme wifi` and `watchme wifi once`.

- **`--metrics.push.url`:** Pushgateway base URL.
- **`--metrics.push.prefix`:** Pushgateway path prefix for reverse proxies.
- **`--metrics.interval`:** Wi-Fi metric collection interval in seconds.
- **`--traces.url`:** OTLP/HTTP trace endpoint.
- **`--traces.interval`:** Active trace interval in seconds.
- **`--traces.cooldown`:** Minimum seconds between non-forced event traces.
- **`--probe.http.timeout`:** Active probe HTTP timeout in seconds.
- **`--probe.http.target`:** Active probe HTTP HEAD target; repeat to probe multiple targets.
- **`--probe.bpf.enabled`:** Boolean switch for the passive BPF probe that watches DHCP/RS/RA/NDP packets.
- **`--probe.bpf.span-max-age`:** Passive probe packet span lookback window in seconds.
- **`--log.level`:** Structured log minimum level.

## Collection points

| Area | Source file | API or mechanism | What it observes |
| --- | --- | --- | --- |
| Wi-Fi snapshot | `Sources/WatchmeWiFi/WiFiSnapshot.swift` | `CoreWLAN.CWWiFiClient.shared().interface()` | Interface name, SSID, BSSID, RSSI, noise, transmit rate, channel. |
| Interface state and addresses | `Sources/WatchmeWiFi/WiFiSnapshot.swift` | `getifaddrs`, `getnameinfo` | Interface up/running state, IPv4 addresses, non-link-local IPv6 addresses. |
| Wi-Fi events | `Sources/WatchmeWiFi/EventMonitors.swift` | `CWEventDelegate` | Power, SSID, BSSID, link, link quality, country code, and mode changes. |
| Network events | `Sources/WatchmeWiFi/EventMonitors.swift` | `SCDynamicStore` notifications | Global and per-interface IPv4/IPv6/DNS/DHCP/link changes. |
| Passive packet timing | `Sources/WatchmeBPF`, `Sources/WatchmeWiFi/BPFMonitor.swift` | `/dev/bpfN`, `ioctl`, `poll`, `read` | DHCPv4 and ICMPv6 control packets during address acquisition. |
| Active probe | `Sources/WatchmeWiFi/ActiveProbe.swift` | `Network.framework` `NWPathMonitor` and `NWConnection` | HTTP HEAD reachability over the Wi-Fi interface. |
| Default route tags | `Sources/WatchmeWiFi/WiFiAgent.swift` | `SCDynamicStoreCopyValue` | Current primary interface, service, and gateway. |
| Location grant | `Sources/WatchmeWiFi/LocationAuthorization.swift` | `CoreLocation.CLLocationManager` | User authorization needed for CoreWLAN SSID/BSSID. |

## Snapshot model

Every metric push and trace starts from a `WiFiSnapshot`.

Snapshot fields:

- `interfaceName`: CoreWLAN interface name, falling back to known CoreWLAN interface names.
- `ssid` / `bssid`: CoreWLAN identity fields.
  These can be `nil` when Location Services redacts identity.
- `isAssociated`: true if SSID or BSSID is present, or if the interface is up, running, and has an IPv4 address.
- `rssiDBM`, `noiseDBM`, `txRateMbps`, `channel`: CoreWLAN quantitative fields.
- `ipv4Addresses`, `ipv6Addresses`: addresses from `getifaddrs`; link-local IPv6 addresses are excluded from the snapshot tag.

Metric labels always include:

- **`interface`:** Interface name or `unknown`.
- **`essid`:** SSID or `unknown`.
- **`bssid`:** BSSID or `unknown`.

Trace root tags always include the snapshot fields below when available:

- **`wifi.associated`:** `true` or `false`.
- **`wifi.identity_available`:** `true` when SSID and BSSID are both present.
- **`wifi.identity_status`:** `available`, `redacted_or_unavailable`, or `disconnected`.
- **`wifi.essid`:** ESSID value, or `unknown`.
- **`wifi.ssid`:** SSID value, or `unknown`.
- **`wifi.bssid`:** BSSID value, or `unknown`.
- **`wifi.snapshot_epoch_ns`:** Snapshot wall-clock time in nanoseconds.
- **`wifi.snapshot_timestamp_source`:** Currently `corewlan_getifaddrs_snapshot`.
- **`wifi.interface`:** Interface name when known.
- **`wifi.rssi_dbm`:** RSSI in dBm when present.
- **`wifi.noise_dbm`:** Noise floor in dBm when present.
- **`wifi.tx_rate_mbps`:** Transmit rate in Mbps when present.
- **`wifi.channel`:** Wi-Fi channel when present.
- **`network.ipv4_addresses`:** Comma-separated local IPv4 addresses.
- **`network.ipv6_addresses`:** Comma-separated local IPv6 addresses.
- **`network.local_ip`:** First IPv4 address when present.

## Metrics

Metrics are encoded as Prometheus text format 0.0.4 and pushed with HTTP `PUT` to:

```text
/metrics/job/watchme_wifi/instance/<Host.current().localizedName>
```

Metrics are pushed:

- once immediately in `watchme wifi once`, then again at trace start;
- at agent startup, then again at startup trace start;
- every `--metrics.interval` seconds in agent mode;
- after CoreWLAN or SystemConfiguration events before event traces;
- at every trace start.

All metrics are gauges.
Optional CoreWLAN fields are omitted when the OS API does not return a value.

| Metric | Labels | Source | Meaning |
| --- | --- | --- | --- |
| `watchme_wifi_rssi_dbm` | `interface`, `essid`, `bssid` | `CWInterface.rssiValue()` | Received signal strength in dBm. |
| `watchme_wifi_noise_dbm` | `interface`, `essid`, `bssid` | `CWInterface.noiseMeasurement()` | Noise floor in dBm. |
| `watchme_wifi_tx_rate_mbps` | `interface`, `essid`, `bssid` | `CWInterface.transmitRate()` | Current transmit rate in Mbps. |
| `watchme_wifi_associated` | `interface`, `essid`, `bssid` | Snapshot association heuristic | `1` when Wi-Fi appears associated, otherwise `0`. |
| `watchme_wifi_info` | `interface`, `essid`, `bssid`, optional `channel` | Snapshot identity and channel | Constant `1` info metric carrying current identity labels. |
| `watchme_wifi_metrics_push_timestamp_seconds` | `interface`, `essid`, `bssid` | `Date().timeIntervalSince1970` | Unix timestamp of metric generation. |

## Trace lifecycle

All trace exports go through `TelemetryClient.exportTrace`, which builds OTel spans with the OpenTelemetry Swift SDK and exports them through OTLP/HTTP.

`TraceRecorder.finish` creates one root span and zero or more child spans.
The root span name is derived from the trace reason:

- lowercased;
- characters outside letters, numbers, `.`, `_`, `-` are replaced with `_`;
- `wifi.` is prepended if the result does not already start with `wifi.`.

Common root tags include every tag listed in the snapshot model section, plus:

- **`reason`:** Trace reason before normalization.
- **`traces.url`:** OTLP/HTTP endpoint.
- **`metrics.push.url`:** Pushgateway base URL.
- **`metrics.push.prefix`:** Pushgateway path prefix.
- **`bpf.enabled`:** `true` or `false`.
- **`trace.root_name`:** Final root span name.
- **`trace.start_epoch_ns`:** Trace assembly start time.
- **`trace.kind`:** `wifi_observability`.
- **`host.name`:** `Host.current().localizedName` or `unknown`.
- **`os.type`:** `macOS`.

### Trace triggers

| Trigger | Root reason | Active probe | Packet spans | Notes |
| --- | --- | --- | --- | --- |
| `watchme wifi once` | `wifi.active` | Yes | Recent packet spans are included without consuming them. | `agent.mode=once`. |
| Agent startup | `wifi.active` | Yes | Recent packet spans are consumed. | `agent.mode=startup`. |
| Active timer | `wifi.active` | Yes | Recent packet spans are consumed. | Runs every `--traces.interval` seconds. |
| CoreWLAN join | `wifi.join` | Yes | Recent packet spans are consumed, plus delayed packet-window trace. | Forced through cooldown. |
| CoreWLAN roam | `wifi.roam` | Yes | Recent packet spans are consumed, plus delayed packet-window trace. | Forced through cooldown. |
| CoreWLAN disconnect | `wifi.disconnect` | Yes | Recent packet spans are consumed. | Classified from snapshot transition. |
| Other CoreWLAN events | Normalized event name, e.g. `wifi.power.changed` | Yes | Recent packet spans are consumed. | `wifi_link_quality_changed` only updates logs and does not trigger a trace. |
| SystemConfiguration join | `wifi.join` | Yes | Recent packet spans are consumed, plus delayed packet-window trace. | Detected when previous snapshot was not associated and current snapshot is. |
| SystemConfiguration IPv4 change while associated | Event reason, e.g. `wifi.network.ipv4_changed` | Yes | Recent packet spans are consumed. | Subject to trigger cooldown. |
| BPF DHCP ACK / ICMPv6 RA / ICMPv6 NA | `wifi.rejoin.packet_window` | Yes | Recent packet spans are included without consuming them. | Delayed 1.25 seconds from packet event. |
| Delayed join/roam packet window | `wifi.rejoin.packet_window` | Yes | Recent packet spans are included without consuming them. | Delayed 2.0 seconds from join/roam. |

`--traces.cooldown` suppresses non-forced event traces.
Join, roam, startup, once, active timer, and packet-window traces bypass or avoid this suppression as implemented by their call sites.

## Emitted spans

This section lists spans emitted by the current code path.

### Root span

| Span name | Parent | Timing | Status | Tags |
| --- | --- | --- | --- | --- |
| Derived root name such as `wifi.active`, `wifi.join`, `wifi.roam`, `wifi.rejoin.packet_window` | None | Covers all child spans, including BPF spans that started before the trigger callback. | Always set to OK by exporter. | Common root tags listed above. |

### Active validation spans

Every trace currently includes active validation because all `emitTrace` call sites pass `includeActive: true`.

| Span name | Parent | Timing | Status | Tags |
| --- | --- | --- | --- | --- |
| `phase.active_validation` | Root | Wall-clock time around all configured active targets. | OK | `phase.name=active_validation`, `phase.source=network_framework_active_probe`, `phase.validation_scope=http_head_targets`, `probe.targets`, `span.source=watchme`, `otel.status_code=OK`. |
| `target.probe` | `phase.active_validation` | Duration of one target's HTTP HEAD probe. | OK when HTTP status is `200..<500`; error otherwise. | `span.source=active_probe`, `active_probe.interface`, `active_probe.required_interface`, `probe.target`, `url.full`, `target.probe.child_span_count`, optional `http.response.status_code`, optional `error`, default route tags. |
| `probe.network.connect` | `target.probe` | Probe start until `NWConnection` reaches `.ready`. | OK | `span.source=network_framework`, `network.framework.phase=dns_tcp_tls_connect`, `net.peer.name`, `net.peer.port`, `probe.target`, `url.scheme`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`; emitted only when the connection reaches ready. |
| `probe.http.head` | `target.probe` | Probe start until response bytes or failure. | OK when HTTP status is `200..<500`; error otherwise. | `span.source=network_framework_active_probe`, `http.request.method=HEAD`, optional `http.response.status_code`, optional `error`, `net.peer.name`, `net.peer.port`, `probe.target`, `url.scheme`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |

Default route tags on `target.probe`:

- **`network.route_source`:** `system_configuration_dynamic_store`.
- **`network.primary_interface`:** `State:/Network/Global/IPv4` `PrimaryInterface`.
- **`network.primary_service`:** `State:/Network/Global/IPv4` `PrimaryService`.
- **`network.gateway`:** `State:/Network/Global/IPv4` `Router`.

### Packet-window phase span

This phase is emitted only when `PassivePacketStore.recentPacketSpans` returns at least one packet-derived span.

| Span name | Parent | Timing | Status | Tags |
| --- | --- | --- | --- | --- |
| `phase.wifi_rejoin_packets` | Root | Window from earliest packet span start to latest packet span end. | OK | `phase.name=wifi_rejoin_packets`, `phase.source=continuous_bpf`, `phase.packet_span_count`, `span.source=watchme`, `otel.status_code=OK`. |

Packet-derived spans are recorded with `phase.wifi_rejoin_packets` as their logical parent and receive additional `wifi.essid` and `wifi.bssid` context.

### DHCPv4 packet spans

DHCP observations are captured from BPF Ethernet frames carrying IPv4 UDP packets on ports 67 or 68.
The DHCP parser reads transaction ID, message type, `yiaddr`, server identifier, and lease time options.

Common DHCP span tags:

- **`span.source`:** `bpf_packet`.
- **`packet.protocol`:** `dhcpv4`.
- **`packet.event`:** Event-specific value.
- **`packet.timestamp_source`:** `bpf_header_timeval`.
- **`packet.timestamp_resolution`:** `microsecond`.
- **`dhcp.xid`:** DHCP transaction ID as `0x%08x`.
- **`network.interface`:** BPF interface name when known.
- **`wifi.essid`:** Added when attached to a trace.
- **`wifi.bssid`:** Added when attached to a trace.

| Span name | Timing | Event tag | Extra tags |
| --- | --- | --- | --- |
| `packet.dhcp.discover_retry_gap` | Between consecutive DHCP DISCOVER packets for the same xid. | `discover_retry_gap` | None. |
| `packet.dhcp.request_retry_gap` | Between consecutive DHCP REQUEST packets for the same xid. | `request_retry_gap` | None. |
| `packet.dhcp.discover_to_offer` | Latest DISCOVER before first OFFER for the same xid to that OFFER. | `discover_to_offer` | Optional `dhcp.server_identifier`. |
| `packet.dhcp.request_to_ack` | Latest REQUEST before first ACK for the same xid to that ACK. | `request_to_ack` | Optional `dhcp.yiaddr`, optional `dhcp.server_identifier`, optional `dhcp.lease_time_seconds`. |

### ICMPv6 packet spans

ICMPv6 observations are captured from BPF Ethernet frames carrying IPv6 ICMPv6 types 133, 134, 135, or 136.

All ICMPv6 packet spans receive:

- **`span.source`:** `bpf_packet` when not already specified.
- **`packet.timestamp_source`:** `bpf_header_timeval`.
- **`packet.timestamp_resolution`:** `microsecond`.
- **`wifi.essid`:** Added when attached to a trace.
- **`wifi.bssid`:** Added when attached to a trace.

| Span name | Timing | Tags |
| --- | --- | --- |
| `packet.icmpv6.router_solicitation_retry_gap` | Between consecutive Router Solicitation packets. | `packet.protocol=icmpv6`, `icmpv6.type=133`, `packet.event=router_solicitation_retry_gap`. |
| `packet.icmpv6.router_solicitation_to_advertisement` | Latest Router Solicitation before a Router Advertisement within 3 seconds to that Advertisement. | `packet.protocol=icmpv6`, `packet.event=router_solicitation_to_advertisement`, `icmpv6.rs.source_ip`, `icmpv6.ra.source_ip`, `icmpv6.ra.destination_ip`, `network.interface`, optional `icmpv6.ra.router_lifetime_seconds`, optional `icmpv6.ra.source_link_layer_address`. |
| `packet.icmpv6.default_router_neighbor_solicitation_retry_gap` | Between consecutive Neighbor Solicitations for the same target address. | `packet.protocol=icmpv6`, `packet.event=neighbor_solicitation_retry_gap`, `icmpv6.nd.target_address`. |
| `packet.icmpv6.default_router_neighbor_resolution` | Latest Neighbor Solicitation before first Neighbor Advertisement for the same target address to that Advertisement. | `packet.protocol=icmpv6`, `packet.event=default_router_neighbor_resolution`, `icmpv6.nd.target_address`, `network.interface`, optional `icmpv6.nd.target_link_layer_address`, optional `icmpv6.nd.source_link_layer_address`. |

## Passive packet store behavior

`PassivePacketStore` is a rolling in-memory store for DHCP and ICMPv6 observations.

- Observations older than 600 seconds are pruned.
- Trace attachment uses `--probe.bpf.span-max-age` as the lookback window; default is 180 seconds.
- `consume=true` suppresses re-emitting the same packet span in later event-triggered traces.
- Packet-window traces use `consume=false` so the delayed trace can show the complete recent packet window.
- Emitted-span de-duplication keys include span name, start time, duration, `packet.event`, `dhcp.xid`, and `icmpv6.nd.target_address`.

## BPF details

The reusable BPF layer is in `Sources/WatchmeBPF`.

- Opens the first available `/dev/bpf0` through `/dev/bpf255`.
- Binds the descriptor to the Wi-Fi interface with `BIOCSETIF`.
- Enables immediate mode so packets are delivered without waiting for the kernel buffer to fill.
- Enables seeing sent packets.
- Requires Ethernet datalink type.
- Reads BPF buffers in a utility queue and walks `bpf_hdr + frame` records using BPF word alignment.
- Converts BPF `timeval` timestamps to wall-clock nanoseconds.

The Wi-Fi BPF monitor only parses:

- Ethernet type `0x0800` IPv4 UDP DHCP packets on ports 67/68.
- Ethernet type `0x86DD` IPv6 ICMPv6 control packets of type 133, 134, 135, or 136.

## Active probe details

The active probe validates the Wi-Fi path, not just general host reachability.

1. Target strings without a scheme are normalized to `https://<target>/`.
2. `NWPathMonitor` finds the Wi-Fi `NWInterface` by name.
3. `NWConnection` is created with TLS parameters and `requiredInterface` set to the Wi-Fi interface.
4. A minimal HTTP/1.1 `HEAD` request is sent over that connection.
5. The status line is parsed from the first response bytes.

A response status in `200..<500` is treated as a successful reachability result; 4xx means the network path worked even if the endpoint rejected the request.

## Event classification

CoreWLAN event callbacks are translated into stable trace reasons:

- **Previous associated, current not associated:** `wifi.disconnect`.
- **Previous not associated, current associated:** `wifi.join`.
- **BSSID changed while associated, same SSID, both BSSIDs known and different:** `wifi.roam`.
- **BSSID changed while associated but not classified as roam:** `wifi.join`.
- **SSID changed while associated:** `wifi.join`.
- **Other event names:** Underscores are replaced with dots, e.g. `wifi_power_changed` becomes `wifi.power.changed`.

SystemConfiguration events are reasoned from key paths:

- **`/DHCP`:** `wifi.network.dhcp_changed`.
- **`/IPv4`:** `wifi.network.ipv4_changed`.
- **`/IPv6`:** `wifi.network.ipv6_changed`.
- **`/DNS`:** `wifi.network.dns_changed`.
- **`/Link`:** `wifi.network.link_changed`.
- **otherwise:** `wifi.network.changed`.

SystemConfiguration event traces are emitted when the event indicates a join or when the primary IPv4 address changed while associated.

## Currently unused span helper

`ActiveProbe.swift` still contains `spanEventsFromURLMetrics`, which converts `URLSessionTaskMetrics` into span events.
The current active probe uses `Network.framework` directly and does not call this helper.
These span names are therefore not emitted by the current `watchme wifi` code path:

- **`probe.dns.resolve`:** `URLSessionTaskMetrics.domainLookupStartDate` to `domainLookupEndDate`.
- **`probe.tcp.connect`:** `connectStartDate` to `connectEndDate`.
- **`probe.tls.handshake`:** `secureConnectionStartDate` to `secureConnectionEndDate`.
- **`probe.http.request_to_first_byte`:** `requestStartDate` to `responseStartDate`.

If URLSession-based probing is removed permanently, this helper should be deleted.
If it is revived, the emitted span list above should be updated.

## Operational checks

Useful commands while changing instrumentation:

```console
$ rg 'watchme_wifi_|recordSpan|SpanEvent|packetSpan' Sources
$ make lint
$ make test
$ make app
$ scripts/watchme-app wifi once --probe.http.target www.apple.com
```

When SSID/BSSID are expected but show as `unknown`, verify that the app bundle path is being used:

```console
$ scripts/watchme-app wifi once
```

Do not run `.build/watchme-app/WatchMe.app/Contents/MacOS/watchme` directly when validating Location-gated Wi-Fi identity fields.
