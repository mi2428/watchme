# WatchMe Wi-Fi observability

@Metadata {
    @PageKind(article)
}

This document describes the current `watchme wifi` implementation.
It is meant to be checked against the source when instrumentation changes.

### Table of contents

- [Scope](#scope)
- [Signal design policy](#signal-design-policy)
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
- [URLSessionTaskMetrics helper](#urlsessiontaskmetrics-helper)
- [Operational checks](#operational-checks)

## Scope

`watchme wifi` turns macOS Wi-Fi state into two observability signal families:

- Prometheus text-format metrics pushed to Pushgateway.
- OpenTelemetry traces exported through OTLP/HTTP.

The Wi-Fi module does not shell out to `ifconfig`, `networksetup`, `airport`, `curl`, or other CLI tools.
Collection is implemented with macOS APIs and file descriptors inside the process.

## Signal design policy

WatchMe Wi-Fi emits primary observations rather than semantic or derived judgments.
The agent should report values that come directly from macOS APIs, packet timestamps, or active probes that are explicitly bound to the Wi-Fi interface.
It should avoid inventing quality scores or event categories whose meaning depends on a local policy.

This is why WatchMe does not emit metrics such as:

- `watchme_wifi_snr_db`
- `watchme_wifi_signal_quality_percent`
- `watchme_wifi_connection_score`
- `watchme_wifi_roam_total`
- `watchme_wifi_join_total`
- `watchme_wifi_disconnect_total`
- `watchme_wifi_channel_change_total`

SNR, signal quality, and connection score are derived quality models.
They are useful dashboard concepts, but the thresholds and weights depend on RF environment, client hardware, AP generation, application workload, and operator preference.
Roam, join, disconnect, and channel-change counters are semantic summaries over lower-level events.
Those summaries are also useful, but encoding them in the agent would make WatchMe's output less neutral and harder to reinterpret later.

The agent instead exposes the primary signals needed to build those views downstream:

- `watchme_wifi_corewlan_event_total` for raw CoreWLAN callback counts such as `power_did_change`, `ssid_did_change`, `bssid_did_change`, and `link_did_change`.
- `watchme_wifi_snapshot_change_total` for observed snapshot field changes such as `associated`, `bssid`, `ssid`, `channel`, and `power_on`.
- `watchme_wifi_info` for categorical OS state such as `phy_mode`, `channel_band`, `channel_width`, `security`, and `country_code`.
- Root trace names such as `wifi.join`, `wifi.roam`, `wifi.power.changed`, `wifi.link.changed`, and `wifi.rejoin.packet_window`.
- BPF packet spans for DHCPv4, router solicitation/advertisement, and neighbor discovery timing.
- Active HTTP, DNS, and gateway probe metrics and spans for Wi-Fi-bound reachability.

Grafana dashboards, Prometheus recording rules, or alert rules may define site-specific semantic views from these primary signals.
For example, an operator can count BSSID changes from `watchme_wifi_snapshot_change_total{field="bssid"}` or define an SNR recording rule from RSSI and noise when that is appropriate for the environment.
Those derived rules should live near the operational policy that gives them meaning, not inside the agent.

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
| Wi-Fi snapshot | `Sources/WatchmeWiFi/WiFiSnapshot.swift` | `CoreWLAN.CWWiFiClient.shared().interface()` | Interface name, SSID, BSSID, RSSI, noise, transmit rate, channel, channel band, channel width, PHY mode, security, country code, interface mode, power state, service state, and transmit power. |
| Interface state and addresses | `Sources/WatchmeWiFi/WiFiSnapshot.swift` | `getifaddrs`, `getnameinfo` | Interface up/running state, IPv4 addresses, non-link-local IPv6 addresses. |
| Wi-Fi events | `Sources/WatchmeWiFi/EventMonitors.swift` | `CWEventDelegate` | Power, SSID, BSSID, link, link quality, country code, and mode changes. |
| Network events | `Sources/WatchmeWiFi/EventMonitors.swift` | `SCDynamicStore` notifications | Global and per-interface IPv4/IPv6/DNS/DHCP/link changes. |
| Passive packet timing | `Sources/WatchmeBPF`, `Sources/WatchmeWiFi/BPFMonitor.swift` | `/dev/bpfN`, `ioctl`, `poll`, `read` | DHCPv4 and ICMPv6 control packets during address acquisition. |
| Active HTTP probe | `Sources/WatchmeWiFi/ActiveProbe.swift` | `Network.framework` `NWPathMonitor` and `NWConnection` | HTTP HEAD reachability over the Wi-Fi interface. |
| Active DNS probe | `Sources/WatchmeWiFi/ActiveDNSProbe.swift` | `Network.framework` UDP `NWConnection` | DNS A query latency through Wi-Fi-bound resolver traffic. |
| Active gateway probe | `Sources/WatchmeWiFi/ActiveGatewayProbe.swift` | `Network.framework` TCP `NWConnection` | First-hop gateway TCP reachability through the Wi-Fi interface. |
| Wi-Fi service route tags | `Sources/WatchmeWiFi/WiFiServiceNetworkState.swift` | `SCDynamicStoreCopyValue`, `SCDynamicStoreCopyKeyList` | DNS resolvers and router for the network service bound to the Wi-Fi interface. |
| Default route tags | `Sources/WatchmeWiFi/WiFiAgent.swift` | `SCDynamicStoreCopyValue` | Current global primary interface, service, and gateway. |
| Location grant | `Sources/WatchmeWiFi/LocationAuthorization.swift` | `CoreLocation.CLLocationManager` | User authorization needed for CoreWLAN SSID/BSSID. |

## Snapshot model

Every metric push and trace starts from a `WiFiSnapshot`.

Snapshot fields:

- `interfaceName`: CoreWLAN interface name, falling back to known CoreWLAN interface names.
- `ssid` / `ssidEncoding` / `bssid`: CoreWLAN identity fields.
  These can be `nil` when Location Services redacts identity.
- `isAssociated`: true if SSID or BSSID is present, or if the interface is up, running, and has an IPv4 address.
- `rssiDBM`, `noiseDBM`, `txRateMbps`, `channel`: CoreWLAN quantitative fields.
- `channelBand`, `channelWidth`, `channelWidthMHz`: CoreWLAN channel metadata.
- `phyMode`, `security`, `interfaceMode`, `countryCode`: CoreWLAN categorical state normalized to stable lowercase labels.
- `transmitPowerMW`, `powerOn`, `serviceActive`: CoreWLAN interface state fields.
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
- **`wifi.essid_encoding`:** `utf8`, `hex`, or `unknown`.
- **`wifi.bssid`:** BSSID value, or `unknown`.
- **`wifi.snapshot_epoch_ns`:** Snapshot wall-clock time in nanoseconds.
- **`wifi.snapshot_timestamp_source`:** Currently `corewlan_getifaddrs_snapshot`.
- **`wifi.interface`:** Interface name when known.
- **`wifi.rssi_dbm`:** RSSI in dBm when present.
- **`wifi.noise_dbm`:** Noise floor in dBm when present.
- **`wifi.tx_rate_mbps`:** Transmit rate in Mbps when present.
- **`wifi.channel`:** Wi-Fi channel when present.
- **`wifi.channel_band`:** `2ghz`, `5ghz`, `6ghz`, or `unknown`.
- **`wifi.channel_width`:** `20mhz`, `40mhz`, `80mhz`, `160mhz`, or `unknown`.
- **`wifi.channel_width_mhz`:** Channel width in MHz when CoreWLAN reports a known width.
- **`wifi.phy_mode`:** `11a`, `11b`, `11g`, `11n`, `11ac`, `11ax`, `11be`, `none`, or `unknown`.
- **`wifi.security`:** CoreWLAN security type normalized to a lowercase label.
- **`wifi.interface_mode`:** `station`, `ibss`, `host_ap`, `none`, or `unknown`.
- **`wifi.country_code`:** CoreWLAN adopted country code, or `unknown`.
- **`wifi.transmit_power_mw`:** Current transmit power in milliwatts when present.
- **`wifi.power_on`:** `true` or `false` when present.
- **`wifi.service_active`:** `true` or `false` when present.
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
- at every trace start;
- after active validation, so the latest HTTP, DNS, and gateway probe samples are available to Prometheus.

Most metrics are gauges.
CoreWLAN event and snapshot change metrics are counters.
Optional CoreWLAN fields are omitted when the OS API does not return a value.
WatchMe does not emit derived Wi-Fi quality scores such as SNR, signal quality percent, or connection score.
Those can be defined in Prometheus or Grafana if an operator wants a site-specific scoring policy.

| Metric | Labels | Source | Meaning |
| --- | --- | --- | --- |
| `watchme_wifi_rssi_dbm` | `interface`, `essid`, `bssid` | `CWInterface.rssiValue()` | Received signal strength in dBm. |
| `watchme_wifi_noise_dbm` | `interface`, `essid`, `bssid` | `CWInterface.noiseMeasurement()` | Noise floor in dBm. |
| `watchme_wifi_tx_rate_mbps` | `interface`, `essid`, `bssid` | `CWInterface.transmitRate()` | Current transmit rate in Mbps. |
| `watchme_wifi_channel_number` | `interface`, `essid`, `bssid` | `CWInterface.wlanChannel().channelNumber` | Current Wi-Fi channel number. |
| `watchme_wifi_channel_width_mhz` | `interface`, `essid`, `bssid` | `CWInterface.wlanChannel().channelWidth` | Current Wi-Fi channel width in MHz when CoreWLAN reports a known width. |
| `watchme_wifi_transmit_power_mw` | `interface`, `essid`, `bssid` | `CWInterface.transmitPower()` | Current Wi-Fi transmit power in milliwatts. |
| `watchme_wifi_power_on` | `interface`, `essid`, `bssid` | `CWInterface.powerOn()` | `1` when Wi-Fi power is on, otherwise `0`. |
| `watchme_wifi_service_active` | `interface`, `essid`, `bssid` | `CWInterface.serviceActive()` | `1` when the Wi-Fi network service is active, otherwise `0`. |
| `watchme_wifi_associated` | `interface`, `essid`, `bssid` | Snapshot association heuristic | `1` when Wi-Fi appears associated, otherwise `0`. |
| `watchme_wifi_info` | `interface`, `essid`, `bssid`, `identity_status`, `essid_encoding`, optional `channel`, `channel_band`, `channel_width`, `phy_mode`, `security`, `interface_mode`, `country_code` | CoreWLAN snapshot categorical fields | Constant `1` info metric carrying current identity and categorical OS labels. |
| `watchme_wifi_metrics_push_timestamp_seconds` | `interface`, `essid`, `bssid` | `Date().timeIntervalSince1970` | Unix timestamp of metric generation. |
| `watchme_wifi_corewlan_event_total` | `interface`, `essid`, `bssid`, `event` | `CWEventDelegate` callback receipt | Count of CoreWLAN event callbacks observed in this process. |
| `watchme_wifi_snapshot_change_total` | `interface`, `essid`, `bssid`, `field` | Consecutive `WiFiSnapshot` comparison | Count of raw snapshot field changes observed in this process. |
| `watchme_wifi_probe_http_success` | `interface`, `essid`, `bssid`, `target`, `scheme` | Wi-Fi-bound active HTTP probe | `1` when the latest HTTP probe returned status `200..<500`, otherwise `0`. |
| `watchme_wifi_probe_http_duration_seconds` | `interface`, `essid`, `bssid`, `target`, `scheme`, `phase` | Wi-Fi-bound active HTTP probe | Duration for `connect`, `http_head`, and `total` phases. |
| `watchme_wifi_probe_http_status_code` | `interface`, `essid`, `bssid`, `target`, `scheme` | Wi-Fi-bound active HTTP probe | HTTP status code from the latest probe when one was received. |
| `watchme_wifi_probe_http_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `target`, `scheme` | Wi-Fi-bound active HTTP probe | Unix timestamp of the latest HTTP probe completion. |
| `watchme_wifi_probe_dns_success` | `interface`, `essid`, `bssid`, `target`, `resolver`, `transport`, `timing_source` | Wi-Fi-bound active DNS probe | `1` when the latest DNS probe returned rcode `0` with at least one answer, otherwise `0`. |
| `watchme_wifi_probe_dns_duration_seconds` | `interface`, `essid`, `bssid`, `target`, `resolver`, `transport`, `timing_source` | Wi-Fi-bound active DNS probe | Duration of the latest DNS query/response, using BPF packet timestamps when correlation succeeds and Network.framework callback time otherwise. |
| `watchme_wifi_probe_dns_rcode` | `interface`, `essid`, `bssid`, `target`, `resolver`, `transport`, `timing_source` | Wi-Fi-bound active DNS probe | DNS response code from the latest DNS probe when a response was parsed. |
| `watchme_wifi_probe_dns_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `target`, `resolver`, `transport`, `timing_source` | Wi-Fi-bound active DNS probe | Unix timestamp of the latest DNS probe completion, using the BPF response packet timestamp when correlation succeeds. |
| `watchme_wifi_probe_gateway_tcp_reachable` | `interface`, `essid`, `bssid`, `gateway`, `port`, `outcome`, `timing_source` | Wi-Fi-bound active gateway TCP probe | `1` when the gateway host was reached, including TCP refusal, otherwise `0`. |
| `watchme_wifi_probe_gateway_tcp_connect_success` | `interface`, `essid`, `bssid`, `gateway`, `port`, `outcome`, `timing_source` | Wi-Fi-bound active gateway TCP probe | `1` when TCP connect reached `.ready`, otherwise `0`. |
| `watchme_wifi_probe_gateway_tcp_duration_seconds` | `interface`, `essid`, `bssid`, `gateway`, `port`, `outcome`, `timing_source` | Wi-Fi-bound active gateway TCP probe | Duration of the latest gateway TCP probe, using BPF SYN-to-response packet timestamps when correlation succeeds and Network.framework callback time otherwise. |
| `watchme_wifi_probe_gateway_tcp_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `gateway`, `port`, `outcome`, `timing_source` | Wi-Fi-bound active gateway TCP probe | Unix timestamp of the latest gateway TCP probe completion, using the BPF response packet timestamp when correlation succeeds. |

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
| `phase.active_validation` | Root | Wall-clock time around all configured active targets. | OK | `phase.name=active_validation`, `phase.source=network_framework_active_probe`, `phase.validation_scope=http_head_targets,dns_targets,gateway_tcp`, `probe.targets`, `probe.dns_resolvers`, `probe.gateway`, `span.source=watchme`, `otel.status_code=OK`. |
| `target.probe` | `phase.active_validation` | Duration of one target's HTTP HEAD probe. | OK when HTTP status is `200..<500`; error otherwise. | `span.source=active_probe`, `active_probe.interface`, `active_probe.required_interface`, `probe.target`, `url.full`, `target.probe.child_span_count`, optional `http.response.status_code`, optional `error`, default route tags, Wi-Fi service route tags. |
| `probe.network.connect` | `target.probe` | Probe start until `NWConnection` reaches `.ready`. | OK | `span.source=network_framework`, `network.framework.phase=dns_tcp_tls_connect`, `net.peer.name`, `net.peer.port`, `probe.target`, `url.scheme`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`; emitted only when the connection reaches ready. |
| `probe.http.head` | `target.probe` | `NWConnection.ready` until response bytes or failure; if the connection never becomes ready, falls back to probe start. | OK when HTTP status is `200..<500`; error otherwise. | `span.source=network_framework_active_probe`, `http.request.method=HEAD`, optional `http.response.status_code`, optional `error`, `net.peer.name`, `net.peer.port`, `probe.target`, `url.scheme`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |
| `probe.dns.resolve` | `phase.active_validation` | UDP DNS query-to-response duration for each active target host and up to two Wi-Fi service DNS resolvers. BPF packet timestamps are used when the query and response can be correlated; Network.framework callback timing is the fallback. | OK when rcode is `0` and at least one answer is present. | `span.source=network_framework_dns_probe`, `probe.target`, `probe.timing_source`, `probe.timestamp_source`, `dns.resolver`, `dns.transport`, optional `dns.rcode`, optional `dns.answer_count`, optional `packet.event=dns_query_to_response`, optional `packet.timestamp_source=bpf_header_timeval`, optional `packet.timestamp_resolution=microsecond`, optional `error`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |
| `probe.gateway.tcp_connect` | `phase.active_validation` | TCP SYN-to-SYN/ACK or SYN-to-RST duration to the Wi-Fi service router on port 53. BPF packet timestamps are used when the packets can be correlated; Network.framework callback timing is the fallback. | OK when the gateway host is reachable; TCP refusal is reachable but not connect success. | `span.source=network_framework_gateway_probe`, `probe.timing_source`, `probe.timestamp_source`, `network.wifi_gateway`, `network.gateway_probe.port`, `network.gateway_probe.outcome`, `network.gateway_probe.reachable`, `network.gateway_probe.connect_success`, optional `packet.event=tcp_syn_to_response`, optional `packet.timestamp_source=bpf_header_timeval`, optional `packet.timestamp_resolution=microsecond`, optional `error`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |

Default route tags on `target.probe`:

- **`network.route_source`:** `system_configuration_dynamic_store`.
- **`network.primary_interface`:** `State:/Network/Global/IPv4` `PrimaryInterface`.
- **`network.primary_service`:** `State:/Network/Global/IPv4` `PrimaryService`.
- **`network.gateway`:** `State:/Network/Global/IPv4` `Router`.

Wi-Fi service route tags on `target.probe`:

- **`network.wifi_interface`:** Wi-Fi interface name used to select the network service.
- **`network.wifi_service`:** SystemConfiguration service ID whose state is bound to the Wi-Fi interface.
- **`network.wifi_gateway`:** Router from `State:/Network/Service/<service>/IPv4`.
- **`network.wifi_dns_servers`:** DNS resolvers from `State:/Network/Service/<service>/DNS`.

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
- UDP DNS packets on port 53 that match a currently registered active DNS probe transaction ID, resolver, and target host.
- TCP SYN/SYN-ACK/RST packets that match a currently registered active gateway probe destination and port.

## Active probe details

The active probe validates the Wi-Fi path, not just general host reachability.

1. Target strings without a scheme are normalized to `https://<target>/`.
2. `NWPathMonitor` finds the Wi-Fi `NWInterface` by name.
3. `NWConnection` is created with TLS parameters and `requiredInterface` set to the Wi-Fi interface.
4. A minimal HTTP/1.1 `HEAD` request is sent over that connection.
5. The status line is parsed from the first response bytes.

A response status in `200..<500` is treated as a successful reachability result; 4xx means the network path worked even if the endpoint rejected the request.
HTTP probe metrics split duration into `connect`, `http_head`, and `total`.
The `connect` phase covers Network.framework readiness and therefore combines DNS, TCP, and TLS work in the current implementation.

DNS active probes use the Wi-Fi service's DNS resolvers instead of the global default route.
For each active target host, WatchMe sends a raw UDP A query over `NWConnection` with `requiredInterface` set to Wi-Fi.
Only the first two Wi-Fi service DNS resolvers are probed to keep a bounded active trace cost.
Before sending the query, WatchMe registers the DNS transaction ID, target host, resolver, and interface with `PassivePacketStore`.
The BPF monitor only stores DNS packets that match that active registration, so normal user DNS traffic is not retained for active probe timing.
When both the query and response are observed, `probe.dns.resolve` and the DNS duration metric use BPF packet timestamps from the BPF header.
If packet correlation fails or BPF is disabled, the same span and metric fall back to Network.framework callback wall-clock timing.

Gateway active probes use the Wi-Fi service's IPv4 router, not `State:/Network/Global/IPv4`.
The probe opens a TCP connection to gateway port 53 over the Wi-Fi interface.
TCP refusal is treated as host reachable because the gateway replied, but `connect_success` remains `0`.
Before opening the connection, WatchMe registers the gateway IP, port, and interface with `PassivePacketStore`.
When BPF observes the outbound SYN and the corresponding inbound SYN/ACK or RST, `probe.gateway.tcp_connect` and the gateway duration metric use BPF packet timestamps.
If packet correlation fails or BPF is disabled, the same span and metric fall back to Network.framework callback wall-clock timing.

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

## URLSessionTaskMetrics helper

`ActiveProbe.swift` still contains `spanEventsFromURLMetrics`, which converts `URLSessionTaskMetrics` into span events.
The current active probe uses `Network.framework` directly for interface binding and does not call this helper.
The active DNS span named `probe.dns.resolve` is emitted by `ActiveDNSProbe.swift`, not by URLSession.
If a future URLSession spike can preserve Wi-Fi interface binding, this helper can map URLSession timings into these additional span names:

- **`probe.tcp.connect`:** `connectStartDate` to `connectEndDate`.
- **`probe.tls.handshake`:** `secureConnectionStartDate` to `secureConnectionEndDate`.
- **`probe.http.request_to_first_byte`:** `requestStartDate` to `responseStartDate`.

If URLSession-based probing is removed permanently, this helper should be deleted.

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
