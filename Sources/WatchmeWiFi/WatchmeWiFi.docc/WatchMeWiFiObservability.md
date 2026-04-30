# WatchMe Wi-Fi observability

@Metadata {
    @PageKind(article)
}

This document describes the current Wi-Fi collector implementation used by `watchme agent --collector.wifi`.
It is meant to be checked against the source when instrumentation changes.

### Table of contents

- [Scope](#scope)
- [Signal design policy](#signal-design-policy)
- [Implementation rationale](#implementation-rationale)
- [Runtime entry points](#runtime-entry-points)
  - [CLI options](#cli-options)
- [OTLP delivery and local spool](#otlp-delivery-and-local-spool)
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
  - [IPv4 ARP packet spans](#ipv4-arp-packet-spans)
  - [ICMPv6 packet spans](#icmpv6-packet-spans)
- [Passive packet store behavior](#passive-packet-store-behavior)
- [BPF details](#bpf-details)
- [Active probe details](#active-probe-details)
- [Event classification](#event-classification)
- [Operational checks](#operational-checks)

## Scope

With `--collector.wifi`, WatchMe Agent turns macOS Wi-Fi state into two OpenTelemetry signal families:

- Metrics exported through OTLP/HTTP.
- OpenTelemetry traces exported through OTLP/HTTP.

The Wi-Fi module does not shell out to `ifconfig`, `networksetup`, `airport`, `curl`, or other CLI tools.
Collection is implemented with macOS APIs and file descriptors inside the process.

## Signal design policy

WatchMe Wi-Fi emits primary observations rather than semantic or derived judgments.
WatchMe Agent should report values that come directly from macOS APIs, packet timestamps, or active probes that are explicitly bound to the Wi-Fi interface.
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
Those summaries are also useful, but encoding them in WatchMe Agent would make WatchMe's output less neutral and harder to reinterpret later.

WatchMe Agent instead exposes the primary signals needed to build those views downstream:

- `watchme_wifi_corewlan_event_total` for raw CoreWLAN callback counts such as `power_did_change`, `ssid_did_change`, `bssid_did_change`, and `link_did_change`.
- `watchme_wifi_snapshot_change_total` for observed snapshot field changes such as `associated`, `bssid`, `ssid`, `channel`, and `power_on`.
- `watchme_wifi_info` for categorical OS state such as `phy_mode`, `channel_band`, `channel_width`, `security`, and `country_code`.
- Root trace names such as `wifi.join`, `wifi.roam`, `wifi.power.changed`, `wifi.link.changed`, and `wifi.rejoin.packet_window`.
- BPF packet spans for DHCPv4, IPv4 ARP, router solicitation/advertisement, and neighbor discovery timing.
- Active internet DNS, ICMP, plain HTTP, and gateway probe metrics and spans for Wi-Fi-bound reachability.

Grafana dashboards, recording rules, or alert rules may define site-specific semantic views from these primary signals.
For example, an operator can count BSSID changes from `watchme_wifi_snapshot_change_total{field="bssid"}` or define an SNR recording rule from RSSI and noise when that is appropriate for the environment.
Those derived rules should live near the operational policy that gives them meaning, not inside WatchMe Agent.

## Implementation rationale

The current feature boundary is intentionally narrow: OS snapshot metrics, raw event counters, Wi-Fi-bound internet DNS/ICMP/plain HTTP probes, Wi-Fi gateway ICMP probing, and BPF packet timing.
This keeps WatchMe focused on primary evidence rather than local interpretation.

Active internet probing is split into DNS, ICMP, and plain HTTP because those checks answer different operational questions.
DNS validates Wi-Fi-bound resolver reachability and produces the concrete remote addresses used by later probes.
ICMP checks address-family reachability without depending on HTTP service behavior.
Plain HTTP checks TCP/80 request-to-first-response timing with packet payloads that BPF can correlate.
Gateway ICMP probing is separate because first-hop reachability is a different failure domain from internet reachability.

DNS runs before ICMP and HTTP on purpose.
ICMP and HTTP consume the DNS probe output rather than invoking another resolver path, so the active validation trace stays explainable end to end.
After DNS, ICMP and HTTP run concurrently across targets and address families so dual-stack and multi-target results describe the same observation point.

BPF timestamping is used only when a probe has registered a narrow packet identity in `PassivePacketStore`.
The monitor then keeps just the packets needed to pair a DNS query/response, ICMP request/reply, HTTP request/first-response, or gateway ICMP request/reply.
If correlation fails, WatchMe still emits the same span and metric with callback or deadline timing and marks the `timing_source` accordingly.

HTTPS, TLS handshake timing, certificate validation, browser page fetch timing, and synthetic quality scores are deliberately out of scope for the Wi-Fi collector used by `watchme agent --collector.wifi`.
Those features need either encrypted-stream instrumentation, browser/application-level probes, or site-specific scoring policy.
They should be added as a separate monitor or downstream dashboard/rule logic unless they can be measured with the same Wi-Fi-bound precision as the current probes.

## Runtime entry points

- **`watchme agent --collector.wifi`:** Long-running WatchMe Agent execution that starts metrics, active trace, CoreWLAN/SystemConfiguration event monitors, and BPF packet monitor.
- **`watchme agent once --collector.wifi`:** One-shot metrics export and one active trace.
- **`watchme agent authorize-location`:** Requests Core Location authorization so CoreWLAN can return SSID/BSSID.
- **`scripts/watchme-app agent ...`:** Runs the `.app` bundle through LaunchServices so macOS TCC applies the app's Location grant; use this path when SSID/BSSID are required.

For SSID/BSSID labels on modern macOS, build and authorize the app bundle:

```console
$ make app
$ scripts/watchme-app agent authorize-location
$ scripts/watchme-app agent once --collector.wifi
```

Running `.build/watchme-app/WatchMe.app/Contents/MacOS/watchme` directly can still behave like a plain CLI process for TCC and may return `unknown` for SSID/BSSID.

### CLI options

The options below apply to `watchme agent --collector.wifi` and `watchme agent once --collector.wifi`.

- **`--otlp.url`:** OTLP/HTTP collector base endpoint. WatchMe derives `/v1/metrics` and `/v1/traces` from this URL. Default: `http://127.0.0.1:4318`.
- **`--wifi.metrics.interval`:** Wi-Fi metric collection interval in seconds. Default: `5`.
- **`--wifi.traces.interval`:** Active trace interval in seconds. Default: `60`.
- **`--wifi.traces.cooldown`:** Minimum seconds between non-forced event traces. Default: `2`.
- **`--wifi.probe.bpf.enabled`:** Boolean switch for the passive BPF probe that watches DHCP/ARP/RS/RA/NDP packets. Default: `true`.
- **`--wifi.probe.bpf.span-max-age`:** Passive probe packet span lookback window in seconds. Default: `180`.
- **`--wifi.probe.gateway.count`:** Gateway ICMP attempts per burst. Default: `4`.
- **`--wifi.probe.gateway.interval`:** Delay between gateway ICMP burst attempts in seconds. Default: `0.05`.
- **`--wifi.probe.internet.target`:** Internet probe host; repeat to probe multiple hosts. Default: `www.wide.ad.jp`, `www.cloudflare.com`.
- **`--wifi.probe.internet.family`:** `ipv4`, `ipv6`, or `dual`; default is `dual`.
- **`--wifi.probe.internet.timeout`:** Internet active probe timeout in seconds. Default: `5`.
- **`--wifi.probe.internet.dns`:** Boolean switch for internet DNS probes. Default: `true`.
- **`--wifi.probe.internet.icmp`:** Boolean switch for internet ICMP echo probes. Default: `true`.
- **`--wifi.probe.internet.http`:** Boolean switch for internet plain HTTP HEAD probes. Default: `true`.
- **`--log.level`:** Structured log minimum level. Default: `debug`.

## OTLP delivery and local spool

Wi-Fi outages, disabled Wi-Fi, captive networks, VPN transitions, or collector restarts can make the OTLP endpoint unreachable exactly when WatchMe is collecting useful evidence.
WatchMe therefore persists retryable OTLP/HTTP export failures locally.

The spool stores the exact OTLP HTTP request payload that WatchMe attempted to send.
It does not reinterpret traces or synthesize replacement timestamps.
Pending payloads are written under `~/.watchme/otlp-spool` by default; set `WATCHME_OTLP_SPOOL_DIR` to override this directory.

Delivery behavior:

- Before sending a current OTLP request, WatchMe replays pending spool files oldest-first.
- A spooled payload is removed only after the collector returns a 2xx HTTP response.
- Retryable failures, such as connection failures, timeouts, HTTP 408, HTTP 429, or HTTP 5xx, leave the payload on disk.
- Non-retryable HTTP status responses, such as most HTTP 4xx responses, drop that payload so a bad request does not permanently block newer signals.
- In long-running mode, recovery is attempted on the next metrics interval, active trace, or event-triggered export.
- In one-shot mode, pending payloads can be flushed by a later `watchme agent once --collector.wifi`, `watchme agent once --collector.system`, or long-running WatchMe Agent execution that can reach the collector.

## Collection points

| Area | Source file | API or mechanism | What it observes |
| --- | --- | --- | --- |
| Wi-Fi snapshot | `Sources/WatchmeWiFi/WiFiSnapshot.swift` | `CoreWLAN.CWWiFiClient.shared().interface()` | Interface name, SSID, BSSID, RSSI, noise, transmit rate, channel, channel band, channel width, PHY mode, security, country code, interface mode, power state, service state, and transmit power. |
| Interface state and addresses | `Sources/WatchmeWiFi/WiFiSnapshot.swift` | `getifaddrs`, `getnameinfo` | Interface up/running state, IPv4 addresses, non-link-local IPv6 addresses. |
| Wi-Fi events | `Sources/WatchmeWiFi/EventMonitors.swift` | `CWEventDelegate` | Power, SSID, BSSID, link, link quality, country code, and mode changes. |
| Network events | `Sources/WatchmeWiFi/EventMonitors.swift` | `SCDynamicStore` notifications | Global and per-interface IPv4/IPv6/DNS/DHCP/link changes. |
| Passive packet timing | `Sources/WatchmeBPF`, `Sources/WatchmeWiFi/BPFMonitor.swift` | `/dev/bpfN`, `BIOCSETF`, `BIOCGSTATS`, `poll`, `read` | DHCPv4, IPv4 ARP, and ICMPv6 control packets during address acquisition, plus registered active DNS, ICMP, HTTP, and gateway packets. |
| Active internet DNS probe | `Sources/WatchmeWiFi/ActiveDNSProbe.swift` | `Network.framework` UDP `NWConnection` | DNS A and AAAA query latency through Wi-Fi-bound resolver traffic. |
| Active internet ICMP probe | `Sources/WatchmeWiFi/ActiveICMPProbe.swift` | Darwin datagram ICMP sockets with `IP_BOUND_IF` / `IPV6_BOUND_IF` | IPv4 and IPv6 internet echo reachability through the Wi-Fi interface. |
| Active internet HTTP probe | `Sources/WatchmeWiFi/ActiveInternetHTTPProbe.swift` | `Network.framework` TCP `NWConnection` | Plain HTTP HEAD reachability over TCP/80 through the Wi-Fi interface. |
| Active gateway probe | `Sources/WatchmeWiFi/ActiveGatewayProbe.swift` | Darwin datagram ICMP sockets with `IP_BOUND_IF` | First-hop gateway ICMP reachability, loss, and jitter through the Wi-Fi interface. |
| Wi-Fi service network state | `Sources/WatchmeWiFi/WiFiServiceNetworkState.swift` | `SCDynamicStoreCopyValue`, `SCDynamicStoreCopyKeyList` | DNS resolvers and router for the network service bound to the Wi-Fi interface. |
| Location grant | `Sources/WatchmeWiFi/LocationAuthorization.swift` | `CoreLocation.CLLocationManager` | User authorization needed for CoreWLAN SSID/BSSID. |

## Snapshot model

Every metric export and trace starts from a `WiFiSnapshot`.

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

Metrics are encoded as OTLP/HTTP JSON and exported to `<--otlp.url>/v1/metrics`.
`MetricSample` gauges become OTel gauge datapoints.
`MetricSample` counters are emitted as cumulative monotonic OTel sum datapoints.
WatchMe keeps a per-series local total by adding source deltas; zero-valued first samples are recorded so expected series exist, and if a source counter decreases WatchMe treats it as a local source reset.

Metrics are exported:

- once immediately in `watchme agent once --collector.wifi`, then again at trace start;
- at WatchMe Agent startup, then again when the startup trace begins;
- every `--wifi.metrics.interval` seconds in long-running WatchMe Agent mode;
- after CoreWLAN or SystemConfiguration events before event traces;
- at every trace start;
- after active validation, so the latest internet DNS, ICMP, HTTP, and gateway probe samples are available to the OTel collector or backend.

Most metrics are gauges.
CoreWLAN event and snapshot change metrics are counters.
Optional CoreWLAN fields are omitted when the OS API does not return a value.
WatchMe does not emit derived Wi-Fi quality scores such as SNR, signal quality percent, or connection score.
Those can be defined downstream if an operator wants a site-specific scoring policy.

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
| `watchme_wifi_metrics_export_timestamp_seconds` | `interface`, `essid`, `bssid` | `Date().timeIntervalSince1970` | Unix timestamp of metric generation. |
| `watchme_wifi_bpf_packets_received_total` | `interface`, `essid`, `bssid`, `filter` | `BIOCGSTATS.bs_recv` | Packets accepted by the WatchMe Wi-Fi BPF descriptor since it was opened. |
| `watchme_wifi_bpf_packets_dropped_total` | `interface`, `essid`, `bssid`, `filter` | `BIOCGSTATS.bs_drop` | Packets dropped by the WatchMe Wi-Fi BPF descriptor since it was opened. |
| `watchme_wifi_corewlan_event_total` | `interface`, `essid`, `bssid`, `event` | `CWEventDelegate` callback receipt | Count of CoreWLAN event callbacks observed in this process. |
| `watchme_wifi_snapshot_change_total` | `interface`, `essid`, `bssid`, `field` | Consecutive `WiFiSnapshot` comparison | Count of raw snapshot field changes observed in this process. |
| `watchme_wifi_probe_internet_dns_success` | `interface`, `essid`, `bssid`, `target`, `family`, `resolver`, `transport`, `record_type`, `timing_source` | Wi-Fi-bound active internet DNS probe | `1` when the latest DNS probe returned rcode `0` with at least one address, otherwise `0`. |
| `watchme_wifi_probe_internet_dns_duration_seconds` | `interface`, `essid`, `bssid`, `target`, `family`, `resolver`, `transport`, `record_type`, `timing_source` | Wi-Fi-bound active internet DNS probe | Duration of the latest DNS query/response, using BPF packet timestamps when correlation succeeds and Network.framework callback time otherwise. |
| `watchme_wifi_probe_internet_dns_rcode` | `interface`, `essid`, `bssid`, `target`, `family`, `resolver`, `transport`, `record_type`, `timing_source` | Wi-Fi-bound active internet DNS probe | DNS response code from the latest DNS probe when a response was parsed. |
| `watchme_wifi_probe_internet_dns_address_count` | `interface`, `essid`, `bssid`, `target`, `family`, `resolver`, `transport`, `record_type`, `timing_source` | Wi-Fi-bound active internet DNS probe | Number of A or AAAA addresses returned by the latest DNS probe. |
| `watchme_wifi_probe_internet_dns_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `target`, `family`, `resolver`, `transport`, `record_type`, `timing_source` | Wi-Fi-bound active internet DNS probe | Unix timestamp of the latest DNS probe completion, using the BPF response packet timestamp when correlation succeeds. |
| `watchme_wifi_probe_internet_icmp_success` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `outcome`, `timing_source` | Wi-Fi-bound active internet ICMP probe | `1` when an echo reply was observed, otherwise `0`. |
| `watchme_wifi_probe_internet_icmp_duration_seconds` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `outcome`, `timing_source` | Wi-Fi-bound active internet ICMP probe | Echo request-to-reply duration, using BPF packet timestamps when correlation succeeds. |
| `watchme_wifi_probe_internet_icmp_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `outcome`, `timing_source` | Wi-Fi-bound active internet ICMP probe | Unix timestamp of the latest ICMP probe completion. |
| `watchme_wifi_probe_internet_http_success` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `scheme`, `outcome`, `timing_source` | Wi-Fi-bound active internet plain HTTP probe | `1` when the latest plain HTTP HEAD probe returned status `200..<500`, otherwise `0`. |
| `watchme_wifi_probe_internet_http_duration_seconds` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `scheme`, `outcome`, `timing_source` | Wi-Fi-bound active internet plain HTTP probe | Request-to-first-response-byte duration, using BPF packet timestamps when correlation succeeds. |
| `watchme_wifi_probe_internet_http_status_code` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `scheme`, `outcome`, `timing_source` | Wi-Fi-bound active internet plain HTTP probe | HTTP status code from the latest probe when one was received. |
| `watchme_wifi_probe_internet_http_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `target`, `family`, `remote_ip`, `scheme`, `outcome`, `timing_source` | Wi-Fi-bound active internet plain HTTP probe | Unix timestamp of the latest HTTP probe completion. |
| `watchme_wifi_probe_gateway_icmp_success` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | `1` when at least one echo reply is received from the gateway, otherwise `0`. |
| `watchme_wifi_probe_gateway_icmp_duration_seconds` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | Mean request-to-reply duration for replies in the latest burst, falling back to the latest attempt duration when all attempts were lost. |
| `watchme_wifi_probe_gateway_icmp_probe_count` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | Number of ICMP echo requests sent in the latest gateway burst probe. |
| `watchme_wifi_probe_gateway_icmp_reply_count` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | Number of echo replies received from the gateway in the latest burst. |
| `watchme_wifi_probe_gateway_icmp_loss_ratio` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | Fraction of ICMP attempts that did not receive a gateway echo reply in the latest burst. |
| `watchme_wifi_probe_gateway_icmp_jitter_seconds` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | Mean absolute difference between consecutive gateway ICMP reply durations in the latest burst. |
| `watchme_wifi_probe_gateway_icmp_last_run_timestamp_seconds` | `interface`, `essid`, `bssid`, `gateway`, `family`, `outcome`, `timing_source` | Wi-Fi-bound active gateway ICMP burst probe | Unix timestamp of the latest gateway ICMP burst completion, using BPF response packet timestamps when correlation succeeds. |

## Trace lifecycle

All trace exports go through `TelemetryClient.exportTrace`, which builds OTel spans with the OpenTelemetry Swift SDK and exports them through OTLP/HTTP.

`TraceRecorder.finish` creates one root span and zero or more child spans.
The root span name is derived from the trace reason:

- lowercased;
- characters outside letters, numbers, `.`, `_`, `-` are replaced with `_`;
- `wifi.` is prepended if the result does not already start with `wifi.`.

Common root tags include every tag listed in the snapshot model section, plus:

- **`reason`:** Trace reason before normalization.
- **`otlp.url`:** OTLP/HTTP collector base endpoint.
- **`bpf.enabled`:** `true` or `false`.
- **`bpf.filter`:** BPF filter profile name when the monitor is active.
- **`bpf.packets_received`:** `BIOCGSTATS` accepted packet count when available.
- **`bpf.packets_dropped`:** `BIOCGSTATS` dropped packet count when available.
- **`trace.root_name`:** Final root span name.
- **`trace.start_epoch_ns`:** Trace assembly start time.
- **`trace.kind`:** `wifi_observability`.
- **`host.name`:** `Host.current().localizedName` or `unknown`.
- **`os.type`:** `macOS`.

### Trace triggers

| Trigger | Root reason | Active probe | Packet spans | Notes |
| --- | --- | --- | --- | --- |
| `watchme agent once --collector.wifi` | `wifi.active` | Yes | Recent packet spans are included without consuming them. | `agent.mode=once`. |
| WatchMe Agent startup | `wifi.active` | Yes | Recent packet spans are consumed. | `agent.mode=startup`. |
| Active timer | `wifi.active` | Yes | Recent packet spans are consumed. | Runs every `--wifi.traces.interval` seconds. |
| CoreWLAN join | `wifi.join` | Yes | Recent packet spans are consumed, plus delayed packet-window trace. | Forced through cooldown. |
| CoreWLAN roam | `wifi.roam` | Yes | Recent packet spans are consumed, plus delayed packet-window trace. | Forced through cooldown. |
| CoreWLAN disconnect | `wifi.disconnect` | Yes | Recent packet spans are consumed. | Classified from snapshot transition. |
| Other CoreWLAN events | Normalized event name, e.g. `wifi.power.changed` | Yes | Recent packet spans are consumed. | `wifi_link_quality_changed` only updates logs and does not trigger a trace. |
| SystemConfiguration join | `wifi.join` | Yes | Recent packet spans are consumed, plus delayed packet-window trace. | Detected when previous snapshot was not associated and current snapshot is. |
| SystemConfiguration IPv4 change while associated | Event reason, e.g. `wifi.network.ipv4_changed` | Yes | Recent packet spans are consumed. | Subject to trigger cooldown. |
| BPF DHCP ACK / ARP reply / ICMPv6 RA / ICMPv6 NA | `wifi.rejoin.packet_window` | Yes | Recent packet spans are included without consuming them. | Delayed 1.25 seconds from packet event. |
| Delayed join/roam packet window | `wifi.rejoin.packet_window` | Yes | Recent packet spans are included without consuming them. | Delayed 2.0 seconds from join/roam. |

`--wifi.traces.cooldown` suppresses non-forced event traces.
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
| `phase.active_validation` | Root | Wall-clock time around all configured active targets. | OK | `phase.name=active_validation`, `phase.source=network_framework_active_probe`, `phase.validation_scope=internet_dns,internet_icmp,internet_http,gateway_icmp`, `probe.internet.targets`, `probe.internet.family`, enabled flags and span counts, `probe.dns_resolvers`, `probe.gateway`, `probe.gateway.burst_count`, `probe.gateway.burst_interval_seconds`, `probe.gateway.probe_count`, `probe.gateway.span_count`, `span.source=watchme`, `otel.status_code=OK`. |
| `probe.internet.dns.resolve` | `phase.active_validation` | UDP DNS query-to-response duration for each active target host, address family, and up to two Wi-Fi service DNS resolvers. BPF packet timestamps are used when the query and response can be correlated; Network.framework callback timing is the fallback. | OK when rcode is `0` and at least one address is present. | `span.source=network_framework_internet_dns_probe`, `probe.target`, `probe.internet.target`, `network.family`, `probe.timing_source`, `probe.timestamp_source`, `dns.resolver`, `dns.transport`, `dns.question.type`, `dns.address_count`, optional `dns.addresses`, optional `dns.rcode`, optional `dns.answer_count`, optional `packet.event=dns_query_to_response`, optional `packet.timestamp_source=bpf_header_timeval`, optional `packet.timestamp_resolution=microsecond`, optional `error`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |
| `probe.internet.icmp.echo` | `phase.active_validation` | ICMP echo request-to-reply duration for each active target host and address family. BPF packet timestamps are used when the request and reply can be correlated. | OK when an echo reply is observed. | `span.source=darwin_icmp_socket`, `probe.target`, `probe.internet.target`, `network.family`, `network.peer.address`, `icmp.outcome`, optional `icmp.identifier`, optional `icmp.sequence`, `probe.timing_source`, `probe.timestamp_source`, optional `packet.event=icmp_echo_request_to_reply`, optional `packet.timestamp_source=bpf_header_timeval`, optional `packet.timestamp_resolution=microsecond`, optional `error`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |
| `probe.internet.http.head` | `phase.active_validation` | Plain HTTP HEAD request-to-first-response-byte duration for each active target host and address family. BPF packet timestamps are used when the request packet and first response packet can be correlated; Network.framework callback timing is the fallback. | OK when HTTP status is `200..<500`. | `span.source=network_framework_plain_http_probe`, `probe.target`, `probe.internet.target`, `network.family`, `network.peer.address`, `net.peer.port=80`, `url.scheme=http`, `http.request.method=HEAD`, `http.outcome`, optional `http.response.status_code`, optional `packet.event=http_request_to_first_response_byte`, optional `packet.timestamp_source=bpf_header_timeval`, optional `packet.timestamp_resolution=microsecond`, optional `error`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |
| `probe.gateway.icmp.echo` | `phase.active_validation` | Gateway ICMP burst duration around multiple echo request/reply attempts to the Wi-Fi service router. BPF packet timestamps are used per attempt when packets can be correlated; wall-clock deadline timing is the fallback. | OK when at least one echo reply is observed. | `span.source=darwin_icmp_gateway_probe`, `probe.timing_source`, `probe.timestamp_source`, `network.family=ipv4`, `network.wifi_gateway`, `network.gateway_probe.protocol=icmp`, `network.gateway_probe.outcome`, `network.gateway_probe.reachable`, `network.gateway_probe.probe_count`, `network.gateway_probe.reply_count`, `network.gateway_probe.lost_count`, `network.gateway_probe.loss_ratio`, `network.gateway_probe.jitter_seconds`, `network.gateway_probe.burst_interval_seconds`, optional `packet.event=icmp_echo_request_to_reply`, optional `packet.timestamp_source=bpf_header_timeval`, optional `packet.timestamp_resolution=microsecond`, optional `error`, `active_probe.interface`, `active_probe.required_interface`, `wifi.essid`, `wifi.bssid`. |

Wi-Fi service network tags:

Active validation uses the SystemConfiguration service attached to the Wi-Fi interface, not the global default route.
This matters on Macs where Ethernet, VPN, or another service owns the default route while Wi-Fi is still being measured.

- **`probe.dns_resolvers`:** DNS resolvers from `State:/Network/Service/<service>/DNS`, attached to `phase.active_validation`.
- **`probe.gateway`:** Router from `State:/Network/Service/<service>/IPv4`, attached to `phase.active_validation`.
- **`network.wifi_gateway`:** Router used by `probe.gateway.icmp.echo`.
- **`network.gateway_probe.protocol`:** `icmp` for gateway probes.
- **`network.gateway_probe.outcome`:** Aggregated gateway burst outcome, such as `reply`, `partial_loss`, `loss`, `mixed`, or `no_samples`.
- **`network.gateway_probe.reachable`:** `true` when at least one gateway echo reply was observed.
- **`network.gateway_probe.probe_count`:** Number of ICMP echo requests in the gateway burst.
- **`network.gateway_probe.reply_count`:** Number of gateway echo replies observed in the burst.
- **`network.gateway_probe.lost_count`:** Number of burst attempts that did not reach the gateway.
- **`network.gateway_probe.loss_ratio`:** `lost_count / probe_count`.
- **`network.gateway_probe.jitter_seconds`:** Mean absolute difference between consecutive reachable attempt durations.
- **`network.gateway_probe.burst_interval_seconds`:** Configured delay between gateway burst attempts.

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

### IPv4 ARP packet spans

ARP observations are captured from BPF Ethernet frames carrying ARP for IPv4 over Ethernet.
These spans explain the period after DHCP when the host has an IPv4 address but still needs to resolve the first-hop gateway's link-layer address.
When the Wi-Fi service gateway is known from SystemConfiguration, packet-window traces keep ARP spans for that gateway; if the gateway is not known yet, the recent ARP window is included without a gateway filter.

Common ARP span tags:

- **`span.source`:** `bpf_packet`.
- **`packet.protocol`:** `arp`.
- **`packet.event`:** Event-specific value.
- **`packet.timestamp_source`:** `bpf_header_timeval`.
- **`packet.timestamp_resolution`:** `microsecond`.
- **`arp.target_ip`:** IPv4 address being resolved.
- **`arp.target_role`:** `gateway` when the target matches the Wi-Fi service router, otherwise `ipv4_neighbor`.
- **`network.gateway`:** Wi-Fi service router when the span target matches it.
- **`network.interface`:** BPF interface name when known.
- **`wifi.essid`:** Added when attached to a trace.
- **`wifi.bssid`:** Added when attached to a trace.

| Span name | Timing | Event tag | Extra tags |
| --- | --- | --- | --- |
| `packet.arp.request_retry_gap` | Between consecutive ARP requests for the same target IPv4 address. | `request_retry_gap` | Optional sender MAC/IP context. |
| `packet.arp.request_to_reply` | Latest ARP request before first reply from the target IPv4 address to that reply. | `request_to_reply` | `arp.sender_ip`, `arp.sender_mac`, optional `network.gateway`. |

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

`PassivePacketStore` is a rolling in-memory store for DHCP, ARP, and ICMPv6 observations, plus the active DNS/ICMP/HTTP registrations and matched packets used for active probe timing correlation.

- DHCP, ARP, ICMPv6, active DNS, active ICMP, and active HTTP packet observations older than 600 seconds are pruned.
- Active probe registrations expire after the probe timeout plus one second.
- Active DNS, ICMP, and HTTP packet observations are retained only when they match a currently registered probe identity.
- Trace attachment uses `--wifi.probe.bpf.span-max-age` as the lookback window; default is 180 seconds.
- `consume=true` suppresses re-emitting the same packet span in later event-triggered traces.
- Packet-window traces use `consume=false` so the delayed trace can show the complete recent packet window.
- ARP packet-window attachment prefers the Wi-Fi service IPv4 router when it is known; otherwise it includes recent ARP request/reply spans without a gateway filter.
- Emitted-span de-duplication keys include span name, start time, duration, `packet.event`, `dhcp.xid`, `icmpv6.nd.target_address`, and `arp.target_ip`.

## BPF details

The reusable BPF layer is in `Sources/WatchmeBPF`.

- Opens the first available `/dev/bpf0` through `/dev/bpf255`.
- Binds the descriptor to the Wi-Fi interface with `BIOCSETIF`.
- Enables immediate mode so packets are delivered without waiting for the kernel buffer to fill.
- Enables seeing sent packets.
- Requires Ethernet datalink type.
- Installs a classic BPF kernel filter with `BIOCSETF`.
  The filter profile is `wifi_control_active_probe_v1` and accepts only ARP, DHCPv4, ICMP, ICMPv6, DNS UDP/53, and plain HTTP TCP/80 traffic.
- Reads `BIOCGSTATS` for accepted and dropped packet counters and exposes them as OTel counters and root trace tags.
- Reads BPF buffers in a utility queue and walks `bpf_hdr + frame` records using BPF word alignment.
- Converts BPF `timeval` timestamps to wall-clock nanoseconds.

The Wi-Fi BPF monitor parses Ethernet frames admitted by the filter, but it only retains or logs packet observations in the narrow cases below:

- Ethernet type `0x0806` ARP packets for IPv4 gateway or neighbor resolution timing.
- Ethernet type `0x0800` IPv4 UDP DHCP packets on ports 67/68.
- Ethernet type `0x86DD` IPv6 ICMPv6 control packets of type 133, 134, 135, or 136.
- UDP DNS packets on port 53 that match a currently registered active DNS probe transaction ID, query type, resolver, and target host.
- ICMP echo request/reply packets that match a currently registered active ICMP probe target address and address family.
- TCP payload packets on port 80 that match a currently registered active plain HTTP probe target address.

## Active probe details

Active internet probes validate the Wi-Fi path to internet hosts, not just general host reachability.
The default targets are `www.wide.ad.jp` and `www.cloudflare.com`.
These defaults are ordinary probe targets, not a guarantee that every network will permit DNS, ICMP, IPv6, or plain HTTP to them; use repeated `--wifi.probe.internet.target` options to choose targets appropriate for the environment.

`--wifi.probe.internet.family=dual` expands each target into independent IPv4 and IPv6 probe work.
`--wifi.probe.internet.family=ipv4` sends only A-record, IPv4 ICMP, and IPv4 HTTP probes.
`--wifi.probe.internet.family=ipv6` sends only AAAA-record, IPv6 ICMP, and IPv6 HTTP probes.
When DNS probing is enabled, target/family/resolver DNS work is executed first because hostname ICMP and HTTP probes need concrete addresses.
After DNS planning, ICMP and HTTP work is executed in parallel across targets and address families.

DNS active probes use the Wi-Fi service's DNS resolvers instead of the global default route.
For each active target host and concrete address family, WatchMe sends a raw UDP A or AAAA query over `NWConnection` with `requiredInterface` set to Wi-Fi.
Only the first two Wi-Fi service DNS resolvers are probed to keep a bounded active trace cost.
Before sending the query, WatchMe registers the DNS transaction ID, query type, target host, resolver, and interface with `PassivePacketStore`.
The BPF monitor only stores DNS packets that match that active registration, so normal user DNS traffic is not retained for active probe timing.
When both the query and response are observed, `probe.internet.dns.resolve` and the DNS duration metric use BPF packet timestamps from the BPF header.
If packet correlation fails or BPF is disabled, the same span and metric fall back to Network.framework callback wall-clock timing.
When DNS probing is enabled but the Wi-Fi service has no DNS resolver, WatchMe emits one failed DNS result per target and concrete address family with `resolver=none` and `timing_source=no_address`.
When `--wifi.probe.internet.dns=false`, no DNS spans or DNS metrics are emitted.
In that mode, ICMP and HTTP probes still run, but hostname targets have no resolved remote address and produce `outcome=no_address`; literal IPv4 or IPv6 targets can still be probed for their matching address family.

ICMP active probes use Darwin datagram ICMP sockets and bind the socket to the Wi-Fi interface with `IP_BOUND_IF` or `IPV6_BOUND_IF`.
Before sending an echo request, WatchMe registers the target address, family, and interface with `PassivePacketStore`.
The BPF monitor stores only echo request/reply packets that match a registered active probe.
The exchange matcher prefers the generated ICMP identifier and sequence when the kernel preserves them, and falls back to the first request/reply pair for the registered target if the datagram ICMP path rewrites those fields.
When both request and reply are observed, `probe.internet.icmp.echo` and the ICMP duration metric use BPF packet timestamps.
When no reply is observed before timeout, the result uses `timing_source=wall_clock_deadline` because there is no response packet timestamp.

Plain HTTP active probes connect to the resolved target address on TCP/80 through Network.framework with `requiredInterface` set to Wi-Fi.
The HTTP request is always `HEAD / HTTP/1.1` with the original target host in the `Host` header.
Before opening the connection, WatchMe registers the target address, port, host, and interface with `PassivePacketStore`.
The BPF monitor stores only TCP payload packets that match a registered active HTTP probe.
When the outbound HEAD packet and inbound first response payload are observed, `probe.internet.http.head` and the HTTP duration metric use BPF packet timestamps.
If packet correlation fails or BPF is disabled, the same span and metric fall back to Network.framework callback wall-clock timing.
HTTPS, TLS handshake timing, certificate validation, and encrypted HTTP response timing are intentionally out of scope for the Wi-Fi collector used by `watchme agent --collector.wifi`.

Gateway active probes use the Wi-Fi service's IPv4 router, not `State:/Network/Global/IPv4`.
The probe sends a short burst of ICMP echo requests to the gateway over the Wi-Fi interface.
Before each request, WatchMe registers the gateway IP, address family, interface, and attempt start time with `PassivePacketStore`.
When BPF observes the outbound echo request and inbound echo reply, `probe.gateway.icmp.echo` and the gateway duration/jitter metrics use BPF packet timestamps for that attempt.
Loss is the fraction of burst attempts that do not receive a gateway echo reply.
If packet correlation fails or BPF is disabled, the same span and metric fall back to wall-clock deadline timing.

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

## Operational checks

Useful commands while changing instrumentation:

```console
$ rg 'watchme_wifi_|recordSpan|SpanEvent|packetSpan' Sources
$ make lint
$ make test
$ make app
$ scripts/watchme-app agent once --collector.wifi --wifi.probe.internet.target www.wide.ad.jp --wifi.probe.internet.target www.cloudflare.com
```

When SSID/BSSID are expected but show as `unknown`, verify that the app bundle path is being used:

```console
$ scripts/watchme-app agent once --collector.wifi
```

Do not run `.build/watchme-app/WatchMe.app/Contents/MacOS/watchme` directly when validating Location-gated Wi-Fi identity fields.
