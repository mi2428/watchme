# ``WatchmeWiFi``

WatchMe Wi-Fi observability support for the `watchme agent --collector.wifi` command.

## Overview

`WatchmeWiFi` owns the Wi-Fi collector, CoreWLAN and SystemConfiguration event monitors, Wi-Fi snapshot collection, active internet DNS/ICMP/plain HTTP probes, active gateway probes, and passive BPF packet timing.
For the full instrumentation map, see <doc:WatchMeWiFiObservability>.

## Topics

### Collector

- ``WiFiCollectorFactory``

### Instrumentation

- <doc:WatchMeWiFiObservability>
