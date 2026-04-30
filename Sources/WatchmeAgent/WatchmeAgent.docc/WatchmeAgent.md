# ``WatchmeAgent``

Collector-oriented command-line entry point for WatchMe.

## Overview

`WatchmeAgent` owns the `watchme agent` command, parses collector selection flags such as `--collector.system` and `--collector.wifi`, applies common OTLP and logging options, and runs selected collectors behind the shared `WatchmeCollector` lifecycle.

The command enables the system collector by default. Wi-Fi collection is explicit because it can require Location authorization, active network probes, and optional BPF packet capture.

## Topics

### Command

- ``AgentCommand``
