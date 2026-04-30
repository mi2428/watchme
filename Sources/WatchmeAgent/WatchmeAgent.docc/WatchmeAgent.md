# ``WatchmeAgent``

Collector-oriented command-line entry point for WatchMe Agent.

## Overview

`WatchmeAgent` owns the `watchme agent` command.
The command parses collector selection flags such as `--collector.system` and `--collector.wifi`, applies common OTLP and logging options, and runs selected collectors behind the shared `WatchmeCollector` lifecycle.

By default, `watchme agent` starts WatchMe Agent with the system collector only.
Wi-Fi collection is explicit because it can require Location authorization, active network probes, and optional BPF packet capture.

## Topics

### Command

- ``AgentCommand``
