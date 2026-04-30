# ``WatchmeAgent``

Collector-oriented command-line entry point for WatchMe Agent.

## Overview

`WatchmeAgent` owns the `watchme agent` command.
The command parses collector selection flags such as `--collector.system` and `--collector.wifi`, applies common OTLP and logging options, and runs selected collectors behind the shared `WatchmeCollector` lifecycle.

By default, `watchme agent` starts WatchMe Agent with all collectors.
Pass one or more `--collector.*` options to run only selected collectors.
Wi-Fi SSID/BSSID labels can still require Location authorization through the app-bundled workflow.

## Topics

### Command

- ``AgentCommand``
