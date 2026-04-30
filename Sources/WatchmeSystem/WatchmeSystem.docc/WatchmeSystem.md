# ``WatchmeSystem``

System collector support for the `watchme agent --collector.system` command.

## Overview

`WatchmeSystem` owns the system collector, CPU time collection, memory page-state collection, disk I/O counter collection, and OTLP metric export.
For the full instrumentation map, see <doc:WatchMeSystemObservability>.

## Topics

### Collector

- ``SystemCollectorFactory``

### Instrumentation

- <doc:WatchMeSystemObservability>
