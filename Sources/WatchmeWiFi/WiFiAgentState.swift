import Foundation

struct WiFiAgentState {
    var snapshots = WiFiAgentSnapshotState()
    var monitors = WiFiAgentMonitorState()
    var timers = WiFiAgentTimerState()
    var trace = WiFiAgentTraceState()
    var identity = WiFiAgentIdentityState()
    var metrics = WiFiMetricState()
    var traceEmissionHandler: ((WiFiTraceEmission) -> Void)?
}

struct WiFiAgentSnapshotState {
    var lastSnapshot = WiFiSnapshot.capture()
    var lastEventSnapshot = WiFiSnapshot.capture()
}

struct WiFiAgentMonitorState {
    var bpfMonitor: PassiveBPFMonitor?
    var bpfInterface: String?
    var coreWLANMonitor: CoreWLANEventMonitor?
    var systemNetworkMonitor: SystemNetworkEventMonitor?
}

struct WiFiAgentTimerState {
    var metricsTimer: DispatchSourceTimer?
    var activeTimer: DispatchSourceTimer?
}

struct WiFiAgentTraceState {
    var lastTrigger = Date.distantPast
    var packetWindowVersion = 0
    var associationTraceVersion = 0
    var associationTracePending = false
    var pendingAssociationTraceWindowFloorEpochNanos: UInt64?
    var lastAssociationTraceCompletedEpochNanos: UInt64?
    var lastAssociationTraceWindowFloorEpochNanos: UInt64?
    var lastDisconnectionEpochNanos: UInt64?
    var disconnectTraceEmittedForCurrentOutage = false
    var packetWindowSuppressedUntil = Date.distantPast
}

struct WiFiAgentIdentityState {
    var lastStatusLogSignature: String?
}

extension WiFiAgent {
    var lastSnapshot: WiFiSnapshot {
        get { state.snapshots.lastSnapshot }
        set { state.snapshots.lastSnapshot = newValue }
    }

    var lastEventSnapshot: WiFiSnapshot {
        get { state.snapshots.lastEventSnapshot }
        set { state.snapshots.lastEventSnapshot = newValue }
    }

    var lastTrigger: Date {
        get { state.trace.lastTrigger }
        set { state.trace.lastTrigger = newValue }
    }

    var bpfMonitor: PassiveBPFMonitor? {
        get { state.monitors.bpfMonitor }
        set { state.monitors.bpfMonitor = newValue }
    }

    var bpfInterface: String? {
        get { state.monitors.bpfInterface }
        set { state.monitors.bpfInterface = newValue }
    }

    var coreWLANMonitor: CoreWLANEventMonitor? {
        get { state.monitors.coreWLANMonitor }
        set { state.monitors.coreWLANMonitor = newValue }
    }

    var systemNetworkMonitor: SystemNetworkEventMonitor? {
        get { state.monitors.systemNetworkMonitor }
        set { state.monitors.systemNetworkMonitor = newValue }
    }

    var metricsTimer: DispatchSourceTimer? {
        get { state.timers.metricsTimer }
        set { state.timers.metricsTimer = newValue }
    }

    var activeTimer: DispatchSourceTimer? {
        get { state.timers.activeTimer }
        set { state.timers.activeTimer = newValue }
    }

    var packetWindowVersion: Int {
        get { state.trace.packetWindowVersion }
        set { state.trace.packetWindowVersion = newValue }
    }

    var associationTraceVersion: Int {
        get { state.trace.associationTraceVersion }
        set { state.trace.associationTraceVersion = newValue }
    }

    var associationTracePending: Bool {
        get { state.trace.associationTracePending }
        set { state.trace.associationTracePending = newValue }
    }

    var pendingAssociationTraceWindowFloorEpochNanos: UInt64? {
        get { state.trace.pendingAssociationTraceWindowFloorEpochNanos }
        set { state.trace.pendingAssociationTraceWindowFloorEpochNanos = newValue }
    }

    var lastAssociationTraceCompletedEpochNanos: UInt64? {
        get { state.trace.lastAssociationTraceCompletedEpochNanos }
        set { state.trace.lastAssociationTraceCompletedEpochNanos = newValue }
    }

    var lastAssociationTraceWindowFloorEpochNanos: UInt64? {
        get { state.trace.lastAssociationTraceWindowFloorEpochNanos }
        set { state.trace.lastAssociationTraceWindowFloorEpochNanos = newValue }
    }

    var lastDisconnectionEpochNanos: UInt64? {
        get { state.trace.lastDisconnectionEpochNanos }
        set { state.trace.lastDisconnectionEpochNanos = newValue }
    }

    var disconnectTraceEmittedForCurrentOutage: Bool {
        get { state.trace.disconnectTraceEmittedForCurrentOutage }
        set { state.trace.disconnectTraceEmittedForCurrentOutage = newValue }
    }

    var packetWindowSuppressedUntil: Date {
        get { state.trace.packetWindowSuppressedUntil }
        set { state.trace.packetWindowSuppressedUntil = newValue }
    }

    var lastIdentityStatusLogSignature: String? {
        get { state.identity.lastStatusLogSignature }
        set { state.identity.lastStatusLogSignature = newValue }
    }

    var metricState: WiFiMetricState {
        get { state.metrics }
        set { state.metrics = newValue }
    }

    var traceEmissionHandler: ((WiFiTraceEmission) -> Void)? {
        get { state.traceEmissionHandler }
        set { state.traceEmissionHandler = newValue }
    }
}
