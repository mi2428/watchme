func internetPathOutcome(_ result: ActiveInternetProbeLaneResult) -> String {
    if result.ok {
        return "success"
    }
    let failedChecks = [
        result.dns.contains { !$0.ok } ? "dns" : nil,
        result.icmp?.ok == false ? "icmp" : nil,
        result.tcp?.ok == false ? "tcp" : nil,
        result.http?.ok == false ? "http" : nil,
    ].compactMap(\.self)
    return failedChecks.isEmpty ? "error" : failedChecks.joined(separator: "_")
}
