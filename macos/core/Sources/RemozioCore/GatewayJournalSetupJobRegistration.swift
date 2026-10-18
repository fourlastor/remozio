import Darwin
import Foundation

/// Operational launchd output only. A PID or ambiguous state never proves stopped work.
struct GatewayJournalSetupJobObservation {
    let loaded: LaunchdJobObservation
    let state: String
    let activeCount: UInt64
    let processID: pid_t?
    static func decode(_ bytes: Data, target: String) throws -> Self {
        let loaded = try LaunchdJobObservation.decode(bytes, target: target)
        guard let text = String(data: bytes, encoding: .utf8) else { throw RuntimeActivationError.unavailable }
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            for key in ["state", "active count", "pid"] where line.hasPrefix("\t" + key + " = ") {
                guard fields[key] == nil else { throw RuntimeActivationError.unavailable }
                let value = String(line.dropFirst(key.count + 4))
                guard !value.isEmpty, value.utf8.count <= 128, !value.contains("\r"), !value.contains("\t") else {
                    throw RuntimeActivationError.unavailable
                }
                fields[key] = value
            }
        }
        guard let state = fields["state"], let count = fields["active count"], let active = UInt64(count),
              count == String(active) else { throw RuntimeActivationError.unavailable }
        var pid: pid_t?
        if let value = fields["pid"] {
            guard let parsed = pid_t(value), parsed > 0, value == String(parsed) else { throw RuntimeActivationError.unavailable }
            pid = parsed
        }
        return .init(loaded: loaded, state: state, activeCount: active, processID: pid)
    }
    func classify(_ job: GatewayJournalSetupJobManifest) -> GatewayJournalSetupJobRegistration.Observation {
        guard loaded.matches(job) else { return .conflicting }
        return state == "not running" && activeCount == 0 && processID == nil ? .matchingStopped : .matchingActive
    }
}

/// Only the derived temporary job is exposed. The Root owner must retain exclusive setup and release scope throughout each call.
/// Native admission and loaded settings remain runtime gates; a matching observation alone does not authenticate a process.
enum GatewayJournalSetupJobRegistration {
    enum Observation: Equatable { case absent, matchingStopped, matchingActive, conflicting }
    static func ensure(_ job: GatewayJournalSetupJobManifest, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try reconcileRegistration(verifyCurrent: verifyCurrent, inspect: { try inspect(job) }, bootstrap: {
            _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootstrap", "system", job.path])
        })
    }
    /// False means cleanup remains pending. Never remove a loaded job while its process might still own journal work.
    static func cleanupStopped(_ job: GatewayJournalSetupJobManifest, verifyCurrent: () throws -> Void) throws -> Bool {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try reconcileCleanup(verifyCurrent: verifyCurrent, inspect: { try inspect(job) }, bootout: {
            _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootout", "system/" + job.label])
        })
    }
    static func isAbsent(_ job: GatewayJournalSetupJobManifest) throws -> Bool {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try inspect(job) == .absent
    }
    private static func inspect(_ job: GatewayJournalSetupJobManifest) throws -> Observation {
        let target = "system/" + job.label
        let result = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["print", target])
        if result.exitCode == 113, result.output.isEmpty,
           let message = String(data: result.errorOutput, encoding: .utf8), message.contains("Could not find service \"" + job.label + "\"") {
            return .absent
        }
        guard result.exitCode == 0 else { throw RuntimeActivationError.unavailable }
        return try GatewayJournalSetupJobObservation.decode(result.output, target: target).classify(job)
    }
    // Logical fixtures cannot establish system-domain admission, producer identity or actual process termination.
    static func reconcileRegistration(verifyCurrent: () throws -> Void, inspect: () throws -> Observation,
                                      bootstrap: () throws -> Void) throws {
        try verifyCurrent()
        switch try inspect() {
        case .matchingStopped, .matchingActive: try verifyCurrent(); return
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .absent: break
        }
        try verifyCurrent()
        do { try bootstrap() } catch { }
        try verifyCurrent()
        switch try inspect() {
        case .matchingStopped, .matchingActive: try verifyCurrent()
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .absent: throw RuntimeActivationError.unavailable
        }
    }
    static func reconcileCleanup(verifyCurrent: () throws -> Void, inspect: () throws -> Observation,
                                 bootout: () throws -> Void) throws -> Bool {
        try verifyCurrent()
        switch try inspect() {
        case .absent: try verifyCurrent(); return true
        case .matchingActive: try verifyCurrent(); return false
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .matchingStopped: break
        }
        try verifyCurrent()
        // Recheck immediately before the exact removal. The owner must exclude another authorized setup request.
        switch try inspect() {
        case .absent: try verifyCurrent(); return true
        case .matchingActive: try verifyCurrent(); return false
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .matchingStopped: break
        }
        try verifyCurrent()
        do { try bootout() } catch { }
        try verifyCurrent()
        switch try inspect() {
        case .absent: try verifyCurrent(); return true
        case .matchingActive, .matchingStopped: try verifyCurrent(); return false
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        }
    }
}
