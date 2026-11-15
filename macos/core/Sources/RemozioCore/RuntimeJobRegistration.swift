import Darwin
import Foundation

/// Operational launchd fields only. They do not prove process health, credentials or immutable job settings.
struct LaunchdJobObservation {
    let path: String
    let program: String
    let arguments: [String]
    let kind: String
    let userName: String?
    let groupName: String?
    let endpoints: Set<String>
    let properties: Set<String>
    let processID: pid_t?
    static func decode(_ bytes: Data, target: String) throws -> Self {
        guard bytes.count <= 65_536, let text = String(data: bytes, encoding: .utf8), !text.utf8.contains(0) else { throw RuntimeActivationError.unavailable }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.first == target + " = {", lines.dropLast().last == "}" else { throw RuntimeActivationError.unavailable }
        var fields: [String: String] = [:], arguments: [String] = [], inArguments = false, sawArguments = false
        var inEndpoints = false, sawEndpoints = false, endpointName: String?, endpointFields: [String: String] = [:]
        var endpoints = Set<String>()
        for line in lines.dropFirst().dropLast(2) {
            if inEndpoints {
                if let name = endpointName {
                    if line == "\t\t}" {
                        guard endpointFields["managed"] == "1", endpointFields["reset"] == "0", endpointFields["hide"] == "0",
                              endpoints.insert(name).inserted else { throw RuntimeActivationError.unavailable }
                        endpointName = nil; endpointFields = [:]; continue
                    }
                    guard line.hasPrefix("\t\t\t"), let separator = line.range(of: " = ") else { throw RuntimeActivationError.unavailable }
                    let key = String(line[line.index(line.startIndex, offsetBy: 3)..<separator.lowerBound])
                    let value = String(line[separator.upperBound...])
                    guard !key.isEmpty, endpointFields[key] == nil, value.utf8.count < 4096 else { throw RuntimeActivationError.unavailable }
                    endpointFields[key] = value; continue
                }
                if line == "\t}" { inEndpoints = false; continue }
                guard line.hasPrefix("\t\t\""), line.hasSuffix("\" = {"), endpoints.count < 8 else { throw RuntimeActivationError.unavailable }
                let name = String(line.dropFirst(3).dropLast(5))
                guard !name.isEmpty, name.utf8.count < 256, name.utf8.allSatisfy({
                    (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45
                }) else { throw RuntimeActivationError.unavailable }
                endpointName = name; continue
            }
            if line == "\tendpoints = {" {
                guard !sawEndpoints else { throw RuntimeActivationError.unavailable }
                sawEndpoints = true; inEndpoints = true; continue
            }
            if inArguments {
                if line == "\t}" { inArguments = false; continue }
                guard line.hasPrefix("\t\t"), arguments.count < 32 else { throw RuntimeActivationError.unavailable }
                let value = String(line.dropFirst(2))
                guard value.utf8.count < 4096, !value.contains("\r"), !value.contains("\t") else { throw RuntimeActivationError.unavailable }
                arguments.append(value); continue
            }
            if line == "\targuments = {" {
                guard !sawArguments else { throw RuntimeActivationError.unavailable }
                inArguments = true; sawArguments = true; continue
            }
            for key in ["path", "program", "type", "username", "group", "properties", "pid"] where line.hasPrefix("\t" + key + " = ") {
                guard fields[key] == nil else { throw RuntimeActivationError.unavailable }
                let value = String(line.dropFirst(key.count + 4))
                guard !value.isEmpty, value.utf8.count < 4096, !value.contains("\r"), !value.contains("\t") else { throw RuntimeActivationError.unavailable }
                fields[key] = value
            }
        }
        guard !inArguments, !inEndpoints, endpointName == nil, sawArguments, sawEndpoints, let path = fields["path"], let program = fields["program"], let kind = fields["type"] else {
            throw RuntimeActivationError.unavailable
        }
        var processID: pid_t?
        if let value = fields["pid"] {
            guard let parsed = pid_t(value), parsed > 1, value == String(parsed) else { throw RuntimeActivationError.unavailable }
            processID = parsed
        }
        return .init(path: path, program: program, arguments: arguments, kind: kind,
            userName: fields["username"], groupName: fields["group"], endpoints: endpoints,
            properties: Set((fields["properties"] ?? "").components(separatedBy: " | ")), processID: processID)
    }
    func matches(_ job: InstalledAccountJobManifest) -> Bool {
        let effectiveUser = userName ?? "root"
        let effectiveGroup = groupName ?? (effectiveUser == "root" ? "wheel" : "")
        return kind == "LaunchDaemon" && path == job.path && program == job.executablePath && arguments == job.arguments
            && effectiveUser == job.userName && effectiveGroup == job.groupName && endpoints == job.machServices
            && properties.isSuperset(of: ["runatload", "keepalive"])
    }
}

/// No stop, remove, replacement or blanket launchctl command is exposed here.
enum RuntimeJobRegistration {
    enum Observation: Equatable { case absent, matching, conflicting }
    static func ensure(_ job: InstalledAccountJobManifest, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try RuntimeMaintenanceBootstrapGuard.withNativeRegistration(job) { verifyAdmission in
            try reconcile(job: job, verifyCurrent: verifyCurrent, requireMaintenanceOpen: { _ in try verifyAdmission() },
                inspect: { try inspect(job) }, bootstrap: {
                    _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootstrap", "system", job.path])
                })
        }
    }
    /// Restoration only. The permit's held account drain replaces the ordinary shared account lease, so this entry takes none.
    /// The ordinary M06a guard is unchanged and still refuses every other bootstrap while the window is active.
    static func ensureRestoration(_ permit: RuntimeMaintenanceRestorationPermit, release: SignedReleaseEvidence) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let job = permit.cohort.job
        guard job.declaration.role == .authority, job.declaration.accountID == permit.cohort.accountID else { throw RuntimeActivationError.changedScope }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        try reconcileRestoration(permit, requireWindow: { window in
            // The machine store closes before every native inspection or bootstrap, as in the ordinary guard.
            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do { try machine.requireRuntimeMaintenanceObservationWindow(window, candidate: release); try machine.close() }
            catch { try? machine.close(); throw error }
            guard try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath).canonicalBytes
                == configuration.canonicalBytes else { throw RuntimePreparationError.changedScope }
        }, inspect: { try inspect(job) }, bootstrap: {
            _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootstrap", "system", job.path])
        })
    }
    /// Same restoration order with ordinary-owner callbacks. Root cannot select them.
    static func reconcileOwnedRestoration(_ permit: RuntimeMaintenanceRestorationPermit,
        requireWindow: (RuntimeMaintenanceWindowRecord) throws -> Void, inspect: () throws -> Observation,
        bootstrap: () throws -> Void) throws {
        try RuntimeMaintenanceOwnedControl.require()
        try reconcileRestoration(permit, requireWindow: requireWindow, inspect: inspect, bootstrap: bootstrap)
    }
    // The stopped job must still be absent. A matching registration here is not ours to adopt.
    private static func reconcileRestoration(_ permit: RuntimeMaintenanceRestorationPermit,
        requireWindow: (RuntimeMaintenanceWindowRecord) throws -> Void, inspect: () throws -> Observation,
        bootstrap: () throws -> Void) throws {
        try permit.withRegistration { _, validate in
            func verify() throws { try validate(); try requireWindow(permit.window); try validate() }
            try verify()
            guard try inspect() == .absent else { throw RuntimeActivationError.conflictingPlan }
            try reconcile(verifyCurrent: verify, inspect: inspect, bootstrap: bootstrap)
        }
    }
    static func inspect(_ job: InstalledAccountJobManifest) throws -> Observation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let target = "system/" + job.declaration.label
        let result = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["print", target])
        if RuntimeJobStopSession.isExactAbsence(result, label: job.declaration.label) { return .absent }
        guard result.exitCode == 0, result.errorOutput.isEmpty else { throw RuntimeActivationError.unavailable }
        return try LaunchdJobObservation.decode(result.output, target: target).matches(job) ? .matching : .conflicting
    }
    static func reconcile(job: InstalledAccountJobManifest, verifyCurrent: () throws -> Void,
        requireMaintenanceOpen: (InstalledAccountJobManifest) throws -> Void,
        inspect: () throws -> Observation, bootstrap: () throws -> Void) throws {
        func verify() throws { try verifyCurrent(); try requireMaintenanceOpen(job); try verifyCurrent() }
        try reconcile(verifyCurrent: verify, inspect: inspect, bootstrap: bootstrap)
    }
    // Sequencing fixtures do not prove system-domain admission or the loaded process's identity.
    static func reconcile(verifyCurrent: () throws -> Void, inspect: () throws -> Observation,
                          bootstrap: () throws -> Void) throws {
        try verifyCurrent()
        switch try inspect() {
        case .matching: try verifyCurrent(); return
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .absent: break
        }
        try verifyCurrent()
        // A failed or timed-out call can still have registered the exact job. Reconcile without replacing it.
        do { try bootstrap() } catch { }
        try verifyCurrent()
        switch try inspect() {
        case .matching: try verifyCurrent()
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .absent: throw RuntimeActivationError.unavailable
        }
    }
}
