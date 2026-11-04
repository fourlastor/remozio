import Darwin
import Foundation

/// Registration removal and known process exit are prerequisites, not proof of whole-runtime quiescence.
/// The owner serializes calls and retains the session, startup fence, machine writer and all update scope.
final class RuntimeJobStopSession {
    enum Observation: Equatable { case absent, matching(pid_t?), conflicting }
    enum Progress: Equatable { case removingRegistration, waitingForObservedProcesses, registrationRemoved }
    private let verifyCurrent: () throws -> Void
    private let inspect: () throws -> Observation
    private let capture: (pid_t) throws -> any RuntimeJobExitWitness
    private let bootout: () throws -> Void
    private var witnesses: [any RuntimeJobExitWitness] = []
    private let ownerPID = getpid()
    static let maximumWitnesses = 64

    static func open(job: InstalledAccountJobManifest, policy: AuthorityCodePolicy, rootActivity: ReleaseActivityToken,
                     verifyOwnerAndFence: @escaping () throws -> Void) throws -> RuntimeJobStopSession {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard job.bundlePath == MachineBootstrap.bundlePath,
              let code = policy.entries.first(where: { $0.role == job.declaration.role && $0.active }) else {
            throw RuntimeActivationError.changedScope
        }
        func verify() throws { try rootActivity.validateExclusive(); try verifyOwnerAndFence() }
        try verify()
        let target = "system/" + job.declaration.label
        return .init(verifyCurrent: verify, inspect: {
            let result = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["print", target])
            return try classify(result, job: job)
        }, capture: { try RuntimeJobProcessObservation.open(job: job, code: code, processID: $0) }, bootout: {
            // Removal can continue after a lost reply. Process witnesses and role barriers establish settlement separately.
            _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootout", target])
        })
    }
    static func isExactAbsence(_ result: BoundedNativeCommand.Result, label: String) -> Bool {
        result.exitCode == 113 && result.output.isEmpty && result.errorOutput ==
            Data(("Bad request.\nCould not find service \"" + label + "\" in domain for system\n").utf8)
    }
    static func classify(_ result: BoundedNativeCommand.Result, job: InstalledAccountJobManifest) throws -> Observation {
        if isExactAbsence(result, label: job.declaration.label) { return .absent }
        guard result.exitCode == 0, result.errorOutput.isEmpty else { throw RuntimeActivationError.unavailable }
        let loaded = try LaunchdJobObservation.decode(result.output, target: "system/" + job.declaration.label)
        return loaded.matches(job) ? .matching(loaded.processID) : .conflicting
    }
    // Fixture seams verify sequencing only. They cannot authorize system-domain removal.
    init(verifyCurrent: @escaping () throws -> Void, inspect: @escaping () throws -> Observation,
         capture: @escaping (pid_t) throws -> any RuntimeJobExitWitness, bootout: @escaping () throws -> Void) {
        self.verifyCurrent = verifyCurrent; self.inspect = inspect; self.capture = capture; self.bootout = bootout
    }
    private func observe() throws -> Observation {
        try verifyCurrent()
        let observed = try inspect()
        if case .conflicting = observed { throw RuntimeActivationError.conflictingPlan }
        if case .matching(let pid?) = observed {
            guard pid > 1 else { throw RuntimeActivationError.unavailable }
            var alreadyObserved = false
            for witness in witnesses where witness.processID == pid {
                if try !witness.hasExited() { alreadyObserved = true }
            }
            if !alreadyObserved {
                guard witnesses.count < Self.maximumWitnesses else { throw RuntimeActivationError.unavailable }
                let witness = try capture(pid)
                guard witness.processID == pid else { throw RuntimeActivationError.changedScope }
                witnesses.append(witness)
            }
        }
        try verifyCurrent()
        return observed
    }
    /// Fresh validation only. Never issue bootout, capture another process, or infer exit from absence here.
    func requireRemoved() throws {
        guard getpid() == ownerPID else { throw RuntimeActivationError.unavailable }
        try verifyCurrent()
        switch try inspect() {
        case .absent: break
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .matching: throw RuntimeActivationError.unavailable
        }
        for witness in witnesses { guard try witness.hasExited() else { throw RuntimeActivationError.unavailable } }
        try verifyCurrent()
    }
    func poll() throws -> Progress {
        guard getpid() == ownerPID else { throw RuntimeActivationError.unavailable }
        var observed = try observe()
        if observed != .absent {
            // Recheck the loaded job immediately before the exact removal. Never replace a conflicting registration.
            observed = try observe()
            if observed != .absent {
                try verifyCurrent()
                do { try bootout() } catch { }
                try verifyCurrent()
                observed = try observe()
            }
        }
        guard observed == .absent else { return .removingRegistration }
        var allExited = true
        for witness in witnesses { if try !witness.hasExited() { allExited = false } }
        try verifyCurrent()
        return allExited ? .registrationRemoved : .waitingForObservedProcesses
    }
}
