import Darwin
import Foundation

/// Records one checked initial publication. Recovery observes actual files and never creates or repairs them.
enum MachineUpdateRetainedSetupInitialCompletion {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Observer = MachineUpdateRetainedSetupInitialObservation
    typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    /// One actual writer frame. Repeated reads check lifetime and admission without querying any store.
    struct Scope: CustomStringConvertible, CustomDebugStringConvertible {
        fileprivate let check: (Bool) throws -> Void
        fileprivate let leave: () -> Void
        private let frame: Observer.Frame
        fileprivate init(check: @escaping (Bool) throws -> Void, leave: @escaping () -> Void, frame: Observer.Frame) {
            self.check = check; self.leave = leave; self.frame = frame
        }
        var description: String { "RetainedSetupInitialCompletionScope(redacted)" }
        var debugDescription: String { description }
        func read() throws -> Observer.Frame { try check(false); return frame }
        func requireActive() throws { try check(false) }
        func withActive<Result>(_ body: () throws -> Result) throws -> Result {
            try check(true); defer { leave() }
            let result = try body(); try requireActive(); return result
        }
    }
    /// Native callers supply custody and host checks separately. Verification callbacks must not query an active machine transaction.
    static func complete(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        readPolicyBoundary: @escaping () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyCurrent: @escaping (Snapshot) throws -> Void, verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
        readMaterial: @escaping (Observer.Scope) throws -> RuntimePreparationMaterial,
        verifyActivity: @escaping (ServiceReleaseActivityReference, Observer.Scope) throws -> Void,
        readArtifact: @escaping (Observer.Artifact, Observer.Scope) throws -> Data?,
        didReadSnapshot: (Snapshot) throws -> Void = { _ in },
        inspectInputs: (Observer.Inputs) throws -> Void = { _ in },
        didStorageStage: (Stage, Scope) throws -> Void = { _, _ in }) throws -> Snapshot {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        guard let record = expected.intent, record.phase == .recorded,
              let reference = expected.activation.runtime.state.reference, reference.serviceActivity != nil else {
            throw RuntimeActivationError.incomplete
        }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self()
        let boundary = expected.activation.runtime.setup.source.actual.admission.machine
        var active = true, violated = false, writerReturned = false
        weak var writer = machine
        defer { active = false; writer = nil }
        func lifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  active, !violated, writer != nil else { throw JournalLeaseError.invalidated }
            try admission.validateMachineBoundary(directory: directory, expected: boundary)
        }
        func actualSnapshot() throws -> Snapshot {
            try lifetime(); guard let writer else { throw JournalLeaseError.invalidated }
            let actual = try writer.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate)
            try lifetime(); try didReadSnapshot(actual); try lifetime(); return actual
        }
        func loan(_ frame: Observer.Frame, _ callback: (Scope) throws -> Void) throws {
            var lent = true, checking = false, operating = false
            defer { lent = false }
            let scope = Scope(check: { enter in
                try lifetime(); guard lent else { throw JournalLeaseError.invalidated }
                guard !checking, !enter || !operating else { violated = true; throw PreparationStoreError.transactionActive }
                checking = true; defer { checking = false }
                if enter { operating = true }
                try lifetime()
            }, leave: { operating = false }, frame: frame)
            try scope.requireActive(); try callback(scope); try scope.requireActive()
        }
        let initial = try actualSnapshot(); try initial.requireSame(as: expected)
        do {
            return try Observer.withCurrent(machine: machine, expected: initial, candidate: candidate,
                directory: directory, admission: admission, fileCustodyAccepted: fileCustodyAccepted,
                readPolicyBoundary: readPolicyBoundary, verifyCurrent: verifyCurrent, verifyServices: verifyServices,
                readMaterial: readMaterial, verifyActivity: verifyActivity, readArtifact: readArtifact,
                inspectInputs: inspectInputs) { observation in
                    _ = try observation.read(initial)
                    let result = try machine.completeRetainedSetupRuntimePublication(reference, expected: initial.activation.runtime,
                        policy: record, candidate: candidate, directory: directory, admission: admission,
                        fileCustodyAccepted: fileCustodyAccepted, verifyScoped: { stage, actual in
                            try lifetime(); let frame = try observation.read(actual)
                            try loan(frame) { try didStorageStage(stage, $0) }
                            _ = try observation.read(actual); try lifetime()
                        })
                    writerReturned = true
                    if initial.activation.runtime.state.configurationPublished { try result.requireSame(as: initial) }
                    else { try result.requirePublication(from: initial, reference: reference) }
                    let actual = try actualSnapshot(); try actual.requireSame(as: result)
                    _ = try observation.read(actual); try lifetime(); return actual
                }
        } catch {
            if writerReturned { try? machine.close() }
            throw error
        }
    }
}
