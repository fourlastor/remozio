import Darwin
import Foundation

/// Sequences initial file publication and its marker. Native callers separately prove identity, custody and host state.
enum MachineUpdateRetainedSetupInitialRuntime {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Selection = MachineUpdateRetainedSetupInitialSelection
    typealias Publication = MachineUpdateRetainedSetupInitialPublication
    typealias Completion = MachineUpdateRetainedSetupInitialCompletion
    typealias Observer = MachineUpdateRetainedSetupInitialObservation
    typealias UseMachine = MachineUpdateRetainedSetupPolicyFrame.UseMachine
    enum Stage { case filesPublished, publicationCompleted }
    struct Scope: CustomStringConvertible, CustomDebugStringConvertible {
        fileprivate let check: (Bool) throws -> Void
        fileprivate let leave: () -> Void
        let snapshot: Snapshot
        let material: RuntimePreparationMaterial?
        let artifact: Observer.Artifact?
        var description: String { "RetainedSetupInitialRuntimeScope(redacted)" }
        var debugDescription: String { description }
        func requireActive() throws { try check(false) }
        func withActive<Value>(_ body: () throws -> Value) throws -> Value {
            try check(true); defer { leave() }
            let result = try body(); try requireActive(); return result
        }
    }
    /// Each machine connection closes before its provider returns. Callback verifiers must not query an active store.
    static func prepare(expected: Snapshot, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool, useMachine: @escaping UseMachine,
        readPolicyBoundary: @escaping () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyCurrent: @escaping (Snapshot) throws -> Void, verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
        readMaterial: @escaping (Scope) throws -> RuntimePreparationMaterial,
        verifyActivity: @escaping (ServiceReleaseActivityReference, Scope) throws -> Void,
        readArtifact: @escaping (Observer.Artifact, Scope) throws -> Data?, publish: @escaping (Scope) throws -> Void,
        didReadSnapshot: @escaping (Snapshot) throws -> Void = { _ in },
        didStage: @escaping (Stage) throws -> Void = { _ in }) throws -> Snapshot {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        guard let record = expected.intent, record.phase == .recorded,
              let reference = expected.activation.runtime.state.reference, reference.serviceActivity != nil else {
            throw RuntimeActivationError.incomplete
        }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self()
        var active = true, inMachine = false, current = expected
        defer { active = false }
        func lifetime() throws {
            guard active, getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            try admission.validateMachineBoundary(directory: directory, expected: expected.activation.runtime.setup.source.actual.admission.machine)
        }
        func host(_ actual: Snapshot) throws {
            try lifetime(); try verifyCurrent(actual); try lifetime()
        }
        func machineStep(_ body: @escaping (PreparationIntentStore) throws -> Snapshot) throws -> Snapshot {
            try lifetime(); guard !inMachine else { throw PreparationStoreError.transactionActive }
            var lent = true, invoked = false, checked: Snapshot?
            defer { lent = false }
            let result = try useMachine { machine in
                try lifetime(); guard lent, !invoked, !inMachine else { throw JournalLeaseError.invalidated }
                invoked = true; inMachine = true; defer { inMachine = false; try? machine.close() }
                let actual = try body(machine); try lifetime(); try machine.close(); checked = actual; return actual
            }
            try lifetime(); guard let checked else { throw JournalLeaseError.invalidated }
            try result.requireSame(as: checked); return result
        }
        func capture(_ previous: Snapshot) throws -> Snapshot {
            try machineStep { machine in
                let actual = try machine.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate)
                try actual.requireSame(as: previous); try host(actual); try didReadSnapshot(actual); try lifetime(); return actual
            }
        }
        func loan<Value>(snapshot: Snapshot, material: RuntimePreparationMaterial? = nil, artifact: Observer.Artifact? = nil,
            validate: @escaping () throws -> Void, _ body: (Scope) throws -> Value) throws -> Value {
            var lent = true, operating = false, violated = false
            defer { lent = false }
            let scope = Scope(check: { enter in
                try lifetime(); try validate()
                guard lent, !violated else { throw JournalLeaseError.invalidated }
                guard !enter || !operating else { violated = true; throw PreparationStoreError.transactionActive }
                if enter { operating = true }
            }, leave: { operating = false }, snapshot: snapshot, material: material, artifact: artifact)
            try scope.requireActive(); let value = try body(scope); try scope.requireActive(); return value
        }
        current = try capture(expected)
        if !current.activation.runtime.state.configurationPublished {
            let before = current
            let publishedFiles = try machineStep { machine in
                let selected = try Publication.prepare(withSelection: { body in
                    try Selection.withCurrent(machine: machine, expected: before, candidate: candidate,
                        recordedStartupPolicy: AuthorityCodePolicy.decode(record.startupPolicy),
                        readPolicyBoundary: readPolicyBoundary, verifyCurrent: host, body: body)
                }, machine: machine, expected: before, candidate: candidate, directory: directory, admission: admission,
                    fileCustodyAccepted: fileCustodyAccepted, verifyCurrent: host, verifyServices: verifyServices,
                    readMaterial: { parent in try loan(snapshot: before, validate: parent.requireActive, readMaterial) },
                    verifyActivity: { activity, parent in try loan(snapshot: before, material: parent.material,
                        validate: parent.requireActive) { try verifyActivity(activity, $0) } },
                    readArtifact: { artifact, parent in try loan(snapshot: before, material: parent.material, artifact: artifact,
                        validate: parent.requireActive) { try readArtifact(artifact, $0) } },
                    publish: { parent in try loan(snapshot: before, material: parent.material, artifact: parent.artifact,
                        validate: parent.requireActive, publish) })
                let finalPair = try readPolicyBoundary(); try record.requireRecorded(finalPair)
                try selected.configuration.binding.requireSourceForPublication(before, current: finalPair, candidate: candidate)
                return before
            }
            try publishedFiles.requireSame(as: before); try didStage(.filesPublished); try lifetime()
            current = try capture(publishedFiles)
        }
        let beforeCompletion = current
        let completed = try machineStep { machine in
            try Completion.complete(machine: machine, expected: beforeCompletion, candidate: candidate, directory: directory,
                admission: admission, fileCustodyAccepted: fileCustodyAccepted, readPolicyBoundary: readPolicyBoundary,
                verifyCurrent: host, verifyServices: verifyServices,
                readMaterial: { parent in try loan(snapshot: parent.snapshot, validate: parent.requireActive, readMaterial) },
                verifyActivity: { activity, parent in try loan(snapshot: parent.snapshot, validate: parent.requireActive) {
                    try verifyActivity(activity, $0)
                } }, readArtifact: { artifact, parent in try loan(snapshot: parent.snapshot, artifact: artifact,
                    validate: parent.requireActive) { try readArtifact(artifact, $0) } })
        }
        if beforeCompletion.activation.runtime.state.configurationPublished { try completed.requireSame(as: beforeCompletion) }
        else { try completed.requirePublication(from: beforeCompletion, reference: reference) }
        try didStage(.publicationCompleted); try lifetime()
        return try capture(completed)
    }
}
