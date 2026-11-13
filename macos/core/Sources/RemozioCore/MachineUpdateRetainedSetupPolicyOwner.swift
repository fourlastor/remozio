import Foundation

/// Sequences retained startup storage only. The native entry must separately prove caller, code and custody.
enum MachineUpdateRetainedSetupPolicyOwner {
    typealias Frame = MachineUpdateRetainedSetupPolicyFrame
    typealias Snapshot = Frame.Snapshot
    typealias Verify = () throws -> Void
    enum JournalAccess { case readOnly, startup }
    enum Stage { case intentRetained, writingRetained, policyCommitted, recorded }
    enum StorageStep { case retention, writing, recorded }
    private final class JournalVerification {
        let closed: Frame.ClosedMachine
        private var body: Verify?
        private var didStage: ((AuthorityJournal.MachineUpdatePolicyCommitStage, @escaping Verify) throws -> Void)?
        init(closed: Frame.ClosedMachine, body: @escaping Verify,
            didStage: @escaping (AuthorityJournal.MachineUpdatePolicyCommitStage, @escaping Verify) throws -> Void) {
            self.closed = closed; self.body = body; self.didStage = didStage
        }
        func expire() { body = nil; didStage = nil }
        func verify() throws {
            try closed.withClosedMachine {
                guard let body else { throw JournalLeaseError.invalidated }; try body()
            }
        }
        func verifyStage(_ stage: AuthorityJournal.MachineUpdatePolicyCommitStage) throws {
            try closed.withClosedMachine {
                guard let didStage else { throw JournalLeaseError.invalidated }
                try verify(); try didStage(stage, self.verify); try verify()
            }
        }
    }
    /// A failure leaves this invocation. A new attempt must read the actual disk state with a new frame.
    /// Verifiers must not query either store or publish external changes.
    static func resume(expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, useMachine: @escaping Frame.UseMachine,
        openJournal: @escaping (JournalAccess) throws -> AuthorityJournal,
        verifySnapshot: @escaping (Snapshot) throws -> Void,
        didStorageStage: @escaping (StorageStep, PreparationIntentStore.CompletionIntentStorageStage, Frame.Scope) throws -> Void = { _, _, _ in },
        didJournalStage: @escaping (AuthorityJournal.MachineUpdatePolicyCommitStage, @escaping Verify) throws -> Void = { _, _ in },
        didStage: @escaping (Stage) throws -> Void = { _ in }) throws -> Snapshot {
        guard expected.activation.origin == .retained, expected.activation.installed == nil,
              expected.activation.state.plan == nil, !expected.activation.state.jobsRegistered,
              let initial = expected.activation.runtime.setup.account?.initialization, initial.complete else {
            throw RuntimeActivationError.incomplete
        }
        try MachineUpdateRetainedSetupPolicyStorage.requireFormats(candidate)
        return try Frame.withInvocation(expected: expected, candidate: candidate, directory: directory,
            admission: admission, verifySnapshot: verifySnapshot) { invocation in
            var current = try invocation.machineStep(expected: expected, useMachine: useMachine) { _, step in try step.read() }
            func readPair() throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
                try admission.validateMachineBoundary(directory: directory, expected: expected.activation.runtime.setup.source.actual.admission.machine)
                let journal = try openJournal(.readOnly); defer { try? journal.close() }
                let pair = try journal.captureRetainedSetupPolicyBoundary(expected: initial)
                try admission.validateMachineBoundary(directory: directory, expected: expected.activation.runtime.setup.source.actual.admission.machine)
                try journal.close(); return pair
            }
            func verifyResult(_ intent: MachineUpdateRetainedSetupPolicyIntentRecord, snapshot: Snapshot) throws -> Snapshot {
                try intent.requireRecorded(readPair())
                let actual = try invocation.machineStep(expected: snapshot, useMachine: useMachine) { _, step in try step.read() }
                try intent.requireRecorded(readPair()); return actual.snapshot
            }
            func record(_ intent: MachineUpdateRetainedSetupPolicyIntentRecord,
                pair: AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Snapshot {
                try intent.requireRecorded(pair); try intent.requireRecorded(readPair())
                let done = try invocation.machineStep(expected: current.snapshot, useMachine: useMachine) { machine, step in
                    _ = try machine.recordRetainedSetupPolicyWrite(intent, boundary: pair, expected: step.read(), candidate: candidate,
                        directory: directory, admission: admission, verifyScoped: { stage, actual in
                            try step.storage(actual, stage: stage, intent: intent, change: .transition,
                                verifyAccount: { try intent.requireRecorded(readPair()) },
                                didStage: { try didStorageStage(.recorded, stage, $0) })
                        })
                    return try step.read()
                }
                try intent.requireRecorded(readPair()); try didStage(.recorded)
                return try verifyResult(intent, snapshot: done.snapshot)
            }
            if let retained = current.snapshot.intent {
                try retained.requireSnapshot(current.snapshot.activation, candidate: candidate)
                switch retained.phase {
                case .recorded: return try verifyResult(retained, snapshot: current.snapshot)
                case .writing:
                    switch try retained.reconciling(readPair()) {
                    case .sourceUnchanged: throw RuntimeActivationError.unavailable
                    case .recorded(let recovered): return try record(recovered, pair: readPair())
                    }
                case .prepared: break
                }
            }
            var captured: MachineUpdateRetainedSetupActivationSource?
            current = try invocation.machineStep(expected: current.snapshot, useMachine: useMachine) { machine, step in
                let journal = try openJournal(.readOnly); defer { try? journal.close() }
                captured = try .capture(owner: expected.activation.runtime.setup.owner, machine: machine,
                    journal: journal, candidate: candidate)
                try journal.close(); return try step.read()
            }
            guard let source = captured else { throw RuntimeActivationError.unavailable }
            let prepared = try current.snapshot.intent ?? MachineUpdateRetainedSetupPolicyIntentRecord(source: source)
            try prepared.requireSource(source)
            func requireInitial() throws {
                guard try readPair() == source.accountPolicy else { throw PreparationStoreError.staleRevision }
            }
            if current.snapshot.intent == nil {
                current = try invocation.machineStep(expected: current.snapshot, useMachine: useMachine) { machine, step in
                    _ = try machine.retainRetainedSetupPolicyIntent(prepared, expected: step.read(), candidate: candidate,
                        directory: directory, admission: admission, verifyScoped: { stage, actual in
                            try step.storage(actual, stage: stage, intent: prepared, change: .retention, verifyAccount: requireInitial,
                                didStage: { try didStorageStage(.retention, stage, $0) })
                        })
                    return try step.read()
                }
                try didStage(.intentRetained)
            }
            let writing = try prepared.preparingWrite(expected: source)
            var acknowledgement: PreparationIntentStore.RetainedSetupPolicyWriteReceipt?
            current = try invocation.machineStep(expected: current.snapshot, useMachine: useMachine) { machine, step in
                acknowledgement = try machine.beginRetainedSetupPolicyWrite(writing, source: source, expected: step.read(),
                    candidate: candidate, directory: directory, admission: admission, verifyScoped: { stage, actual in
                        try step.storage(actual, stage: stage, intent: writing, change: .transition, verifyAccount: requireInitial,
                            didStage: { try didStorageStage(.writing, stage, $0) })
                    })
                return try step.read()
            }
            try didStage(.writingRetained)
            guard let acknowledgement, acknowledgement.changed, acknowledgement.current == writing else { throw RuntimeActivationError.unavailable }
            let closed = current, writingSnapshot = current.snapshot
            let receipt = try closed.withClosedMachine {
                try acknowledgement.withFirstWritingUse { use in
                    try admission.withMachineAdmission { loan in
                        let verification = JournalVerification(closed: closed, body: {
                            try use.validate()
                            try loan.validateMachineBoundary(directory: directory,
                                expected: writingSnapshot.activation.runtime.setup.source.actual.admission.machine)
                            _ = try invocation.machineStep(expected: writingSnapshot, useMachine: useMachine) { _, step in try step.read() }
                            try use.validate(); try loan.validate()
                        }, didStage: didJournalStage)
                        defer { verification.expire() }
                        try verification.verify()
                        let journal = try openJournal(.startup); defer { try? journal.close() }
                        let result = try journal.commitRetainedSetupStartupPolicy(source: source, use: use,
                            candidate: candidate, verifyExternal: verification.verifyStage)
                        try journal.close(); return result
                    }
                }
            }
            try didStage(.policyCommitted)
            let pair = try readPair(), recorded = try writing.recording(receipt)
            try recorded.requireRecorded(pair); return try record(recorded, pair: pair)
        }
    }
}
