import Darwin
import Foundation

/// Owns synchronous machine frames only. Production journal sequencing remains absent until P03c.
enum MachineUpdateRetainedSetupPolicyFrame {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias MachineBody = (PreparationIntentStore) throws -> Snapshot
    typealias UseMachine = (@escaping MachineBody) throws -> Snapshot
    enum Change { case retention, transition }
    struct Scope {
        fileprivate let reader: () throws -> Snapshot
        func read() throws -> Snapshot { try reader() }
        func verify() throws { _ = try read() }
    }
    final class ClosedMachine {
        let snapshot: Snapshot
        private let machine: PreparationIntentStore
        private let invocation: Invocation
        fileprivate init(snapshot: Snapshot, machine: PreparationIntentStore, invocation: Invocation) {
            self.snapshot = snapshot; self.machine = machine; self.invocation = invocation
        }
        /// Keeps the exact closed writer alive while its weak acknowledgement is used.
        func withClosedMachine<Value>(_ body: () throws -> Value) throws -> Value {
            try invocation.validate(); try machine.requireClosedForRetainedSetupPolicyWrite()
            let value = try body()
            try machine.requireClosedForRetainedSetupPolicyWrite(); try invocation.validate(); return value
        }
    }
    final class Step {
        private weak var machine: PreparationIntentStore?
        private let invocation: Invocation
        private let candidate: SignedReleaseEvidence
        private var verifySnapshot: ((Snapshot) throws -> Void)?
        private var active = true, reading = false
        private var callbackFrame: Snapshot?
        private(set) var expected: Snapshot
        fileprivate init(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
            invocation: Invocation, verifySnapshot: @escaping (Snapshot) throws -> Void) {
            self.machine = machine; self.expected = expected; self.candidate = candidate
            self.invocation = invocation; self.verifySnapshot = verifySnapshot
        }
        var scope: Scope { .init(reader: { [weak self] in
            guard let self else { throw JournalLeaseError.invalidated }; return try self.read()
        }) }
        fileprivate func expire() { active = false; callbackFrame = nil; machine = nil; verifySnapshot = nil }
        func read() throws -> Snapshot {
            try invocation.validate()
            guard active, let machine, let verifySnapshot else { throw JournalLeaseError.invalidated }
            guard !reading else { throw PreparationStoreError.transactionActive }
            reading = true; defer { reading = false }
            let actual: Snapshot
            if let callbackFrame { actual = callbackFrame }
            else { actual = try machine.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate) }
            try actual.requireSame(as: expected); try verifySnapshot(actual); try invocation.validate(); return actual
        }
        func storage(_ actual: Snapshot, stage: PreparationIntentStore.CompletionIntentStorageStage,
            intent: MachineUpdateRetainedSetupPolicyIntentRecord, change: Change,
            verifyAccount: () throws -> Void, didStage: (Scope) throws -> Void) throws {
            try invocation.validate()
            guard active, callbackFrame == nil else { throw PreparationStoreError.transactionActive }
            if stage == .afterMutation {
                switch change {
                case .retention: try actual.requireRetention(intent, from: expected)
                case .transition: try actual.requireTransition(intent, from: expected)
                }
                expected = actual
            } else { try actual.requireSame(as: expected) }
            callbackFrame = actual; defer { callbackFrame = nil }
            _ = try read(); try verifyAccount(); try didStage(scope); try verifyAccount(); _ = try read()
        }
    }
    final class Invocation {
        private final class MachineCall {
            var body: ((PreparationIntentStore, Step) throws -> Snapshot)?
            init(_ body: @escaping (PreparationIntentStore, Step) throws -> Snapshot) { self.body = body }
        }
        fileprivate struct Context {
            let candidate: SignedReleaseEvidence
            let directory: ReleaseDestinationLease
            let admission: UpdateOrdinaryAdmissionLease
            let expectedBoundary: PreparationFileIdentity
            let verifySnapshot: (Snapshot) throws -> Void
        }
        private let processID = getpid(), thread = pthread_self()
        private var context: Context?
        fileprivate init(context: Context) { self.context = context }
        fileprivate func expire() { context = nil }
        fileprivate func validate() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard context != nil else { throw JournalLeaseError.invalidated }
        }
        private func verify(_ actual: Snapshot) throws {
            try validate(); guard let context else { throw JournalLeaseError.invalidated }
            try context.admission.validateMachineBoundary(directory: context.directory, expected: context.expectedBoundary)
            try context.verifySnapshot(actual)
            try context.admission.validateMachineBoundary(directory: context.directory, expected: context.expectedBoundary)
            try validate()
        }
        func machineStep(expected: Snapshot, useMachine: UseMachine,
            body: @escaping (PreparationIntentStore, Step) throws -> Snapshot) throws -> ClosedMachine {
            try verify(expected); guard let context else { throw JournalLeaseError.invalidated }
            let call = MachineCall(body), candidate = context.candidate
            var entered = false, active = true, violated = false, observed: Snapshot?, used: PreparationIntentStore?
            defer { active = false; call.body = nil }
            let reported = try useMachine { machine in
                try self.validate()
                guard active, !entered else { violated = true; throw PreparationStoreError.invalidTransition }
                guard let body = call.body else { throw JournalLeaseError.invalidated }
                entered = true; used = machine
                let step = Step(machine: machine, expected: expected, candidate: candidate,
                    invocation: self, verifySnapshot: { try self.verify($0) })
                defer { step.expire() }
                _ = try step.read(); let actual = try body(machine, step)
                try step.read().requireSame(as: actual); observed = actual; return actual
            }
            guard !violated else { throw PreparationStoreError.invalidTransition }
            guard let observed, let used else { throw RuntimeActivationError.unavailable }
            try used.requireClosedForRetainedSetupPolicyWrite()
            try reported.requireSame(as: observed); try verify(reported)
            return ClosedMachine(snapshot: reported, machine: used, invocation: self)
        }
    }
    /// Providers must close their exact connection before returning. Verifiers must not query either store or publish changes.
    static func withInvocation<Value>(expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifySnapshot: @escaping (Snapshot) throws -> Void, body: (Invocation) throws -> Value) throws -> Value {
        let invocation = Invocation(context: .init(candidate: candidate, directory: directory, admission: admission,
            expectedBoundary: expected.activation.runtime.setup.source.actual.admission.machine, verifySnapshot: verifySnapshot))
        defer { invocation.expire() }
        return try body(invocation)
    }
}
