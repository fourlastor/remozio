import CryptoKit
import Darwin
import Foundation

/// Durable public choices only. This value grants no file, metadata, native custody or service authority.
struct MachineUpdateRetainedSetupInitialSelection: CustomStringConvertible, CustomDebugStringConvertible {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    let configuration: RuntimeRetainedSetupInitialConfiguration
    let inputs: Inputs
    let importDigest: Data?
    let relayDigest: Data?
    let digest: Data
    var description: String { "MachineUpdateRetainedSetupInitialSelection(redacted)" }
    var debugDescription: String { description }
    struct Scope {
        fileprivate let checked: () throws -> MachineUpdateRetainedSetupInitialSelection
        func read() throws -> MachineUpdateRetainedSetupInitialSelection { try checked() }
        func verify() throws { _ = try read() }
    }
    private init(snapshot: Snapshot, current: AuthorityJournal.MachineUpdatePolicyBoundary,
        candidate: SignedReleaseEvidence, recordedStartupPolicy: AuthorityCodePolicy, inputs: Inputs) throws {
        try inputs.requireSource(snapshot.activation.runtime)
        configuration = try .init(snapshot: snapshot, current: current, candidate: candidate,
            currentCodePolicy: recordedStartupPolicy, importIntent: inputs.intent, relayPlan: inputs.relay?.plan)
        self.inputs = inputs
        importDigest = try inputs.intent.map { Data(SHA256.hash(data: try $0.bytes)) }
        relayDigest = inputs.relay?.snapshot?.digest
        var hash = SHA256(); hash.update(data: Data("Remozio/RetainedSetupInitialSelection/v1\0".utf8))
        hash.update(data: try configuration.digest); hash.update(data: Data([inputs.journalPresent ? 1 : 0]))
        for value in [importDigest, relayDigest] {
            hash.update(data: Data([value == nil ? 0 : 1])); if let value { hash.update(data: value) }
        }
        digest = Data(hash.finalize())
    }
    func requireSame(as other: Self) throws {
        try inputs.requireSame(as: other.inputs)
        guard digest == other.digest else { throw RuntimeActivationError.changedScope }
    }
    /// Opens actual import storage without creating it. Absence is never a caller-supplied selection.
    static func withCurrent<Result>(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        recordedStartupPolicy: AuthorityCodePolicy,
        readPolicyBoundary: @escaping () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyCurrent: @escaping (Snapshot) throws -> Void,
        body: (Self, Scope) throws -> Result) throws -> Result {
        guard let record = expected.intent, record.phase == .recorded,
              !expected.activation.runtime.state.configurationPublished else { throw RuntimeActivationError.incomplete }
        let current = try readPolicyBoundary()
        let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: expected, current: current, candidate: candidate)
        try binding.requireStartupPolicy(recordedStartupPolicy)
        func run(journal: SharedSetupImportJournal?,
            readRelay: @escaping (SharedSetupImportIntent) throws -> Inputs.RelaySelection) throws -> Result {
            let processID = getpid(), thread = pthread_self()
            var active = true, reading = false, violated = false
            weak var writer = machine
            var verification: ((Snapshot) throws -> Void)? = verifyCurrent
            var pairReader: (() throws -> AuthorityJournal.MachineUpdatePolicyBoundary)? = readPolicyBoundary
            defer { active = false; writer = nil; verification = nil; pairReader = nil }
            func lifetime() throws {
                guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                      active, !violated, writer != nil else { throw JournalLeaseError.invalidated }
            }
            func verifySource() throws {
                try lifetime()
                guard let writer, let verification, let pairReader else { throw JournalLeaseError.invalidated }
                try writer.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate).requireSame(as: expected)
                try verification(expected); try lifetime(); try record.requireRecorded(pairReader())
                try writer.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate).requireSame(as: expected)
                try lifetime()
            }
            func capture() throws -> Inputs {
                try lifetime()
                guard !reading else { violated = true; throw PreparationStoreError.transactionActive }
                reading = true; defer { reading = false }
                try verifySource()
                let actual = try Inputs.capture(expected: expected.activation.runtime, journal: journal,
                    verifyCurrent: verifySource, readRelay: readRelay)
                try verifySource(); return actual
            }
            let selected = try Self(snapshot: expected, current: current, candidate: candidate,
                recordedStartupPolicy: recordedStartupPolicy, inputs: capture())
            let scope = Scope(checked: {
                try selected.inputs.requireSame(as: capture()); try lifetime(); return selected
            })
            try scope.verify(); let result = try body(selected, scope); try scope.verify(); return result
        }
        return try machine.withSharedImportJournal { journal in
            if let journal {
                return try machine.withSharedImportSnapshot(journal: journal) { directory, owner in
                    try run(journal: journal, readRelay: { try Inputs.RelaySelection.read($0, directory: directory, owner: owner) })
                }
            }
            return try run(journal: nil, readRelay: { _ in throw SharedSetupImportError.wrongScope })
        }
    }
}
