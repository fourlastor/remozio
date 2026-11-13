import Darwin
import Foundation

/// Observes eight derived initial files. The caller supplies actual frames and retains native custody separately.
enum MachineUpdateRetainedSetupInitialObservation {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    struct Frame: CustomStringConvertible, CustomDebugStringConvertible {
        let snapshot: Snapshot
        let binding: RuntimeRetainedSetupReleaseBinding
        let bundle: RuntimeConfigurationBundle
        let material: RuntimePreparationMaterial
        let inputs: Inputs
        var description: String { "RetainedSetupInitialObservationFrame(redacted)" }
        var debugDescription: String { description }
    }
    /// One callback loan. Its checks perform no machine, policy, import, relay or material query.
    struct Scope: CustomStringConvertible, CustomDebugStringConvertible {
        fileprivate let check: (Bool) throws -> Void
        fileprivate let leave: () -> Void
        let snapshot: Snapshot
        let artifact: Artifact?
        var description: String { "RetainedSetupInitialObservationScope(redacted)" }
        var debugDescription: String { description }
        func requireActive() throws { try check(false) }
        func withActive<Result>(_ body: () throws -> Result) throws -> Result {
            try check(true); defer { leave() }
            let result = try body(); try requireActive(); return result
        }
    }
    struct Observation {
        fileprivate let checked: (Snapshot) throws -> Frame
        /// The caller lends its actual transaction frame. This value grants no writer or startup authority.
        func read(_ actual: Snapshot) throws -> Frame { try checked(actual) }
    }
    /// Opens actual input storage once. Writer callbacks must not call public machine readers from verifyCurrent.
    static func withCurrent<Result>(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        readPolicyBoundary: @escaping () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyCurrent: @escaping (Snapshot) throws -> Void, verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
        readMaterial: @escaping (Scope) throws -> RuntimePreparationMaterial,
        verifyActivity: @escaping (ServiceReleaseActivityReference, Scope) throws -> Void,
        readArtifact: @escaping (Artifact, Scope) throws -> Data?,
        inspectInputs: (Inputs) throws -> Void = { _ in },
        body: (Observation) throws -> Result) throws -> Result {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        guard let record = expected.intent, record.phase == .recorded,
              let reference = expected.activation.runtime.state.reference, reference.serviceActivity != nil else {
            throw RuntimeActivationError.incomplete
        }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self()
        let boundary = expected.activation.runtime.setup.source.actual.admission.machine
        var active = true, observing = false, violated = false, observations = 0
        weak var writer = machine
        defer { active = false; writer = nil }
        func lifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  active, !violated, writer != nil else { throw JournalLeaseError.invalidated }
            try admission.validateMachineBoundary(directory: directory, expected: boundary)
        }
        func run(journal: SharedSetupImportJournal?,
            readRelay: (SharedSetupImportIntent) throws -> Inputs.RelaySelection) throws -> Result {
            let inputs = try Inputs.capture(expected: expected.activation.runtime, journal: journal,
                verifyCurrent: lifetime, readRelay: readRelay)
            try lifetime(); try inspectInputs(inputs); try lifetime()
            var retainedMaterial: Data?
            func loan<Value>(_ actual: Snapshot, artifact: Artifact? = nil, _ callback: (Scope) throws -> Value) throws -> Value {
                var lent = true, checking = false, operating = false
                defer { lent = false }
                let scope = Scope(check: { enter in
                    try lifetime(); guard lent else { throw JournalLeaseError.invalidated }
                    guard !checking, !enter || !operating else { violated = true; throw PreparationStoreError.transactionActive }
                    checking = true; defer { checking = false }
                    if enter { operating = true }
                    try lifetime()
                }, leave: { operating = false }, snapshot: actual, artifact: artifact)
                try scope.requireActive(); let value = try callback(scope); try scope.requireActive(); return value
            }
            let observation = Observation(checked: { actual in
                try lifetime()
                guard !observing, observations < 10 else { violated = true; throw PreparationStoreError.transactionActive }
                observing = true; observations += 1; defer { observing = false }
                do {
                    if actual.activation.runtime.state.configurationPublished && !expected.activation.runtime.state.configurationPublished {
                        try actual.requirePublication(from: expected, reference: reference)
                    } else { try actual.requireSame(as: expected) }
                    try verifyCurrent(actual); try lifetime()
                    try verifyServices(actual.activation.runtime.plan); try lifetime()
                    let current = try readPolicyBoundary(); try lifetime(); try record.requireRecorded(current)
                    let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: actual, current: current, candidate: candidate)
                    let first = try loan(actual, readMaterial), bytes = try first.encoded
                    guard try first.reference == reference, try first.services.encoded == actual.activation.runtime.plan.encoded,
                          let activity = first.serviceActivity else { throw RuntimePreparationError.conflictingMaterial }
                    if let retainedMaterial, bytes != retainedMaterial { throw RuntimePreparationError.conflictingMaterial }
                    try loan(actual) { try verifyActivity(activity, $0) }
                    let bundle = try RuntimeConfigurationBundle.retainedSetupInitialObservation(snapshot: actual,
                        current: current, candidate: candidate, inputs: inputs)
                    let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: first)
                    guard artifacts.count == 8, Set(artifacts.map(\.path)).count == 8 else { throw RuntimePreparationError.incomplete }
                    for artifact in artifacts {
                        let bytes = try loan(actual, artifact: artifact) { try readArtifact(artifact, $0) }
                        guard bytes == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
                    }
                    let second = try loan(actual, readMaterial)
                    guard try second.encoded == bytes else { throw RuntimePreparationError.conflictingMaterial }
                    try loan(actual) { try verifyActivity(activity, $0) }
                    try verifyServices(actual.activation.runtime.plan); try lifetime()
                    let final = try readPolicyBoundary(); try lifetime(); try record.requireRecorded(final)
                    try binding.requireSourceForPublication(actual, current: final, candidate: candidate)
                    try verifyCurrent(actual); try lifetime(); retainedMaterial = bytes
                    return Frame(snapshot: actual, binding: binding, bundle: bundle, material: first, inputs: inputs)
                } catch { violated = true; throw error }
            })
            try lifetime(); let result = try body(observation); try lifetime(); return result
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
