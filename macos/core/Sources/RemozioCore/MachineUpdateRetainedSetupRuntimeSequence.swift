import Darwin
import Foundation

/// Sequences retained setup owners. Native providers and authenticated callers remain separate responsibilities.
enum MachineUpdateRetainedSetupRuntimeSequence {
    typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    typealias Frame = PreparationIntentStore.RetainedImportFrame
    typealias Material = MachineUpdateRetainedSetupMaterialSnapshot
    typealias Policy = MachineUpdateRetainedSetupPolicySnapshot
    typealias MachineBody = (PreparationIntentStore) throws -> Frame
    typealias UseMachine = (@escaping MachineBody) throws -> Frame
    /// Each provider uses its existing owner, lends actual frames, and closes its machine before returning.
    struct Providers {
        let material: (Material, @escaping (Material) throws -> Void) throws -> RuntimePreparationState
        let policy: (Policy, @escaping (Policy) throws -> Void) throws -> Policy
        let publication: (Policy, @escaping (Policy) throws -> Void) throws -> Policy
        let acknowledgement: (Frame, @escaping (Frame) throws -> Void) throws -> (frame: Frame, advanced: Bool)
    }
    static func prepare(owner: LocalAccountIdentity, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool, useMachine: @escaping UseMachine,
        providers: Providers, verifyCurrent: @escaping (Entry) throws -> Void,
        didCapture: @escaping (Frame) throws -> Void = { _ in }) throws -> Frame {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self()
        var active = true, providing = false, violated = false, captures = 0
        defer { active = false }
        func lifetime() throws {
            guard active, !violated, getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            try admission.validate()
        }
        func same(_ actual: Frame, _ expected: Frame) throws {
            try actual.entry.requireSame(as: expected.entry); try actual.inputs.requireSame(as: expected.inputs)
        }
        func entry(_ value: Policy) throws -> Entry {
            try .init(runtime: value.activation.runtime, activation: value.activation.state, intent: value.intent, candidate: candidate)
        }
        func capture() throws -> Frame {
            try lifetime(); guard !providing, captures < 6 else { throw PreparationStoreError.transactionActive }
            captures += 1
            var lent = true, invoked = false, checked: Frame?
            defer { lent = false }
            let result = try useMachine { machine in
                try lifetime(); guard lent, !invoked else { throw JournalLeaseError.invalidated }
                invoked = true; defer { try? machine.close() }
                func read(_ journal: SharedSetupImportJournal?,
                    relay: (SharedSetupImportIntent) throws -> Inputs.RelaySelection) throws -> Frame {
                    let actual = try machine.retainedSetupInitialRuntimeEntry(owner: owner, candidate: candidate)
                    let inputs = try Inputs.capture(expected: actual.runtime, journal: journal,
                        verifyCurrent: machine.validateStorageLease, readRelay: relay)
                    try admission.validateMachineBoundary(directory: directory,
                        expected: actual.runtime.setup.source.actual.admission.machine)
                    try verifyCurrent(actual); try lifetime(); return (actual, inputs)
                }
                let actual = try machine.withSharedImportJournal { journal in
                    if let journal { return try machine.withSharedImportSnapshot(journal: journal) { path, user in
                        try read(journal, relay: { try .read($0, directory: path, owner: user) })
                    } }
                    return try read(nil, relay: { _ in throw SharedSetupImportError.wrongScope })
                }
                try machine.close(); checked = actual; return actual
            }
            try lifetime(); guard let checked else { throw JournalLeaseError.invalidated }
            try same(result, checked); try didCapture(result); try lifetime(); return result
        }
        func provider<Loan, Value>(_ run: (@escaping (Loan) throws -> Void) throws -> Value,
            verify: @escaping (Loan) throws -> Void) throws -> Value {
            try lifetime(); guard !providing else { throw PreparationStoreError.transactionActive }
            providing = true; var lent = true, checking = false, checked = false
            defer { providing = false; lent = false }
            let result = try run { actual in
                try lifetime(); guard lent, !checking else { violated = true; throw JournalLeaseError.invalidated }
                checking = true; defer { checking = false }
                do { try verify(actual); try lifetime(); checked = true } catch { violated = true; throw error }
            }
            try lifetime(); guard checked else { throw JournalLeaseError.invalidated }; return result
        }
        var current = try capture()
        func policy() throws {
            let before = current
            guard let initial = before.entry.policy else { throw RuntimePreparationError.incomplete }
            var observed = initial
            let returned = try provider({ try providers.policy(initial, $0) }, verify: { actual in
                if actual.intent == observed.intent { try actual.requireSame(as: observed) }
                else if let record = actual.intent {
                    if observed.intent == nil { try actual.requireRetention(record, from: observed) }
                    else { try actual.requireTransition(record, from: observed) }
                } else { throw PreparationStoreError.staleRevision }
                observed = actual; try verifyCurrent(entry(actual))
            })
            try returned.requireSame(as: observed)
            guard returned.intent?.phase == .recorded else { throw RuntimePreparationError.incomplete }
            current = try capture(); try current.entry.requireSame(as: entry(returned))
            try current.inputs.requireSame(as: before.inputs)
        }
        let writing = current.entry.intent?.phase == .writing
        if writing { try policy() }
        if !current.entry.runtime.state.configurationPublished {
            let before = current
            let initial = try Material(runtime: before.entry.runtime, activation: before.entry.activation)
            let returned = try provider({ try providers.material(initial, $0) }, verify: { actual in
                if before.entry.runtime.state.reference != nil { try actual.requireSame(as: initial) }
                else if let reference = actual.runtime.state.reference { try actual.requireRetained(reference, from: initial) }
                else { try actual.requireSame(as: initial) }
            })
            current = try capture()
            guard returned == current.entry.runtime.state, let reference = returned.reference else { throw RuntimePreparationError.incomplete }
            if before.entry.runtime.state.reference == nil { try current.entry.requireMaterial(reference, from: before.entry) }
            else { try current.entry.requireSame(as: before.entry) }
            try current.inputs.requireSame(as: before.inputs)
        }
        if !writing { try policy() }
        let beforePublication = current
        guard let initial = current.entry.policy, let publicationReference = initial.activation.runtime.state.reference else { throw RuntimePreparationError.incomplete }
        var observedPublication = initial
        let published = try provider({ try providers.publication(initial, $0) }, verify: { actual in
            if actual.activation.runtime.state.configurationPublished && !initial.activation.runtime.state.configurationPublished {
                try actual.requirePublication(from: initial, reference: publicationReference)
            } else { try actual.requireSame(as: initial) }
            observedPublication = actual; try verifyCurrent(entry(actual))
        })
        try published.requireSame(as: observedPublication)
        guard published.activation.runtime.state.configurationPublished else { throw RuntimePreparationError.incomplete }
        current = try capture(); try current.entry.requireSame(as: entry(published))
        try current.inputs.requireSame(as: beforePublication.inputs)
        if current.inputs.intent != nil {
            let before = current
            var observed = before
            let returned = try provider({ try providers.acknowledgement(before, $0) }, verify: { actual in
                if before.inputs.intent?.phase == .retained && actual.inputs.intent?.phase == .runtimePublished {
                    try actual.entry.requireAcknowledgement(inputs: actual.inputs, from: before.entry, previousInputs: before.inputs)
                } else { try same(actual, before) }
                observed = actual; try verifyCurrent(actual.entry)
            })
            try same(returned.frame, observed)
            if before.inputs.intent?.phase == .retained {
                guard returned.advanced else { throw SharedSetupImportError.conflict }
                try returned.frame.entry.requireAcknowledgement(inputs: returned.frame.inputs, from: before.entry, previousInputs: before.inputs)
            } else {
                guard !returned.advanced else { throw SharedSetupImportError.conflict }; try same(returned.frame, before)
            }
            current = try capture(); try same(current, returned.frame)
        }
        let final = try capture(); try same(final, current); return final
    }
}
