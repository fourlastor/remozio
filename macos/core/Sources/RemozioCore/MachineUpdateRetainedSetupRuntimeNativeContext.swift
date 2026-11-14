import Darwin
import Foundation

/// Native custody and owned verification have separate scopes. A11d supplies executing-code approval before any provider can use them.
enum MachineUpdateRetainedSetupRuntimeNativeContext {
    typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    typealias Frame = PreparationIntentStore.RetainedImportFrame
    typealias Material = MachineUpdateRetainedSetupMaterialSnapshot
    typealias Policy = MachineUpdateRetainedSetupPolicySnapshot
    typealias Verify = () throws -> Void
    fileprivate struct Controls {
        let validateCustody: Verify
        let validateRelease: (Entry) throws -> Void
        let validateExecutingCode: Verify
        let lookupOwner: (UInt32) throws -> LocalAccountIdentity
        let validateServices: (ServiceAccountPlan) throws -> Void
    }
    final class Context {
        private let processID = getpid(), thread = pthread_self()
        private let candidate: SignedReleaseEvidence
        private var approved: Frame?
        private var body: ((Entry, Verify) throws -> Void)?
        private var executing = false
        fileprivate init(expected: Frame, candidate: SignedReleaseEvidence, body: @escaping (Entry, Verify) throws -> Void) {
            approved = expected; self.candidate = candidate; self.body = body
        }
        private func requireActive() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0, body != nil else {
                throw JournalLeaseError.invalidated
            }
        }
        private func entry(_ value: Policy) throws -> Entry {
            try .init(runtime: value.activation.runtime, activation: value.activation.state, intent: value.intent, candidate: candidate)
        }
        private func accept(_ next: (Frame) throws -> Frame) throws {
            try requireActive()
            guard !executing, let body, let approved else { expire(); throw JournalLeaseError.invalidated }
            executing = true; defer { executing = false }
            do {
                let actual = try next(approved); try actual.inputs.requireSource(actual.entry.runtime)
                try body(actual.entry, requireActive); try requireActive(); self.approved = actual
            } catch { expire(); throw error }
        }
        func verifyEntry(_ actual: Entry) throws {
            try accept { before in try actual.requireSame(as: before.entry); return (actual, before.inputs) }
        }
        func verifyFrame(_ actual: Frame) throws {
            try accept { before in
                try actual.entry.requireSame(as: before.entry); try actual.inputs.requireSame(as: before.inputs); return actual
            }
        }
        func verifyMaterial(_ actual: Material) throws {
            try accept { before in
                let value = try Entry(runtime: actual.runtime, activation: actual.activation,
                    intent: before.entry.intent, candidate: candidate)
                if actual.runtime.state == before.entry.runtime.state { try value.requireSame(as: before.entry) }
                else if let reference = actual.runtime.state.reference { try value.requireMaterial(reference, from: before.entry) }
                else { throw PreparationStoreError.staleRevision }
                return (value, before.inputs)
            }
        }
        func verifyPolicy(_ actual: Policy) throws {
            try accept { before in
                let value = try entry(actual)
                if actual.intent == before.entry.intent { try value.requireSame(as: before.entry) }
                else if let record = actual.intent {
                    if before.entry.intent == nil { try value.requirePolicyRetention(record, from: before.entry) }
                    else { try value.requirePolicyTransition(record, from: before.entry) }
                } else { throw PreparationStoreError.staleRevision }
                return (value, before.inputs)
            }
        }
        func verifyPublication(_ actual: Policy) throws {
            try accept { before in
                let value = try entry(actual)
                if value.runtime.state == before.entry.runtime.state { try value.requireSame(as: before.entry) }
                else {
                    guard let reference = before.entry.runtime.state.reference else { throw RuntimePreparationError.incomplete }
                    try value.requirePublication(from: before.entry, reference: reference)
                }
                return (value, before.inputs)
            }
        }
        func verifyAcknowledgement(_ actual: Frame) throws {
            try accept { before in
                if actual.inputs == before.inputs { try actual.entry.requireSame(as: before.entry) }
                else { try actual.entry.requireAcknowledgement(inputs: actual.inputs, from: before.entry, previousInputs: before.inputs) }
                return actual
            }
        }
        fileprivate func currentEntry() throws -> Entry {
            try requireActive()
            guard !executing, let approved else { expire(); throw JournalLeaseError.invalidated }
            return approved.entry
        }
        fileprivate func verifyLast() throws {
            try requireActive(); guard let approved else { throw JournalLeaseError.invalidated }; try verifyFrame(approved)
        }
        fileprivate func expire() { body = nil; approved = nil }
    }
    /// Performs no machine, policy, import or relay query. The owner lends actual frames, including transaction frames.
    fileprivate static func withOwnedContext<Value>(expected: Frame, candidate: SignedReleaseEvidence, controls: Controls,
        perform: (Context) throws -> Value) throws -> Value {
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        try MachineUpdateRetainedSetupPolicyStorage.requireMaintenanceWriteFormats(expected.entry.runtime.setup.source.actual.schemaVersion, candidate: candidate)
        try Entry(runtime: expected.entry.runtime, activation: expected.entry.activation,
            intent: expected.entry.intent, candidate: candidate).requireSame(as: expected.entry)
        try expected.inputs.requireSource(expected.entry.runtime)
        let context = Context(expected: expected, candidate: candidate) { actual, active in
            func metadata() throws {
                try active(); try controls.validateCustody(); try active()
                try controls.validateRelease(actual); try controls.validateCustody(); try active()
                try controls.validateExecutingCode(); try controls.validateCustody(); try active()
                try actual.runtime.setup.requireOwner(controls.lookupOwner(actual.runtime.setup.owner.uid))
                try controls.validateCustody(); try active()
                try controls.validateServices(actual.runtime.plan); try controls.validateCustody(); try active()
            }
            try metadata()
        }
        defer { context.expire() }
        try context.verifyLast(); let result = try perform(context); try context.verifyLast(); return result
    }
    /// Only A11d's held current-authority scope will construct this approval. Custody alone cannot supply it.
    final class CurrentAuthorityApproval {
        private let processID = getpid(), thread = pthread_self()
        private var release: ((Entry, SignedReleaseEvidence) throws -> Void)?
        private var code: Verify?
        fileprivate init(release: @escaping (Entry, SignedReleaseEvidence) throws -> Void, code: @escaping Verify) {
            self.release = release; self.code = code
        }
        fileprivate func verifyRelease(_ entry: Entry, candidate: SignedReleaseEvidence) throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0, let release, code != nil else { throw JournalLeaseError.invalidated }
            try release(entry, candidate)
        }
        func verifyCode() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0, release != nil, let code else { throw JournalLeaseError.invalidated }
            try code()
        }
        fileprivate func expire() { release = nil; code = nil }
    }
    /// Root resource custody only. It proves no executing-code approval or provider authority.
    final class NativeCustody {
        private let processID = getpid(), thread = pthread_self()
        private let directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease
        private var verify: Verify?
        private var checking = false
        fileprivate init(directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, verify: @escaping Verify) {
            self.directory = directory; self.admission = admission; self.verify = verify
        }
        func requireActive() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard !checking, let verify else { expire(); throw JournalLeaseError.invalidated }
            checking = true; defer { checking = false }
            do { try verify(); guard self.verify != nil else { throw JournalLeaseError.invalidated } }
            catch { expire(); throw error }
        }
        func withResources<Value>(_ body: (ReleaseDestinationLease, UpdateOrdinaryAdmissionLease) throws -> Value) throws -> Value {
            try requireActive()
            do { let result = try body(directory, admission); try requireActive(); return result }
            catch { expire(); throw error }
        }
        fileprivate func expire() { verify = nil }
    }
    private static func withApprovalLoan<Value>(release: @escaping (Entry, SignedReleaseEvidence) throws -> Void,
        code: @escaping Verify, perform: (CurrentAuthorityApproval) throws -> Value) throws -> Value {
        let approval = CurrentAuthorityApproval(release: release, code: code)
        defer { approval.expire() }; return try perform(approval)
    }
    /// Only a real held authority scope can enter this producer. Approval expires on return and throw.
    static func withCurrentAuthorityApproval<Value>(from scope: MachineUpdateRetainedSetupRuntimeNativeAuthority.HeldScope,
        perform: (CurrentAuthorityApproval) throws -> Value) throws -> Value {
        try scope.requireActive()
        return try withApprovalLoan(release: { try scope.verifyRelease($0, candidate: $1) }, code: scope.verifyCode) { approval in
            let result = try perform(approval); try scope.requireActive(); return result
        }
    }
    final class NativeContext {
        let verification: Context
        private let custody: NativeCustody
        fileprivate init(_ context: Context, custody: NativeCustody) { verification = context; self.custody = custody }
        func withResources<Value>(_ body: (ReleaseDestinationLease, UpdateOrdinaryAdmissionLease) throws -> Value) throws -> Value {
            try custody.withResources(body)
        }
        func withMachine<Value>(opening: PreparationIntentStore.Opening, closing: MachineClosing = .provider,
            perform: (PreparationIntentStore) throws -> Value) throws -> Value {
            try withMachine(expected: verification.currentEntry(), opening: opening, closing: closing, perform: perform)
        }
        func withMachine<Value>(expected: Entry, opening: PreparationIntentStore.Opening, closing: MachineClosing = .provider,
            perform: (PreparationIntentStore) throws -> Value) throws -> Value {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try verification.verifyEntry(expected)
            return try withResources { _, _ in
                try MachineUpdateRetainedSetupRuntimeNativeContext.withOpenedMachine(open: {
                    let machine = try PreparationIntentStore(lease: InstallationStorageLease.acquire(directoryPath: MachineBootstrap.machineDirectory),
                        macID: expected.runtime.preparation.macID, maximumRecords: 64, initialize: false, opening: opening)
                    do { try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory); return machine }
                    catch { try? machine.close(); throw error }
                }, closing: closing, perform: perform)
            }
        }
    }
    enum MachineClosing { case provider, owner }
    /// Owned machines exercise the same close path. This helper cannot construct a native context or approval.
    static func withOpenedMachine<Value>(open: () throws -> PreparationIntentStore, closing: MachineClosing = .provider,
        perform: (PreparationIntentStore) throws -> Value) throws -> Value {
        let machine = try open()
        do {
            try machine.validateStorageLease(); let result = try perform(machine)
            switch closing {
            case .provider: try machine.validateStorageLease(); try machine.close()
            case .owner: try machine.requireClosedForRetainedSetupPolicyWrite()
            }
            return result
        } catch { try? machine.close(); throw error }
    }
    /// The native context accepts only the held current-authority approval capability.
    static func withNativeContext<Value>(custody: NativeCustody, approval: CurrentAuthorityApproval,
        expected: Frame, candidate: SignedReleaseEvidence, perform: (NativeContext) throws -> Value) throws -> Value {
        try custody.withResources { _, _ in
            let controls = Controls(validateCustody: custody.requireActive,
                validateRelease: { try approval.verifyRelease($0, candidate: candidate) }, validateExecutingCode: approval.verifyCode,
                lookupOwner: LocalAccountDirectory.lookup, validateServices: { plan in
                    let services = try NativeServiceAccountDirectory(accountID: plan.accountID, ownerUID: plan.ownerUID)
                    for claim in plan.claims { try services.validateGroup(claim); try services.validateUser(claim, ownerUID: plan.ownerUID) }
                })
            return try withOwnedContext(expected: expected, candidate: candidate, controls: controls) {
                try perform(NativeContext($0, custody: custody))
            }
        }
    }
    /// Opens only real fixed Root resources. It cannot construct a verification context without A11d approval.
    static func withNativeCustody<Value>(machineDirectory: String, expected: Frame, candidate: SignedReleaseEvidence,
        perform: (NativeCustody) throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let runtime = expected.entry.runtime, original = runtime.setup.source.actual
        guard machineDirectory == MachineBootstrap.machineDirectory, original.inventory.bundlePath == MachineBootstrap.bundlePath,
              !original.candidate.selected, let initial = runtime.setup.account?.initialization, initial.complete,
              initial.macID == runtime.preparation.macID, initial.installationID == runtime.preparation.installationID,
              initial.accountID == runtime.preparation.accountID, initial.initializationBytes == runtime.preparation.initializationBytes else {
            throw MachineUpdateActivationError.wrongBoundary
        }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        try MachineUpdateRetainedSetupPolicyStorage.requireMaintenanceWriteFormats(expected.entry.runtime.setup.source.actual.schemaVersion, candidate: candidate)
        func fresh() throws {
            _ = try readCustodyFrame(expected: expected, candidate: candidate, openMachine: {
                let machine = try PreparationIntentStore(lease: InstallationStorageLease.acquire(directoryPath: machineDirectory),
                    macID: initial.macID, maximumRecords: 64, initialize: false, opening: .retainedPolicyVerification)
                do { try machine.validateStorageLease(nativeDirectory: machineDirectory); return machine }
                catch { try? machine.close(); throw error }
            }, lookupOwner: LocalAccountDirectory.lookup)
        }
        try fresh()
        let directory = try ReleaseDestinationLease.acquire(path: machineDirectory); defer { directory.close() }
        let admission = try UpdateOrdinaryAdmissionLease.open(machineDirectory: machineDirectory, expected: original.admission.machine)
        defer { admission.close() }
        let bundle = URL(fileURLWithPath: original.inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path); defer { placement.close() }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let identity = try placement.preparationCopyIdentity(name: bundle.lastPathComponent)
        try fresh()
        let custody = NativeCustody(directory: directory, admission: admission) {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try admission.validateMachineBoundary(directory: directory, expected: original.admission.machine)
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
            try runtime.setup.requireOwner(LocalAccountDirectory.lookup(uid: runtime.setup.owner.uid))
            let services = try NativeServiceAccountDirectory(accountID: runtime.plan.accountID, ownerUID: runtime.plan.ownerUID)
            for claim in runtime.plan.claims { try services.validateGroup(claim); try services.validateUser(claim, ownerUID: runtime.plan.ownerUID) }
        }
        defer { custody.expire() }
        try custody.requireActive(); let result = try perform(custody); try custody.requireActive(); return result
    }
    /// Actual read-only frames only. The opener cannot supply a fabricated snapshot, and every exit closes its connection.
    static func readCustodyFrame(expected: Frame, candidate: SignedReleaseEvidence,
        openMachine: () throws -> PreparationIntentStore, lookupOwner: (UInt32) throws -> LocalAccountIdentity) throws -> Frame {
        let machine = try openMachine()
        do {
            try machine.validateStorageLease()
            let actual = try machine.retainedSetupInitialRuntimeEntry(owner: expected.entry.runtime.setup.owner, candidate: candidate)
            try actual.requireSame(as: expected.entry)
            try actual.runtime.setup.requireOwner(lookupOwner(actual.runtime.setup.owner.uid))
            for claim in try machine.retainedSetupCompatibilityOwners(expected: actual.runtime.setup.source, candidate: candidate) {
                try LocalAccountDirectory.validateOwnership(lookupOwner(claim.ownerUID), uid: claim.ownerUID, directoryID: claim.directoryID)
            }
            let inputs = try machine.withSharedImportJournal { journal in
                if let journal { return try machine.withSharedImportSnapshot(journal: journal) { path, owner in
                    try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: actual.runtime, journal: journal,
                        verifyCurrent: { try machine.validateStorageLease() }, readRelay: { try .read($0, directory: path, owner: owner) })
                } }
                return try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: actual.runtime, journal: nil,
                    verifyCurrent: { try machine.validateStorageLease() }, readRelay: { _ in throw SharedSetupImportError.wrongScope })
            }
            try inputs.requireSame(as: expected.inputs)
            try machine.retainedSetupInitialRuntimeEntry(owner: actual.runtime.setup.owner, candidate: candidate).requireSame(as: actual)
            try machine.close(); return (actual, inputs)
        } catch { try? machine.close(); throw error }
    }
    #if DEBUG
    /// Negative-only seam. No caller receives this approval before the shared producer loan has expired.
    static func expiredApprovalForTesting(bodyThrows: Bool) throws -> CurrentAuthorityApproval {
        var escaped: CurrentAuthorityApproval?
        do {
            try withApprovalLoan(release: { _, _ in throw JournalLeaseError.rootRequired }, code: { throw JournalLeaseError.rootRequired }) {
                escaped = $0; if bodyThrows { throw JournalLeaseError.invalidated }
            }
        } catch { guard bodyThrows, error as? JournalLeaseError == .invalidated else { throw error } }
        guard let escaped else { throw JournalLeaseError.invalidated }; return escaped
    }
    struct TestControls {
        let validateCustody: Verify
        let validateRelease: (Entry) throws -> Void
        let validateExecutingCode: Verify
        let lookupOwner: (UInt32) throws -> LocalAccountIdentity
        let validateServices: (ServiceAccountPlan) throws -> Void
    }
    /// Test controls cannot construct NativeCustody, CurrentAuthorityApproval or NativeContext.
    static func withTestContext<Value>(expected: Frame, candidate: SignedReleaseEvidence, controls: TestControls,
        perform: (Context) throws -> Value) throws -> Value {
        try withOwnedContext(expected: expected, candidate: candidate,
            controls: Controls(validateCustody: controls.validateCustody, validateRelease: controls.validateRelease,
                validateExecutingCode: controls.validateExecutingCode, lookupOwner: controls.lookupOwner,
                validateServices: controls.validateServices), perform: perform)
    }
    #endif
}
