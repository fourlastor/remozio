import Darwin
import Foundation
import RemozioProtocol

/// Authenticates fresh native reads and sealed writer loans. The private writer authorizes each changed frame.
enum MachineUpdateRetainedSetupPromotionNativeContext {
    typealias Snapshot = MachineUpdateRetainedSetupCompletionSnapshot
    typealias Verify = () throws -> Void

    /// Owned controls exercise ordering. They grant no native identity, placement or admission authority.
    struct Controls {
        let openMachine: () throws -> PreparationIntentStore
        let lookupOwner: (UInt32) throws -> LocalAccountIdentity
        let validateCustody: Verify
        let inspectRelease: () throws -> SignedReleaseEvidence
        let validateExecutingCode: Verify
        let validateServices: (Snapshot) throws -> Void
        let readMaterial: (AccountPreparationIntent) throws -> Data
        let validateActivity: (AccountPreparationIntent, ServiceReleaseActivityReference, @escaping Verify) throws -> Void
    }

    /// A synchronous context. Retaining it never retains permission to use its closed resources.
    final class Context {
        private let processID = getpid()
        private let thread = pthread_self()
        private let lock = NSRecursiveLock()
        private var body: ((Snapshot, PreparationIntentStore.RetainedSetupPromotionFrameLoan?) throws -> Void)?
        private var writerFrame: PreparationIntentStore.RetainedSetupPromotionFrameLoan?
        private var approved: Snapshot?
        private var executing = false
        fileprivate init(_ body: @escaping (Snapshot, PreparationIntentStore.RetainedSetupPromotionFrameLoan?) throws -> Void) { self.body = body }

        func verify(_ frame: Snapshot) throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            try lock.withLock {
                guard !executing, let body else { expire(); throw JournalLeaseError.invalidated }
                executing = true; defer { executing = false }
                do {
                    try body(frame, writerFrame)
                    guard self.body != nil else { throw JournalLeaseError.invalidated }
                    approved = frame
                } catch { expire(); throw error }
            }
        }
        fileprivate func requireActive() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            try lock.withLock { guard body != nil else { throw JournalLeaseError.invalidated } }
        }
        fileprivate func withWriterFrame<Value>(_ loan: PreparationIntentStore.RetainedSetupPromotionFrameLoan,
            perform: () throws -> Value) throws -> Value {
            try requireActive()
            return try lock.withLock {
                guard !executing, writerFrame == nil else { throw JournalLeaseError.invalidated }
                writerFrame = loan; defer { writerFrame = nil }
                let value = try perform(); try verifyLast(); return value
            }
        }
        fileprivate func verifyLast() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            try lock.withLock {
                guard let approved else { throw JournalLeaseError.invalidated }
                try verify(approved)
            }
        }
        fileprivate func expire() { lock.withLock { body = nil; approved = nil; writerFrame = nil } }
    }

    /// Proves native custody only during its enclosing scope. Owned contexts cannot construct this type.
    final class NativeContext {
        private let context: Context
        fileprivate init(_ context: Context) { self.context = context }
        func verify(_ frame: Snapshot) throws { try context.verify(frame) }
        func requireActive() throws { try context.requireActive() }
        func withWriterFrame<Value>(_ loan: PreparationIntentStore.RetainedSetupPromotionFrameLoan,
            perform: () throws -> Value) throws -> Value { try context.withWriterFrame(loan, perform: perform) }
    }

    /// Opens no authority pair and exposes no registration, policy writer or startup operation.
    static func withNativeScope<Value>(machineDirectory: String, expected: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, perform: (NativeContext) throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let initial = try requireExpected(expected, candidate: candidate, currentCodePolicy: currentCodePolicy)
        _ = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: initial.accountID,
            journalPath: initial.journalPath, continuityPath: initial.continuityPath)
        let original = expected.activation.runtime.setup.source.actual
        guard machineDirectory == MachineBootstrap.machineDirectory, original.inventory.bundlePath == MachineBootstrap.bundlePath,
              !original.candidate.selected,
              let app = currentCodePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let setup = currentCodePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw MachineUpdateActivationError.wrongBoundary
        }
        func fresh() throws {
            try readFresh(approved: expected, candidate: candidate,
                openMachine: { try PreparationIntentStore.open(directoryPath: machineDirectory, macID: initial.macID) },
                lookupOwner: LocalAccountDirectory.lookup).requireSame(as: expected)
        }
        try fresh()
        let directory = try ReleaseDestinationLease.acquire(path: machineDirectory)
        defer { directory.close() }
        try fresh()
        let admission = try UpdateOrdinaryAdmissionLease.open(machineDirectory: machineDirectory, expected: original.admission.machine)
        defer { admission.close() }
        try fresh()
        let bundle = URL(fileURLWithPath: original.inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        try fresh()
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        try fresh()
        let identity = try placement.preparationCopyIdentity(name: bundle.lastPathComponent)
        try fresh()
        let controls = Controls(openMachine: {
            try PreparationIntentStore.open(directoryPath: machineDirectory, macID: initial.macID)
        }, lookupOwner: LocalAccountDirectory.lookup, validateCustody: {
            try admission.validateMachineBoundary(directory: directory, expected: original.admission.machine)
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else {
                throw JournalLeaseError.identityChanged
            }
        }, inspectRelease: {
            try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
        }, validateExecutingCode: {
            let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
            guard try DynamicCodeValidation.selfPath() == original.inventory.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw RuntimeActivationError.changedScope
            }
        }, validateServices: { frame in
            let runtime = frame.activation.runtime
            let services = try NativeServiceAccountDirectory(accountID: runtime.preparation.accountID, ownerUID: runtime.preparation.ownerUID)
            for claim in runtime.plan.claims {
                try services.validateGroup(claim); try services.validateUser(claim, ownerUID: runtime.preparation.ownerUID)
            }
        }, readMaterial: { account in
            let paths = try RuntimePreparationPaths(accountID: account.accountID)
            return try ProtectedServiceConfiguration.read(path: paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name)
        }, validateActivity: { account, activity, current in
            try RuntimeMaterialPreparation.validateServiceActivity(account: account, activity: activity, verifyCurrent: current)
        })
        return try withOwnedContext(expected: expected, candidate: candidate, currentCodePolicy: currentCodePolicy,
            controls: controls) { try perform(NativeContext($0)) }
    }

    /// Fixture connections still use the real store readers. No callback can provide an unchecked snapshot or writer view.
    static func withOwnedContext<Value>(expected: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, controls: Controls, perform: (Context) throws -> Value) throws -> Value {
        _ = try requireExpected(expected, candidate: candidate, currentCodePolicy: currentCodePolicy)
        let context = Context { approved, writer in
            try requireApproved(approved, from: expected, candidate: candidate)
            func frame() throws {
                try controls.validateCustody()
                if let writer { try writer.verify(approved) }
                else {
                    let actual = try readFresh(approved: approved, candidate: candidate,
                        openMachine: controls.openMachine, lookupOwner: controls.lookupOwner)
                    try actual.requireSame(as: approved)
                }
                try controls.validateCustody()
            }
            func external<Result>(_ read: () throws -> Result) throws -> Result {
                try frame(); let value = try read(); try frame(); return value
            }
            func metadata() throws {
                try frame()
                let release = try external(controls.inspectRelease)
                try requireRelease(release, approved: approved, candidate: candidate, currentCodePolicy: currentCodePolicy)
                try external(controls.validateExecutingCode)
                let owner = try external { try controls.lookupOwner(approved.activation.runtime.setup.owner.uid) }
                try approved.activation.runtime.setup.requireOwner(owner)
                try external { try controls.validateServices(approved) }
                try frame()
            }
            try MachineUpdateRetainedSetupPromotionNativeSupport.withScopedVerification(metadata) { current in
                try current()
                let account = approved.activation.runtime.preparation
                let bytes = try external { try controls.readMaterial(account) }
                let activity = try requireMaterial(bytes, approved: approved)
                try current()
                try controls.validateActivity(account, activity, current)
                try current()
                guard try external({ try controls.readMaterial(account) }) == bytes else {
                    throw RuntimePreparationError.conflictingMaterial
                }
                try current()
            }
        }
        defer { context.expire() }
        try context.verify(expected)
        let value = try perform(context)
        try context.verifyLast(); return value
    }

    /// Compares owned evidence values only. The native path must inspect the protected installed copy afresh.
    static func requireRelease(_ release: SignedReleaseEvidence, approved: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy) throws {
        let actual = approved.activation.runtime.setup.source.actual
        try actual.inventory.compareRelease(release)
        guard try InstallationInventory.digest(release) == InstallationInventory.digest(candidate) else {
            throw RuntimeActivationError.changedScope
        }
        try actual.seal.requireCurrentInventory(actual.inventory, epoch: actual.installed, candidate: release)
        try RuntimeRetainedSetupActivationPlan.requireFormats(release)
        try MachineUpdateRetainedSetupPolicyStorage.requireReaderFormats(release)
        try approved.activation.requireCompletionReaderFormats(candidate: release)
        try ReleaseGenerationPreflight.validate(release, against: currentCodePolicy)
        for role in [AuthorityCodeRole.app, .setupController] {
            guard let entry = currentCodePolicy.entries.first(where: { $0.role == role && $0.active }),
                  let component = release.manifest.components.first(where: { $0.role == role }),
                  component.teamID == entry.teamID, component.identifier == entry.identifier,
                  component.generation == entry.installedGeneration,
                  release.codeDirectoryHashes[role] == entry.codeDirectoryHash else { throw RuntimeActivationError.changedScope }
        }
    }

    /// Decodes values only. Custody and recorded service activity must also be checked by the enclosing context.
    static func requireMaterial(_ bytes: Data, approved: Snapshot) throws -> ServiceReleaseActivityReference {
        let material = try RuntimePreparationMaterial.decode(bytes)
        try material.services.validate(account: approved.activation.runtime.preparation)
        guard try material.reference == approved.activation.runtime.state.reference,
              try material.services.encoded == approved.activation.runtime.plan.encoded,
              let activity = material.serviceActivity else { throw RuntimePreparationError.conflictingMaterial }
        return activity
    }

    /// Compares the owner's frame; it does not authorize a migration or protect rows for a future writer.
    static func requireApproved(_ approved: Snapshot, from initial: Snapshot, candidate: SignedReleaseEvidence) throws {
        guard let policy = try initial.intent?.committedPolicy?.snapshot().policy else { throw RuntimeActivationError.incomplete }
        _ = try requireExpected(initial, candidate: candidate, currentCodePolicy: policy)
        _ = try requireExpected(approved, candidate: candidate, currentCodePolicy: policy)
        let before = initial.activation.runtime.setup.source.actual, after = approved.activation.runtime.setup.source.actual
        guard before.schemaVersion == after.schemaVersion || before.schemaVersion == 26 && after.schemaVersion == 27 else {
            throw PreparationStoreError.staleRevision
        }
        if before.schemaVersion == after.schemaVersion, before.currentRowsDigest == after.currentRowsDigest {
            try approved.requireSame(as: initial)
        } else { try approved.requirePromotionMetadataChange(from: initial) }
    }

    private static func readFresh(approved: Snapshot, candidate: SignedReleaseEvidence,
        openMachine: () throws -> PreparationIntentStore, lookupOwner: (UInt32) throws -> LocalAccountIdentity) throws -> Snapshot {
        let machine = try openMachine()
        do {
            let owner = approved.activation.runtime.setup.owner
            let actual = try machine.retainedSetupCompletionSnapshot(owner: owner, candidate: candidate)
            try actual.requireSame(as: approved)
            _ = try RuntimeStableCompatibilityCapture.capture(machine: machine,
                expected: actual.activation.runtime.setup.source, candidate: candidate, lookup: lookupOwner)
            try machine.retainedSetupCompletionSnapshot(owner: owner, candidate: candidate).requireSame(as: actual)
            try machine.close(); return actual
        } catch { try? machine.close(); throw error }
    }

    private static func requireExpected(_ expected: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy) throws -> AuthorityInitializationIntent {
        try expected.requireSame(as: .init(activation: expected.activation, intent: expected.intent, candidate: candidate))
        let runtime = expected.activation.runtime
        guard expected.intent?.phase == .recorded, [Int64(26), 27, 28].contains(runtime.setup.source.actual.schemaVersion),
              let initial = runtime.setup.account?.initialization, initial.complete,
              initial.macID == runtime.preparation.macID, initial.installationID == runtime.preparation.installationID,
              initial.accountID == runtime.preparation.accountID, initial.initializationBytes == runtime.preparation.initializationBytes,
              runtime.state.reference?.serviceActivity != nil else { throw RuntimeActivationError.incomplete }
        guard let committed = try expected.intent?.committedPolicy?.snapshot(), committed.policy == currentCodePolicy else {
            throw RuntimeActivationError.changedScope
        }
        return initial
    }
}
