import Darwin
import Foundation
import RemozioProtocol

/// Verifies native custody around policy frames. Frame owns actual store reads and transaction loans.
enum MachineUpdateRetainedSetupPolicyNativeContext {
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Verify = () throws -> Void
    /// Owned controls prove ordering only. They cannot create a NativeContext.
    struct Controls {
        let validateCustody: Verify
        let inspectRelease: () throws -> SignedReleaseEvidence
        let validateExecutingCode: Verify
        let lookupOwner: (UInt32) throws -> LocalAccountIdentity
        let validateServices: (Snapshot) throws -> Void
        let readMaterial: (AccountPreparationIntent) throws -> Data
        let validateActivity: (AccountPreparationIntent, ServiceReleaseActivityReference, @escaping Verify) throws -> Void
    }
    final class Context {
        private let processID = getpid(), thread = pthread_self()
        private var body: ((Snapshot) throws -> Void)?
        private var approved: Snapshot
        private var executing = false
        fileprivate init(expected: Snapshot, body: @escaping (Snapshot) throws -> Void) { approved = expected; self.body = body }
        fileprivate func requireActive() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard body != nil else { throw JournalLeaseError.invalidated }
        }
        func verify(_ actual: Snapshot) throws {
            try requireActive()
            guard !executing, let body else { expire(); throw JournalLeaseError.invalidated }
            executing = true; defer { executing = false }
            do {
                if actual.intent == approved.intent { try actual.requireSame(as: approved) }
                else if let intent = actual.intent {
                    if approved.intent == nil { try actual.requireRetention(intent, from: approved) }
                    else { try actual.requireTransition(intent, from: approved) }
                } else { throw PreparationStoreError.staleRevision }
                try body(actual); try requireActive(); approved = actual
            } catch { expire(); throw error }
        }
        fileprivate func verifyLast() throws { try requireActive(); try verify(approved) }
        fileprivate func expire() { body = nil }
    }
    /// Only the real Root factory constructs this scope. Every resource loan ends with the scope.
    final class NativeContext {
        private let context: Context
        private let directory: ReleaseDestinationLease
        private let admission: UpdateOrdinaryAdmissionLease
        fileprivate init(_ context: Context, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease) {
            self.context = context; self.directory = directory; self.admission = admission
        }
        func verify(_ actual: Snapshot) throws { try context.verify(actual) }
        func withResources<Value>(_ body: (ReleaseDestinationLease, UpdateOrdinaryAdmissionLease) throws -> Value) throws -> Value {
            try context.verifyLast(); let value = try body(directory, admission); try context.verifyLast(); return value
        }
    }
    /// Opens no journal and calls no policy writer. Real native execution remains an attended check.
    static func withNativeScope<Value>(machineDirectory: String, expected: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, perform: (NativeContext) throws -> Value) throws -> Value {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let initial = try requireExpected(expected, candidate: candidate)
        let original = expected.activation.runtime.setup.source.actual
        guard machineDirectory == MachineBootstrap.machineDirectory, original.inventory.bundlePath == MachineBootstrap.bundlePath,
              !original.candidate.selected,
              let app = currentCodePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let setup = currentCodePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw MachineUpdateActivationError.wrongBoundary
        }
        func fresh() throws {
            let machine = try PreparationIntentStore.open(directoryPath: machineDirectory, macID: initial.macID)
            defer { try? machine.close() }
            try machine.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate).requireSame(as: expected)
            _ = try RuntimeStableCompatibilityCapture.capture(machine: machine,
                expected: expected.activation.runtime.setup.source, candidate: candidate, lookup: LocalAccountDirectory.lookup)
            try machine.retainedSetupPolicySnapshot(owner: expected.activation.runtime.setup.owner, candidate: candidate).requireSame(as: expected)
            try machine.close()
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
        let controls = Controls(validateCustody: {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try admission.validateMachineBoundary(directory: directory, expected: original.admission.machine)
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
        }, inspectRelease: { try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier) },
        validateExecutingCode: {
            let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
            guard try DynamicCodeValidation.selfPath() == original.inventory.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw RuntimeActivationError.changedScope
            }
        }, lookupOwner: LocalAccountDirectory.lookup, validateServices: { frame in
            let runtime = frame.activation.runtime
            let services = try NativeServiceAccountDirectory(accountID: runtime.preparation.accountID, ownerUID: runtime.preparation.ownerUID)
            for claim in runtime.plan.claims { try services.validateGroup(claim); try services.validateUser(claim, ownerUID: runtime.preparation.ownerUID) }
        }, readMaterial: { account in
            let paths = try RuntimePreparationPaths(accountID: account.accountID)
            return try ProtectedServiceConfiguration.read(path: paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name)
        }, validateActivity: { account, activity, current in
            try RuntimeMaterialPreparation.validateServiceActivity(account: account, activity: activity, verifyCurrent: current)
        })
        return try withOwnedContext(expected: expected, candidate: candidate, currentCodePolicy: currentCodePolicy,
            controls: controls) { try perform(NativeContext($0, directory: directory, admission: admission)) }
    }
    /// Checks no store. Frame supplies actual reads or a checked transaction frame before invoking this verifier.
    static func withOwnedContext<Value>(expected: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, controls: Controls, perform: (Context) throws -> Value) throws -> Value {
        _ = try requireExpected(expected, candidate: candidate)
        let context = Context(expected: expected) { frame in
            func metadata() throws {
                try controls.validateCustody()
                try requireRelease(controls.inspectRelease(), approved: frame, candidate: candidate, currentCodePolicy: currentCodePolicy)
                try controls.validateCustody(); try controls.validateExecutingCode(); try controls.validateCustody()
                try frame.activation.runtime.setup.requireOwner(controls.lookupOwner(frame.activation.runtime.setup.owner.uid))
                try controls.validateCustody(); try controls.validateServices(frame); try controls.validateCustody()
            }
            try metadata()
            let account = frame.activation.runtime.preparation, bytes = try controls.readMaterial(frame.activation.runtime.preparation)
            try metadata(); let activity = try requireMaterial(bytes, approved: frame)
            try withActivityVerification(metadata) { current in try controls.validateActivity(account, activity, current) }
            try metadata(); guard try controls.readMaterial(account) == bytes else { throw RuntimePreparationError.conflictingMaterial }
            try metadata()
        }
        defer { context.expire() }
        try context.verify(expected); let value = try perform(context); try context.verifyLast(); return value
    }
    private final class ActivityVerification {
        let processID = getpid(), thread = pthread_self()
        var body: Verify?
        var executing = false
        init(_ body: @escaping Verify) { self.body = body }
        func verify() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
            guard !executing, let body else { self.body = nil; throw JournalLeaseError.invalidated }
            executing = true; defer { executing = false }
            do { try body(); guard self.body != nil else { throw JournalLeaseError.invalidated } }
            catch { self.body = nil; throw error }
        }
    }
    private static func withActivityVerification<Value>(_ verify: Verify, perform: (@escaping Verify) throws -> Value) throws -> Value {
        try withoutActuallyEscaping(verify) { body in
            let loan = ActivityVerification(body); defer { loan.body = nil }
            try loan.verify(); let value = try perform(loan.verify); try loan.verify(); return value
        }
    }
    static func requireRelease(_ release: SignedReleaseEvidence, approved: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy) throws {
        let actual = approved.activation.runtime.setup.source.actual
        try actual.inventory.compareRelease(release)
        guard try InstallationInventory.digest(release) == InstallationInventory.digest(candidate) else { throw RuntimeActivationError.changedScope }
        try actual.seal.requireCurrentInventory(actual.inventory, epoch: actual.installed, candidate: release)
        try MachineUpdateRetainedSetupPolicyStorage.requireFormats(release)
        try ReleaseGenerationPreflight.validate(release, against: currentCodePolicy)
        for role in [AuthorityCodeRole.app, .setupController] {
            guard let entry = currentCodePolicy.entries.first(where: { $0.role == role && $0.active }),
                  let component = release.manifest.components.first(where: { $0.role == role }),
                  component.teamID == entry.teamID, component.identifier == entry.identifier,
                  component.generation == entry.installedGeneration, release.codeDirectoryHashes[role] == entry.codeDirectoryHash else {
                throw RuntimeActivationError.changedScope
            }
        }
    }
    static func requireMaterial(_ bytes: Data, approved: Snapshot) throws -> ServiceReleaseActivityReference {
        let material = try RuntimePreparationMaterial.decode(bytes), runtime = approved.activation.runtime
        try material.services.validate(account: runtime.preparation)
        guard try material.reference == runtime.state.reference, try material.services.encoded == runtime.plan.encoded,
              let activity = material.serviceActivity else { throw RuntimePreparationError.conflictingMaterial }
        return activity
    }
    private static func requireExpected(_ expected: Snapshot, candidate: SignedReleaseEvidence) throws -> AuthorityInitializationIntent {
        try expected.requireSame(as: .init(activation: expected.activation, intent: expected.intent, candidate: candidate))
        let runtime = expected.activation.runtime
        guard MachineUpdateRetainedSetupPolicyStorage.stableSchemaVersions.contains(runtime.setup.source.actual.schemaVersion),
              let initial = runtime.setup.account?.initialization, initial.complete,
              initial.macID == runtime.preparation.macID, initial.installationID == runtime.preparation.installationID,
              initial.accountID == runtime.preparation.accountID, initial.initializationBytes == runtime.preparation.initializationBytes,
              runtime.state.reference?.serviceActivity != nil else { throw RuntimeActivationError.incomplete }
        return initial
    }
}
