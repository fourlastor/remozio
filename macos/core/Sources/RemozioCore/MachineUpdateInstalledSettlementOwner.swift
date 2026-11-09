import Darwin
import Foundation
import Synchronization

/// Composes the live installed owners and the terminal writer under the original closed admission.
final class MachineUpdateInstalledSettlementOwner: Sendable {
    private let coordinator: MachineUpdateInstalledReadinessCoordinator
    private let reader: MachineUpdateInstalledSettlementReader
    private let terminal: MachineUpdateInstalledTerminalReadBridge
    private let commitClaimed = Mutex(false)

    fileprivate init(coordinator: MachineUpdateInstalledReadinessCoordinator,
        reader: MachineUpdateInstalledSettlementReader, terminal: MachineUpdateInstalledTerminalReadBridge) {
        self.coordinator = coordinator
        self.reader = reader
        self.terminal = terminal
    }

    static func open(configurationPath: String, plan: MachineUpdateInstalledReadinessPlan,
        candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        access: MachineUpdateRestartSharedActivity, recovery: MachineUpdateFinalizationRecoveryOwner, parent: pid_t) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard parent > 1, getppid() == parent else { throw JournalLeaseError.unsafeMetadata }
        try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        let reader = try MachineUpdateInstalledSettlementReader(configurationPath: configurationPath,
            plan: plan, candidate: candidate, directory: directory, access: access, recovery: recovery, parent: parent)
        do {
            let terminal = try MachineUpdateInstalledTerminalReadBridge(plan: plan, candidate: candidate,
                readFinishing: { try reader.readFinishing() }, readStable: { try reader.readStable() })
            let coordinator = try MachineUpdateNativeInstalledReadiness.coordinator(plan: plan, candidate: candidate,
                terminal: terminal, acquireActivity: { try access.acquireShared() })
            return .init(coordinator: coordinator, reader: reader, terminal: terminal)
        } catch {
            reader.close()
            throw error
        }
    }

    enum Outcome: Sendable {
        case peerVerified(PreparationIntentStore.StableCompletionCommit)
        case recovered(PreparationIntentStore.StableCompletionCommit, originalFailure: any Error)
    }

    struct UnconfirmedCommit: Error {
        let originalFailure: any Error
        let adoptionFailure: any Error
    }

    struct CleanupFailure: Error {
        let settlement: Result<Outcome, any Error>
        let cleanup: any Error
    }

    /// Confirms durable settlement and records whether the live peer checks also completed. The recovery owner retains admission.
    func commitStableUpdate() async throws -> Outcome {
        try commitClaimed.withLock { claimed in
            guard !claimed else { throw PreparationStoreError.invalidTransition }
            claimed = true
        }
        let outcome: Result<Outcome, any Error>
        do {
            let receipt = try await coordinator.withVerifiedReadiness { [reader, terminal] readiness in
                try terminal.settle(verifyLive: { try readiness.validate() }, write: { verify in
                    try reader.commit { stage, scope in
                        try Task.checkCancellation()
                        try reader.verifyIdentity()
                        try reader.verifyPublishedFiles()
                        try verify(stage, scope)
                        try reader.verifyIdentity()
                        try Task.checkCancellation()
                    }
                })
            }
            outcome = .success(.peerVerified(receipt))
        } catch let originalFailure {
            if reader.needsCommitAdoption(after: originalFailure) {
                do { outcome = .success(.recovered(try reader.adoptCommit(), originalFailure: originalFailure)) }
                catch { outcome = .failure(UnconfirmedCommit(originalFailure: originalFailure, adoptionFailure: error)) }
            } else { outcome = .failure(originalFailure) }
        }
        do { try await close() }
        catch { throw CleanupFailure(settlement: outcome, cleanup: error) }
        return try outcome.get()
    }

    func close() async throws {
        defer { terminal.close(); reader.close() }
        try await coordinator.close()
    }
}

private final class MachineUpdateInstalledSettlementReader: @unchecked Sendable {
    private let configurationPath: String
    private let host: InstalledAuthorityCommandConfiguration
    private let plan: MachineUpdateInstalledReadinessPlan
    private let candidate: SignedReleaseEvidence
    private let directory: ReleaseDestinationLease
    private let access: MachineUpdateRestartSharedActivity
    private let loan: MachineUpdateRestartReadinessLoan
    // Keep the original drain owner alive while this reader holds a loan.
    private let recovery: MachineUpdateFinalizationRecoveryOwner
    private let installed: ReleaseDestinationLease
    private let prepared: ReleaseDestinationLease
    private let replacement: MachineUpdateReplacementRecord
    private let configuration: MachineUpdateConfigurationEpoch.Archive
    private let backend: MachineUpdateBackendEpoch.Archive
    private let publication: MachineUpdateCompletionPublicationRecord
    private let publicationPlan: MachineUpdateCompletionPublicationPlan
    private let parent: pid_t
    private let root: AuthorityCodeEntry
    private let app: AuthorityCodeEntry
    private let bundle = URL(fileURLWithPath: MachineBootstrap.bundlePath)
    private let lock = NSRecursiveLock()
    private var closed = false
    private var commitAcknowledged = false

    init(configurationPath: String, plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, access: MachineUpdateRestartSharedActivity,
        recovery: MachineUpdateFinalizationRecoveryOwner, parent: pid_t) throws {
        guard plan.focusedAccountID == nil else { throw PreparationStoreError.invalidTransition }
        let host = try InstalledAuthorityCommandConfiguration.load(path: configurationPath)
        let paths = try RuntimePreparationPaths(accountID: host.command.accountID)
        let source = plan.view.compatibility.source.actual
        guard configurationPath == paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name,
              host.machineDirectory == MachineBootstrap.machineDirectory, directory.path == host.machineDirectory,
              source.inventory.bundlePath == MachineBootstrap.bundlePath,
              let root = host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw InstalledAuthorityCommandError.wrongInstallation
        }
        _ = try plan.selectAuthority(host: host)
        let configuration = try source.installed.configuration()
        let backend = try source.installed.backend()
        let publication = try source.installed.publicationSource()
        let publicationPlan = try source.installed.plan(candidate: candidate)
        guard publication.filesPublished, publication.inventoryState == .pending else {
            throw PreparationStoreError.invalidTransition
        }
        try publication.requirePlan(publicationPlan)
        let replacement = try MachineUpdateReplacementRecord.decode(configuration.artifact(9))
        let bundle = URL(fileURLWithPath: MachineBootstrap.bundlePath)
        let installed = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        let prepared = try ReleaseDestinationLease.acquire(path: replacement.preparedParent)
        let loan = try access.acquireShared()
        self.configurationPath = configurationPath
        self.host = host
        self.plan = plan
        self.candidate = candidate
        self.directory = directory
        self.access = access
        self.recovery = recovery
        self.installed = installed
        self.prepared = prepared
        self.replacement = replacement
        self.configuration = configuration
        self.backend = backend
        self.publication = publication
        self.publicationPlan = publicationPlan
        self.parent = parent
        self.loan = loan
        self.root = root
        self.app = app
        try verifyIdentity()
    }

    private func verifyBoundaries() throws {
        guard !closed, getuid() == 0, geteuid() == 0 else { throw InstalledAuthorityCommandError.unavailable }
        guard getppid() == parent else { throw JournalLeaseError.unsafeMetadata }
        let source = plan.view.compatibility.source.actual
        try loan.requireScope(macID: source.inventory.macID, installationID: source.inventory.installationID,
            activationAttempt: source.activation.attemptID)
        try loan.validateMachineBoundary(directory: directory, expected: source.admission.machine)
        try MachineUpdateRestartPlacement.require(replacement, installed: installed, prepared: prepared)
    }

    func verifyIdentity() throws {
        try lock.withLock {
            try verifyBoundaries()
            let source = plan.view.compatibility.source.actual
            guard try DynamicCodeValidation.selfPath() == bundle.appendingPathComponent(InstalledAuthorityCommandConfiguration.executablePath).path,
                  try InstalledAuthorityCommandConfiguration.load(path: configurationPath).canonicalBytes == host.canonicalBytes else {
                throw InstalledAuthorityCommandError.changedConfiguration
            }
            try DynamicCodeValidation.validateSelf(requirement: AuthoritySelfValidation.requirement(for: root))
            _ = try installed.inspectInstalledApplication(name: replacement.installedName)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try host.validateRelease(release, bundlePath: bundle.path)
            guard try DurableReleasePreparation.digest(release) == source.activation.updateID,
                  try InstallationInventory.digest(release) == InstallationInventory.digest(candidate) else {
                throw InstalledAuthorityCommandError.wrongRelease
            }
            try verifyBoundaries()
        }
    }

    func verifyPublishedFiles() throws {
        try lock.withLock {
            try MachineUpdateCompletionPublicationFiles.requireNative(publicationPlan, publication: publication,
                verifyCurrent: verifyBoundaries)
            try MachineUpdateCompletionPublicationFiles.requireBackendMetadataNative(backend: backend,
                configuration: configuration, verifyCurrent: verifyBoundaries)
        }
    }

    func readFinishing() throws -> MachineUpdateInstalledReadinessPlan {
        try withMachine { machine in
            let current = try machine.withCurrentMachineUpdateReadiness(candidate: candidate, directory: directory, loan: loan) {
                try MachineUpdateInstalledReadinessPlan(scope: $0, candidate: candidate)
            }
            try verifyPublishedFiles()
            return current
        }
    }

    func readStable() throws -> MachineUpdateStableReleaseSnapshot {
        try withMachine { machine in
            let current = try machine.stableMachineUpdateSnapshot(candidate: candidate)
            try verifyPublishedFiles()
            return current
        }
    }

    func commit(_ verify: (PreparationIntentStore.CompletionIntentStorageStage, PreparationIntentStore.StableCompletionScope) throws -> Void)
        throws -> PreparationIntentStore.StableCompletionCommit {
        try withMachine { machine in
            let receipt = try machine.commitStableMachineUpdate(expected: plan, candidate: candidate, directory: directory,
                loan: loan, verifyScoped: verify)
            commitAcknowledged = true
            return receipt
        }
    }

    func needsCommitAdoption(after error: any Error) -> Bool {
        error as? PreparationStoreError == .stableCommitUnconfirmed || lock.withLock { commitAcknowledged }
    }

    /// Resolves a lost acknowledgment with the original loan, even when the task was cancelled after COMMIT.
    func adoptCommit() throws -> PreparationIntentStore.StableCompletionCommit {
        try withMachine { machine in
            try machine.adoptStableMachineUpdate(expected: plan, candidate: candidate, directory: directory, loan: loan) { _, _ in
                try verifyIdentity()
                try verifyPublishedFiles()
                try verifyIdentity()
            }
        }
    }

    private func withMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
        try lock.withLock {
            try verifyIdentity()
            let machine = try PreparationIntentStore.open(directoryPath: host.machineDirectory, macID: host.command.macID)
            do {
                let result = try body(machine)
                try machine.close()
                try verifyIdentity()
                return result
            } catch {
                try? machine.close()
                throw error
            }
        }
    }

    func close() {
        lock.withLock {
            guard !closed else { return }
            closed = true
            loan.close()
            access.close()
            installed.close()
            prepared.close()
            directory.close()
        }
    }

    deinit { close() }
}
