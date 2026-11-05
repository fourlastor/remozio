import Darwin
import Foundation

struct RuntimeAuditUpgradeOperationAdapters {
    let fencePresent: () throws -> Bool
    let prepare: (PreparationIntentStore, ReleaseActivityToken, @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeOperation.Binding?
    let restore: (PreparationIntentStore, RuntimeAuditUpgradeGraphRecord, @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeOperation.Binding
    /// The coordinator must borrow the activity token. The operation releases it after closing the machine writer.
    let coordinator: (PreparationIntentStore, RuntimeAuditUpgradeOperation.Binding, ReleaseActivityToken, @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeCutoverCoordinator
    let restart: (RuntimeAuditUpgradeOperation.Binding, @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeRestart.Result
}

/// Serialized ownership across preparation, durable cutover and registration recovery. No saved phase recreates live authority.
final class RuntimeAuditUpgradeOperation: @unchecked Sendable {
    struct Binding { let graph: RuntimeAuditUpgradeGraph; let record: RuntimeAuditUpgradeGraphRecord }
    /// `readyToRestart` means the cutover completed: target files and metadata are durable and the startup fence is removed.
    /// `registrationObserved` reports confirmed launchd registrations only. No progress value reports or verifies service health.
    enum Progress: Equatable {
        case waitingForActivity, waitingForMachine, graphPrepared, waitingForQuiescence
        case filesChanging, filesVerified, metadataCommitted, readyToRestart
        case registrationObserved(RuntimeAuditUpgradeRestart.Result), alreadyCurrent
    }
    private let scope: SetupAuditUpgradeScope
    private let release: SignedReleaseEvidence
    private let policy: AuthorityCodePolicy
    private let activity: ReleaseActivityBarrier
    private let openMachine: () throws -> PreparationIntentStore
    private let adapters: RuntimeAuditUpgradeOperationAdapters
    private let verify: @Sendable () throws -> Void
    private let lock = NSRecursiveLock()
    private let processID = getpid()
    private var token: ReleaseActivityToken?
    private var machine: PreparationIntentStore?
    private var coordinator: RuntimeAuditUpgradeCutoverCoordinator?
    private var binding: Binding?
    private var restarting = false
    private var terminal: Progress?
    private var active = false
    private var retired = false
    private var closed = false

    static func open(scope: SetupAuditUpgradeScope) throws -> RuntimeAuditUpgradeOperation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try scope.validateLifetime()
        let policy = try scope.account.initialAuthority.codePolicy
        guard let app = policy.entries.first(where: { $0.role == .app && $0.active }) else { throw RuntimeActivationError.invalidPlan }
        let release = try SignedReleaseInspection.inspect(URL(fileURLWithPath: scope.inventory.bundlePath), teamID: app.teamID, appIdentifier: app.identifier)
        try scope.inventory.compareRelease(release)
        let activity = try ReleaseActivityBarrier.open(machineDirectory: MachineBootstrap.machineDirectory)
        let adapters = RuntimeAuditUpgradeOperationAdapters(fencePresent: {
            try ProtectedServiceConfiguration.readOptionalAuditFence(accountID: scope.account.accountID) != nil
        }, prepare: { machine, token, verify in
            try RuntimeAuditUpgradeNativePreparation.prepare(machine: machine, scope: scope, installedRelease: release,
                currentPolicy: policy, rootActivity: token, verifyOwner: verify)
        }, restore: { machine, record, verify in
            let stored = try RuntimeAuditUpgradeGraphStorage.restore(machine: machine, expected: record,
                installedRelease: release, currentPolicy: policy, verifyOwner: verify)
            let graph = try RuntimeAuditUpgradeGraph.decode(machine.runtimeAuditGraphBytes(stored), expectedDigest: stored.contentDigest,
                installedRelease: release, currentPolicy: policy, ownership: .native)
            return .init(graph: graph, record: stored)
        }, coordinator: { machine, binding, token, verify in
            try .openWithNativeDrain(machine: machine, graph: binding.graph, record: binding.record,
                installedRelease: release, currentPolicy: policy, rootActivity: token, rootActivityOwnership: .borrowed,
                verifyOwner: verify)
        }, restart: { binding, verify in
            try RuntimeAuditUpgradeRestart.resume(graph: binding.graph, record: binding.record,
                installedRelease: release, currentPolicy: policy, verifyOwner: verify)
        })
        return try .init(scope: scope, release: release, policy: policy, activity: activity,
            openMachine: { try PreparationIntentStore.open(directoryPath: MachineBootstrap.machineDirectory, macID: scope.account.macID) }, adapters: adapters)
    }
    static func openOwned(scope: SetupAuditUpgradeScope, installedRelease: SignedReleaseEvidence, activity: ReleaseActivityBarrier,
                          openMachine: @escaping () throws -> PreparationIntentStore,
                          adapters: RuntimeAuditUpgradeOperationAdapters) throws -> RuntimeAuditUpgradeOperation {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return try .init(scope: scope, release: installedRelease, policy: scope.account.initialAuthority.codePolicy,
            activity: activity, openMachine: openMachine, adapters: adapters)
    }
    private init(scope: SetupAuditUpgradeScope, release: SignedReleaseEvidence, policy: AuthorityCodePolicy,
                 activity: ReleaseActivityBarrier, openMachine: @escaping () throws -> PreparationIntentStore,
                 adapters: RuntimeAuditUpgradeOperationAdapters) throws {
        try scope.validateLifetime(); try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(release, policy: policy)
        self.scope = scope; self.release = release; self.policy = policy; self.activity = activity
        self.openMachine = openMachine; self.adapters = adapters
        verify = { try scope.validateLifetime(); try Task.checkCancellation() }
    }
    private func check(_ machine: PreparationIntentStore) throws {
        try verify(); try machine.validateStorageLease()
        guard let inventory = try machine.inventory(), inventory.macID == scope.inventory.macID,
              inventory.installationID == scope.inventory.installationID, inventory.releaseDigest == scope.inventory.releaseDigest,
              inventory.bundlePath == scope.inventory.bundlePath,
              try machine.accountPreparation(ownerUID: scope.account.ownerUID) == scope.account,
              try machine.initialization(accountID: scope.account.accountID) == scope.initialization else {
            throw AdministrativeSetupError.changedInstallation
        }
        try inventory.compareRelease(release); try verify()
    }
    /// A completed cutover with no fence needs registration recovery, not another stop or source snapshot.
    private func inspectCompleted() throws -> Bool {
        let shared = try activity.acquireShared(); defer { shared.close() }
        let store = try openMachine()
        do {
            try check(store)
            if let current = try store.runtimeAuditCutover(accountID: scope.account.accountID),
               current.phase == .metadataCommitted, try !adapters.fencePresent() {
                binding = try adapters.restore(store, current.graph, verify); try store.close()
                restarting = true; return true
            }
            try store.close(); return false
        } catch { try? store.close(); throw error }
    }
    func advance() throws -> Progress {
        guard getpid() == processID else { throw RuntimeActivationError.unavailable }
        return try lock.withLock {
            guard !closed, !retired, !active else { throw RuntimeActivationError.unavailable }
            active = true; defer { active = false }
            do {
                try verify()
                if let terminal { return terminal }
                if restarting {
                    guard let binding else { throw RuntimePreparationError.incomplete }
                    let result = try adapters.restart(binding, verify)
                    let progress = Progress.registrationObserved(result); terminal = progress; return progress
                }
                if token == nil {
                    do { if try inspectCompleted() { return .readyToRestart } }
                    catch ReleaseActivityError.busy { return .waitingForActivity }
                    catch JournalLeaseError.busy { return .waitingForMachine }
                    do { token = try activity.acquireExclusive() } catch ReleaseActivityError.busy { return .waitingForActivity }
                }
                if machine == nil {
                    do { machine = try openMachine() } catch JournalLeaseError.busy { return .waitingForMachine }
                }
                guard let machine, let token else { throw RuntimePreparationError.incomplete }
                try token.validateExclusive(); try check(machine)
                if coordinator == nil {
                    let current = try machine.runtimeAuditCutover(accountID: scope.account.accountID)
                    let existingFence = try adapters.fencePresent()
                    if let current, current.phase == .metadataCommitted, !existingFence {
                        binding = try adapters.restore(machine, current.graph, verify)
                        try machine.close(); self.machine = nil; token.close(); self.token = nil
                        restarting = true; return .readyToRestart
                    }
                    if let current, current.phase != .selected || existingFence {
                        binding = try adapters.restore(machine, current.graph, verify)
                    } else {
                        binding = try adapters.prepare(machine, token, verify)
                        if let current, let binding {
                            _ = try machine.selectRuntimeAuditCutover(binding.graph, record: binding.record, replacing: current,
                                installedRelease: release, currentPolicy: policy)
                        }
                    }
                    guard let binding else {
                        guard try machine.runtimePreparation(accountID: scope.account.accountID).reference?.auditDeliveryVersion == 1 else {
                            throw RuntimePreparationError.incomplete
                        }
                        try machine.close(); self.machine = nil; token.close(); self.token = nil
                        terminal = .alreadyCurrent; return .alreadyCurrent
                    }
                    coordinator = try adapters.coordinator(machine, binding, token, verify)
                    return .graphPrepared
                }
                guard let coordinator else { throw RuntimePreparationError.incomplete }
                switch try coordinator.advance() {
                case .waitingForQuiescence: return .waitingForQuiescence
                case .filesChanging: return .filesChanging
                case .filesVerified: return .filesVerified
                case .metadataCommitted: return .metadataCommitted
                case .eligibleForRestart:
                    // The coordinator releases its drain first. The borrowed activity token outlives the machine writer.
                    try coordinator.releaseForRestart(); self.coordinator = nil
                    try machine.close(); self.machine = nil; token.close(); self.token = nil
                    restarting = true; return .readyToRestart
                }
            } catch { retired = true; throw error }
        }
    }
    /// Rechecks the live caller before encoding an observation. This does not borrow the machine writer.
    func validateReply() throws {
        guard getpid() == processID else { throw RuntimeActivationError.unavailable }
        try lock.withLock {
            guard !closed, !retired, !active else { throw RuntimeActivationError.unavailable }
            try verify()
        }
    }
    /// Release runtime owners and the machine writer before releasing authorization and setup admission. Cleanup requires no rights.
    func close() throws {
        guard getpid() == processID else { throw RuntimeActivationError.unavailable }
        try lock.withLock {
            guard !active else { throw RuntimeActivationError.unavailable }
            guard !closed else { return }
            retired = true; active = true; defer { active = false }
            try coordinator?.close(); coordinator = nil
            try machine?.close(); machine = nil
            token?.close(); token = nil
            try scope.close(); closed = true
        }
    }
    deinit { if getpid() == processID { try? coordinator?.close(); try? machine?.close(); token?.close(); try? scope.close() } }
}
