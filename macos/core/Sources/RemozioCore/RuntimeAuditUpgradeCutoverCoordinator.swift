import Darwin
import Foundation

/// Implementations retain real runtime owners. A persisted phase or callback result cannot recreate these resources.
protocol RuntimeAuditCutoverQuiescence: AnyObject {
    /// Cheap, read-only lifetime checks for all retained locks and owners. Must not reenter the machine store.
    func validateLifetime() throws
    /// Fresh job/process, journal and management settlement checks. No stop or repair operation is allowed here.
    func validateComplete() throws
    func close() throws
}

/// Serialized durable sequence. The native drain retains runtime resources; a separate owner must restart services.
final class RuntimeAuditUpgradeCutoverCoordinator {
    enum Progress: Equatable { case waitingForQuiescence, filesChanging, filesVerified, metadataCommitted, eligibleForRestart }
    /// Borrowed activity remains with the surrounding admission lease when this coordinator closes.
    enum RootActivityOwnership { case owned, borrowed }
    private enum Placement {
        case native
        case owned([RuntimeAuditUpgradeFiles.Area: ProtectedSetupDirectory], RuntimeAuditUpgradeArtifactSnapshot.MissingImports?, uid_t)
    }
    private let machine: PreparationIntentStore
    private let graph: RuntimeAuditUpgradeGraph
    private let record: RuntimeAuditUpgradeGraphRecord
    private let release: SignedReleaseEvidence
    private let policy: AuthorityCodePolicy
    private let rootActivity: ReleaseActivityToken
    private let verifyOwner: () throws -> Void
    private let acquireQuiescence: (RuntimeAuditUpgradeCutoverRecord) throws -> (any RuntimeAuditCutoverQuiescence)?
    private let closePendingQuiescence: () throws -> Void
    private let placement: Placement
    private let processID = getpid()
    private var quiescence: (any RuntimeAuditCutoverQuiescence)?
    private var active = false
    private var retired = false
    private var closed = false
    private var eligible = false
    private var ownsRootActivity = false
    private var ownsPendingQuiescence = false

    static func open(machine: PreparationIntentStore, graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                     installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy, rootActivity: ReleaseActivityToken,
                     rootActivityOwnership: RootActivityOwnership = .owned,
                     verifyOwner: @escaping () throws -> Void,
                     acquireQuiescence: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> (any RuntimeAuditCutoverQuiescence)?,
                     closePendingQuiescence: @escaping () throws -> Void = {}) throws -> RuntimeAuditUpgradeCutoverCoordinator {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory); try graph.requireOwner(0)
        return try .init(machine: machine, graph: graph, record: record, release: installedRelease, policy: currentPolicy,
            rootActivity: rootActivity, rootActivityOwnership: rootActivityOwnership, verifyOwner: verifyOwner,
            acquireQuiescence: acquireQuiescence, closePendingQuiescence: closePendingQuiescence, placement: .native)
    }
    static func openOwned(machine: PreparationIntentStore, graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                          installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy, rootActivity: ReleaseActivityToken,
                          rootActivityOwnership: RootActivityOwnership = .owned,
                          directories: [RuntimeAuditUpgradeFiles.Area: ProtectedSetupDirectory], owner: uid_t,
                          missingImports: RuntimeAuditUpgradeArtifactSnapshot.MissingImports? = nil,
                          verifyOwner: @escaping () throws -> Void,
                          acquireQuiescence: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> (any RuntimeAuditCutoverQuiescence)?,
                          closePendingQuiescence: @escaping () throws -> Void = {}) throws -> RuntimeAuditUpgradeCutoverCoordinator {
        guard owner > 0, getuid() == owner, geteuid() == owner, graph.snapshot.ownership == .ordinaryOwnerFixture else {
            throw JournalLeaseError.unsafeMetadata
        }
        return try .init(machine: machine, graph: graph, record: record, release: installedRelease, policy: currentPolicy,
            rootActivity: rootActivity, rootActivityOwnership: rootActivityOwnership, verifyOwner: verifyOwner, acquireQuiescence: acquireQuiescence,
            closePendingQuiescence: closePendingQuiescence, placement: .owned(directories, missingImports, owner))
    }
    private init(machine: PreparationIntentStore, graph: RuntimeAuditUpgradeGraph, record: RuntimeAuditUpgradeGraphRecord,
                 release: SignedReleaseEvidence, policy: AuthorityCodePolicy, rootActivity: ReleaseActivityToken,
                 rootActivityOwnership: RootActivityOwnership,
                 verifyOwner: @escaping () throws -> Void,
                 acquireQuiescence: @escaping (RuntimeAuditUpgradeCutoverRecord) throws -> (any RuntimeAuditCutoverQuiescence)?,
                 closePendingQuiescence: @escaping () throws -> Void, placement: Placement) throws {
        self.machine = machine; self.graph = graph; self.record = record; self.release = release; self.policy = policy
        self.rootActivity = rootActivity; self.verifyOwner = verifyOwner; self.acquireQuiescence = acquireQuiescence; self.closePendingQuiescence = closePendingQuiescence; self.placement = placement
        try verifyRoot(); try machine.validateStorageLease(); try record.validate(graph)
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(release, policy: policy)
        _ = try machine.selectRuntimeAuditCutover(graph, record: record, installedRelease: release, currentPolicy: policy)
        try verifyRoot(); ownsRootActivity = rootActivityOwnership == .owned; ownsPendingQuiescence = true
    }
    private func verifyRoot() throws {
        guard !closed, getpid() == processID else { throw RuntimeActivationError.unavailable }
        // Metadata transactions validate their own lease. Their callbacks must not invoke machine-store methods.
        try rootActivity.validateExclusive(); try verifyOwner()
    }
    private func verifyLifetime() throws {
        try verifyRoot(); guard let quiescence else { throw RuntimeActivationError.unavailable }; try quiescence.validateLifetime()
    }
    private func verifyComplete() throws { try verifyLifetime(); try quiescence!.validateComplete(); try verifyLifetime() }
    private func inspect(_ expectation: RuntimeAuditUpgradeFiles.Expectation, complete: Bool) throws {
        if complete { try verifyComplete() } else { try verifyRoot() }
        let check = complete ? verifyLifetime : verifyRoot
        switch placement {
        case .native: _ = try RuntimeAuditUpgradeFiles.validateNative(graph, expectation: expectation, verifyOwnerAndBarrier: check)
        case .owned(let directories, let missing, let owner):
            _ = try RuntimeAuditUpgradeFiles.validate(graph, directories: directories, owner: owner, missingImports: missing,
                expectation: expectation, verifyOwnerAndBarrier: check)
        }
        if complete { try verifyComplete() } else { try verifyRoot() }
    }
    private func publishFence(_ current: RuntimeAuditUpgradeCutoverRecord) throws {
        switch placement {
        case .native:
            _ = try RuntimeAuditUpgradeStartupFenceStorage.publish(machine: machine, expected: current,
                installedRelease: release, currentPolicy: policy, verifyOwnerAndBarrier: verifyRoot)
        case .owned(let directories, _, let owner):
            guard let directory = directories[.services] else { throw RuntimePreparationError.incomplete }
            _ = try RuntimeAuditUpgradeStartupFenceStorage.publishOwned(machine: machine, expected: current,
                installedRelease: release, currentPolicy: policy, directory: directory, owner: owner, verifyOwnerAndBarrier: verifyRoot)
        }
    }
    private func applyFiles(_ current: RuntimeAuditUpgradeCutoverRecord) throws {
        try verifyComplete()
        switch placement {
        case .native:
            _ = try RuntimeAuditUpgradeFiles.apply(machine: machine, expected: current, graph: graph, installedRelease: release,
                currentPolicy: policy, rootActivity: rootActivity, verifyOwnerAndBarrier: verifyLifetime)
        case .owned(let directories, let missing, let owner):
            _ = try RuntimeAuditUpgradeFiles.applyOwned(machine: machine, expected: current, graph: graph, installedRelease: release,
                currentPolicy: policy, directories: directories, owner: owner, missingImports: missing,
                rootActivity: rootActivity, verifyOwnerAndBarrier: verifyLifetime)
        }
        try verifyComplete()
    }
    private func removeFence(_ current: RuntimeAuditUpgradeCutoverRecord) throws {
        let check = { try self.inspect(.targetOnly, complete: true) }
        switch placement {
        case .native:
            _ = try RuntimeAuditUpgradeStartupFenceStorage.removeAfterMetadataCommit(machine: machine, expected: current,
                installedRelease: release, currentPolicy: policy, verifyOwnerBarrierAndTargets: check)
        case .owned(let directories, _, let owner):
            guard let directory = directories[.services] else { throw RuntimePreparationError.incomplete }
            _ = try RuntimeAuditUpgradeStartupFenceStorage.removeOwned(machine: machine, expected: current,
                installedRelease: release, currentPolicy: policy, directory: directory, owner: owner, verifyOwnerBarrierAndTargets: check)
        }
    }
    func advance() throws -> Progress {
        guard !active, !closed, !retired else { throw RuntimeActivationError.unavailable }
        active = true; defer { active = false }
        do {
            try verifyRoot()
            guard let current = try machine.runtimeAuditCutover(accountID: graph.snapshot.plan.sourceAccount.accountID),
                  current.graph == record else { throw PreparationStoreError.staleRevision }
            if current.phase == .selected { try inspect(.sourceOnly, complete: false) }
            if current.phase != .metadataCommitted { try publishFence(current) }
            if quiescence == nil { quiescence = try acquireQuiescence(current) }
            guard quiescence != nil else { return .waitingForQuiescence }
            try verifyComplete()
            switch current.phase {
            case .selected:
                _ = try machine.advanceRuntimeAuditCutover(current, graph: graph, to: .filesChanging,
                    installedRelease: release, currentPolicy: policy, verifyBarrierAndArtifacts: { try self.inspect(.sourceOnly, complete: true) })
                return .filesChanging
            case .filesChanging:
                try applyFiles(current)
                _ = try machine.advanceRuntimeAuditCutover(current, graph: graph, to: .filesVerified,
                    installedRelease: release, currentPolicy: policy, verifyBarrierAndArtifacts: { try self.inspect(.targetOnly, complete: true) })
                return .filesVerified
            case .filesVerified:
                _ = try machine.commitRuntimeAuditCutover(current, graph: graph, installedRelease: release, currentPolicy: policy,
                    verifyBarrierAndTargets: { try self.inspect(.targetOnly, complete: true) })
                return .metadataCommitted
            case .metadataCommitted:
                try removeFence(current); eligible = true; return .eligibleForRestart
            }
        } catch { retired = true; throw error }
    }
    /// Release held barriers only after a freshly verified completed cutover. This does not start or report healthy services.
    func releaseForRestart() throws {
        guard !active, !closed, !retired, eligible else { throw RuntimeActivationError.unavailable }
        active = true; defer { active = false }
        do {
            try inspect(.targetOnly, complete: true)
            guard let current = try machine.runtimeAuditCutover(accountID: graph.snapshot.plan.sourceAccount.accountID),
                  current.graph == record, current.phase == .metadataCommitted else { throw PreparationStoreError.staleRevision }
            try removeFence(current)
            try releaseResources()
        } catch { retired = true; throw error }
    }
    /// Failure cleanup preserves the persisted record and startup fence. A new owner must reacquire live authority to resume.
    func close() throws {
        guard !active else { throw JournalDatabaseError.transactionActive }
        guard !closed else { return }
        try releaseResources()
    }
    private func releaseResources() throws {
        try quiescence?.close(); quiescence = nil
        if ownsPendingQuiescence { try closePendingQuiescence(); ownsPendingQuiescence = false }
        if ownsRootActivity { rootActivity.close(); ownsRootActivity = false }
        closed = true
    }
    deinit {
        try? quiescence?.close()
        if ownsPendingQuiescence { try? closePendingQuiescence() }
        if ownsRootActivity { rootActivity.close() }
    }
}
