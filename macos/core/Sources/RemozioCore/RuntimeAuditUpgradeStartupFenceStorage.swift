import Darwin
import Foundation

/// Fixed interruption marker operations. The caller must hold its verified owner and live runtime barriers throughout.
enum RuntimeAuditUpgradeStartupFenceStorage {
    static func publish(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                        installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                        verifyOwnerAndBarrier: () throws -> Void) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)
        let directory = try openNative(expected); defer { directory.close() }
        return try publishCopy(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            directory: directory, owner: 0, verifyOwnerAndBarrier: verifyOwnerAndBarrier)
    }
    static func removeAfterMetadataCommit(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                                         installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                                         verifyOwnerBarrierAndTargets: () throws -> Void) throws -> GatewaySettingsFenceRemoval.Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)
        let directory = try openNative(expected); defer { directory.close() }
        return try removeCopy(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            directory: directory, owner: 0, verifyOwnerBarrierAndTargets: verifyOwnerBarrierAndTargets)
    }
    private static func openNative(_ expected: RuntimeAuditUpgradeCutoverRecord) throws -> ProtectedSetupDirectory {
        let path = try RuntimePreparationPaths(accountID: expected.graph.upgrade.intent.source.services.accountID).serviceDirectory
        return try .init(anchor: "/", relativePath: String(path.dropFirst()), owner: 0, visibility: .sharedMetadata, createIfMissing: false)
    }
    static func publishOwned(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                             installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                             directory: ProtectedSetupDirectory, owner: uid_t, verifyOwnerAndBarrier: () throws -> Void,
                             didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        guard owner > 0, owner < UInt32.max else { throw JournalLeaseError.unsafeMetadata }
        return try publishCopy(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            directory: directory, owner: owner, verifyOwnerAndBarrier: verifyOwnerAndBarrier, didStage: didStage)
    }
    static func removeOwned(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                            installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                            directory: ProtectedSetupDirectory, owner: uid_t, verifyOwnerBarrierAndTargets: () throws -> Void,
                            didValidate: () throws -> Void = {}, didRemove: () throws -> Void = {}) throws -> GatewaySettingsFenceRemoval.Result {
        guard owner > 0, owner < UInt32.max else { throw JournalLeaseError.unsafeMetadata }
        return try removeCopy(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            directory: directory, owner: owner, verifyOwnerBarrierAndTargets: verifyOwnerBarrierAndTargets,
            didValidate: didValidate, didRemove: didRemove)
    }
    private static func verify(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                               installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                               directory: ProtectedSetupDirectory, owner: uid_t, verifyOwner: () throws -> Void) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        try RuntimeAuditUpgradeRecord.validatePreparation(expected.graph.upgrade.intent, release: installedRelease, policy: currentPolicy)
        try verifyOwner(); try machine.validateStorageLease(); try directory.validate()
        guard try machine.runtimeAuditCutover(accountID: expected.graph.upgrade.intent.source.services.accountID) == expected else {
            throw PreparationStoreError.staleRevision
        }
    }
    private static func publishCopy(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                                    installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                                    directory: ProtectedSetupDirectory, owner: uid_t, verifyOwnerAndBarrier: () throws -> Void,
                                    didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        guard expected.phase != .metadataCommitted else { throw PreparationStoreError.invalidTransition }
        let bytes = try RuntimeAuditUpgradeStartupFence(expected).encoded
        func check() throws { try verify(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            directory: directory, owner: owner, verifyOwner: verifyOwnerAndBarrier) }
        try check()
        return try AdministrativeSetupPublication.publish(bytes, file: .auditUpgradeStartupFence, directory: directory,
            owner: owner, verify: check, didStage: didStage)
    }
    private static func removeCopy(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeCutoverRecord,
                                   installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                                   directory: ProtectedSetupDirectory, owner: uid_t, verifyOwnerBarrierAndTargets: () throws -> Void,
                                   didValidate: () throws -> Void = {}, didRemove: () throws -> Void = {}) throws -> GatewaySettingsFenceRemoval.Result {
        guard expected.phase == .metadataCommitted else { throw PreparationStoreError.invalidTransition }
        let bytes = try RuntimeAuditUpgradeStartupFence(expected).encoded
        func check() throws { try verify(machine: machine, expected: expected, installedRelease: installedRelease, currentPolicy: currentPolicy,
            directory: directory, owner: owner, verifyOwner: verifyOwnerBarrierAndTargets) }
        try check()
        return try GatewaySettingsFenceRemoval.removeAuditStartupFence(bytes, directory: directory, owner: owner,
            verifyCurrent: check, didValidate: didValidate, didRemove: didRemove)
    }
}
