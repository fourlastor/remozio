import Darwin
import Foundation

/// Restores a private historical copy from committed bytes. It never changes the live runtime or proves currentness.
enum RuntimeAuditUpgradeGraphStorage {
    enum Stage: CaseIterable { case metadataValidated, filePublished, fileVerified, ledgerRecorded }

    static func restore(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeGraphRecord,
                        installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                        verifyOwner: () throws -> Void) throws -> RuntimeAuditUpgradeGraphRecord {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyOwner(); try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)
        let paths = try RuntimePreparationPaths(accountID: expected.upgrade.intent.source.services.accountID)
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { directory.close() }
        return try restoreCopy(machine: machine, expected: expected, installedRelease: installedRelease,
            currentPolicy: currentPolicy, directory: directory, owner: 0, ownership: .native, verifyOwner: verifyOwner)
    }

    // The ordinary-owner seam cannot claim native placement or Root custody.
    static func restoreOwned(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeGraphRecord,
                             installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                             directory: ProtectedSetupDirectory, owner: uid_t, verifyOwner: () throws -> Void,
                             didStage: (Stage) throws -> Void = { _ in },
                             publicationStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeGraphRecord {
        guard owner > 0, owner < UInt32.max else { throw JournalLeaseError.unsafeMetadata }
        return try restoreCopy(machine: machine, expected: expected, installedRelease: installedRelease,
            currentPolicy: currentPolicy, directory: directory, owner: owner, ownership: .ordinaryOwnerFixture,
            verifyOwner: verifyOwner, didStage: didStage, publicationStage: publicationStage)
    }

    private static func restoreCopy(machine: PreparationIntentStore, expected: RuntimeAuditUpgradeGraphRecord,
                                    installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                                    directory: ProtectedSetupDirectory, owner: uid_t,
                                    ownership: RuntimeAuditUpgradeArtifactSnapshot.Ownership,
                                    verifyOwner: () throws -> Void, didStage: (Stage) throws -> Void = { _ in },
                                    publicationStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeGraphRecord {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try RuntimeAuditUpgradeGraphRecord.validateCapabilities(installedRelease, policy: currentPolicy)
        var retained = expected
        func verify() throws {
            try verifyOwner(); try machine.validateStorageLease(); try directory.validate()
            guard let current = try machine.runtimeAuditGraph(accountID: expected.upgrade.intent.source.services.accountID,
                contentDigest: expected.contentDigest), current == retained ||
                    (current.phase == .fileStored && current.upgrade == retained.upgrade) else { throw PreparationStoreError.staleRevision }
            retained = current
        }
        try verify()
        let bytes = try machine.runtimeAuditGraphBytes(retained)
        let graph = try RuntimeAuditUpgradeGraph.decode(bytes, expectedDigest: retained.contentDigest,
            installedRelease: installedRelease, currentPolicy: currentPolicy, ownership: ownership)
        try retained.validate(graph); try graph.requireOwner(owner)
        if ownership == .native {
            let paths = try RuntimePreparationPaths(accountID: graph.upgrade.intent.source.services.accountID)
            guard directory.path == paths.privateDirectory else { throw JournalLeaseError.invalidPath }
        }
        try didStage(.metadataValidated); try verify()
        let file = AdministrativeSetupPublication.File.auditUpgradeGraph(intentID: graph.upgrade.intent.id, contentDigest: graph.digest)
        _ = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner,
            verify: verify, didStage: publicationStage)
        try didStage(.filePublished); try verify()
        let readback = try ProtectedServiceConfiguration.readAuditGraph(anchor: directory.path, intentID: graph.upgrade.intent.id,
            contentDigest: graph.digest, owner: owner)
        let confirmed = try RuntimeAuditUpgradeGraph.decode(readback, expectedDigest: graph.digest,
            installedRelease: installedRelease, currentPolicy: currentPolicy, ownership: ownership)
        guard confirmed.bytes == bytes else { throw RuntimePreparationError.conflictingMaterial }
        try didStage(.fileVerified); try verify()
        retained = try machine.markRuntimeAuditGraphStored(retained, graph: graph, installedRelease: installedRelease, currentPolicy: currentPolicy)
        try didStage(.ledgerRecorded); try verify()
        return retained
    }
}
