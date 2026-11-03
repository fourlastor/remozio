import Darwin
import Foundation

/// Stages one private candidate beside the immutable source. It never replaces a live file or activates a service.
enum RuntimeAuditUpgradeStaging {
    enum Stage: CaseIterable { case sourceValidated, candidatePublished, candidateVerified, ledgerRecorded }

    static func stage(machine: PreparationIntentStore, account: AccountPreparationIntent,
                      expected: RuntimeAuditUpgradeRecord, currentPolicy: AuthorityCodePolicy,
                      installedRelease: SignedReleaseEvidence, verifyCurrent: () throws -> Void) throws -> RuntimeAuditUpgradeRecord {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        let authority = try AccountPreparationController.authorityDirectory(accountID: account.accountID)
        let path = (authority as NSString).deletingLastPathComponent + "/Runtime"
        let directory = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0, createIfMissing: false)
        defer { directory.close() }
        return try stageOwned(machine: machine, account: account, expected: expected, currentPolicy: currentPolicy,
            installedRelease: installedRelease, directory: directory, owner: 0, verifyCurrent: verifyCurrent,
            verifyActivity: { activity in
                try RuntimeMaterialPreparation.validateServiceActivity(account: account, activity: activity, verifyCurrent: verifyCurrent)
            })
    }

    // Same-owner fixtures exercise private publication and recovery, not Root placement, signing or native service ownership.
    static func stageOwned(machine: PreparationIntentStore, account: AccountPreparationIntent,
                           expected: RuntimeAuditUpgradeRecord, currentPolicy: AuthorityCodePolicy,
                           installedRelease: SignedReleaseEvidence, directory: ProtectedSetupDirectory, owner: uid_t,
                           verifyCurrent: () throws -> Void, verifyActivity: (ServiceReleaseActivityReference) throws -> Void,
                           didStage: (Stage) throws -> Void = { _ in },
                           publicationStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeRecord {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try RuntimeAuditUpgradeRecord.validatePreparation(expected.intent, release: installedRelease, policy: currentPolicy)
        try expected.intent.source.validate(account: account, services: expected.intent.source.services)
        try verifyCurrent(); try directory.validate()
        guard var retained = try machine.runtimeAuditUpgrade(accountID: account.accountID), retained.intent == expected.intent,
              retained == expected || (retained.phase == .materialStaged && expected.phase == .retained) else {
            throw RuntimePreparationError.changedScope
        }
        func verify() throws {
            try verifyCurrent(); try machine.validateAccountPreparation(account)
            guard try machine.runtimeAuditUpgrade(accountID: account.accountID) == retained else { throw RuntimePreparationError.changedScope }
            try directory.validate()
        }
        func readSource() throws -> Data {
            do { return try ProtectedServiceConfiguration.read(anchor: directory.path,
                relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: owner) }
            catch JournalLeaseError.system(let code) where code == ENOENT { throw RuntimePreparationError.missingMaterial }
        }
        try verify()
        let sourceBytes = try readSource(), source = try RuntimePreparationMaterial.decode(sourceBytes)
        guard try source.reference == retained.intent.source,
              let activity = retained.intent.target.serviceActivity else { throw RuntimePreparationError.conflictingMaterial }
        try verifyActivity(activity); try verify()
        let candidate = try RuntimeAuditMaterialUpgrade.prepare(material: source, expected: retained.intent.source,
            account: account, activity: activity, installedRelease: installedRelease, policy: currentPolicy)
        let bytes = try candidate.encoded
        guard try candidate.reference == retained.intent.target else { throw RuntimePreparationError.conflictingMaterial }
        func verifySource() throws {
            try verify(); try verifyActivity(activity)
            guard try readSource() == sourceBytes else { throw RuntimePreparationError.conflictingMaterial }
            try verify()
        }
        try verifySource(); try didStage(.sourceValidated); try verifySource()
        let file = AdministrativeSetupPublication.File.auditUpgradeMaterial(intentID: retained.intent.id)
        _ = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner,
            verify: verifySource, didStage: publicationStage)
        try didStage(.candidatePublished); try verifySource()
        let confirmedBytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
        let confirmed = try RuntimePreparationMaterial.decode(confirmedBytes)
        guard confirmedBytes == bytes, try confirmed.reference == retained.intent.target else { throw RuntimePreparationError.conflictingMaterial }
        try verifySource(); try didStage(.candidateVerified); try verifySource()
        retained = try machine.markRuntimeAuditMaterialStaged(retained, currentPolicy: currentPolicy, installedRelease: installedRelease)
        try didStage(.ledgerRecorded); try verifySource()
        return retained
    }
}
