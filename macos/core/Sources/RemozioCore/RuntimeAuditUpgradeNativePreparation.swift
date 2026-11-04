import Darwin
import Foundation

/// Prepares a graph from unchanged source files. Started cutovers must restore their selected historical graph instead.
enum RuntimeAuditUpgradeNativePreparation {
    static func prepare(machine: PreparationIntentStore, scope: SetupAuditUpgradeScope,
                        installedRelease: SignedReleaseEvidence, currentPolicy: AuthorityCodePolicy,
                        rootActivity: ReleaseActivityToken, verifyOwner: @escaping @Sendable () throws -> Void) throws -> RuntimeAuditUpgradeOperation.Binding? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws { try rootActivity.validateExclusive(); try verifyOwner() }
        try verify(); try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory)
        let account = scope.account
        guard try machine.accountPreparation(ownerUID: account.ownerUID) == account,
              let source = try machine.runtimePreparation(accountID: account.accountID).reference else { throw RuntimePreparationError.incomplete }
        if source.auditDeliveryVersion == 1 { return nil }
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let bytes = try ProtectedServiceConfiguration.read(anchor: paths.privateDirectory,
            relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: 0)
        let material = try RuntimePreparationMaterial.decode(bytes)
        guard try material.reference == source else { throw RuntimePreparationError.conflictingMaterial }
        _ = try RuntimeAuditUpgradeSourcePlan.retain(machine: machine, account: account,
            installedRelease: installedRelease, rootActivity: rootActivity, verifyOwner: verifyOwner)
        let retained = try machine.runtimeAuditUpgrade(accountID: account.accountID)
        let record: RuntimeAuditUpgradeRecord
        if let retained {
            guard retained.intent.source == source else { throw RuntimePreparationError.changedScope }
            record = retained
        } else {
            let activity: ServiceReleaseActivityReference
            if let existing = source.serviceActivity {
                try RuntimeMaterialPreparation.validateServiceActivity(account: account, activity: existing, verifyCurrent: verify)
                activity = existing
            } else {
                let prepared = try ServiceReleaseActivityFileProvisioning.prepare(account: account, services: source.services,
                    mode: .createIfAbsent, expected: nil, verifyCurrent: verify)
                activity = try .init(services: source.services, identities: prepared.identities)
            }
            let target = try RuntimeAuditMaterialUpgrade.prepare(material: material, expected: source, account: account,
                activity: activity, installedRelease: installedRelease, policy: currentPolicy)
            record = try machine.retainRuntimeAuditUpgrade(.init(source: source, target: target.reference, policy: currentPolicy),
                currentPolicy: currentPolicy, installedRelease: installedRelease)
        }
        try verify()
        let staged = try RuntimeAuditUpgradeStaging.stage(machine: machine, account: account, expected: record,
            currentPolicy: currentPolicy, installedRelease: installedRelease, verifyCurrent: verify)
        let capture = try RuntimeAuditUpgradeCaptureScope.capture(machine: machine, expected: staged,
            installedRelease: installedRelease, currentPolicy: currentPolicy, verifyOwner: verify)
        defer { capture.close() }
        let graph = try RuntimeAuditUpgradeGraph(observation: RuntimeAuditUpgradeCollector.capture(scope: capture),
            upgrade: staged, installedRelease: installedRelease, currentPolicy: currentPolicy)
        let retainedGraph = try machine.retainRuntimeAuditGraph(graph, installedRelease: installedRelease, currentPolicy: currentPolicy)
        let stored = try RuntimeAuditUpgradeGraphStorage.restore(machine: machine, expected: retainedGraph,
            installedRelease: installedRelease, currentPolicy: currentPolicy, verifyOwner: verify)
        try verify(); return .init(graph: graph, record: stored)
    }
}
