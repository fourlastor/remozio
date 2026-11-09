import Darwin
import Foundation

/// Current native finishing facts. This observation grants no ordinary startup, policy writer or admission authority.
struct MachineUpdateNativeFinalizationObservation {
    let snapshot: MachineUpdateFinalizationSnapshot
    let candidate: SignedReleaseEvidence
    let plan: MachineUpdateCompletionPublicationPlan
    let paired: [AuthorityJournal.MachineUpdatePolicyBoundary]
    let readiness: MachineUpdateInstalledReadinessPlan?
}

enum MachineUpdateNativeFinalization {
    /// Uses the caller's actual machine loan. It opens no second machine reader and changes no metadata.
    static func capture(configurationPath: String, scope: PreparationIntentStore.CompletionFinalizationScope)
        throws -> MachineUpdateNativeFinalizationObservation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let frame = try scope.read()
        guard case .installed(let captured) = frame, captured.schemaVersion == 23,
              captured.activation.phase == .finishing else { throw PreparationStoreError.invalidTransition }
        let retainedSource = try scope.readRetainedSource()
        try retainedSource.actual.requireSame(as: captured)
        let archive = captured.installed, configuration = try archive.configuration(), backend = try archive.backend()
        let intent = try archive.completionIntent(), publication = try archive.publicationSource()
        guard publication.filesPublished, publication.inventoryState == .pending,
              try archive.inventory() == captured.inventory else { throw PreparationStoreError.staleRevision }
        try captured.activation.requireFinalizationSource(.decode(intent.record.activation))
        let host = try InstalledAuthorityCommandConfiguration.load(path: configurationPath)
        let paths = try RuntimePreparationPaths(accountID: host.command.accountID)
        guard host.jobPlacement == .systemAccount, host.machineDirectory == MachineBootstrap.machineDirectory,
              captured.inventory.bundlePath == MachineBootstrap.bundlePath,
              host.command.macID == captured.inventory.macID, host.installationID == captured.inventory.installationID,
              configurationPath == paths.privateDirectory + "/" + AdministrativeSetupPublication.File.commandHost.name,
              captured.initializations.contains(where: { $0.accountID == host.command.accountID && $0.complete }),
              let account = configuration.record.accounts.first(where: { $0.accountID == host.command.accountID }),
              account.ownerUID == host.command.callerUID,
              let retained = try configuration.configuration(accountID: host.command.accountID),
              retained.completion.host.canonicalBytes == host.canonicalBytes,
              let root = host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw InstalledAuthorityCommandError.wrongInstallation
        }
        let replacement = try MachineUpdateReplacementRecord.decode(configuration.artifact(9))
        let bundle = URL(fileURLWithPath: MachineBootstrap.bundlePath)
        let installed = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { installed.close() }
        let prepared = try ReleaseDestinationLease.acquire(path: replacement.preparedParent)
        defer { prepared.close() }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: host.machineDirectory)
        let shared = try activity.acquireShared(); defer { shared.close() }
        let requirement = try AuthoritySelfValidation.requirement(for: root)
        func verifyIdentity() throws -> SignedReleaseEvidence {
            try shared.validate(); try scope.read().requireSame(as: frame)
            try MachineUpdateRestartPlacement.require(replacement, installed: installed, prepared: prepared)
            guard installed.path + "/" + replacement.installedName == bundle.path,
                  try DynamicCodeValidation.selfPath() == bundle.appendingPathComponent(InstalledAuthorityCommandConfiguration.executablePath).path,
                  try InstalledAuthorityCommandConfiguration.load(path: configurationPath).canonicalBytes == host.canonicalBytes else {
                throw InstalledAuthorityCommandError.wrongExecutable
            }
            try DynamicCodeValidation.validateSelf(requirement: requirement)
            _ = try installed.inspectInstalledApplication(name: replacement.installedName)
            let actual = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try host.validateRelease(actual, bundlePath: bundle.path)
            guard try DurableReleasePreparation.digest(actual) == captured.activation.updateID,
                  try InstallationInventory.digest(actual) == captured.inventory.releaseDigest else {
                throw InstalledAuthorityCommandError.wrongRelease
            }
            try scope.read().requireSame(as: frame); try shared.validate(); return actual
        }
        let candidate = try verifyIdentity()
        func verify() throws { _ = try verifyIdentity() }
        try archive.validate(candidate: candidate)
        let compatibility = try scope.readCompatibility()
        try compatibility.validate(candidate, policy: host.codePolicy, scope: scope)
        let plan = try archive.plan(candidate: candidate); try publication.requirePlan(plan)
        guard let entry = plan.entries.first(where: { $0.accountID == host.command.accountID && $0.file == .host }) else {
            throw InstalledAuthorityCommandError.changedConfiguration
        }
        try entry.requireActual(host.canonicalBytes, state: .published)
        let paired = try MachineUpdateInstalledPolicyRead.readNative(scope: scope, candidate: candidate, verifyCurrent: verify)
        try MachineUpdateCompletionPublicationFiles.requireNative(plan, publication: publication, verifyCurrent: verify)
        try MachineUpdateCompletionPublicationFiles.requireBackendMetadataNative(backend: backend, configuration: configuration,
            verifyCurrent: verify)
        let final = try MachineUpdateInstalledPolicyRead.readNative(scope: scope, candidate: candidate, verifyCurrent: verify)
        guard final == paired else { throw PreparationStoreError.staleRevision }
        let readiness = try selectReadiness(host: host, compatibility: compatibility, scope: scope, candidate: candidate)
        try compatibility.requireCurrent(scope: scope)
        try scope.readRetainedSource().requireSame(as: retainedSource)
        try scope.read().requireSame(as: frame); try verify()
        return .init(snapshot: captured, candidate: candidate, plan: plan, paired: paired, readiness: readiness)
    }

    /// The native entry has already checked the retained host bytes before it selects readiness.
    static func selectReadiness(host: InstalledAuthorityCommandConfiguration,
        compatibility: MachineUpdateInstalledCompatibilitySnapshot, scope: PreparationIntentStore.CompletionFinalizationScope,
        candidate: SignedReleaseEvidence) throws -> MachineUpdateInstalledReadinessPlan? {
        guard host.installedReadinessEnabled else { return nil }
        let selected = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: candidate,
            focusedAccountID: host.command.accountID)
        _ = try selected.selectAuthority(host: host)
        try selected.view.compatibility.requireSame(as: compatibility)
        return selected
    }
}
