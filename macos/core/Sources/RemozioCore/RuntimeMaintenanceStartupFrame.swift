import Foundation

/// Current protected metadata. It grants no execution or custody rights.
struct RuntimeMaintenanceStartupFrame {
    let source: MachineUpdateStableRuntimeSource
    let window: RuntimeMaintenanceWindowRecord?
}

/// Declarations captured under fresh custody. Gate file identities are separate from account directory UUIDs.
struct RuntimeMaintenanceStartupFloor: @unchecked Sendable {
    let source: MachineUpdateStableRuntimeSource
    let initial: AuthorityInitializationIntent
    let host: InstalledAuthorityCommandConfiguration
    let cohort: RuntimeMaintenanceAuthorityCohort
    let code: AuthorityCodeEntry
    init(frame: RuntimeMaintenanceStartupFrame, release: SignedReleaseEvidence) throws {
        guard let row = frame.window else { throw PreparationStoreError.notFound }
        let source = frame.source, actual = source.actual, inventory = actual.inventory
        let account = try source.account(row.scope.authority.accountID, ownerUID: row.scope.authority.ownerUID)
        guard let initial = account.initialization, initial.complete,
              let configured = try actual.installed.configuration().configuration(accountID: account.accountID),
              let prepared = account.preparation, prepared.ownerUID == row.scope.authority.ownerUID,
              Self.bytes(prepared.directoryID) == row.scope.authority.directoryID,
              let target = source.preparations.first(where: { $0.accountID == row.scope.target.accountID }),
              target.ownerUID == row.scope.target.ownerUID, Self.bytes(target.directoryID) == row.scope.target.directoryID,
              inventory.macID == row.scope.macID, inventory.installationID == row.scope.installationID,
              inventory.releaseDigest == row.scope.releaseDigest,
              initial.macID == inventory.macID, initial.installationID == inventory.installationID,
              !inventory.accounts.contains(where: { $0.accountID == row.scope.target.accountID }),
              actual.admission.macID == inventory.macID, actual.admission.installationID == inventory.installationID else {
            throw RuntimePreparationError.changedScope
        }
        let host = configured.completion.host
        guard host.jobPlacement == .systemAccount, host.machineDirectory == MachineBootstrap.machineDirectory,
              host.command.accountID == account.accountID, host.command.callerUID == account.ownerUID,
              host.installationID == inventory.installationID, host.releaseDigest == inventory.releaseDigest,
              let code = host.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        try inventory.compareRelease(release); try host.validateRelease(release, bundlePath: inventory.bundlePath)
        try RuntimeMaintenanceCommitments.requireStartupRestoration(row, initial: initial, host: host,
            inventory: inventory, candidate: release)
        let job = try InstalledAccountJobManifest(accountID: account.accountID, role: .authority,
            executionUID: 0, userName: "root", bundlePath: inventory.bundlePath,
            gatewaySettingsControlEnabled: host.gatewaySettingsControlEnabled,
            installedReadinessEnabled: host.installedReadinessEnabled)
        try job.validate(job.bytes, inventory: inventory, release: release)
        self.source = source; self.initial = initial; self.host = host; self.code = code
        cohort = try .init(startupJob: job, host: host, inventory: inventory,
            registration: actual.admission, targetAccountID: row.scope.target.accountID)
    }
    func requireCurrent(_ frame: RuntimeMaintenanceStartupFrame, window: RuntimeMaintenanceWindowRecord,
        release: SignedReleaseEvidence) throws {
        guard frame.window == window else { throw PreparationStoreError.staleRevision }
        let other = try Self(frame: frame, release: release)
        let accounts = [window.scope.authority.accountID, window.scope.target.accountID]
        guard other.source.actual.inventory == source.actual.inventory,
              other.source.actual.admission == source.actual.admission,
              other.source.preparations.filter({ accounts.contains($0.accountID) })
                == source.preparations.filter({ accounts.contains($0.accountID) }),
              other.source.initializations.filter({ accounts.contains($0.accountID) })
                == source.initializations.filter({ accounts.contains($0.accountID) }),
              other.host.canonicalBytes == host.canonicalBytes, other.initial == initial,
              other.cohort.job.bytes == cohort.job.bytes else { throw RuntimePreparationError.changedScope }
    }
    private static func bytes(_ value: UUID) -> Data {
        var uuid = value.uuid; return withUnsafeBytes(of: &uuid) { Data($0) }
    }
}
