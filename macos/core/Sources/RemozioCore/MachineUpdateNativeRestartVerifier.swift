import Darwin
import Foundation

/// Verifies retained restart inputs without opening another machine store or taking another drain.
final class MachineUpdateNativeRestartVerifier: @unchecked Sendable {
    private let snapshot: MachineUpdateRestartSnapshot
    private let host: InstalledAuthorityCommandConfiguration
    private let sourceAccess: MachineUpdateHealthSourceAccess
    private let readCurrent: @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot
    private let owned: OwnedInputs?

    /// Fixtures supply their own placement leases and replace only platform inspection and file access.
    struct OwnedInputs {
        let installed: ReleaseDestinationLease
        let prepared: ReleaseDestinationLease
        let inspect: (URL) throws -> SignedReleaseEvidence
        let requireConfiguration: (Data, () throws -> Void) throws -> Void
        let requireBackend: (Data, () throws -> Void) throws -> Void
    }

    /// The restart coordinator serializes fresh reads on its machine store and lends any active read scope.
    init(snapshot: MachineUpdateRestartSnapshot, host: InstalledAuthorityCommandConfiguration,
        sourceAccess: MachineUpdateHealthSourceAccess,
        readCurrent: @escaping @Sendable (MachineUpdateRestartReadinessLoan) throws -> MachineUpdateRestartSnapshot,
        owned: OwnedInputs? = nil) {
        self.snapshot = snapshot; self.host = host; self.sourceAccess = sourceAccess; self.readCurrent = readCurrent
        self.owned = owned
    }

    func verification(loan: MachineUpdateRestartReadinessLoan, verifyAuthority: @escaping @Sendable () throws -> Void)
        -> @Sendable () throws -> Void {
        { [self] in
            try verifyAuthority()
            try validate(loan)
            try loan.validate()
        }
    }

    func validate(_ loan: MachineUpdateRestartReadinessLoan) throws {
        if let owned {
            try Self.requireInLease(snapshot, host: host, installed: owned.installed, prepared: owned.prepared,
                loan: loan, sourceAccess: sourceAccess, readCurrent: { try readCurrent(loan) }, inspect: owned.inspect,
                requireConfiguration: owned.requireConfiguration, requireBackend: owned.requireBackend)
            return
        }
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard let replacement = snapshot.source.replacement.replacement,
              replacement.installedParent + "/" + replacement.installedName == MachineBootstrap.bundlePath,
              let app = host.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw MachineUpdateReplacementError.changedBinding
        }
        let installed = try ReleaseDestinationLease.acquire(path: replacement.installedParent)
        defer { installed.close() }
        let prepared = try ReleaseDestinationLease.acquire(path: replacement.preparedParent)
        defer { prepared.close() }
        try Self.requireInLease(snapshot, host: host, installed: installed, prepared: prepared, loan: loan,
            sourceAccess: sourceAccess, readCurrent: { try readCurrent(loan) }, inspect: { bundle in
                try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            }, requireConfiguration: { account, verify in
                try MachineUpdateConfigurationFiles.requirePublishedNative(snapshot.configuration, accountID: account, verify: verify)
            }, requireBackend: { account, verify in
                try MachineUpdateBackendPublicationFiles.requireNative(snapshot.backend, configuration: snapshot.configuration,
                    accountID: account, verifyCurrent: verify)
            })
    }

    /// Owned fixtures inject the signed inspection and protected file readers. Admission and placement use their real leases.
    static func requireInLease(_ snapshot: MachineUpdateRestartSnapshot, host: InstalledAuthorityCommandConfiguration,
        installed: ReleaseDestinationLease, prepared: ReleaseDestinationLease, loan: MachineUpdateRestartReadinessLoan,
        sourceAccess: MachineUpdateHealthSourceAccess, readCurrent: () throws -> MachineUpdateRestartSnapshot,
        inspect: (URL) throws -> SignedReleaseEvidence,
        requireConfiguration: (Data, () throws -> Void) throws -> Void,
        requireBackend: (Data, () throws -> Void) throws -> Void) throws {
        let context = snapshot.source.replacement, activation = context.activation
        guard activation.phase == .restartChecking, let replacement = context.replacement,
              snapshot.configuration.record.publication?.complete == true,
              snapshot.backend.record.publication?.complete == true,
              let backendAccounts = snapshot.backend.record.accounts,
              let selected = try snapshot.configuration.configuration(accountID: host.command.accountID),
              selected.startup.host.canonicalBytes == host.canonicalBytes else {
            throw RuntimePreparationError.changedScope
        }
        try replacement.requireScope(activation: activation, inventory: context.inventory, candidate: context.candidate)
        func boundary() throws {
            try loan.requireScope(macID: activation.macID, installationID: activation.installationID,
                activationAttempt: activation.attemptID)
            try MachineUpdateRestartPlacement.require(replacement, installed: installed, prepared: prepared)
            try loan.validate()
        }
        try boundary()
        try sourceAccess.requireCurrent(snapshot, read: readCurrent)
        try boundary()
        let bundle = URL(fileURLWithPath: installed.path).appendingPathComponent(replacement.installedName)
        _ = try installed.inspectInstalledApplication(name: replacement.installedName)
        let release = try inspect(bundle)
        guard try DurableReleasePreparation.digest(release) == activation.updateID else {
            throw InstalledAuthorityCommandError.wrongRelease
        }
        try host.validateRelease(release, bundlePath: bundle.path)
        try boundary()
        for account in snapshot.configuration.record.accounts where account.configurationPublished {
            try requireConfiguration(account.accountID, boundary)
        }
        for account in backendAccounts where account.sourceDigest != nil {
            try requireBackend(account.accountID, boundary)
        }
        try sourceAccess.requireCurrent(snapshot, read: readCurrent)
        try boundary()
    }
}
