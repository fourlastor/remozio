import Darwin
import Foundation

/// Reads a complete selected-account configuration snapshot. No file, journal, phase or service changes here.
enum RuntimeAuditUpgradeCollector {
    struct Result: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let artifacts: RuntimeAuditUpgradeArtifactSnapshot
        let gatewayJournalIdentity: GatewayJournalFileIdentity?
        var description: String { "RuntimeAuditUpgradeCollector.Result(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    static func capture(scope: RuntimeAuditUpgradeCaptureScope) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try scope.withCurrent {
            let paths = try RuntimePreparationPaths(accountID: scope.account.accountID)
            var directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory] = [:]
            var held: [ProtectedSetupDirectory] = []
            defer { for directory in held.reversed() { directory.close() } }
            func open(_ path: String, _ visibility: ProtectedSetupDirectory.Visibility) throws -> ProtectedSetupDirectory {
                try scope.validateLifetime()
                let value = try ProtectedSetupDirectory(anchor: "/", relativePath: String(path.dropFirst()), owner: 0,
                    visibility: visibility, createIfMissing: false)
                held.append(value); return value
            }
            directories[.runtime] = try open(paths.privateDirectory, .privateState)
            directories[.services] = try open(paths.serviceDirectory, .sharedMetadata)
            directories[.clients] = try open(RuntimePreparationPaths.sharedDirectory, .sharedMetadata)
            directories[.jobs] = try open(InstalledAccountJobManifest.directory, .sharedMetadata)
            let machine = try open(MachineBootstrap.machineDirectory, .privateState)
            let exists = try machine.withPrivateDirectory { parent -> Bool in
                var info = stat()
                if fstatat(parent, "SharedSetupImport", &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
            }
            let missing: RuntimeAuditUpgradeArtifactSnapshot.MissingImports?
            if exists { directories[.imports] = try open(MachineBootstrap.machineDirectory + "/SharedSetupImport", .privateState); missing = nil }
            else { missing = try .observe(machine: machine, owner: 0, ownership: .native, verifyCurrent: scope.validateLifetime) }
            guard let claim = scope.record.intent.source.services.claims.first(where: { $0.role == .gateway }),
                  let services = directories[.services] else { throw RuntimePreparationError.changedScope }
            return try collect(scope: scope, directories: directories, owner: 0, ownership: .native, missingImports: missing,
                observeJournal: {
                    try GatewayJournalFileProvisioning.observe(parent: services, processOwner: 0, serviceUID: claim.number,
                        serviceGID: claim.number, expected: scope.journal.intent?.files, verifyCurrent: scope.validateLifetime)
                })
        }
    }
    // Owned fixtures use the real store, private decoders and source snapshot. Role isolation remains unqualified.
    static func captureOwned(scope: RuntimeAuditUpgradeCaptureScope,
                             directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory], owner: uid_t,
                             missingImports: RuntimeAuditUpgradeArtifactSnapshot.MissingImports? = nil,
                             observeJournal: () throws -> GatewayJournalFileIdentity?) throws -> Result {
        guard owner > 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        return try collect(scope: scope, directories: directories, owner: owner, ownership: .ordinaryOwnerFixture,
            missingImports: missingImports, observeJournal: observeJournal)
    }
    private static func collect(scope: RuntimeAuditUpgradeCaptureScope,
                                directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory], owner: uid_t,
                                ownership: RuntimeAuditUpgradeArtifactSnapshot.Ownership,
                                missingImports: RuntimeAuditUpgradeArtifactSnapshot.MissingImports?,
                                observeJournal: () throws -> GatewayJournalFileIdentity?) throws -> Result {
        try scope.withCurrent {
            guard let runtime = directories[.runtime], let services = directories[.services], let clientsDirectory = directories[.clients] else {
                throw RuntimePreparationError.incomplete
            }
            func read(_ file: AdministrativeSetupPublication.File, _ directory: ProtectedSetupDirectory, optional: Bool = false) throws -> Data? {
                try scope.validateLifetime(); try directory.validate()
                let present = try directory.withDirectory { parent -> Bool in
                    var info = stat()
                    if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                    guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
                }
                if !present {
                    guard optional else { throw RuntimePreparationError.missingMaterial }; return nil
                }
                return try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                    owner: owner, privateFile: file.mode == 0o600)
            }
            let material = try RuntimePreparationMaterial.decode(read(.runtimeRecord, runtime)!)
            guard try material.reference == scope.record.intent.source else { throw RuntimePreparationError.conflictingMaterial }
            let clients = try RuntimeActivationClients.load(directory: clientsDirectory, owner: owner,
                ownerUID: scope.account.ownerUID, verifyCurrent: scope.validateLifetime)
            let gatewayMaterial = try read(.gatewayMaterial, runtime, optional: true).map(GatewayPreparationMaterial.decode)
            let service = try read(.gatewayJournalService, services, optional: true).map(GatewayJournalSetupServiceConfiguration.decode)
            let fence = try read(.gatewaySettingsFence, services, optional: true).map(GatewayRuntimeSettingsFence.decode)
            let imported: RuntimeAuditUpgradeImportPreparation?
            if let expected = scope.imported, let record = scope.importRecord {
                guard let directory = directories[.imports] else { throw RuntimePreparationError.changedScope }
                imported = try .captureOwned(scope.preparation, expected: expected, source: record, account: scope.account,
                    inventory: scope.inventory, directory: directory, owner: owner, verifyCurrent: scope.validateLifetime,
                    loadMaterial: { plan, created in
                        guard let bytes = try read(.relayRunMaterial, runtime, optional: true) else { return nil }
                        guard let plan, let created else { throw RuntimePreparationError.changedScope }
                        return try .decode(bytes, expected: expected, plan: plan, created: created,
                            runtime: scope.record.intent.source, account: scope.account, inventory: scope.inventory)
                    })
            } else { imported = nil }
            let transport = try read(.transportRelayReference, services, optional: true).map { bytes in
                guard let port = scope.preparation.source.transport.relayPort else { throw RuntimePreparationError.changedScope }
                return try RelayRunCredentialReference.decodeForTransport(bytes, runtime: scope.record.intent.source, relayPort: port)
            }
            let graph = try RuntimeAuditUpgradeArtifactPlan(scope.preparation, material: material, account: scope.account,
                initialization: scope.initialization, inventory: scope.inventory, clients: clients, installedRelease: scope.installedRelease,
                sourceJobsRegistered: scope.foreground.jobsRegistered,
                gateway: .init(material: gatewayMaterial, reference: scope.gateway.reference, journal: scope.journal,
                    activation: scope.gatewayActivation, settings: scope.settings, service: service, fence: fence),
                imported: imported, transportRelayReference: transport)
            let observed = try observeJournal()
            if let expected = scope.journal.intent?.files, observed != expected { throw JournalLeaseError.identityChanged }
            let snapshot = try RuntimeAuditUpgradeArtifactSnapshot.capture(graph, directories: directories, owner: owner,
                ownership: ownership, missingImports: missingImports, verifyCurrent: scope.validateLifetime)
            guard try observeJournal() == observed else { throw JournalLeaseError.identityChanged }
            try snapshot.validate(directories: directories, owner: owner, ownership: ownership,
                missingImports: missingImports, verifyCurrent: scope.validateLifetime)
            return .init(artifacts: snapshot, gatewayJournalIdentity: observed)
        }
    }
}
