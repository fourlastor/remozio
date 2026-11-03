import CryptoKit
import Darwin
import Foundation

/// Captured import dependencies only. No journal phase, provider resource or live reference changes here.
struct RuntimeAuditUpgradeImportPreparation: CustomStringConvertible, CustomDebugStringConvertible {
    struct PreservedFile {
        let file: AdministrativeSetupPublication.File
        let bytes: Data
    }
    let intent: SharedSetupImportIntent
    let source: SharedSetupImportCompatibilitySnapshot.Record
    let preservedFiles: [PreservedFile]
    let sourceMaterial: RelayRunCredentialMaterial?
    let targetMaterial: RelayRunCredentialMaterial?
    let targetReference: RelayRunCredentialReference?
    var description: String { "RuntimeAuditUpgradeImportPreparation(redacted)" }
    var debugDescription: String { description }

    /// The owner retains machine/import scope and verifies the current signed setup process throughout this capture.
    static func capture(_ preparation: RuntimeAuditUpgradePreparation, expected: SharedSetupImportIntent,
                        source: SharedSetupImportCompatibilitySnapshot.Record, account: AccountPreparationIntent,
                        inventory: InstallationInventory, verifyCurrent: () throws -> Void) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verifyCurrent()
        try validateScope(preparation, expected: expected, source: source, account: account, inventory: inventory)
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let runtime = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.privateDirectory.dropFirst()),
            owner: 0, createIfMissing: false)
        defer { runtime.close() }
        let imports = try ProtectedSetupDirectory(anchor: "/", relativePath: String(MachineBootstrap.machineDirectory.dropFirst()) + "/SharedSetupImport",
            owner: 0, createIfMissing: false)
        defer { imports.close() }
        func verify() throws {
            try verifyCurrent(); try runtime.validate(); try imports.validate()
            let retained = try RuntimePreparationMaterial.decode(ProtectedServiceConfiguration.read(anchor: runtime.path,
                relativePath: AdministrativeSetupPublication.File.runtimeRecord.name, owner: 0))
            guard try retained.reference == preparation.intent.source else { throw RuntimePreparationError.changedScope }
        }
        try verify()
        let value = try captureOwned(preparation, expected: expected, source: source, account: account, inventory: inventory,
            directory: imports, owner: 0, verifyCurrent: verify, loadMaterial: { plan, created in
                let file = AdministrativeSetupPublication.File.relayRunMaterial
                let present = try runtime.withPrivateDirectory { parent in
                    var info = stat()
                    if fstatat(parent, file.name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
                    guard errno == ENOENT else { throw JournalLeaseError.system(errno) }; return false
                }
                guard present else { return nil }
                guard let plan, let created else { throw RuntimePreparationError.changedScope }
                return try .decode(ProtectedServiceConfiguration.read(anchor: runtime.path, relativePath: file.name, owner: 0),
                    expected: expected, plan: plan, created: created, runtime: preparation.intent.source,
                    account: account, inventory: inventory)
            })
        try verify(); return value
    }
    private static func validateScope(_ preparation: RuntimeAuditUpgradePreparation, expected: SharedSetupImportIntent,
                                      source: SharedSetupImportCompatibilitySnapshot.Record, account: AccountPreparationIntent,
                                      inventory: InstallationInventory) throws {
        try preparation.intent.source.validate(account: account, services: preparation.intent.source.services)
        guard expected.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)),
              source.accountID == expected.scope.accountID, source.operationID == expected.operationID,
              source.revision == expected.revision, source.phase == expected.phase.rawValue,
              try source.digest == Data(SHA256.hash(data: expected.bytes)), source.portableVersion == expected.originalPortableVersion,
              try source.settingsVersion == expected.recipe.settingsVersion else { throw RuntimePreparationError.changedScope }
    }
    // Owned fixtures qualify import leaf checks only. They do not establish native Root or service-file custody.
    static func captureOwned(_ preparation: RuntimeAuditUpgradePreparation, expected: SharedSetupImportIntent,
                             source: SharedSetupImportCompatibilitySnapshot.Record, account: AccountPreparationIntent,
                             inventory: InstallationInventory, directory: ProtectedSetupDirectory, owner: uid_t,
                             verifyCurrent: () throws -> Void,
                             loadMaterial: (SharedSetupImportRelayPlan?, SharedSetupRelayProvisioningRecord?) throws -> RelayRunCredentialMaterial?) throws -> Self {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try verifyCurrent()
        try validateScope(preparation, expected: expected, source: source, account: account, inventory: inventory)
        try directory.validate()
        func snapshot() throws -> SharedSetupImportCompatibilitySnapshot.Record {
            let plan = try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner)
            let created = try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: owner)
            let access = try SharedSetupAccessApplicationStorage.read(expected: expected, plan: plan,
                createdTunnel: created, directory: directory, owner: owner)
            return try .init(accountID: source.accountID, operationID: source.operationID, revision: source.revision,
                phase: source.phase, digest: source.digest, portableVersion: source.portableVersion, settingsVersion: source.settingsVersion,
                relay: SharedSetupImportRelayStorage.snapshot(expected: expected, directory: directory, owner: owner),
                relayProvisioning: SharedSetupRelayProvisioningStorage.snapshot(expected: expected, plan: plan, directory: directory, owner: owner),
                accessApplication: SharedSetupAccessApplicationStorage.snapshot(expected: expected, plan: plan,
                    createdTunnel: created, directory: directory, owner: owner),
                dnsRecord: SharedSetupDNSStorage.snapshot(expected: expected, plan: plan, createdTunnel: created,
                    application: access, directory: directory, owner: owner),
                runCredential: SharedSetupRelayRunReferenceStorage.snapshot(expected: expected, plan: plan, created: created,
                    directory: directory, owner: owner))
        }
        func verify() throws {
            try verifyCurrent(); try directory.validate()
            guard try snapshot() == source else { throw RuntimePreparationError.changedScope }
        }
        try verify()
        let plan = try SharedSetupImportRelayStorage.read(expected: expected, directory: directory, owner: owner)
        let created = try SharedSetupRelayProvisioningStorage.read(expected: expected, plan: plan, directory: directory, owner: owner)
        if expected.recipe.cloudflare != nil {
            guard let plan, preparation.source.transport.relayPort == plan.port else { throw RuntimePreparationError.changedScope }
        }
        let material = try loadMaterial(plan, created)
        let targetMaterial: RelayRunCredentialMaterial?, targetReference: RelayRunCredentialReference?
        if let material {
            guard let plan, let created else { throw RuntimePreparationError.changedScope }
            let actual = try material.reference
            _ = try RelayRunCredentialMaterial.decode(material.encoded, expected: expected, plan: plan, created: created,
                runtime: preparation.intent.source, account: account, inventory: inventory)
            if let published = source.runCredential {
                guard published.reference == actual else { throw RuntimePreparationError.conflictingMaterial }
            }
            targetMaterial = try material.preparingAuditUpgrade(preparation, expected: actual)
            targetReference = try source.runCredential == nil ? nil : targetMaterial?.reference
        } else {
            guard source.runCredential == nil else { throw RuntimePreparationError.missingMaterial }
            targetMaterial = nil; targetReference = nil
        }
        let accountID = expected.scope.accountID
        let files: [(AdministrativeSetupPublication.File, SharedSetupImportRelayStorage.Snapshot?)] = [
            (.importRelayPlan(accountID: accountID), source.relay),
            (.importRelayProvisioning(accountID: accountID), source.relayProvisioning),
            (.importAccessApplication(accountID: accountID), source.accessApplication),
            (.importDNSRecord(accountID: accountID), source.dnsRecord)]
        var preserved: [PreservedFile] = []
        for (file, retained) in files {
            if let retained {
                let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name, owner: owner)
                guard Data(SHA256.hash(data: bytes)) == retained.digest else { throw RuntimePreparationError.changedScope }
                preserved.append(.init(file: file, bytes: bytes))
            }
        }
        try verify()
        let confirmed = try loadMaterial(plan, created)
        guard try confirmed?.encoded == material?.encoded else { throw RuntimePreparationError.changedScope }
        try verify()
        return .init(intent: expected, source: source, preservedFiles: preserved,
            sourceMaterial: material, targetMaterial: targetMaterial, targetReference: targetReference)
    }
}
