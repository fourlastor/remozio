import Foundation

/// Checked retained plan values and proposed jobs. Ordinary activation state cannot hold this type.
struct RuntimeRetainedSetupActivationPlan: CustomStringConvertible, CustomDebugStringConvertible {
    private final class Storage: Sendable {
        let archive: RuntimeRetainedSetupActivationArchive
        let consumerHosts: GatewaySettingsNativeHostPlan
        let authorityJob: InstalledAccountJobManifest
        let transportJob: InstalledAccountJobManifest
        @inline(never)
        init(archive: RuntimeRetainedSetupActivationArchive, consumerHosts: GatewaySettingsNativeHostPlan,
            authorityJob: InstalledAccountJobManifest, transportJob: InstalledAccountJobManifest) {
            self.archive = archive; self.consumerHosts = consumerHosts
            self.authorityJob = authorityJob; self.transportJob = transportJob
        }
    }
    private let storage: Storage
    var archive: RuntimeRetainedSetupActivationArchive { storage.archive }
    static let formatName = RuntimeRetainedSetupActivationArchive.formatName
    static let maximumBytes = RuntimeRetainedSetupActivationArchive.maximumBytes
    var formatVersion: UInt64 { RuntimeRetainedSetupActivationArchive.formatVersion }
    var reference: RuntimeMaterialReference { archive.reference }
    var bundlePath: String { archive.bundlePath }
    var host: InstalledAuthorityCommandConfiguration { archive.host }
    var transport: TransportPairingStartupConfiguration { archive.transport }
    var consumerHosts: GatewaySettingsNativeHostPlan { storage.consumerHosts }
    var gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration { archive.gatewaySettingsHost }
    var retainedSetupBinding: RuntimeRetainedSetupReleaseBinding { archive.binding }
    var retainedSetupInventory: InstallationInventory { archive.inventory }
    var phoneRoutingVersion: UInt64? { archive.phoneRoutingVersion }
    var phoneAuditVersion: UInt64? { archive.phoneAuditVersion }
    var phoneUpdateSchedulingVersion: UInt64? { archive.phoneUpdateSchedulingVersion }
    var authorityJob: InstalledAccountJobManifest { storage.authorityJob }
    var transportJob: InstalledAccountJobManifest { storage.transportJob }
    var accountID: Data { reference.services.accountID }
    var description: String { "RuntimeRetainedSetupActivationPlan(redacted)" }
    var debugDescription: String { description }

    /// The archive owns all wire and input checks. This value derives proposed jobs without native admission.
    init(archive: RuntimeRetainedSetupActivationArchive) throws {
        _ = try archive.encoded
        let selected = try GatewaySettingsNativeHostPlan(host: archive.gatewaySettingsHost)
        guard archive.transport.settingsHost == selected.transport else { throw RuntimeActivationError.invalidPlan }
        let services = archive.reference.services, host = archive.host
        let authorityJob = try InstalledAccountJobManifest(accountID: services.accountID, role: .authority,
            executionUID: 0, userName: "root", bundlePath: archive.bundlePath,
            gatewaySettingsControlEnabled: host.gatewaySettingsControlEnabled,
            installedReadinessEnabled: host.installedReadinessEnabled, retainedSetupHealthEnabled: true)
        let transportJob = try selected.job(.transport)
        storage = .init(archive: archive, consumerHosts: selected, authorityJob: authorityJob, transportJob: transportJob)
    }
    static var requirements: [RetainedReleaseFormat] { get throws {
        try MachineUpdatePreflightCompatibility.retainedSetupActivationRequirements
    } }
    static func requireFormats(_ candidate: SignedReleaseEvidence) throws {
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        for requirement in try requirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == requirement.role })?.formats.first(where: {
                $0.name == requirement.name
            }), requirement.readVersions.isSubset(of: format.readers), requirement.writeVersions.isSubset(of: format.writers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    func validate(account: AccountPreparationIntent, reference: RuntimeMaterialReference) throws {
        try self.reference.validate(account: account, services: reference.services)
        guard self.reference == reference else { throw RuntimeActivationError.changedScope }
        try retainedSetupBinding.requirePreparation(account)
        try retainedSetupBinding.requireHistoricalRuntime(reference)
        try retainedSetupBinding.requireStartupPolicy(host.codePolicy)
    }
    /// Checks values only. The owner must independently authenticate current stores, files and admission.
    func requireConfigurationScope(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
        inventory: InstallationInventory) throws {
        try validate(account: account, reference: reference)
        let binding = retainedSetupBinding
        guard bundlePath == inventory.bundlePath, account.storagePrepared, initialization.complete,
              initialization.macID == account.macID, initialization.installationID == account.installationID,
              initialization.accountID == account.accountID, initialization.releaseDigest == account.releaseDigest,
              initialization.initializationBytes == account.initializationBytes,
              try MachineUpdateActivationRecord.digest(initialization.bytes) == binding.initializationDigest,
              inventory.macID == binding.macID, inventory.installationID == binding.installationID,
              inventory.releaseDigest == binding.installedReleaseDigest else { throw RuntimeActivationError.changedScope }
    }
    func configurationBundle(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
        inventory: InstallationInventory, clients: RuntimeActivationClients) throws -> RuntimeConfigurationBundle {
        try .init(retaining: self, account: account, initialization: initialization, inventory: inventory, clients: clients)
    }
    /// Adds proposed declarations only. No store write or job registration occurs here.
    func enrolledInventory(_ inventory: InstallationInventory) throws -> InstallationInventory {
        let services = reference.services
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == retainedSetupBinding.installedReleaseDigest, inventory.bundlePath == bundlePath else {
            throw RuntimeActivationError.changedScope
        }
        let account = try InstallationAccount(accountID: services.accountID, ownerUID: services.ownerUID)
        if let existing = inventory.accounts.first(where: { $0.accountID == account.accountID || $0.ownerUID == account.ownerUID }),
           existing != account { throw RuntimeActivationError.conflictingPlan }
        var declarations = inventory.services
        for job in [authorityJob, transportJob] {
            if let existing = declarations.first(where: {
                $0.label == job.declaration.label || ($0.accountID == account.accountID && $0.role == job.declaration.role && $0.domainUID == nil)
            }) {
                guard existing == job.declaration else { throw RuntimeActivationError.conflictingPlan }
            } else {
                guard job.declaration.executionUID == 0 || !declarations.contains(where: {
                    $0.executionUID == job.declaration.executionUID && $0.accountID != account.accountID
                }) else { throw RuntimeActivationError.conflictingPlan }
                declarations.append(job.declaration)
            }
        }
        return try .init(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
            bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
            accounts: inventory.accounts.contains(account) ? inventory.accounts : inventory.accounts + [account],
            services: declarations, formatVersion: inventory.formatVersion)
    }
    var encoded: Data { get throws { try archive.encoded } }
    static func decode(_ bytes: Data) throws -> Self {
        try .init(archive: RuntimeRetainedSetupActivationArchive.decode(bytes))
    }
}
