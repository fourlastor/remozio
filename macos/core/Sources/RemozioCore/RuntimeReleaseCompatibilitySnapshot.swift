import Foundation
import RemozioProtocol

/// Retained setup and runtime requirements. This snapshot contains no imported credentials or update authority.
struct RuntimeReleaseCompatibilitySnapshot: Sendable {
    struct Runtime: Equatable, Sendable {
        let reference: RuntimeMaterialReference
        let configurationPublished: Bool
        let activationRecord: Data?
        let jobsRegistered: Bool
    }
    struct Gateway: Equatable, Sendable {
        let accountID: Data
        let activationRecord: Data
        let configurationPublished: Bool
        let jobRegistered: Bool
        let activeSettings: Data?
        let pendingSettings: Data?
        let settingsPhase: Int64?
    }
    struct Inputs: Equatable, Sendable {
        private(set) var schemaVersion: Int64
        let macID: Data
        let inventory: Data?
        let runtimes: [Runtime]
        let gateways: [Gateway]
        let sharedImport: SharedSetupImportCompatibilitySnapshot?
        let auditUpgrades: [RuntimeAuditUpgradeRecord]
        let auditGraphs: [RuntimeAuditUpgradeGraphRecord]
        let auditCutovers: [RuntimeAuditUpgradeCutoverRecord]
        /// Canonical update admission registration bytes at schema 16 and later, so a registration change makes earlier inputs stale.
        let updateAdmissionRegistration: Data?
        /// Canonical machine update activation record bytes at schema 17 and later, so an activation change makes earlier inputs stale.
        private(set) var machineUpdateActivation: Data?
        /// Canonical machine update replacement record bytes at schema 18 and later, so a replacement change makes earlier inputs stale.
        let machineUpdateReplacement: Data?
        /// The canonical header binds every retained configuration row and its publication revision.
        let machineUpdateConfigurationEpoch: Data?
        let machineUpdateBackendEpoch: Data?
        private(set) var completionIntent: Data?
        private(set) var completionPublication: Data?
        let installedRelease: Data?
        init(schemaVersion: Int64, macID: Data, inventory: Data?, runtimes: [Runtime], gateways: [Gateway],
             sharedImport: SharedSetupImportCompatibilitySnapshot? = nil, auditUpgrades: [RuntimeAuditUpgradeRecord] = [],
             auditGraphs: [RuntimeAuditUpgradeGraphRecord] = [], auditCutovers: [RuntimeAuditUpgradeCutoverRecord] = [],
             updateAdmissionRegistration: Data? = nil, machineUpdateActivation: Data? = nil, machineUpdateReplacement: Data? = nil, machineUpdateConfigurationEpoch: Data? = nil, machineUpdateBackendEpoch: Data? = nil,
             completionIntent: Data? = nil, completionPublication: Data? = nil, installedRelease: Data? = nil) {
            self.schemaVersion = schemaVersion; self.macID = macID; self.inventory = inventory
            self.runtimes = runtimes; self.gateways = gateways; self.sharedImport = sharedImport; self.auditUpgrades = auditUpgrades; self.auditGraphs = auditGraphs; self.auditCutovers = auditCutovers
            self.updateAdmissionRegistration = updateAdmissionRegistration; self.machineUpdateActivation = machineUpdateActivation
            self.machineUpdateReplacement = machineUpdateReplacement
            self.machineUpdateConfigurationEpoch = machineUpdateConfigurationEpoch
            self.machineUpdateBackendEpoch = machineUpdateBackendEpoch
            self.completionIntent = completionIntent
            self.completionPublication = completionPublication
            self.installedRelease = installedRelease
        }
        /// Projects the historical restart source from a verified completion frame.
        func completionSourceInputs() -> Self {
            var copy = self
            copy.schemaVersion = 20
            copy.completionIntent = nil
            copy.completionPublication = nil
            return copy
        }
        /// Copies every field and replaces only the activation bytes, so a field added later cannot be dropped.
        func replacingMachineUpdateActivation(_ value: Data?) -> Self {
            var copy = self; copy.machineUpdateActivation = value; return copy
        }
    }
    let inputs: Inputs
    let requirements: RetainedReleaseRequirements
    private var native: Bool { (inputs.runtimes.contains { $0.reference.serviceActivity != nil } || !inputs.auditUpgrades.isEmpty || !inputs.auditGraphs.isEmpty || !inputs.auditCutovers.isEmpty) }

    static func capture(machine: PreparationIntentStore) throws -> Self {
        try describe(inputs: machine.retainedRuntimeCompatibilityInputs())
    }

    static func describe(inputs: Inputs) throws -> Self {
        let native = (inputs.runtimes.contains { $0.reference.serviceActivity != nil } || !inputs.auditUpgrades.isEmpty || !inputs.auditGraphs.isEmpty || !inputs.auditCutovers.isEmpty)
        var formats = try native ? GatewaySettingsNativeHostPlan.releaseRequirements.formats : []
        func include(_ role: AuthorityCodeRole, _ name: String, _ reads: Set<UInt64>, _ writes: Set<UInt64>) throws {
            if let index = formats.firstIndex(where: { $0.role == role && $0.name == name }) {
                let current = formats[index]
                formats[index] = try .init(role: role, name: name, readVersions: current.readVersions.union(reads),
                    writeVersions: current.writeVersions.union(writes))
            } else { formats.append(try .init(role: role, name: name, readVersions: reads, writeVersions: writes)) }
        }
        if inputs.schemaVersion >= 15 {
            for item in try UpdateSchedulingCandidateRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 16 {
            for item in try UpdateAdmissionRegistrationRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 17 {
            for item in try MachineUpdateActivationRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if let bytes = inputs.machineUpdateActivation, try MachineUpdateActivationRecord.decode(bytes).formatVersion == 2 {
            for item in try MachineUpdateActivationRecord.preflightRequirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 18 {
            for item in try MachineUpdateReplacementRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 19 {
            for item in try MachineUpdateConfigurationEpochRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if let bytes = inputs.machineUpdateConfigurationEpoch {
            for item in try MachineUpdateConfigurationEpochRecord.retainedRequirements(bytes) {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 20 {
            for item in try MachineUpdateBackendEpochRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if let bytes = inputs.machineUpdateBackendEpoch,
           try MachineUpdateBackendEpochRecord.decode(bytes).publication != nil {
            for item in try MachineUpdateBackendEpochRecord.publicationRequirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 21 {
            guard inputs.completionIntent != nil else { throw PreparationStoreError.corruptRecord }
            for item in try MachineUpdateCompletionIntentRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 22 {
            guard inputs.completionPublication != nil else { throw PreparationStoreError.corruptRecord }
            for item in try MachineUpdateCompletionPublicationRecord.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        if inputs.schemaVersion >= 23 {
            guard let encoded = inputs.installedRelease else { throw PreparationStoreError.corruptRecord }
            let record = try MachineUpdateInstalledReleaseRecord.decode(encoded)
            var installed = try MachineUpdateInstalledReleaseRecord.requirements + MachineUpdateActivationRecord.finalizationRequirements
            if record.formatVersion == 2 { installed += try MachineUpdateInstalledReleaseRecord.provenanceRequirements }
            for item in installed { try include(item.role, item.name, item.readVersions, item.writeVersions) }
        }
        if inputs.schemaVersion >= 24 {
            var stable = try MachineUpdateStableReleaseRecord.requirements
            if inputs.schemaVersion >= 25 { stable += try MachineUpdateRetainedSetupPolicyStorage.readerRequirements }
            if inputs.schemaVersion >= 26 { stable += try MachineUpdateRetainedSetupCompletionStorage.readerRequirements }
            if inputs.schemaVersion >= 27 { stable += try MachineUpdateRetainedSetupPromotionStorage.readerRequirements }
            if inputs.schemaVersion >= 28 { stable += try MachineUpdateRetainedSetupPromotionReadyStorage.readerRequirements }
            if inputs.schemaVersion >= 29 { stable += try RuntimeMaintenanceWindowStorage.readerRequirements }
            for item in stable { try include(item.role, item.name, item.readVersions, item.writeVersions) }
        }
        if native {
            for item in try CommandMonitorActivityContract.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
        }
        let upgrades = inputs.auditUpgrades + inputs.auditGraphs.map(\.upgrade) + inputs.auditCutovers.map { $0.graph.upgrade }
        if !upgrades.isEmpty {
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, RuntimeAuditUpgradeRecord.formatName, [1], role == .setupController ? [1] : [])
            }
            for record in try PhoneAuditReleaseContract.requirements + PhoneAuditReleaseContract.deliveryRequirements {
                try include(record.role, record.name, record.readVersions, record.writeVersions)
            }
            for upgrade in upgrades {
                for reference in [upgrade.intent.source, upgrade.intent.target] {
                    for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
                        try include(role, RuntimeMaterialReference.formatName, [reference.formatVersion], role == .setupController ? [reference.formatVersion] : [])
                    }
                    for role in [AuthorityCodeRole.authority, .setupController] {
                        try include(role, RuntimePreparationMaterial.formatName, [reference.formatVersion], role == .setupController ? [reference.formatVersion] : [])
                    }
                }
            }
        }
        if !inputs.auditGraphs.isEmpty {
            for record in try RuntimeAuditUpgradeGraph.requirements {
                try include(record.role, record.name, record.readVersions, record.writeVersions)
            }
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, RuntimeAuditUpgradeGraphRecord.formatName, [1], role == .setupController ? [1] : [])
            }
        }
        if !inputs.auditCutovers.isEmpty {
            for item in try RuntimeAuditUpgradeStartupFence.requirements {
                try include(item.role, item.name, item.readVersions, item.writeVersions)
            }
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, RuntimeAuditUpgradeCutoverRecord.formatName, [1], role == .setupController ? [1] : [])
            }
        }
        if let imports = inputs.sharedImport {
            let portableVersions = Set(imports.records.flatMap { [$0.portableVersion, $0.settingsVersion] })
            try include(.setupController, SharedSetupImportJournal.formatName, SharedSetupImportJournal.supportedVersions,
                SharedSetupImportJournal.supportedVersions)
            if !portableVersions.isEmpty { try include(.setupController, PortableSetup.formatName, portableVersions, portableVersions) }
            // A crash can retain private material before its public reference is committed.
            if imports.records.contains(where: { $0.runCredential != nil ||
                ($0.relay != nil && $0.phase >= SetupPortableImportProgress.Phase.runtimePublished.rawValue) }) {
                try include(.setupController, RelayRunCredentialMaterial.formatName, [1], [1])
            }
            if imports.records.contains(where: { $0.runCredential != nil }) {
                try include(.setupController, RelayRunCredentialReference.formatName, [1], [1])
            }
            if imports.records.contains(where: { $0.runCredential?.reference.runtime.serviceActivity != nil }) {
                try include(.transport, RelayRunCredentialReference.formatName, [1], [])
            }
            if imports.records.contains(where: { $0.dnsRecord != nil }) {
                try include(.setupController, SharedSetupDNSRecord.formatName, [1], [1])
            }
            if imports.records.contains(where: { $0.accessApplication != nil }) {
                try include(.setupController, SharedSetupAccessApplicationRecord.formatName, [1], [1])
            }
            if imports.records.contains(where: { $0.relayProvisioning != nil }) {
                try include(.setupController, SharedSetupRelayProvisioningRecord.formatName, [1], [1])
            }
            if imports.records.contains(where: { $0.relay != nil }) {
                try include(.setupController, SharedSetupImportRelayPlan.formatName, [1], [1])
            }
        }
        if !inputs.gateways.isEmpty {
            let settings = inputs.gateways.contains { $0.activeSettings != nil || $0.pendingSettings != nil }
            let versions: Set<UInt64> = settings ? GatewayRuntimeCommit.supportedVersions : [1]
            for record in try GatewayRuntimeRecordFormats.requirements(commitVersions: versions, settingsRetained: settings) {
                try include(record.role, record.name, record.readVersions, record.writeVersions)
            }
        }
        if !inputs.runtimes.isEmpty {
            let schema = UInt64(inputs.schemaVersion)
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, "authority.installation-preparation", [schema], [schema])
            }
        }
        for runtime in inputs.runtimes {
            let plan = try runtime.activationRecord.map(RuntimeActivationCompatibilityProjection.decode)
            let materialVersion = runtime.reference.formatVersion
            let transportVersion: UInt64 = runtime.reference.serviceActivity == nil ? 1 : 2
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, RuntimePreparationMaterial.formatName, [materialVersion], role == .setupController ? [materialVersion] : [])
                if let plan {
                    let activationVersion = plan.formatVersion
                    try include(role, RuntimeActivationPlan.formatName, [activationVersion], role == .setupController ? [activationVersion] : [])
                }
            }
            for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
                try include(role, RuntimeMaterialReference.formatName, [materialVersion], role == .setupController ? [materialVersion] : [])
            }
            if runtime.configurationPublished || plan != nil {
                for role in [AuthorityCodeRole.transport, .setupController] {
                    try include(role, "transport.pairing-config", [transportVersion], role == .setupController ? [transportVersion] : [])
                }
            }
            if plan?.phoneRoutingVersion != nil {
                for record in try PhoneRoutingReleaseContract.requirements {
                    try include(record.role, record.name, record.readVersions, record.writeVersions)
                }
            }
            if plan?.phoneAuditVersion != nil {
                for record in try PhoneAuditReleaseContract.requirements {
                    try include(record.role, record.name, record.readVersions, record.writeVersions)
                }
            }
            if plan?.phoneUpdateSchedulingVersion != nil {
                for record in try PhoneUpdateSchedulingReleaseContract.requirements {
                    try include(record.role, record.name, record.readVersions, record.writeVersions)
                }
            }
            if case .retained(let retained)? = plan {
                for item in try RuntimeRetainedSetupReleaseBinding.requirements {
                    try include(item.role, item.name, item.readVersions, item.writeVersions)
                }
                if retained.host.installedReadinessEnabled {
                    let version = MachineUpdateAuthorityReadinessDeclaration.version
                    try include(.authority, MachineUpdateAuthorityReadinessDeclaration.formatName, [version], [version])
                }
            }
            let control = plan?.host.gatewaySettingsControlEnabled ?? (runtime.reference.serviceActivity != nil)
            let version: UInt64
            if case .retained(let retained)? = plan { version = retained.host.formatVersion }
            else { version = control ? 3 : 2 }
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, "authority.command-host-config", [version], [version])
                if control { try include(role, GatewaySettingsControlReleaseValidation.formatName, [1], [1]) }
            }
        }
        return try .init(inputs: inputs, requirements: .init(formats: formats, requests: []))
    }
    /// Pins external public snapshots in addition to the machine SQLite rows. Digests contain no credential bytes.
    static func externalSourceDigest(sharedImport: SharedSetupImportCompatibilitySnapshot?) throws -> Data {
        func identity(_ value: ProtectedStorageLease.DirectoryIdentity) -> CBORValue {
            .array([.unsigned(UInt64(bitPattern: Int64(value.device))), .unsigned(UInt64(value.inode))])
        }
        func file(_ value: (ProtectedStorageLease.DirectoryIdentity, Data)?) -> CBORValue {
            value.map { .array([identity($0.0), .bytes($0.1)]) } ?? .null
        }
        let imported: CBORValue
        if let snapshot = sharedImport {
            let records = snapshot.records.map { record in
                CBORValue.map([0: .bytes(record.accountID), 1: .bytes(record.operationID), 2: .bytes(record.revision),
                    3: .unsigned(record.phase), 4: .bytes(record.digest), 5: .unsigned(record.portableVersion),
                    6: .unsigned(record.settingsVersion), 7: file(record.relay.map { ($0.identity, $0.digest) }),
                    8: file(record.relayProvisioning.map { ($0.identity, $0.digest) }),
                    9: file(record.accessApplication.map { ($0.identity, $0.digest) }),
                    10: file(record.dnsRecord.map { ($0.identity, $0.digest) }),
                    11: file(record.runCredential.map { ($0.identity, $0.digest) })])
            }
            imported = .map([0: .array(snapshot.directories.map(identity)), 1: identity(snapshot.database),
                2: identity(snapshot.writer), 3: .array(records)])
        } else { imported = .null }
        // Schema 19 has no separate retained-setup provisioning store.
        let bytes = try DeterministicCBOR.encode(.map([0: imported, 1: .array([])]),
            limits: .init(maxBytes: 262144, maxDepth: 6, maxItems: 16384))
        return MachineUpdateActivationRecord.digest(Data("Remozio/MachineEpochExternalSource/v1\0".utf8) + bytes)
    }
    func requireCurrent(machine: PreparationIntentStore) throws {
        guard try machine.retainedRuntimeCompatibilityInputs() == inputs else { throw RuntimeActivationError.changedScope }
    }
    /// Native placement, stopping services, migration and activation are separate operations.
    func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy, machine: PreparationIntentStore) throws {
        try validate(release, policy: policy, verifyCurrent: { try requireCurrent(machine: machine) })
    }
    /// Validates the same requirements under a caller's scoped machine transaction.
    func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy, verifyCurrent: () throws -> Void) throws {
        try verifyCurrent()
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: requirements)
        if inputs.sharedImport != nil {
            guard release.manifest.components.first(where: { $0.role == .setupController })?.relativePath == AdministrativeSetupConfiguration.executablePath else {
                throw RuntimeActivationError.changedScope
            }
        }
        if native || !inputs.gateways.isEmpty {
            let paths: [(AuthorityCodeRole, String)] = [
                (.authority, InstalledAuthorityCommandConfiguration.executablePath),
                (.transport, "Contents/Library/LaunchServices/RemozioTransport"),
                (.notificationGateway, GatewayJournalSetupServiceConfiguration.executableRelativePath),
                (.setupController, AdministrativeSetupConfiguration.executablePath)]
            for (role, path) in paths {
                guard release.manifest.components.first(where: { $0.role == role })?.relativePath == path else {
                    throw RuntimeActivationError.changedScope
                }
            }
        }
        try verifyCurrent()
    }
}
