import Foundation

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
        let schemaVersion: Int64
        let macID: Data
        let inventory: Data?
        let runtimes: [Runtime]
        let gateways: [Gateway]
        let sharedImport: SharedSetupImportCompatibilitySnapshot?
        init(schemaVersion: Int64, macID: Data, inventory: Data?, runtimes: [Runtime], gateways: [Gateway],
             sharedImport: SharedSetupImportCompatibilitySnapshot? = nil) {
            self.schemaVersion = schemaVersion; self.macID = macID; self.inventory = inventory
            self.runtimes = runtimes; self.gateways = gateways; self.sharedImport = sharedImport
        }
    }
    let inputs: Inputs
    let requirements: RetainedReleaseRequirements
    private var native: Bool { inputs.runtimes.contains { $0.reference.serviceActivity != nil } }

    static func capture(machine: PreparationIntentStore) throws -> Self {
        let inputs = try machine.retainedRuntimeCompatibilityInputs()
        let native = inputs.runtimes.contains { $0.reference.serviceActivity != nil }
        var formats = try native ? GatewaySettingsNativeHostPlan.releaseRequirements.formats : []
        func include(_ role: AuthorityCodeRole, _ name: String, _ reads: Set<UInt64>, _ writes: Set<UInt64>) throws {
            if let index = formats.firstIndex(where: { $0.role == role && $0.name == name }) {
                let current = formats[index]
                formats[index] = try .init(role: role, name: name, readVersions: current.readVersions.union(reads),
                    writeVersions: current.writeVersions.union(writes))
            } else { formats.append(try .init(role: role, name: name, readVersions: reads, writeVersions: writes)) }
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
            let plan = try runtime.activationRecord.map(RuntimeActivationPlan.decode)
            let materialVersion: UInt64 = runtime.reference.serviceActivity == nil ? 1 : 2
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, RuntimePreparationMaterial.formatName, [materialVersion], role == .setupController ? [materialVersion] : [])
                if let plan {
                    let activationVersion: UInt64 = plan.consumerHosts == nil ? 1 : 2
                    try include(role, RuntimeActivationPlan.formatName, [activationVersion], role == .setupController ? [activationVersion] : [])
                }
            }
            for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
                try include(role, RuntimeMaterialReference.formatName, [materialVersion], role == .setupController ? [materialVersion] : [])
            }
            if runtime.configurationPublished || plan != nil {
                for role in [AuthorityCodeRole.transport, .setupController] {
                    try include(role, "transport.pairing-config", [materialVersion], role == .setupController ? [materialVersion] : [])
                }
            }
            let control = plan?.host.gatewaySettingsControlEnabled ?? (runtime.reference.serviceActivity != nil)
            let version: UInt64 = control ? 3 : 2
            for role in [AuthorityCodeRole.authority, .setupController] {
                try include(role, "authority.command-host-config", [version], [version])
                if control { try include(role, GatewaySettingsControlReleaseValidation.formatName, [1], [1]) }
            }
        }
        return try .init(inputs: inputs, requirements: .init(formats: formats, requests: []))
    }
    func requireCurrent(machine: PreparationIntentStore) throws {
        guard try machine.retainedRuntimeCompatibilityInputs() == inputs else { throw RuntimeActivationError.changedScope }
    }
    /// Native placement, stopping services, migration and activation are separate operations.
    func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy, machine: PreparationIntentStore) throws {
        try requireCurrent(machine: machine)
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
        try requireCurrent(machine: machine)
    }
}
