import Foundation

/// Reads retained configuration values. It grants no enrollment, registration, native custody or request authority.
struct RuntimeRetainedSetupPublishedSelection: CustomStringConvertible, CustomDebugStringConvertible {
    private final class Storage {
        let binding: RuntimeRetainedSetupReleaseBinding
        let bundle: RuntimeConfigurationBundle
        let host: InstalledAuthorityCommandConfiguration
        init(binding: RuntimeRetainedSetupReleaseBinding, bundle: RuntimeConfigurationBundle,
            host: InstalledAuthorityCommandConfiguration) {
            self.binding = binding; self.bundle = bundle; self.host = host
        }
    }
    private let storage: Storage
    var binding: RuntimeRetainedSetupReleaseBinding { storage.binding }
    var bundle: RuntimeConfigurationBundle { storage.bundle }
    var host: InstalledAuthorityCommandConfiguration { storage.host }
    var description: String { "RuntimeRetainedSetupPublishedSelection(redacted)" }
    var debugDescription: String { description }
    private init(binding: RuntimeRetainedSetupReleaseBinding, bundle: RuntimeConfigurationBundle,
        host: InstalledAuthorityCommandConfiguration) {
        storage = .init(binding: binding, bundle: bundle, host: host)
    }

    /// The caller authenticates current metadata and material custody around every injected read.
    static func capture(snapshot: MachineUpdateRetainedSetupPolicySnapshot,
        readPolicyBoundary: () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        material: RuntimePreparationMaterial, candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        verifyCurrent: () throws -> Void,
        read: (RuntimePublishedArtifactValidation.Artifact) throws -> Data) throws -> Self {
        try verifyCurrent()
        let current = try readPolicyBoundary()
        try verifyCurrent()
        let activation = snapshot.activation, runtime = activation.runtime, setup = runtime.setup
        guard activation.origin == .retained, activation.installed == nil,
              activation.state.plan == nil, !activation.state.jobsRegistered,
              setup.account?.inInventory == false, runtime.state.configurationPublished,
              let reference = runtime.state.reference else { throw RuntimeActivationError.changedScope }
        let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: candidate)
        guard let intent = snapshot.intent else { throw RuntimeActivationError.incomplete }
        try binding.requireStartupPolicy(currentCodePolicy)
        try binding.requireHistoricalRuntime(material.reference)
        guard try material.services.encoded == runtime.plan.encoded, reference.serviceActivity != nil else {
            throw RuntimePreparationError.conflictingMaterial
        }
        func verify() throws {
            try verifyCurrent()
            let current = try readPolicyBoundary()
            try intent.requireRecorded(current)
            try binding.requireRecordedBoundary(current)
            try verifyCurrent()
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: runtime.preparation.accountID), owner = runtime.preparation.ownerUID
        func captured(_ path: String, _ access: RuntimePublishedArtifactValidation.Access) throws -> Data {
            try verify()
            let bytes = try read(.init(path: path, bytes: Data(), access: access))
            try verify(); return bytes
        }
        func client(_ file: AdministrativeSetupPublication.File) throws -> Data {
            try captured(RuntimePreparationPaths.sharedDirectory + "/" + file.name, .publicRoot)
        }
        let command = try AuthorityCommandStartupConfiguration.decode(captured(paths.commandConfiguration, .privateRoot))
        let transport = try TransportPairingStartupConfiguration.decodeForReleaseArchive(captured(paths.transportConfiguration, .publicRoot))
        let clients = try RuntimeActivationClients(presence: .decode(client(.presenceClient(ownerUID: owner))),
            pairing: .decode(client(.pairingClient(ownerUID: owner))), frontend: .decode(client(.frontendClient(ownerUID: owner))))
        guard transport.settingsHost?.retainedSetupBinding == binding else { throw RuntimeActivationError.changedScope }
        let bundle = try RuntimeConfigurationBundle.stableCompleted(snapshot: runtime, reference: reference,
            candidate: candidate, currentCodePolicy: currentCodePolicy, command: command, transport: transport, clients: clients)
        guard try bundle.gatewaySettingsHost?.retainedSetupBinding == binding else { throw RuntimeActivationError.changedScope }
        try RuntimePublishedArtifactValidation.validate(bundle: bundle, material: material, verifyCurrent: verify, read: read)
        let inventory = setup.source.actual.inventory, label = bundle.paths.namespace + ".authority"
        let initial = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, codePolicy: currentCodePolicy,
            command: bundle.command, label: label, plistName: label + ".plist", jobPlacement: .systemAccount)
        let host = try initial.enablingGatewaySettingsControl(release: candidate)
        try host.validateRelease(candidate, bundlePath: inventory.bundlePath)
        try verify()
        let final = try readPolicyBoundary()
        try binding.requireSourceForPublication(snapshot, current: final, candidate: candidate)
        try verify()
        return .init(binding: binding, bundle: bundle, host: host)
    }
}
