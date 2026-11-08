import Foundation
import RemozioProtocol

/// Retained setup and selected settings. This value grants no native access or publication authority.
struct RuntimeReleaseBackendSource: CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.release-backend-source"
    static let maximumBytes = 1_048_576
    var foreground: RuntimeActivationPlan { storage.foreground }
    var activation: GatewayRuntimeActivationPlan { storage.activation }
    var journal: GatewayJournalPreparationState { storage.journal }
    var revision: GatewayRuntimeSettingsRevision? { storage.revision }
    var inventory: InstallationInventory { storage.inventory }
    var inventoryDigest: Data { MachineUpdateActivationRecord.digest(inventory.canonicalBytes) }
    var pair: GatewayRuntimeExtensions { storage.pair }
    var gateway: GatewayServiceConfiguration { storage.gateway }
    var commit: GatewayRuntimeCommit { storage.commit }
    private let storage: Storage
    private final class Storage: Sendable {
        let foreground: RuntimeActivationPlan
        let activation: GatewayRuntimeActivationPlan
        let journal: GatewayJournalPreparationState
        let revision: GatewayRuntimeSettingsRevision?
        let inventory: InstallationInventory
        let pair: GatewayRuntimeExtensions
        let gateway: GatewayServiceConfiguration
        let commit: GatewayRuntimeCommit
        @inline(never) init(foreground: RuntimeActivationPlan, activation: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState, revision: GatewayRuntimeSettingsRevision?, inventory: InstallationInventory, pair: GatewayRuntimeExtensions, gateway: GatewayServiceConfiguration, commit: GatewayRuntimeCommit) {
            self.foreground = foreground
            self.activation = activation
            self.journal = journal
            self.revision = revision
            self.inventory = inventory
            self.pair = pair
            self.gateway = gateway
            self.commit = commit
        }
    }
    var description: String { "RuntimeReleaseBackendSource(redacted)" }
    var debugDescription: String { description }

    init(foreground: RuntimeActivationPlan, activation: GatewayRuntimeActivationPlan,
         journal: GatewayJournalPreparationState, settings: GatewayRuntimeSettingsState,
         inventory: InstallationInventory) throws {
        guard journal.intent != nil, journal.initialized, settings.pending == nil, settings.phase == nil else { throw GatewayPreparationError.incomplete }
        let pair: GatewayRuntimeExtensions, commit: GatewayRuntimeCommit
        let proposal: GatewayConfigurationBundle
        if let revision = settings.active {
            proposal = try revision.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            pair = try .init(settings: revision, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            commit = try .init(pair, settings: revision, gateway: proposal.gateway)
        } else {
            proposal = try activation.proposal(journal: journal, foreground: foreground, inventory: inventory)
            pair = activation.extensions
            commit = try .init(pair)
        }
        storage = .init(foreground: foreground, activation: activation, journal: journal, revision: settings.active,
            inventory: inventory, pair: pair, gateway: proposal.gateway, commit: commit)
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName),
            2: .bytes(foreground.encoded), 3: .bytes(activation.encoded), 4: .bytes(journal.intent!.encoded),
            5: .bytes(inventory.canonicalBytes), 6: try revision.map { .bytes(try $0.encoded) } ?? .null]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), f[1] == .text(formatName), case .bytes(let foreground) = f[2],
              case .bytes(let activation) = f[3], case .bytes(let journal) = f[4], case .bytes(let inventory) = f[5] else {
            throw GatewayPreparationError.invalidRecord
        }
        let base = try RuntimeActivationPlan.decode(foreground), revision: GatewayRuntimeSettingsRevision?
        switch f[6] {
        case .bytes(let bytes)?: revision = try .decode(bytes)
        case .null?: revision = nil
        default: throw GatewayPreparationError.invalidRecord
        }
        let value = try Self(foreground: base, activation: .decode(activation),
            journal: .init(intent: GatewayJournalSetupIntent.decode(journal), initialized: true),
            settings: .init(active: revision, pending: nil, phase: nil),
            inventory: .decode(inventory, expectedMacID: base.reference.services.macID))
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    var digest: Data { get throws {
        MachineUpdateActivationRecord.digest(Data("Remozio/RuntimeReleaseBackendSource/v1\0".utf8) + (try encoded))
    } }
    /// The scoped owner must supply protected readers and keep the machine admission closed.
    func requirePublished(read: (AdministrativeSetupPublication.File) throws -> Data,
                          readFence: () throws -> GatewayRuntimeSettingsFence?,
                          verifyCurrent: () throws -> Void) throws {
        try verifyCurrent(); guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
        let expected: [(AdministrativeSetupPublication.File, Data)] = try [
            (.authorityGatewayRuntime, pair.authority.encoded), (.transportGatewayRuntime, pair.transport.encoded),
            (.gatewayConfiguration, gateway.canonicalBytes), (.gatewayRuntimeCommit, commit.encoded)]
        func check() throws {
            for (file, bytes) in expected { try verifyCurrent(); guard try read(file) == bytes else { throw GatewayPreparationError.changedScope } }
            if let revision {
                guard try read(.gatewaySettingsRevision) == revision.encoded else { throw GatewayPreparationError.changedScope }
            }
            guard try readFence() == nil else { throw GatewayPreparationError.changedScope }
            try verifyCurrent()
        }
        try check(); try check()
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 19)
}

/// Proposed backend values. The machine owner must retain the plan and recheck every source before publication.
struct RuntimeReleaseBackendPlan: CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.release-backend-plan"
    static let maximumBytes = 2_097_152
    var configuration: RuntimeReleaseConfigurationPlan { storage.configuration }
    var source: RuntimeReleaseBackendSource { storage.source }
    var sourceConfiguration: RuntimeReleaseConfigurationSource { storage.sourceConfiguration }
    var gateway: GatewayServiceConfiguration { storage.gateway }
    var transportWake: TransportWakeStartupConfiguration { storage.transportWake }
    private let storage: Storage
    private final class Storage: Sendable {
        let configuration: RuntimeReleaseConfigurationPlan
        let source: RuntimeReleaseBackendSource
        let sourceConfiguration: RuntimeReleaseConfigurationSource
        let gateway: GatewayServiceConfiguration
        let transportWake: TransportWakeStartupConfiguration
        @inline(never) init(configuration: RuntimeReleaseConfigurationPlan, source: RuntimeReleaseBackendSource, sourceConfiguration: RuntimeReleaseConfigurationSource, gateway: GatewayServiceConfiguration, transportWake: TransportWakeStartupConfiguration) {
            self.configuration = configuration
            self.source = source
            self.sourceConfiguration = sourceConfiguration
            self.gateway = gateway
            self.transportWake = transportWake
        }
    }
    var binding: RuntimeReleaseBinding { configuration.binding }
    var policyStage: RuntimeReleasePolicyStage { configuration.policyStage }
    var description: String { "RuntimeReleaseBackendPlan(redacted)" }
    var debugDescription: String { description }

    init(configuration: RuntimeReleaseConfigurationPlan, source: RuntimeReleaseBackendSource,
         sourceConfiguration: RuntimeReleaseConfigurationSource, machine: MachineUpdateRestartSource,
         currentPolicy: AuthorityCodePolicySnapshot, candidate: SignedReleaseEvidence) throws {
        try configuration.requireSourceForPublication(machine, currentPolicy: currentPolicy, candidate: candidate,
            host: sourceConfiguration.host, transport: sourceConfiguration.transport,
            gateway: sourceConfiguration.gateway, clients: sourceConfiguration.clients)
        guard source.inventoryDigest == MachineUpdateActivationRecord.digest(machine.replacement.inventory.canonicalBytes) else {
            throw GatewayPreparationError.changedScope
        }
        try self.init(configuration: configuration, source: source, sourceConfiguration: sourceConfiguration)
    }
    private init(configuration: RuntimeReleaseConfigurationPlan, source: RuntimeReleaseBackendSource,
                 sourceConfiguration: RuntimeReleaseConfigurationSource) throws {
        guard configuration.sourceDigest == (try sourceConfiguration.digest),
              source.inventoryDigest == configuration.binding.sourceInventoryDigest,
              source.inventory.releaseDigest == configuration.binding.previousInstalledReleaseDigest,
              source.inventory.macID == configuration.binding.macID,
              source.inventory.installationID == configuration.binding.installationID,
              sourceConfiguration.host.releaseDigest == configuration.binding.previousInstalledReleaseDigest,
              sourceConfiguration.gateway.installedReleaseDigest == configuration.binding.previousInstalledReleaseDigest,
              source.foreground.reference == configuration.gateway.runtime,
              source.foreground.bundlePath == configuration.gateway.bundlePath,
              source.pair.authority.material.runtime == configuration.gateway.runtime,
              source.pair.authority.codePolicy == sourceConfiguration.gateway.codePolicy,
              source.pair.transport.codePolicy == sourceConfiguration.gateway.codePolicy,
              let previousWake = source.pair.transport.wake else { throw GatewayPreparationError.changedScope }
        try source.pair.authority.validate(authority: sourceConfiguration.host)
        try source.pair.transport.validate(transport: sourceConfiguration.transport)
        let policy = configuration.host.codePolicy
        func code(_ role: AuthorityCodeRole) throws -> AuthorityCodeEntry {
            guard let value = policy.entries.first(where: { $0.role == role && $0.active }) else { throw GatewayPreparationError.changedScope }
            return value
        }
        let root = try code(.authority), transport = try code(.transport), companion = try code(.notificationGateway)
        let old = source.gateway
        guard let endpoint = old.wakeEndpoint else { throw GatewayPreparationError.incomplete }
        let wakeEndpoint = try GatewayWakeEndpointConfiguration(serviceName: endpoint.serviceName,
            transportUID: endpoint.transportUID, teamID: transport.teamID, componentIdentifier: transport.identifier,
            approvedCodeDirectoryHashes: [transport.codeDirectoryHash], maximumConnections: endpoint.maximumConnections,
            maximumOperations: endpoint.maximumOperations, challengeLifetimeMillis: endpoint.challengeLifetimeMillis)
        let gateway = try GatewayServiceConfiguration(registration: old.registration, receiptPublicKey: old.receiptPublicKey,
            directoryPath: old.directoryPath, providerPath: old.providerPath, receiptKeyPath: old.receiptKeyPath,
            serviceUID: old.serviceUID, ownerUID: old.ownerUID, serviceName: old.serviceName,
            teamID: root.teamID, authorityIdentifier: root.identifier, authorityHashes: [root.codeDirectoryHash],
            project: old.project, packageName: old.packageName, settings: old.settings, wakeEndpoint: wakeEndpoint)
        let signer = previousWake.wake
        let wake = try GatewayWakeSignerConfiguration(binding: signer.binding, credentialID: signer.credentialID,
            transportUID: signer.transportUID, ownerUID: signer.ownerUID, gatewayUID: signer.gatewayPolicy.expectedUserID,
            serviceName: signer.serviceName, teamID: companion.teamID, gatewayIdentifier: companion.identifier,
            gatewayHashes: [companion.codeDirectoryHash], custody: signer.custody, keyRecordPath: signer.keyRecordPath,
            publicKey: signer.publicKey, timeoutMilliseconds: signer.timeoutMilliseconds)
        let transportWake = try TransportWakeStartupConfiguration(transport: configuration.transport.transport, wake: wake, pollMilliseconds: previousWake.pollMilliseconds)
        storage = .init(configuration: configuration, source: source, sourceConfiguration: sourceConfiguration,
            gateway: gateway, transportWake: transportWake)
        _ = try encoded
    }
    /// Projects settled settings through the installed policy. The caller must retain fresh protected scope checks.
    func projectingSettledInstalledSettings(_ settings: GatewayRuntimeSettingsState,
        candidate: SignedReleaseEvidence) throws -> Self {
        guard policyStage == .completion, settings.pending == nil, settings.phase == nil,
              try InstallationInventory.digest(candidate) == binding.installedReleaseDigest,
              let transportHost = configuration.transport.settingsHost else { throw GatewayPreparationError.changedScope }
        try binding.requireCompletionPolicy(configuration.host.codePolicy)
        try configuration.host.validateRelease(candidate, bundlePath: configuration.gateway.bundlePath)
        try configuration.gateway.validateRelease(candidate); try transportHost.validateRelease(candidate)
        if let previous = source.revision {
            guard let current = settings.active, current.sequence >= previous.sequence else {
                throw GatewayPreparationError.changedScope
            }
            if current.sequence == previous.sequence {
                guard try current.encoded == previous.encoded else { throw GatewayPreparationError.changedScope }
            }
        }
        let current = try RuntimeReleaseBackendSource(foreground: source.foreground, activation: source.activation,
            journal: source.journal, settings: settings, inventory: source.inventory)
        return try Self(configuration: configuration, source: current, sourceConfiguration: sourceConfiguration)
    }
    func requireSourceForPublication(configuration: RuntimeReleaseConfigurationPlan, source: RuntimeReleaseBackendSource,
                                    sourceConfiguration: RuntimeReleaseConfigurationSource, machine: MachineUpdateRestartSource,
                                    currentPolicy: AuthorityCodePolicySnapshot, candidate: SignedReleaseEvidence) throws {
        let current = try Self(configuration: configuration, source: source, sourceConfiguration: sourceConfiguration,
            machine: machine, currentPolicy: currentPolicy, candidate: candidate)
        guard try current.encoded == encoded else { throw GatewayPreparationError.changedScope }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(configuration.encoded),
            3: .bytes(source.encoded), 4: .bytes(sourceConfiguration.encoded),
            5: .bytes(gateway.canonicalBytes), 6: .bytes(transportWake.canonicalBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...6),
              f[0] == .unsigned(1), f[1] == .text(formatName), case .bytes(let configuration) = f[2],
              case .bytes(let source) = f[3], case .bytes(let original) = f[4],
              case .bytes = f[5], case .bytes = f[6] else { throw GatewayPreparationError.invalidRecord }
        let value = try Self(configuration: .decode(configuration), source: .decode(source), sourceConfiguration: .decode(original))
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 19)
}
