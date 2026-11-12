import Foundation
import RemozioProtocol

/// Proposed configuration values. Fresh protected source checks and the machine owner remain mandatory before publication.
struct RuntimeReleaseConfigurationPlan: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.release-configuration"
    private final class Storage: Sendable {
        let binding: RuntimeReleaseBinding
        let policyStage: RuntimeReleasePolicyStage
        let sourceDigest: Data
        let host: InstalledAuthorityCommandConfiguration
        let transport: TransportPairingStartupConfiguration
        let gateway: GatewaySettingsConsumerHostConfiguration
        let clients: RuntimeActivationClients
        @inline(never)
        init(binding: RuntimeReleaseBinding, policyStage: RuntimeReleasePolicyStage, sourceDigest: Data,
            host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
            gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) {
            self.binding = binding
            self.policyStage = policyStage
            self.sourceDigest = sourceDigest
            self.host = host
            self.transport = transport
            self.gateway = gateway
            self.clients = clients
        }
    }
    private let storage: Storage
    var binding: RuntimeReleaseBinding { storage.binding }
    var policyStage: RuntimeReleasePolicyStage { storage.policyStage }
    var sourceDigest: Data { storage.sourceDigest }
    var host: InstalledAuthorityCommandConfiguration { storage.host }
    var transport: TransportPairingStartupConfiguration { storage.transport }
    var gateway: GatewaySettingsConsumerHostConfiguration { storage.gateway }
    var clients: RuntimeActivationClients { storage.clients }
    var description: String { "RuntimeReleaseConfigurationPlan(redacted)" }
    var debugDescription: String { description }

    init(accountID: Data, source: MachineUpdateRestartSource, currentPolicy: AuthorityCodePolicySnapshot,
         candidate: SignedReleaseEvidence, host sourceHost: InstalledAuthorityCommandConfiguration,
         transport sourceTransport: TransportPairingStartupConfiguration,
         gateway sourceGateway: GatewaySettingsConsumerHostConfiguration, clients sourceClients: RuntimeActivationClients,
         stage: RuntimeReleasePolicyStage) throws {
        let policy = try MachineUpdatePolicyPlan(source: currentPolicy, candidate: candidate)
        let binding = try RuntimeReleaseBinding(accountID: accountID, source: source, candidate: candidate, policy: policy)
        let reference = sourceGateway.runtime
        try binding.requireHistoricalRuntime(reference)
        guard sourceGateway.releaseBinding == nil, sourceGateway.bundlePath == source.replacement.inventory.bundlePath,
              let initial = source.accounts.first(where: { $0.accountID == accountID })?.initialization,
              sourceHost.command.presence.wake.request.service.journalDirectory == (initial.journalPath as NSString).deletingLastPathComponent,
              sourceHost.command.presence.wake.request.service.continuityDirectory == (initial.continuityPath as NSString).deletingLastPathComponent else {
            throw RuntimeActivationError.changedScope
        }
        try Self.validateValues(host: sourceHost, transport: sourceTransport, gateway: sourceGateway, clients: sourceClients,
            releaseDigest: binding.previousInstalledReleaseDigest, policy: currentPolicy.policy)
        let targetPolicy = stage == .startup ? policy.startupPolicy : policy.completionPolicy
        let command = try Self.command(sourceHost.command, policy: targetPolicy)
        let host = try InstalledAuthorityCommandConfiguration(machineDirectory: sourceHost.machineDirectory,
            installationID: sourceHost.installationID, releaseDigest: binding.installedReleaseDigest, codePolicy: targetPolicy,
            command: command, label: sourceHost.label, plistName: sourceHost.plistName,
            jobPlacement: sourceHost.jobPlacement, gatewaySettingsControlEnabled: sourceHost.gatewaySettingsControlEnabled, installedReadinessEnabled: sourceHost.installedReadinessEnabled)
        let transportHost = try GatewaySettingsConsumerHostConfiguration(role: .transport, runtime: reference,
            bundlePath: sourceGateway.bundlePath, codePolicy: targetPolicy, releaseBinding: binding, policyStage: stage)
        let gateway = try GatewaySettingsConsumerHostConfiguration(role: .gateway, runtime: reference,
            bundlePath: sourceGateway.bundlePath, codePolicy: targetPolicy, releaseBinding: binding, policyStage: stage)
        let transport = try Self.transport(sourceTransport, host: transportHost, policy: targetPolicy)
        let clients = try Self.clients(sourceClients, policy: targetPolicy)
        try self.init(binding: binding, stage: stage,
            sourceDigest: Self.digest(host: sourceHost, transport: sourceTransport, gateway: sourceGateway, clients: sourceClients),
            host: host, transport: transport, gateway: gateway, clients: clients)
        try host.validateRelease(candidate, bundlePath: gateway.bundlePath)
        try gateway.validateRelease(candidate); try transportHost.validateRelease(candidate)
    }
    private init(binding: RuntimeReleaseBinding, stage: RuntimeReleasePolicyStage, sourceDigest: Data,
                 host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
                 gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) throws {
        guard sourceDigest.count == 32, gateway.releaseBinding == binding, gateway.policyStage == stage,
              transport.settingsHost?.releaseBinding == binding, transport.settingsHost?.policyStage == stage else {
            throw RuntimeActivationError.invalidPlan
        }
        try binding.requireHistoricalRuntime(gateway.runtime); try binding.requirePolicy(host.codePolicy, stage: stage)
        try Self.validateValues(host: host, transport: transport, gateway: gateway, clients: clients,
            releaseDigest: binding.installedReleaseDigest, policy: host.codePolicy)
        storage = .init(binding: binding, policyStage: stage, sourceDigest: sourceDigest,
            host: host, transport: transport, gateway: gateway, clients: clients)
    }
    /// Call within fresh scoped machine and protected file reads. This value does not hold those read capabilities.
    func requireSourceForPublication(_ source: MachineUpdateRestartSource, currentPolicy: AuthorityCodePolicySnapshot,
                                    candidate: SignedReleaseEvidence, host: InstalledAuthorityCommandConfiguration,
                                    transport: TransportPairingStartupConfiguration,
                                    gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) throws {
        let proposed = try Self(accountID: binding.accountID, source: source, currentPolicy: currentPolicy,
            candidate: candidate, host: host, transport: transport, gateway: gateway, clients: clients, stage: policyStage)
        let retained = self.host.installedReadinessEnabled && !proposed.host.installedReadinessEnabled
            ? try proposed.selectingInstalledRootReadiness(candidate: candidate) : proposed
        guard try retained.encoded == encoded else { throw RuntimeActivationError.changedScope }
    }

    /// Selects readiness for the completion plan. The caller still owns file publication and job settlement.
    func selectingInstalledRootReadiness(candidate: SignedReleaseEvidence) throws -> Self {
        guard policyStage == .completion else { throw RuntimeActivationError.changedScope }
        try MachineUpdateAuthorityReadinessJobTransition.requireRelease(candidate, policy: host.codePolicy)
        let selected = try host.enablingInstalledReadiness(release: candidate)
        try selected.validateRelease(candidate, bundlePath: gateway.bundlePath)
        return try .init(binding: binding, stage: policyStage, sourceDigest: sourceDigest,
            host: selected, transport: transport, gateway: gateway, clients: clients)
    }

    static func retainingCompletedSetup(snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        clients sourceClients: RuntimeActivationClients) throws -> (archive: RuntimeRetainedSetupCompletionArchive, sourceDigest: Data,
            host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
            gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) {
        try RuntimeRetainedSetupCompletionBinding.requireCompletedHostFormats(candidate)
        let archive = try RuntimeRetainedSetupCompletionArchive(snapshot: snapshot, current: current, candidate: candidate)
        let original = try archive.originalActivation(), binding = archive.binding
        let sourceGateway = original.gatewaySettingsHost
        try binding.startupBinding.requireStartupPolicy(original.host.codePolicy)
        try validateValues(host: original.host, transport: original.transport, gateway: sourceGateway, clients: sourceClients,
            releaseDigest: binding.startupBinding.installedReleaseDigest, policy: original.host.codePolicy)
        let policy = current.policy.policy
        try binding.requireCompletionPolicy(policy)
        let command = try Self.command(original.host.command, policy: policy)
        let host = try InstalledAuthorityCommandConfiguration(machineDirectory: original.host.machineDirectory,
            installationID: original.host.installationID, releaseDigest: binding.startupBinding.installedReleaseDigest,
            codePolicy: policy, command: command, label: original.host.label, plistName: original.host.plistName,
            jobPlacement: original.host.jobPlacement, gatewaySettingsControlEnabled: original.host.gatewaySettingsControlEnabled,
            installedReadinessEnabled: original.host.installedReadinessEnabled)
        let gateway = try GatewaySettingsConsumerHostConfiguration.retainedSetupCompletion(role: .gateway, runtime: original.reference,
            bundlePath: original.bundlePath, codePolicy: policy, binding: binding)
        let transportHost = try gateway.selecting(role: .transport)
        let transport = try Self.transport(original.transport, host: transportHost, policy: policy)
        let clients = try Self.clients(sourceClients, policy: policy)
        try host.validateRelease(candidate, bundlePath: gateway.bundlePath)
        try gateway.validateRelease(candidate); try transportHost.validateRelease(candidate)
        return (archive: archive,
            sourceDigest: try digest(host: original.host, transport: original.transport, gateway: sourceGateway, clients: sourceClients),
            host: host, transport: transport, gateway: gateway, clients: clients)
    }
    /// Checks completed archive values only. It grants no current source, publication, or startup authority.
    static func requireRetainedCompletionValues(archive: RuntimeRetainedSetupCompletionArchive,
        host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
        gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) throws {
        guard gateway.retainedSetupCompletionBinding == archive.binding, gateway.policyStage == .completion,
              transport.settingsHost?.retainedSetupCompletionBinding == archive.binding else { throw RuntimeActivationError.changedScope }
        try archive.binding.requireHistoricalRuntime(gateway.runtime)
        try archive.binding.requireCompletionPolicy(host.codePolicy)
        try validateValues(host: host, transport: transport, gateway: gateway, clients: clients,
            releaseDigest: archive.binding.startupBinding.installedReleaseDigest, policy: host.codePolicy)
    }

    private static func code(_ role: AuthorityCodeRole, _ policy: AuthorityCodePolicy) throws -> AuthorityCodeEntry {
        guard let code = policy.entries.first(where: { $0.role == role && $0.active }) else { throw RuntimeActivationError.changedScope }
        return code
    }
    private static func require(_ actual: XPCPeerPolicy, role: AuthorityCodeRole, uid: UInt32,
                                policy: AuthorityCodePolicy) throws {
        let code = try code(role, policy), expected = try XPCPeerPolicy(teamID: code.teamID,
            componentIdentifier: code.identifier, approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: uid)
        guard actual.expectedUserID == expected.expectedUserID, actual.expectedAuditSessionID == expected.expectedAuditSessionID,
              actual.requirement == expected.requirement else { throw RuntimeActivationError.changedScope }
    }
    private static func validateValues(host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
                                       gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients,
                                       releaseDigest: Data, policy: AuthorityCodePolicy) throws {
        let reference = gateway.runtime, services = reference.services, command = host.command
        let presence = command.presence, wake = presence.wake, request = wake.request, service = request.service
        let paths = try RuntimePreparationPaths(accountID: services.accountID)
        guard let transportHost = transport.settingsHost, transportHost.role == .transport, gateway.role == .gateway,
              transportHost.runtime == reference, transportHost.bundlePath == gateway.bundlePath,
              transportHost.releaseBinding == gateway.releaseBinding, transportHost.policyStage == gateway.policyStage,
              host.jobPlacement == .systemAccount, host.gatewaySettingsControlEnabled,
              host.installationID == services.installationID, host.releaseDigest == releaseDigest,
              gateway.installedReleaseDigest == releaseDigest, transportHost.installedReleaseDigest == releaseDigest,
              try host.codePolicy.bytes == policy.bytes, try gateway.codePolicy.bytes == policy.bytes,
              try transportHost.codePolicy.bytes == policy.bytes,
              command.macID == services.macID, command.accountID == services.accountID, command.callerUID == services.ownerUID,
              let transportClaim = services.claims.first(where: { $0.role == .transport }),
              let gatewayClaim = services.claims.first(where: { $0.role == .gateway }),
              request.authorityPublicKey == services.authorityPublicKey, wake.registration == reference.gateway,
              request.keyRecordPath == paths.authorityDirectory + "/Key/" + AuthorityKeyProvisioning.recordFileName,
              service.serviceName == paths.authorityService,
              service.auditVersions == Set(reference.auditDeliveryVersion.map { [$0] } ?? []),
              wake.gatewayServiceName == paths.gatewayService,
              try presence.pairing?.transportPublicKey == reference.transportPublicKeyX963,
              command.execution?.monitorPath == gateway.bundlePath + "/Contents/Helpers/RemozioCommandMonitor",
              command.execution?.childPath == gateway.bundlePath + "/Contents/Helpers/RemozioCommandChild" else {
            throw RuntimeActivationError.changedScope
        }
        try transportHost.validate(transport: transport.transport, pairing: transport.control)
        try transportHost.validate(transport: transport.transport, pairing: clients.pairing)
        try require(service.transportPolicy, role: .transport, uid: transportClaim.number, policy: policy)
        try require(wake.gatewayPolicy, role: .notificationGateway, uid: gatewayClaim.number, policy: policy)
        try require(presence.endpoint.appPolicy, role: .app, uid: services.ownerUID, policy: policy)
        let p = clients.presence, f = clients.frontend
        guard p.macID == services.macID, p.accountID == services.accountID, p.ownerUID == services.ownerUID,
              p.serviceName == paths.presenceService, f.macID == services.macID, f.accountID == services.accountID,
              f.serviceName == paths.commandService else { throw RuntimeActivationError.changedScope }
        try require(p.rootPolicy, role: .authority, uid: 0, policy: policy)
        try require(f.authorityPolicy, role: .authority, uid: 0, policy: policy)
        if let signer = transport.wake?.wake {
            let registration = reference.gateway
            let expected = try GatewaySubmissionBinding(ownerID: registration.ownerID, macID: registration.macID,
                accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch)
            guard signer.binding == expected, signer.transportUID == transportClaim.number,
                  signer.ownerUID == services.ownerUID, signer.serviceName == paths.gatewayWakeService,
                  signer.custody == .protectedFile, signer.keyRecordPath == paths.transportWakeKey else {
                throw RuntimeActivationError.changedScope
            }
            try require(signer.gatewayPolicy, role: .notificationGateway, uid: gatewayClaim.number, policy: policy)
        }
    }
    private static func command(_ old: AuthorityCommandStartupConfiguration, policy: AuthorityCodePolicy) throws -> AuthorityCommandStartupConfiguration {
        let p = old.presence, w = p.wake, r = w.request, s = r.service
        let t = try code(.transport, policy), g = try code(.notificationGateway, policy), a = try code(.app, policy)
        let service = try AuthorityServiceConfiguration(macID: s.macID, accountID: s.accountID,
            journalDirectory: s.journalDirectory, serviceName: s.serviceName, teamID: t.teamID,
            transportIdentifier: t.identifier, transportHashes: [t.codeDirectoryHash], transportUID: s.transportPolicy.expectedUserID,
            maximumPayloadBytes: s.maximumPayloadBytes, minimumEnvelopeVersion: s.minimumEnvelopeVersion,
            auditVersions: s.auditVersions, maximumConnections: s.maximumConnections,
            handshakeTimeoutMilliseconds: s.handshakeTimeoutMilliseconds, maximumOperations: s.maximumOperations,
            continuityDirectory: s.continuityDirectory)
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: r.keyRecordPath,
            authorityPublicKey: r.authorityPublicKey, maintenanceIntervalMilliseconds: r.maintenanceIntervalMilliseconds)
        let wake = try AuthorityWakeStartupConfiguration(request: request, registration: w.registration,
            gatewayServiceName: w.gatewayServiceName, gatewayUID: w.gatewayPolicy.expectedUserID, teamID: g.teamID,
            gatewayIdentifier: g.identifier, gatewayHashes: [g.codeDirectoryHash], leaseMilliseconds: w.leaseMilliseconds,
            pollMilliseconds: w.pollMilliseconds, timeoutMilliseconds: w.timeoutMilliseconds, phonePush: w.phonePush)
        let presence = try AuthorityPresenceStartupConfiguration(wake: wake, ownerUID: p.presence.ownerUID,
            appServiceName: p.endpoint.serviceName, teamID: a.teamID, appIdentifier: a.identifier,
            appHashes: [a.codeDirectoryHash], policy: p.presence.policy, pairing: p.pairing)
        return try .init(presence: presence, serviceName: old.serviceName, policyPath: old.policyPath,
            environment: old.environment, submissionLimits: old.submissionLimits, captureLimits: old.captureLimits,
            maximumSessions: old.maximumSessions, receiveWaitMilliseconds: old.receiveWaitMilliseconds,
            replyTimeoutMilliseconds: old.replyTimeoutMilliseconds, maximumAncestryEntries: old.maximumAncestryEntries,
            approvalLifetimeMilliseconds: old.approvalLifetimeMilliseconds, execution: old.execution)
    }
    private static func pairing(_ old: TransportPairingControlConfiguration, policy: AuthorityCodePolicy) throws -> TransportPairingControlConfiguration {
        let a = try code(.app, policy), t = try code(.transport, policy)
        return try .init(macID: old.macID, accountID: old.accountID, ownerUID: old.ownerUID,
            transportUID: old.transportUID, serviceName: old.serviceName, teamID: a.teamID,
            appIdentifier: a.identifier, appHashes: [a.codeDirectoryHash], transportIdentifier: t.identifier,
            transportHashes: [t.codeDirectoryHash], timeoutMilliseconds: old.timeoutMilliseconds,
            setupTimeoutMilliseconds: old.setupTimeoutMilliseconds, maximumCandidates: old.maximumCandidates)
    }
    private static func transport(_ old: TransportPairingStartupConfiguration, host: GatewaySettingsConsumerHostConfiguration,
                                  policy: AuthorityCodePolicy) throws -> TransportPairingStartupConfiguration {
        let source = old.transport, r = try code(.authority, policy), g = try code(.notificationGateway, policy)
        let direct = try ApprovalTransportConfiguration(macID: source.macID, accountID: source.accountID,
            ownerUID: source.ownerUID, serviceUID: source.serviceUID, authorityServiceName: source.authorityServiceName,
            teamID: r.teamID, authorityIdentifier: r.identifier, authorityHashes: [r.codeDirectoryHash],
            identitySource: source.identitySource, identityPublicKeyInfo: source.identityPublicKeyInfo,
            maximumConnections: source.maximumConnections, timeoutMilliseconds: source.timeoutMilliseconds,
            refreshMilliseconds: source.refreshMilliseconds)
        let wake: TransportWakeStartupConfiguration?
        if let previous = old.wake {
            let s = previous.wake
            let signer = try GatewayWakeSignerConfiguration(binding: s.binding, credentialID: s.credentialID,
                transportUID: s.transportUID, ownerUID: s.ownerUID, gatewayUID: s.gatewayPolicy.expectedUserID,
                serviceName: s.serviceName, teamID: g.teamID, gatewayIdentifier: g.identifier,
                gatewayHashes: [g.codeDirectoryHash], custody: s.custody, keyRecordPath: s.keyRecordPath,
                publicKey: s.publicKey, timeoutMilliseconds: s.timeoutMilliseconds)
            wake = try .init(transport: direct, wake: signer, pollMilliseconds: previous.pollMilliseconds)
        } else { wake = nil }
        return try .init(transport: direct, control: pairing(old.control, policy: policy), wake: wake,
            relayPort: old.relayPort, settingsHost: host)
    }
    private static func clients(_ old: RuntimeActivationClients, policy: AuthorityCodePolicy) throws -> RuntimeActivationClients {
        let r = try code(.authority, policy), p = old.presence, f = old.frontend
        return try .init(presence: .init(macID: p.macID, accountID: p.accountID, ownerUID: p.ownerUID,
            serviceName: p.serviceName, teamID: r.teamID, rootIdentifier: r.identifier, rootHashes: [r.codeDirectoryHash],
            timeoutMilliseconds: p.timeoutMilliseconds), pairing: pairing(old.pairing, policy: policy),
            frontend: .init(macID: f.macID, accountID: f.accountID, serviceName: f.serviceName, teamID: r.teamID,
                authorityIdentifier: r.identifier, authorityHashes: [r.codeDirectoryHash], submissionLimits: f.submissionLimits,
                defaultIOMode: f.defaultIOMode, defaultDisconnectBehavior: f.defaultDisconnectBehavior, readiness: f.readiness))
    }
    private static func digest(host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
                               gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) throws -> Data {
        try RuntimeReleaseConfigurationSource(host: host, transport: transport, gateway: gateway, clients: clients).digest
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(try binding.encoded),
            3: .unsigned(policyStage.rawValue), 4: .bytes(sourceDigest), 5: .bytes(host.canonicalBytes),
            6: .bytes(transport.canonicalBytes), 7: .bytes(try gateway.encoded),
            8: .bytes(clients.presence.canonicalBytes), 9: .bytes(clients.pairing.canonicalBytes),
            10: .bytes(clients.frontend.canonicalBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...10),
              f[0] == .unsigned(1), f[1] == .text(formatName), case .unsigned(let rawStage) = f[3],
              let stage = RuntimeReleasePolicyStage(rawValue: rawStage) else { throw RuntimeActivationError.invalidPlan }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let bytes) = f[key] else { throw RuntimeActivationError.invalidPlan }; return bytes
        }
        let value = try Self(binding: .decode(data(2)), stage: stage, sourceDigest: data(4), host: .decode(data(5)),
            transport: .decodeForReleaseArchive(data(6)), gateway: .decodeForReleaseArchive(data(7)),
            clients: .init(presence: .decode(data(8)), pairing: .decode(data(9)), frontend: .decode(data(10))))
        guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }; return value
    }
    static let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 23)
}
