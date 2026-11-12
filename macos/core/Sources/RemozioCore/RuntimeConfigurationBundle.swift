import Foundation
import RemozioProtocol

/// Fixed per-account locations. Only privileged setup may create or publish these paths.
struct RuntimePreparationPaths: Sendable {
    static let sharedDirectory = "/Library/Application Support/Remozio"
    let privateDirectory: String
    let serviceDirectory: String
    let authorityDirectory: String
    let namespace: String
    init(accountID: Data) throws {
        guard accountID.count == 16 else { throw RuntimePreparationError.invalidRecord }
        let suffix = LowercaseHexadecimal.encode(accountID)
        authorityDirectory = try AccountPreparationController.authorityDirectory(accountID: accountID)
        privateDirectory = (authorityDirectory as NSString).deletingLastPathComponent + "/Runtime"
        serviceDirectory = Self.sharedDirectory + "/Services/" + suffix
        namespace = "dev.remozio.account." + suffix
    }
    var commandConfiguration: String { privateDirectory + "/" + AdministrativeSetupPublication.File.commandConfiguration.name }
    var policy: String { privateDirectory + "/" + AdministrativeSetupPublication.File.elevationPolicy.name }
    var transportConfiguration: String { serviceDirectory + "/" + AdministrativeSetupPublication.File.transportConfiguration.name }
    var transportIdentity: String { serviceDirectory + "/transport-identity.cbor" }
    var authorityService: String { namespace + ".authority" }
    var commandService: String { namespace + ".commands" }
    var gatewaySettingsControlService: String { namespace + ".gateway-settings-control" }
    var presenceService: String { namespace + ".presence" }
    var pairingService: String { namespace + ".pairing" }
    var gatewayService: String { namespace + ".gateway" }
    var gatewayWakeService: String { namespace + ".gateway.wake" }
    var gatewayConfiguration: String { serviceDirectory + "/gateway-host.cbor" }
    var gatewayDirectory: String { serviceDirectory + "/Gateway" }
    var gatewayProvider: String { serviceDirectory + "/gateway-provider.json" }
    var gatewayReceiptKey: String { serviceDirectory + "/gateway-receipt-key.cbor" }
    var transportWakeKey: String { serviceDirectory + "/transport-wake-key.cbor" }
}

/// Scoped configuration values. Construction does not prove protected placement or activate any service.
struct RuntimeConfigurationBundle: CustomStringConvertible {
    let paths: RuntimePreparationPaths
    let command: AuthorityCommandStartupConfiguration
    let transport: TransportPairingStartupConfiguration
    var gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration? { get throws {
        guard let host = transport.settingsHost else { return nil }
        return try host.selecting(role: .gateway)
    } }
    let presenceClient: AuthorityPresenceClientConfiguration
    let pairingClient: TransportPairingControlConfiguration
    let frontendClient: CommandFrontendConfiguration
    let elevationPolicy: CommandElevationPolicy
    var description: String { "RuntimeConfigurationBundle(redacted)" }

    static func initial(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
                        reference: RuntimeMaterialReference, inventory: InstallationInventory,
                        importIntent: SharedSetupImportIntent? = nil,
                        presencePolicyOverride: PresenceConfiguration? = nil,
                        relayPlan: SharedSetupImportRelayPlan? = nil, relayPortOverride: UInt16? = nil) throws -> Self {
        let selected = try initialSelection(account: account, inventory: inventory, importIntent: importIntent,
            presencePolicyOverride: presencePolicyOverride, relayPlan: relayPlan, relayPortOverride: relayPortOverride)
        return try .init(account: account, initialization: initialization, reference: reference, inventory: inventory,
            presencePolicy: selected.presence, relayPort: selected.relayPort,
            environment: [.init(name: Data("PATH".utf8), value: Data("/usr/bin:/bin:/usr/sbin:/sbin".utf8), source: .minimal)],
            submissionLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192),
            captureLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192))
    }

    private static func initialSelection(account: AccountPreparationIntent, inventory: InstallationInventory,
        importIntent: SharedSetupImportIntent?, presencePolicyOverride: PresenceConfiguration?,
        relayPlan: SharedSetupImportRelayPlan?, relayPortOverride: UInt16?) throws -> (presence: PresenceConfiguration, relayPort: UInt16?) {
        let presence: PresenceConfiguration
        let relayPort: UInt16?
        if let importIntent, importIntent.recipe.cloudflare != nil {
            guard let relayPlan else { throw RuntimePreparationError.incomplete }
            try relayPlan.validate(expected: importIntent)
            guard relayPortOverride == nil || relayPortOverride == relayPlan.port else { throw SharedSetupImportError.conflict }
            relayPort = relayPlan.port
        } else {
            guard relayPlan == nil else { throw SharedSetupImportError.conflict }
            relayPort = relayPortOverride
        }
        if let importIntent {
            guard importIntent.scope == (try SharedSetupImportIntent.Scope(account: account, inventory: inventory)) else {
                throw SharedSetupImportError.wrongScope
            }
            presence = try importIntent.recipe.settings.defaults.presence
            if let other = presencePolicyOverride {
                guard other.idleMilliseconds == presence.idleMilliseconds,
                      other.observationLifetimeMilliseconds == presence.observationLifetimeMilliseconds,
                      other.unavailableGraceMilliseconds == presence.unavailableGraceMilliseconds else { throw SharedSetupImportError.conflict }
            }
        } else { presence = try presencePolicyOverride ?? .init(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000) }
        return (presence, relayPort)
    }

    /// Initial stable publication only. The caller must retain admission and recheck this source around every file operation.
    static func stableInitial(snapshot: MachineUpdateStableRuntimePreparationSnapshot, reference: RuntimeMaterialReference,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        importIntent: SharedSetupImportIntent? = nil, presencePolicyOverride: PresenceConfiguration? = nil,
        relayPlan: SharedSetupImportRelayPlan? = nil, relayPortOverride: UInt16? = nil) throws -> Self {
        try stableInitial(snapshot: snapshot, reference: reference, candidate: candidate, currentCodePolicy: currentCodePolicy,
            retainedSetupBinding: nil, importIntent: importIntent, presencePolicyOverride: presencePolicyOverride,
            relayPlan: relayPlan, relayPortOverride: relayPortOverride)
    }

    /// Uses the exact recorded startup pair. Native custody and publication remain the caller's separate obligations.
    static func retainedSetupInitial(snapshot: MachineUpdateRetainedSetupPolicySnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, importIntent: SharedSetupImportIntent? = nil,
        presencePolicyOverride: PresenceConfiguration? = nil, relayPlan: SharedSetupImportRelayPlan? = nil,
        relayPortOverride: UInt16? = nil) throws -> Self {
        let binding = try RuntimeRetainedSetupReleaseBinding(snapshot: snapshot, current: current, candidate: candidate)
        try binding.requireStartupPolicy(currentCodePolicy)
        let runtime = snapshot.activation.runtime
        guard snapshot.activation.origin == .retained, snapshot.activation.installed == nil,
              snapshot.activation.state.plan == nil, !snapshot.activation.state.jobsRegistered,
              runtime.setup.account?.inInventory == false, !runtime.state.configurationPublished,
              let reference = runtime.state.reference, reference.serviceActivity != nil else { throw RuntimePreparationError.changedScope }
        return try stableInitial(snapshot: runtime, reference: reference, candidate: candidate, currentCodePolicy: currentCodePolicy,
            retainedSetupBinding: binding, importIntent: importIntent, presencePolicyOverride: presencePolicyOverride,
            relayPlan: relayPlan, relayPortOverride: relayPortOverride)
    }

    private static func stableInitial(snapshot: MachineUpdateStableRuntimePreparationSnapshot, reference: RuntimeMaterialReference,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        retainedSetupBinding: RuntimeRetainedSetupReleaseBinding?, importIntent: SharedSetupImportIntent? = nil, presencePolicyOverride: PresenceConfiguration? = nil,
        relayPlan: SharedSetupImportRelayPlan? = nil, relayPortOverride: UInt16? = nil) throws -> Self {
        guard !snapshot.state.configurationPublished,
              snapshot.state.reference == nil || snapshot.state.reference == reference,
              let initialization = snapshot.setup.account?.initialization, initialization.complete else {
            throw RuntimePreparationError.changedScope
        }
        let account = snapshot.preparation, source = snapshot.setup.source, actual = source.actual
        try reference.validate(account: account, services: snapshot.plan)
        let provisioning = try source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        try validateScope(account: account, initialization: initialization, reference: reference, inventory: provisioning)
        guard provisioning.bundlePath == actual.inventory.bundlePath else { throw RuntimePreparationError.changedScope }
        try actual.seal.requireCurrentInventory(actual.inventory, epoch: actual.installed, candidate: candidate)
        try actual.inventory.compareRelease(candidate); try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        try ReleaseGenerationPreflight.validate(candidate, against: currentCodePolicy)
        let required: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway,
            .commandFrontend, .commandMonitor, .commandChild, .setupController]
        guard required.allSatisfy({ role in currentCodePolicy.entries.contains { $0.role == role && $0.active } }) else {
            throw RuntimePreparationError.changedScope
        }
        for entry in currentCodePolicy.entries where entry.active {
            guard let component = candidate.manifest.components.first(where: { $0.role == entry.role }),
                  entry.teamID == component.teamID, entry.identifier == component.identifier,
                  entry.installedGeneration == component.generation,
                  entry.codeDirectoryHash == candidate.codeDirectoryHashes[entry.role] else { throw RuntimePreparationError.changedScope }
        }
        if reference.serviceActivity != nil {
            try GatewaySettingsNativeHostPlan(reference: reference, bundlePath: actual.inventory.bundlePath,
                policy: currentCodePolicy, retainedSetupBinding: retainedSetupBinding).validateRelease(candidate)
        }
        let selected = try initialSelection(account: account, inventory: provisioning, importIntent: importIntent,
            presencePolicyOverride: presencePolicyOverride, relayPlan: relayPlan, relayPortOverride: relayPortOverride)
        return try .init(checkedAccount: account, initialization: initialization, reference: reference,
            codeInventory: actual.inventory, codePolicy: currentCodePolicy, retainedSetupBinding: retainedSetupBinding,
            presencePolicy: selected.presence, relayPort: selected.relayPort,
            environment: [.init(name: Data("PATH".utf8), value: Data("/usr/bin:/bin:/usr/sbin:/sbin".utf8), source: .minimal)],
            submissionLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192),
            captureLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192))
    }

    init(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
         reference: RuntimeMaterialReference, inventory: InstallationInventory,
         presencePolicy: PresenceConfiguration, relayPort: UInt16? = nil, environment: [CapturedEnvironmentEntry],
         submissionLimits: CBORLimits, captureLimits: CBORLimits) throws {
        try Self.validateScope(account: account, initialization: initialization, reference: reference, inventory: inventory)
        try self.init(checkedAccount: account, initialization: initialization, reference: reference,
            codeInventory: inventory, codePolicy: account.initialAuthority.codePolicy,
            presencePolicy: presencePolicy, relayPort: relayPort, environment: environment,
            submissionLimits: submissionLimits, captureLimits: captureLimits)
    }
    private init(checkedAccount account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
        reference: RuntimeMaterialReference, codeInventory inventory: InstallationInventory, codePolicy policy: AuthorityCodePolicy,
        retainedSetupBinding: RuntimeRetainedSetupReleaseBinding? = nil, presencePolicy: PresenceConfiguration, relayPort: UInt16?, environment: [CapturedEnvironmentEntry],
        submissionLimits: CBORLimits, captureLimits: CBORLimits) throws {
        func entry(_ role: AuthorityCodeRole) throws -> AuthorityCodeEntry {
            guard let value = policy.entries.first(where: { $0.role == role && $0.active }) else {
                throw RuntimePreparationError.invalidRecord
            }
            return value
        }
        let app = try entry(.app), authority = try entry(.authority), transportCode = try entry(.transport)
        let gateway = try entry(.notificationGateway)
        _ = try entry(.commandFrontend); _ = try entry(.commandMonitor); _ = try entry(.commandChild)
        guard let transportClaim = reference.services.claims.first(where: { $0.role == .transport }),
              let gatewayClaim = reference.services.claims.first(where: { $0.role == .gateway }),
              app.teamID == authority.teamID, app.teamID == transportCode.teamID, app.teamID == gateway.teamID else {
            throw RuntimePreparationError.invalidRecord
        }
        paths = try RuntimePreparationPaths(accountID: account.accountID)
        let service = try AuthorityServiceConfiguration(macID: account.macID, accountID: account.accountID,
            journalDirectory: (initialization.journalPath as NSString).deletingLastPathComponent,
            serviceName: paths.authorityService, teamID: transportCode.teamID, transportIdentifier: transportCode.identifier,
            transportHashes: [transportCode.codeDirectoryHash], transportUID: transportClaim.number,
            auditVersions: Set(reference.auditDeliveryVersion.map { [$0] } ?? []),
            continuityDirectory: (initialization.continuityPath as NSString).deletingLastPathComponent)
        let request = try AuthorityRequestStartupConfiguration(service: service,
            keyRecordPath: paths.authorityDirectory + "/Key/" + AuthorityKeyProvisioning.recordFileName,
            authorityPublicKey: reference.services.authorityPublicKey)
        let wake = try AuthorityWakeStartupConfiguration(request: request, registration: reference.gateway,
            gatewayServiceName: paths.gatewayService, gatewayUID: gatewayClaim.number, teamID: gateway.teamID,
            gatewayIdentifier: gateway.identifier, gatewayHashes: [gateway.codeDirectoryHash])
        let presence = try AuthorityPresenceStartupConfiguration(wake: wake, ownerUID: account.ownerUID,
            appServiceName: paths.presenceService, teamID: app.teamID, appIdentifier: app.identifier,
            appHashes: [app.codeDirectoryHash], policy: presencePolicy,
            pairing: .init(transportPublicKey: reference.transportPublicKeyX963))
        let execution = try AuthorityCommandExecutionConfiguration(
            monitorPath: inventory.bundlePath + "/Contents/Helpers/RemozioCommandMonitor",
            childPath: inventory.bundlePath + "/Contents/Helpers/RemozioCommandChild")
        command = try .init(presence: presence, serviceName: paths.commandService, policyPath: paths.policy,
            environment: environment, submissionLimits: submissionLimits, captureLimits: captureLimits, execution: execution)
        let direct = try ApprovalTransportConfiguration(macID: account.macID, accountID: account.accountID,
            ownerUID: account.ownerUID, serviceUID: transportClaim.number, authorityServiceName: paths.authorityService,
            teamID: authority.teamID, authorityIdentifier: authority.identifier, authorityHashes: [authority.codeDirectoryHash],
            identitySource: .protectedFile(path: paths.transportIdentity), identityPublicKeyInfo: reference.transportPublicKeyInfo)
        pairingClient = try .init(macID: account.macID, accountID: account.accountID, ownerUID: account.ownerUID,
            transportUID: transportClaim.number, serviceName: paths.pairingService, teamID: app.teamID,
            appIdentifier: app.identifier, appHashes: [app.codeDirectoryHash], transportIdentifier: transportCode.identifier,
            transportHashes: [transportCode.codeDirectoryHash])
        let baseTransport = try TransportPairingStartupConfiguration(transport: direct, control: pairingClient, relayPort: relayPort)
        if reference.serviceActivity != nil {
            transport = try GatewaySettingsNativeHostPlan(reference: reference, bundlePath: inventory.bundlePath,
                policy: policy, retainedSetupBinding: retainedSetupBinding).selecting(baseTransport)
        } else { transport = baseTransport }
        presenceClient = try .init(macID: account.macID, accountID: account.accountID, ownerUID: account.ownerUID,
            serviceName: paths.presenceService, teamID: authority.teamID, rootIdentifier: authority.identifier,
            rootHashes: [authority.codeDirectoryHash])
        frontendClient = try .init(macID: account.macID, accountID: account.accountID, serviceName: paths.commandService,
            teamID: authority.teamID, authorityIdentifier: authority.identifier, authorityHashes: [authority.codeDirectoryHash],
            submissionLimits: submissionLimits, defaultIOMode: .pty, defaultDisconnectBehavior: .terminate,
            readiness: .init(timeoutMilliseconds: 30_000))
        elevationPolicy = try account.commandPolicy
        guard command.canonicalBytes.count <= ProtectedServiceConfiguration.maximumBytes,
              transport.canonicalBytes.count <= ProtectedServiceConfiguration.maximumBytes else {
            throw RuntimePreparationError.invalidRecord
        }
    }

    static func validateScope(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
                              reference: RuntimeMaterialReference, inventory: InstallationInventory) throws {
        try reference.validate(account: account, services: reference.services)
        guard account.storagePrepared, initialization.complete,
              initialization.accountID == account.accountID, initialization.macID == account.macID,
              initialization.installationID == account.installationID, initialization.releaseDigest == account.releaseDigest,
              initialization.initializationBytes == account.initializationBytes,
              inventory.macID == account.macID, inventory.installationID == account.installationID,
              inventory.releaseDigest == account.releaseDigest else { throw RuntimePreparationError.changedScope }
    }

    /// Preserves startup and client values after checking their scope.
    init(retaining plan: RuntimeActivationPlan, account: AccountPreparationIntent,
         initialization: AuthorityInitializationIntent, inventory: InstallationInventory,
         clients: RuntimeActivationClients) throws {
        try plan.requireConfigurationScope(account: account, initialization: initialization, inventory: inventory)
        try self.init(retaining: plan.host.command, transport: plan.transport, reference: plan.reference,
            account: account, initialization: initialization, inventory: inventory,
            policy: account.initialAuthority.codePolicy, clients: clients)
    }

    /// Retains checked v6 values. This overload cannot create an ordinary executable activation plan.
    init(retaining plan: RuntimeRetainedSetupActivationPlan, account: AccountPreparationIntent,
        initialization: AuthorityInitializationIntent, inventory: InstallationInventory, clients: RuntimeActivationClients) throws {
        try plan.requireConfigurationScope(account: account, initialization: initialization, inventory: inventory)
        try self.init(retaining: plan.host.command, transport: plan.transport, reference: plan.reference,
            account: account, initialization: initialization, inventory: inventory, policy: plan.host.codePolicy, clients: clients)
    }

    /// Validates completed bytes against current code and frozen provisioning. It does not rebuild tunable values.
    static func stableCompleted(snapshot: MachineUpdateStableRuntimePreparationSnapshot, reference: RuntimeMaterialReference,
        candidate: SignedReleaseEvidence, currentCodePolicy: AuthorityCodePolicy,
        command: AuthorityCommandStartupConfiguration, transport: TransportPairingStartupConfiguration,
        clients: RuntimeActivationClients) throws -> Self {
        guard snapshot.state.configurationPublished, snapshot.state.reference == reference,
              let initialization = snapshot.setup.account?.initialization, initialization.complete else {
            throw RuntimePreparationError.changedScope
        }
        let account = snapshot.preparation, source = snapshot.setup.source, actual = source.actual
        try reference.validate(account: account, services: snapshot.plan)
        let provisioning = try source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        try validateScope(account: account, initialization: initialization, reference: reference, inventory: provisioning)
        guard provisioning.bundlePath == actual.inventory.bundlePath else { throw RuntimePreparationError.changedScope }
        try actual.seal.requireCurrentInventory(actual.inventory, epoch: actual.installed, candidate: candidate)
        try actual.inventory.compareRelease(candidate); try MachineUpdateStableReleaseRecord.requireFormats(candidate)
        try ReleaseGenerationPreflight.validate(candidate, against: currentCodePolicy)
        let required: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway,
            .commandFrontend, .commandMonitor, .commandChild, .setupController]
        guard required.allSatisfy({ role in currentCodePolicy.entries.contains { $0.role == role && $0.active } }) else {
            throw RuntimePreparationError.changedScope
        }
        for entry in currentCodePolicy.entries where entry.active {
            guard let component = candidate.manifest.components.first(where: { $0.role == entry.role }),
                  entry.teamID == component.teamID, entry.identifier == component.identifier,
                  entry.installedGeneration == component.generation,
                  entry.codeDirectoryHash == candidate.codeDirectoryHashes[entry.role] else { throw RuntimePreparationError.changedScope }
        }
        if reference.serviceActivity != nil {
            guard let host = transport.settingsHost, host.runtime == reference,
                  host.role == .transport, try host.codePolicy.bytes == currentCodePolicy.bytes else {
                throw RuntimePreparationError.changedScope
            }
            try host.requireConfigurationScope(account: account, inventory: actual.inventory)
            try host.validateRelease(candidate)
            try host.validate(transport: transport.transport, pairing: clients.pairing)
        } else { guard transport.settingsHost == nil else { throw RuntimePreparationError.changedScope } }
        return try .init(retaining: command, transport: transport, reference: reference,
            account: account, initialization: initialization, inventory: actual.inventory,
            policy: currentCodePolicy, clients: clients)
    }

    private init(retaining command: AuthorityCommandStartupConfiguration, transport transportConfiguration: TransportPairingStartupConfiguration,
        reference: RuntimeMaterialReference, account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
        inventory: InstallationInventory, policy: AuthorityCodePolicy, clients: RuntimeActivationClients) throws {
        let paths = try RuntimePreparationPaths(accountID: account.accountID), services = reference.services
        func peer(_ role: AuthorityCodeRole, _ uid: UInt32) throws -> XPCPeerPolicy {
            guard let entry = policy.entries.first(where: { $0.role == role && $0.active }) else {
                throw RuntimeActivationError.changedScope
            }
            return try .init(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: uid)
        }
        func matches(_ actual: XPCPeerPolicy, _ expected: XPCPeerPolicy) -> Bool {
            actual.requirement == expected.requirement && actual.expectedUserID == expected.expectedUserID &&
                actual.expectedAuditSessionID == expected.expectedAuditSessionID
        }
        guard let transport = services.claims.first(where: { $0.role == .transport }),
              let gateway = services.claims.first(where: { $0.role == .gateway }) else { throw RuntimeActivationError.changedScope }
        let rootPeer = try peer(.authority, 0), appPeer = try peer(.app, account.ownerUID)
        let transportPeer = try peer(.transport, transport.number), gatewayPeer = try peer(.notificationGateway, gateway.number)
        _ = try peer(.commandFrontend, account.ownerUID)
        _ = try peer(.commandMonitor, 0); _ = try peer(.commandChild, 0)
        let presence = command.presence, wake = presence.wake, request = wake.request
        let service = request.service, direct = transportConfiguration.transport, control = transportConfiguration.control
        guard service.macID == account.macID, service.accountID == account.accountID,
              service.journalDirectory == (initialization.journalPath as NSString).deletingLastPathComponent,
              service.continuityDirectory == (initialization.continuityPath as NSString).deletingLastPathComponent,
              service.serviceName == paths.authorityService, matches(service.transportPolicy, transportPeer),
              service.auditVersions == Set(reference.auditDeliveryVersion.map { [$0] } ?? []),
              request.keyRecordPath == paths.authorityDirectory + "/Key/" + AuthorityKeyProvisioning.recordFileName,
              request.authorityPublicKey == services.authorityPublicKey,
              wake.registration == reference.gateway, wake.gatewayServiceName == paths.gatewayService,
              matches(wake.gatewayPolicy, gatewayPeer),
              presence.presence.macID == account.macID, presence.presence.accountID == account.accountID,
              presence.presence.ownerUID == account.ownerUID, presence.endpoint.serviceName == paths.presenceService,
              matches(presence.endpoint.appPolicy, appPeer),
              try presence.pairing?.transportPublicKey == reference.transportPublicKeyX963,
              command.serviceName == paths.commandService, command.policyPath == paths.policy,
              command.execution?.monitorPath == inventory.bundlePath + "/Contents/Helpers/RemozioCommandMonitor",
              command.execution?.childPath == inventory.bundlePath + "/Contents/Helpers/RemozioCommandChild",
              direct.macID == account.macID, direct.accountID == account.accountID,
              direct.ownerUID == account.ownerUID, direct.serviceUID == transport.number,
              direct.authorityServiceName == paths.authorityService, matches(direct.authorityPolicy, rootPeer),
              direct.identitySource == .protectedFile(path: paths.transportIdentity),
              direct.identityPublicKeyInfo == reference.transportPublicKeyInfo,
              control.macID == account.macID, control.accountID == account.accountID,
              control.ownerUID == account.ownerUID, control.transportUID == transport.number,
              control.serviceName == paths.pairingService, matches(control.appPolicy, appPeer),
              matches(control.transportPolicy, transportPeer) else { throw RuntimeActivationError.changedScope }
        if let signer = transportConfiguration.wake?.wake {
            let registration = reference.gateway
            let binding = try GatewaySubmissionBinding(ownerID: registration.ownerID, macID: registration.macID,
                accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch)
            guard signer.binding == binding, signer.transportUID == transport.number, signer.ownerUID == account.ownerUID,
                  matches(signer.gatewayPolicy, gatewayPeer), signer.serviceName == paths.gatewayWakeService,
                  signer.custody == .protectedFile, signer.keyRecordPath == paths.transportWakeKey else {
                throw RuntimeActivationError.changedScope
            }
        }
        let p = clients.presence, c = clients.pairing, f = clients.frontend
        guard p.macID == account.macID, p.accountID == account.accountID, p.ownerUID == account.ownerUID,
              p.serviceName == paths.presenceService, matches(p.rootPolicy, rootPeer),
              c.macID == account.macID, c.accountID == account.accountID, c.ownerUID == account.ownerUID,
              c.transportUID == transport.number, c.serviceName == paths.pairingService,
              matches(c.appPolicy, appPeer), matches(c.transportPolicy, transportPeer),
              f.macID == account.macID, f.accountID == account.accountID, f.serviceName == paths.commandService,
              matches(f.authorityPolicy, rootPeer) else { throw RuntimeActivationError.changedScope }
        self.paths = paths; self.command = command; self.transport = transportConfiguration
        presenceClient = p; pairingClient = c; frontendClient = f; elevationPolicy = try account.commandPolicy
    }
}
