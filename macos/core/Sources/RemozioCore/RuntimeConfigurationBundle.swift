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
        let suffix = accountID.map { String(format: "%02x", $0) }.joined()
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

/// Bootstrap configuration only. Construction does not prove protected placement or activate any service.
struct RuntimeConfigurationBundle: CustomStringConvertible {
    let paths: RuntimePreparationPaths
    let command: AuthorityCommandStartupConfiguration
    let transport: TransportPairingStartupConfiguration
    var gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration? { get throws {
        guard let host = transport.settingsHost else { return nil }
        return try .init(role: .gateway, runtime: host.runtime, bundlePath: host.bundlePath, codePolicy: host.codePolicy)
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
        return try .init(account: account, initialization: initialization, reference: reference, inventory: inventory,
            presencePolicy: presence, relayPort: relayPort,
            environment: [.init(name: Data("PATH".utf8), value: Data("/usr/bin:/bin:/usr/sbin:/sbin".utf8), source: .minimal)],
            submissionLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192),
            captureLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192))
    }

    init(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
         reference: RuntimeMaterialReference, inventory: InstallationInventory,
         presencePolicy: PresenceConfiguration, relayPort: UInt16? = nil, environment: [CapturedEnvironmentEntry],
         submissionLimits: CBORLimits, captureLimits: CBORLimits) throws {
        try reference.validate(account: account, services: reference.services)
        guard account.storagePrepared, initialization.complete,
              initialization.accountID == account.accountID, initialization.macID == account.macID,
              initialization.installationID == account.installationID, initialization.releaseDigest == account.releaseDigest,
              initialization.initializationBytes == account.initializationBytes,
              inventory.macID == account.macID, inventory.installationID == account.installationID,
              inventory.releaseDigest == account.releaseDigest else { throw RuntimePreparationError.changedScope }
        let policy = try account.initialAuthority.codePolicy
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
                policy: policy).selecting(baseTransport)
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
}
