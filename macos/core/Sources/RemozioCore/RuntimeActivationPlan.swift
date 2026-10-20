import Foundation
import RemozioProtocol

public enum RuntimeActivationError: Error, Equatable {
    case incomplete, invalidPlan, conflictingPlan, changedScope, unavailable, exhausted
}

/// Frozen activation inputs. A plan neither registers jobs nor proves runtime health.
struct RuntimeActivationPlan: CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.activation-plan"
    static let supportedVersions: Set<UInt64> = [1, 2]
    let reference: RuntimeMaterialReference
    let bundlePath: String
    let host: InstalledAuthorityCommandConfiguration
    let transport: TransportPairingStartupConfiguration
    let consumerHosts: GatewaySettingsNativeHostPlan?
    var gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration? { consumerHosts?.gateway }
    let authorityJob: InstalledAccountJobManifest
    let transportJob: InstalledAccountJobManifest
    var description: String { "RuntimeActivationPlan(redacted)" }
    var debugDescription: String { description }
    var accountID: Data { reference.services.accountID }

    init(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
         runtime: RuntimePreparationState, inventory: InstallationInventory,
         gatewaySettingsRelease: SignedReleaseEvidence? = nil, importIntent: SharedSetupImportIntent? = nil,
         relayPlan: SharedSetupImportRelayPlan? = nil) throws {
        guard runtime.configurationPublished, let reference = runtime.reference else { throw RuntimeActivationError.incomplete }
        let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization, reference: reference,
            inventory: inventory, importIntent: importIntent, relayPlan: relayPlan)
        let label = bundle.paths.namespace + ".authority"
        var host = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, codePolicy: account.initialAuthority.codePolicy,
            command: bundle.command, label: label, plistName: label + ".plist", jobPlacement: .systemAccount)
        if let gatewaySettingsRelease { host = try host.enablingGatewaySettingsControl(release: gatewaySettingsRelease) }
        if reference.serviceActivity != nil {
            guard let gatewaySettingsRelease else { throw RuntimeActivationError.incomplete }
            try GatewaySettingsNativeHostPlan(reference: reference, bundlePath: inventory.bundlePath,
                policy: host.codePolicy).validateRelease(gatewaySettingsRelease)
        }
        try self.init(reference: reference, bundlePath: inventory.bundlePath, host: host,
            transport: bundle.transport, gatewaySettingsHost: bundle.gatewaySettingsHost)
        try validate(account: account, reference: reference)
    }
    /// The native file verifier uses the pinned plan policy. The owner independently binds it to the retained import.
    func configurationBundle(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
                             inventory: InstallationInventory) throws -> RuntimeConfigurationBundle {
        try .initial(account: account, initialization: initialization, reference: reference, inventory: inventory,
            presencePolicyOverride: host.command.presence.presence.policy, relayPortOverride: transport.relayPort)
    }
    private init(reference: RuntimeMaterialReference, bundlePath: String, host: InstalledAuthorityCommandConfiguration,
                 transport: TransportPairingStartupConfiguration,
                 gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration? = nil) throws {
        let selected: GatewaySettingsNativeHostPlan?
        if reference.serviceActivity != nil {
            let plan = try GatewaySettingsNativeHostPlan(reference: reference, bundlePath: bundlePath, policy: host.codePolicy)
            guard host.gatewaySettingsControlEnabled, gatewaySettingsHost == plan.gateway,
                  transport.settingsHost == plan.transport else { throw RuntimeActivationError.invalidPlan }
            selected = plan
        } else {
            guard gatewaySettingsHost == nil, transport.settingsHost == nil else { throw RuntimeActivationError.invalidPlan }
            selected = nil
        }
        let services = reference.services, paths = try RuntimePreparationPaths(accountID: services.accountID)
        guard let claim = services.claims.first(where: { $0.role == .transport }),
              let gateway = services.claims.first(where: { $0.role == .gateway }),
              host.jobPlacement == .systemAccount, host.installationID == services.installationID, host.releaseDigest == services.releaseDigest,
              host.command.macID == services.macID, host.command.accountID == services.accountID, host.command.callerUID == services.ownerUID,
              host.command.presence.wake.registration == reference.gateway,
              host.command.presence.wake.request.authorityPublicKey == services.authorityPublicKey,
              host.command.presence.wake.gatewayPolicy.expectedUserID == gateway.number,
              host.command.presence.wake.gatewayServiceName == paths.gatewayService,
              host.command.presence.wake.request.service.transportPolicy.expectedUserID == claim.number,
              try host.command.presence.pairing?.transportPublicKey == reference.transportPublicKeyX963,
              transport.transport.macID == services.macID, transport.transport.accountID == services.accountID,
              transport.transport.ownerUID == services.ownerUID, transport.transport.serviceUID == claim.number,
              transport.transport.authorityServiceName == paths.authorityService,
              transport.transport.identitySource == .protectedFile(path: paths.transportIdentity),
              transport.transport.identityPublicKeyInfo == reference.transportPublicKeyInfo,
              transport.control.serviceName == paths.pairingService,
              host.canonicalBytes.count <= ProtectedServiceConfiguration.maximumBytes,
              transport.canonicalBytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw RuntimeActivationError.invalidPlan }
        func policy(_ role: AuthorityCodeRole, _ uid: UInt32) throws -> XPCPeerPolicy {
            guard let entry = host.codePolicy.entries.first(where: { $0.role == role && $0.active }) else { throw RuntimeActivationError.invalidPlan }
            return try .init(teamID: entry.teamID, componentIdentifier: entry.identifier,
                approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: uid)
        }
        guard try transport.transport.authorityPolicy.requirement == policy(.authority, 0).requirement,
              try transport.control.appPolicy.requirement == policy(.app, services.ownerUID).requirement,
              try transport.control.transportPolicy.requirement == policy(.transport, claim.number).requirement else {
            throw RuntimeActivationError.invalidPlan
        }
        self.reference = reference; self.bundlePath = bundlePath; self.host = host; self.transport = transport
        consumerHosts = selected
        authorityJob = try .init(accountID: services.accountID, role: .authority, executionUID: 0, userName: "root", bundlePath: bundlePath,
            gatewaySettingsControlEnabled: host.gatewaySettingsControlEnabled)
        if let selected { transportJob = try selected.job(.transport) }
        else { transportJob = try .init(accountID: services.accountID, role: .transport, executionUID: claim.number, userName: claim.name, bundlePath: bundlePath) }
    }
    func validate(account: AccountPreparationIntent, reference: RuntimeMaterialReference) throws {
        try self.reference.validate(account: account, services: reference.services)
        guard self.reference == reference, try host.codePolicy.bytes == account.initialAuthority.codePolicy.bytes else {
            throw RuntimeActivationError.changedScope
        }
    }
    /// Add only this account and its exact jobs. Preserve other accounts and refuse conflicting declarations.
    func enrolledInventory(_ inventory: InstallationInventory) throws -> InstallationInventory {
        let services = reference.services
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == services.releaseDigest, inventory.bundlePath == bundlePath else { throw RuntimeActivationError.changedScope }
        let account = try InstallationAccount(accountID: services.accountID, ownerUID: services.ownerUID)
        if let existing = inventory.accounts.first(where: { $0.accountID == account.accountID || $0.ownerUID == account.ownerUID }), existing != account {
            throw RuntimeActivationError.conflictingPlan
        }
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
    var encoded: Data { get throws {
        var fields: [UInt64: CBORValue] = [0: .unsigned(consumerHosts == nil ? 1 : 2), 1: .bytes(try reference.encoded),
            2: .text(bundlePath), 3: .bytes(host.canonicalBytes), 4: .bytes(transport.canonicalBytes)]
        if let gatewaySettingsHost { fields[5] = .bytes(try gatewaySettingsHost.encoded) }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .unsigned(let version) = f[0], version == 1 || version == 2,
              Set(f.keys) == Set(UInt64(0)...(version == 1 ? 4 : 5)),
              case .bytes(let reference) = f[1], case .text(let path) = f[2],
              case .bytes(let host) = f[3], case .bytes(let transport) = f[4] else { throw RuntimeActivationError.invalidPlan }
        let gateway: GatewaySettingsConsumerHostConfiguration?
        if version == 1 { gateway = nil }
        else {
            guard case .bytes(let metadata) = f[5] else { throw RuntimeActivationError.invalidPlan }
            gateway = try .decode(metadata)
        }
        let result = try Self(reference: .decode(reference), bundlePath: path, host: .decode(host),
            transport: .decode(transport), gatewaySettingsHost: gateway)
        guard try result.encoded == bytes else { throw RuntimeActivationError.invalidPlan }; return result
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 262144, maxDepth: 1, maxItems: 13) } }
}

/// Historical registration progress. It is not a current launchd or process health result.
struct RuntimeActivationState {
    let plan: RuntimeActivationPlan?
    let jobsRegistered: Bool
}
