import Foundation
import RemozioProtocol

public enum RuntimeActivationError: Error, Equatable {
    case incomplete, invalidPlan, conflictingPlan, changedScope, unavailable, exhausted
}

/// Frozen activation inputs. A plan neither registers jobs nor proves runtime health.
struct RuntimeActivationPlan: CustomStringConvertible, CustomDebugStringConvertible {
    let reference: RuntimeMaterialReference
    let bundlePath: String
    let host: InstalledAuthorityCommandConfiguration
    let transport: TransportPairingStartupConfiguration
    let authorityJob: InstalledAccountJobManifest
    let transportJob: InstalledAccountJobManifest
    var description: String { "RuntimeActivationPlan(redacted)" }
    var debugDescription: String { description }
    var accountID: Data { reference.services.accountID }

    init(account: AccountPreparationIntent, initialization: AuthorityInitializationIntent,
         runtime: RuntimePreparationState, inventory: InstallationInventory,
         gatewaySettingsRelease: SignedReleaseEvidence? = nil) throws {
        guard runtime.configurationPublished, let reference = runtime.reference else { throw RuntimeActivationError.incomplete }
        let bundle = try RuntimeConfigurationBundle.initial(account: account, initialization: initialization, reference: reference, inventory: inventory)
        let label = bundle.paths.namespace + ".authority"
        var host = try InstalledAuthorityCommandConfiguration(machineDirectory: MachineBootstrap.machineDirectory,
            installationID: inventory.installationID, releaseDigest: inventory.releaseDigest, codePolicy: account.initialAuthority.codePolicy,
            command: bundle.command, label: label, plistName: label + ".plist", jobPlacement: .systemAccount)
        if let gatewaySettingsRelease { host = try host.enablingGatewaySettingsControl(release: gatewaySettingsRelease) }
        try self.init(reference: reference, bundlePath: inventory.bundlePath, host: host, transport: bundle.transport)
        try validate(account: account, reference: reference)
    }
    private init(reference: RuntimeMaterialReference, bundlePath: String, host: InstalledAuthorityCommandConfiguration,
                 transport: TransportPairingStartupConfiguration) throws {
        // Activity metadata cannot select jobs until both native consumers retain their lifetime scopes.
        guard reference.serviceActivity == nil else { throw RuntimeActivationError.unavailable }
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
        authorityJob = try .init(accountID: services.accountID, role: .authority, executionUID: 0, userName: "root", bundlePath: bundlePath,
            gatewaySettingsControlEnabled: host.gatewaySettingsControlEnabled)
        transportJob = try .init(accountID: services.accountID, role: .transport, executionUID: claim.number, userName: claim.name, bundlePath: bundlePath)
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
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(reference.encoded), 2: .text(bundlePath),
            3: .bytes(host.canonicalBytes), 4: .bytes(transport.canonicalBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .unsigned(1), case .bytes(let reference) = f[1], case .text(let path) = f[2],
              case .bytes(let host) = f[3], case .bytes(let transport) = f[4] else { throw RuntimeActivationError.invalidPlan }
        let result = try Self(reference: .decode(reference), bundlePath: path, host: .decode(host), transport: .decode(transport))
        guard try result.encoded == bytes else { throw RuntimeActivationError.invalidPlan }; return result
    }
    static var limits: CBORLimits { get throws { try .init(maxBytes: 262144, maxDepth: 1, maxItems: 11) } }
}

/// Historical registration progress. It is not a current launchd or process health result.
struct RuntimeActivationState {
    let plan: RuntimeActivationPlan?
    let jobsRegistered: Bool
}
