import Darwin
import Foundation
import Security

extension GatewaySettingsConsumerRole {
    func recoveryServiceName(accountID: Data) throws -> String {
        try serviceName(accountID: accountID) + ".recovery"
    }
}

/// Exact signed recovery participants. The caller must independently authenticate the protected account scope.
struct GatewaySettingsRecoveryNativePolicy: Sendable {
    let consumer: AuthorityCodeEntry
    let authority: AuthorityCodeEntry
    let serviceUID: UInt32
    init(role: GatewaySettingsConsumerRole, services: ServiceAccountPlan,
         codePolicy: AuthorityCodePolicy, release: SignedReleaseEvidence) throws {
        try GatewayRuntimeSettingsFenceReleaseValidation.validateRecovery(release, policy: codePolicy)
        guard try InstallationInventory.digest(release) == services.releaseDigest,
              let consumer = codePolicy.entries.first(where: { $0.role == role.codeRole && $0.active }),
              let authority = codePolicy.entries.first(where: { $0.role == .authority && $0.active }),
              let claim = services.claims.first(where: { $0.role == (role == .gateway ? .gateway : .transport) }),
              release.manifest.components.first(where: { $0.role == .authority })?.relativePath
                == InstalledAuthorityCommandConfiguration.executablePath else { throw GatewayPreparationError.changedScope }
        self.consumer = consumer; self.authority = authority; serviceUID = claim.number
    }
}

extension GatewaySettingsConsumerChannel {
    /// Authority can recover retained settings without impersonating the administrator setup process.
    static func recovery(role: GatewaySettingsConsumerRole, services: ServiceAccountPlan,
                         codePolicy: AuthorityCodePolicy, release: SignedReleaseEvidence, expectedGeneration: UUID?,
                         timeoutMilliseconds: UInt64 = 5000,
                         verifyCurrent: @escaping @Sendable () throws -> Void) throws -> GatewaySettingsConsumerChannel {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let pins = try GatewaySettingsRecoveryNativePolicy(role: role, services: services, codePolicy: codePolicy, release: release)
        let peer = try XPCPeerPolicy(teamID: pins.consumer.teamID, componentIdentifier: pins.consumer.identifier,
            approvedCodeDirectoryHashes: [pins.consumer.codeDirectoryHash], expectedUserID: pins.serviceUID)
        let local = try XPCPeerPolicy(teamID: pins.authority.teamID, componentIdentifier: pins.authority.identifier,
            approvedCodeDirectoryHashes: [pins.authority.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
        }
        try verify(); try verifyCurrent()
        return try .init(driver: NativeGatewaySettingsConsumerDriver(serviceName: role.recoveryServiceName(accountID: services.accountID), policy: peer),
            role: role, macID: services.macID, accountID: services.accountID, expectedGeneration: expectedGeneration,
            timeoutMilliseconds: timeoutMilliseconds, requestVersion: 2, verifyAccount: verify,
            verifyCurrent: verifyCurrent, challenge: {
                try GatewaySettingsRecoveryChallenge.make()
            })
    }
}

private enum GatewaySettingsRecoveryChallenge {
    static func make() throws -> Data {
        var bytes = Data(count: 32)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw GatewayPreparationError.invalidRecord
        }
        return bytes
    }
}

private struct NativeGatewaySettingsRecoveryEndpointBuilder: GatewaySettingsConsumerEndpointBuilding {
    let authority: AuthorityCodeEntry
    let access: GatewaySettingsConsumerAccess
    let activity: @Sendable () throws -> any OwnedReleaseActivity
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
              onHandshake: @escaping @Sendable () -> Void,
              onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsConsumerXPCEndpoint {
        try .init(recoveryConnection: connection, authorityCode: authority, access: access, budget: budget,
            acquireActivity: activity, onHandshake: onHandshake, onClose: onClose)
    }
}

extension GatewaySettingsConsumerXPCListener {
    /// The distinct Mach service accepts only the pinned Root Authority, never a union of controller code requirements.
    static func recovery(services: ServiceAccountPlan, codePolicy: AuthorityCodePolicy, release: SignedReleaseEvidence,
                         access: GatewaySettingsConsumerAccess,
                         acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity) throws -> GatewaySettingsConsumerXPCListener {
        try access.requireNativeProcess()
        guard services.macID == access.binding.macID, services.accountID == access.binding.accountID else {
            throw GatewayPreparationError.changedScope
        }
        let pins = try GatewaySettingsRecoveryNativePolicy(role: access.binding.role, services: services, codePolicy: codePolicy, release: release)
        guard pins.serviceUID == access.serviceUID, services.ownerUID == access.ownerUID else { throw GatewayPreparationError.changedScope }
        let local = try XPCPeerPolicy(teamID: pins.consumer.teamID, componentIdentifier: pins.consumer.identifier,
            approvedCodeDirectoryHashes: [pins.consumer.codeDirectoryHash], expectedUserID: pins.serviceUID)
        let peer = try XPCPeerPolicy(teamID: pins.authority.teamID, componentIdentifier: pins.authority.identifier,
            approvedCodeDirectoryHashes: [pins.authority.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            try access.requireNativeProcess(); try DynamicCodeValidation.validateSelf(requirement: local.requirement)
            try access.verifyCurrent()
        }
        try verify()
        let listener = NSXPCListener(machServiceName: try access.binding.role.recoveryServiceName(accountID: services.accountID))
        peer.configure(listener)
        return try .init(listener: listener, builder: NativeGatewaySettingsRecoveryEndpointBuilder(
            authority: pins.authority, access: access, activity: acquireActivity), verifyCurrent: verify)
    }
}
