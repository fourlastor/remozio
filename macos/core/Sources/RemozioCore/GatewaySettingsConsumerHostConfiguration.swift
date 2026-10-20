import Foundation
import RemozioProtocol

/// Immutable public bootstrap inputs. Decoding does not authenticate the publisher or start a backend.
struct GatewaySettingsConsumerHostConfiguration: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let version: UInt64 = 1
    static let supportedVersions: Set<UInt64> = [version]
    static let formatName = "runtime.gateway-settings-consumer-host"
    let role: GatewaySettingsConsumerRole
    let runtime: RuntimeMaterialReference
    let bundlePath: String
    let codePolicy: AuthorityCodePolicy
    var description: String { "GatewaySettingsConsumerHostConfiguration(redacted)" }
    var debugDescription: String { description }
    var consumerCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == role.codeRole && $0.active }! }
    var setupCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == .setupController && $0.active }! }
    var serviceRole: ServiceAccountRole { role == .transport ? .transport : .gateway }
    var activity: ServiceReleaseActivityReference { runtime.serviceActivity! }
    var serviceUID: UInt32 { runtime.services.claims.first { $0.role == serviceRole }!.number }
    var serviceName: String { get throws { try role.serviceName(accountID: runtime.services.accountID) } }

    init(role: GatewaySettingsConsumerRole, runtime: RuntimeMaterialReference, bundlePath: String,
         codePolicy: AuthorityCodePolicy) throws {
        let parts = bundlePath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        let required: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .setupController]
        let codes = required.compactMap { role in codePolicy.entries.first { $0.role == role && $0.active } }
        guard runtime.serviceActivity != nil, bundlePath.hasPrefix("/"), bundlePath.hasSuffix(".app"),
              bundlePath.utf8.count < 4096, !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              codes.count == required.count, Set(codes.map(\.teamID)).count == 1,
              Set(codes.map(\.identifier)).count == codes.count else { throw GatewayPreparationError.invalidRecord }
        try runtime.serviceActivity?.validate(services: runtime.services)
        self.role = role; self.runtime = runtime; self.bundlePath = bundlePath; self.codePolicy = codePolicy
        _ = try encoded
    }
    /// Setup must compare these inputs with the current retained account and installation before publication.
    func validate(account: AccountPreparationIntent, inventory: InstallationInventory) throws {
        let services = runtime.services
        try runtime.validate(account: account, services: services)
        guard inventory.macID == services.macID, inventory.installationID == services.installationID,
              inventory.releaseDigest == services.releaseDigest, inventory.bundlePath == bundlePath,
              try codePolicy.bytes == account.initialAuthority.codePolicy.bytes else { throw GatewayPreparationError.changedScope }
    }
    /// Actual signature inspection and protected placement remain prerequisites for native startup.
    func validateRelease(_ release: SignedReleaseEvidence) throws {
        guard try InstallationInventory.digest(release) == runtime.services.releaseDigest else { throw GatewayPreparationError.changedScope }
        try ReleaseGenerationPreflight.validate(release, against: codePolicy)
        for code in codePolicy.entries where code.active {
            guard let component = release.manifest.components.first(where: { $0.role == code.role }),
                  component.generation == code.installedGeneration,
                  release.codeDirectoryHashes[code.role] == code.codeDirectoryHash else { throw GatewayPreparationError.changedScope }
        }
        try GatewaySettingsConsumerReleaseValidation.validate(release, role: role, consumer: consumerCode, setup: setupCode)
        for code in [role.codeRole, .setupController] {
            guard let format = release.manifest.components.first(where: { $0.role == code })?.formats.first(where: { $0.name == Self.formatName }),
                  format.readers.contains(Self.version), code != .setupController || format.writers.contains(Self.version) else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
    func validate(transport: ApprovalTransportConfiguration, pairing: TransportPairingControlConfiguration) throws {
        let services = runtime.services, paths = try RuntimePreparationPaths(accountID: runtime.services.accountID)
        guard role == .transport, transport.macID == services.macID, transport.accountID == services.accountID,
              transport.ownerUID == services.ownerUID, transport.serviceUID == serviceUID,
              transport.identityPublicKeyInfo == runtime.transportPublicKeyInfo,
              transport.identitySource == .protectedFile(path: paths.transportIdentity),
              transport.authorityServiceName == paths.authorityService, pairing.serviceName == paths.pairingService,
              pairing.macID == services.macID, pairing.accountID == services.accountID,
              pairing.ownerUID == services.ownerUID, pairing.transportUID == serviceUID else { throw GatewayPreparationError.changedScope }
        func require(_ actual: XPCPeerPolicy, role: AuthorityCodeRole, uid: UInt32) throws {
            let code = codePolicy.entries.first { $0.role == role && $0.active }!
            let expected = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
                approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: uid)
            guard actual.expectedUserID == uid, actual.requirement == expected.requirement else { throw GatewayPreparationError.changedScope }
        }
        try require(transport.authorityPolicy, role: .authority, uid: 0)
        try require(pairing.appPolicy, role: .app, uid: services.ownerUID)
        try require(pairing.transportPolicy, role: .transport, uid: serviceUID)
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(Self.version), 1: .text("remozio-gateway-settings-consumer-host"),
            2: .unsigned(role.rawValue), 3: .bytes(runtime.encoded), 4: .text(bundlePath), 5: .bytes(codePolicy.bytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...5), fields[0] == .unsigned(Self.version),
              fields[1] == .text("remozio-gateway-settings-consumer-host"), case .unsigned(let raw) = fields[2],
              let role = GatewaySettingsConsumerRole(rawValue: raw), case .bytes(let runtime) = fields[3],
              case .text(let path) = fields[4], case .bytes(let policy) = fields[5] else { throw GatewayPreparationError.invalidRecord }
        let value = try Self(role: role, runtime: .decode(runtime), bundlePath: path, codePolicy: .decode(policy))
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    static let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 13)
}
