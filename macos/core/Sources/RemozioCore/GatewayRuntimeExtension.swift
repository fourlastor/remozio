import CryptoKit
import Foundation
import RemozioProtocol

/// Root-owned optional metadata. Decoding grants no activation, native admission or current health.
struct GatewayRuntimeExtension: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    enum Target: UInt64, Sendable { case authority = 1, transport = 2 }
    let target: Target
    let intentID: Data
    let intentDigest: Data
    let foregroundDigest: Data
    let baseDigest: Data
    let material: GatewayMaterialReference
    let codePolicy: AuthorityCodePolicy
    let wake: TransportWakeStartupConfiguration?
    var description: String { "GatewayRuntimeExtension(redacted)" }
    var debugDescription: String { description }
    var setupCode: AuthorityCodeEntry { codePolicy.entries.first { $0.role == .setupController }! }
    private var purpose: String { target == .authority ? "remozio-authority-phone-push-runtime" : "remozio-transport-phone-push-runtime" }

    init(target: Target, intentID: Data, intentDigest: Data, foregroundDigest: Data, baseDigest: Data,
         material: GatewayMaterialReference, codePolicy: AuthorityCodePolicy, wake: TransportWakeStartupConfiguration?) throws {
        guard intentID.count == 16, intentDigest.count == 32, foregroundDigest.count == 32, baseDigest.count == 32,
              (target == .authority) == (wake == nil) else { throw GatewayPreparationError.invalidRecord }
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .setupController]
        let codes = roles.compactMap { role in codePolicy.entries.first { $0.role == role && $0.active } }
        guard codes.count == roles.count, Set(codes.map(\.teamID)).count == 1,
              Set(codes.map(\.identifier)).count == roles.count else { throw GatewayPreparationError.changedScope }
        self.target = target; self.intentID = intentID; self.intentDigest = intentDigest; self.foregroundDigest = foregroundDigest
        self.baseDigest = baseDigest; self.material = material; self.codePolicy = codePolicy; self.wake = wake
    }
    func validate(authority base: InstalledAuthorityCommandConfiguration) throws {
        let services = material.runtime.services, request = base.command.presence.wake
        guard target == .authority, baseDigest == Data(SHA256.hash(data: base.canonicalBytes)), codePolicy == base.codePolicy,
              base.command.macID == services.macID, base.command.accountID == services.accountID,
              base.command.callerUID == services.ownerUID, request.registration == material.runtime.gateway,
              request.request.authorityPublicKey == services.authorityPublicKey,
              try base.command.presence.pairing?.transportPublicKey == material.runtime.transportPublicKeyX963,
              request.phonePush == nil || request.phonePush?.canonicalBytes == material.phonePush.canonicalBytes,
              let transport = services.claims.first(where: { $0.role == .transport }),
              let gateway = services.claims.first(where: { $0.role == .gateway }),
              request.request.service.transportPolicy.expectedUserID == transport.number,
              request.gatewayPolicy.expectedUserID == gateway.number else { throw GatewayPreparationError.changedScope }
        _ = try material.phonePush.registrationPolicy(material.runtime.gateway)
    }
    func validate(transport base: TransportPairingStartupConfiguration) throws {
        let services = material.runtime.services, configuration = base.transport
        let paths = try RuntimePreparationPaths(accountID: services.accountID), registration = material.runtime.gateway
        let binding = try GatewaySubmissionBinding(ownerID: registration.ownerID, macID: registration.macID, accountID: registration.accountID,
            gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch)
        guard target == .transport, let wake, baseDigest == Data(SHA256.hash(data: base.canonicalBytes)),
              configuration.macID == services.macID, configuration.accountID == services.accountID,
              configuration.ownerUID == services.ownerUID, configuration.identityPublicKeyInfo == material.runtime.transportPublicKeyInfo,
              let transport = services.claims.first(where: { $0.role == .transport }), configuration.serviceUID == transport.number,
              let gateway = services.claims.first(where: { $0.role == .gateway }),
              wake.transport.canonicalBytes == configuration.canonicalBytes, wake.wake.binding == binding,
              wake.wake.credentialID == material.wakeCredentialID, wake.wake.publicKey == material.wakePublicKey,
              wake.wake.custody == .protectedFile, wake.wake.keyRecordPath == paths.transportWakeKey,
              wake.wake.gatewayPolicy.expectedUserID == gateway.number, wake.wake.serviceName == paths.gatewayWakeService,
              base.wake == nil || base.wake?.canonicalBytes == wake.canonicalBytes else { throw GatewayPreparationError.changedScope }
        try require(configuration.authorityPolicy, role: .authority, uid: 0)
        try require(base.control.appPolicy, role: .app, uid: services.ownerUID)
        try require(base.control.transportPolicy, role: .transport, uid: transport.number)
        try require(wake.wake.gatewayPolicy, role: .notificationGateway, uid: gateway.number)
    }
    private func require(_ policy: XPCPeerPolicy, role: AuthorityCodeRole, uid: UInt32) throws {
        guard let code = codePolicy.entries.first(where: { $0.role == role && $0.active }) else { throw GatewayPreparationError.invalidRecord }
        let expected = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
            approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: uid)
        guard policy.expectedUserID == uid, policy.requirement == expected.requirement else { throw GatewayPreparationError.changedScope }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(purpose), 2: .unsigned(target.rawValue), 3: .bytes(intentID),
            4: .bytes(intentDigest), 5: .bytes(foregroundDigest), 6: .bytes(baseDigest), 7: .bytes(material.encoded),
            8: .bytes(codePolicy.bytes), 9: wake.map { .bytes($0.canonicalBytes) } ?? .null]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...9),
              f[0] == .unsigned(1), case .unsigned(let role) = f[2], let target = Target(rawValue: role),
              case .bytes(let id) = f[3], case .bytes(let intent) = f[4], case .bytes(let foreground) = f[5],
              case .bytes(let base) = f[6], case .bytes(let material) = f[7], case .bytes(let policy) = f[8] else {
            throw GatewayPreparationError.invalidRecord
        }
        let wake: TransportWakeStartupConfiguration?
        switch f[9] { case .null?: wake = nil; case .bytes(let value)?: wake = try .decode(value); default: throw GatewayPreparationError.invalidRecord }
        let result = try Self(target: target, intentID: id, intentDigest: intent, foregroundDigest: foreground, baseDigest: base,
            material: .decode(material), codePolicy: .decode(policy), wake: wake)
        guard f[1] == .text(result.purpose), try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 21)
}
