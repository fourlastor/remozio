import CryptoKit
import Foundation
import RemozioProtocol
import Security

enum MachineUpdateRoleChallengeError: Error, Equatable {
    case invalidMessage, changedScope, unavailable, invalidSignature, randomFailure
}

/// An authenticated challenge reply. Runtime protocol and journal checks remain separate requirements.
struct MachineUpdateAuthenticatedRoleReply: Sendable {
    let requirement: MachineUpdateRestartHealthPlan.Requirement
    let challengeDigest: Data
    fileprivate init(requirement: MachineUpdateRestartHealthPlan.Requirement, challengeDigest: Data) {
        self.requirement = requirement; self.challengeDigest = challengeDigest
    }
}

/// One challenge per instance. Closing or attempting verification consumes the challenge, including a failed attempt.
final class MachineUpdateRoleChallengeSession: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private enum State { case issued, verifying, consumed, closed }
    private let lock = NSLock()
    private var state = State.issued
    private let challenge: Challenge
    private let verifyCurrent: @Sendable () throws -> Void
    var request: Data { get throws { try challenge.encoded } }

    init(requirement: Requirement, authorityReadinessRequest: Data? = nil, verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        try verifyCurrent()
        var nonce = Data(count: 32)
        let status = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw MachineUpdateRoleChallengeError.randomFailure }
        if let authorityReadinessRequest {
            let root = try Challenge.decode(authorityReadinessRequest)
            try Self.requireSameScope(gateway: requirement, root: root.requirement)
            nonce = Self.gatewayNonce(authorityReadinessRequest)
        }
        challenge = try Challenge(nonce: nonce, requirement: requirement)
        self.verifyCurrent = verifyCurrent
        try verifyCurrent()
    }

    /// The owner supplies fresh peer authentication. A signature alone does not authenticate executing code or its UID.
    func accept(_ bytes: Data, authenticatePeer: @Sendable (Requirement) throws -> Void) throws -> MachineUpdateAuthenticatedRoleReply {
        try lock.withLock {
            guard state == .issued else { throw MachineUpdateRoleChallengeError.unavailable }
            state = .verifying
        }
        defer { lock.withLock { if state == .verifying { state = .consumed } } }
        try verifyCurrent(); try authenticatePeer(challenge.requirement)
        let proof = try Self.authenticateReply(bytes, challenge: challenge)
        try verifyCurrent()
        return try lock.withLock {
            guard state == .verifying else { throw MachineUpdateRoleChallengeError.unavailable }
            state = .consumed
            return proof
        }
    }

    func close() { lock.withLock { state = .closed } }
    deinit { close() }

    /// The runtime owner supplies its retained requirement, identity checks and signing operation.
    static func answer(_ bytes: Data, expected: Requirement, verifyCurrent: () throws -> Void,
                       sign: (Data) throws -> Data) throws -> Data {
        try verifyCurrent()
        let challenge = try Challenge.decode(bytes, expected: expected)
        let signature = try sign(challenge.signedBytes)
        guard signature.count == 64 else { throw MachineUpdateRoleChallengeError.invalidMessage }
        let result = try reply(request: challenge.encoded, signature: signature)
        try verifyCurrent(); return result
    }

    /// Parses untrusted scope only. A native peer guard must authenticate Root before any owner or key is opened.
    static func decodeRequestedRequirement(_ bytes: Data) throws -> Requirement {
        try Challenge.decode(bytes).requirement
    }

    /// Verifies public signatures only. Native code, UID, freshness and history require their separate owners.
    static func verifyGatewayReply(request: Data, response: Data, expected: Requirement, boundTo root: Data) throws -> MachineUpdateAuthenticatedRoleReply {
        try requireGatewayChallenge(request, boundTo: root)
        return try authenticateReply(response, challenge: Challenge.decode(request, expected: expected))
    }
    static func requireGatewayChallenge(_ bytes: Data, boundTo root: Data) throws {
        let gateway = try Challenge.decode(bytes), authority = try Challenge.decode(root)
        try requireSameScope(gateway: gateway.requirement, root: authority.requirement)
        guard gateway.nonce == gatewayNonce(root) else { throw MachineUpdateRoleChallengeError.changedScope }
    }
    private static func requireSameScope(gateway: Requirement, root: Requirement) throws {
        guard root.role == .authority, root.executionUID == 0, gateway.role == .notificationGateway,
              gateway.binding == root.binding, gateway.configurationEpoch == root.configurationEpoch,
              gateway.configurationRevision == root.configurationRevision, gateway.backendEpoch == root.backendEpoch,
              gateway.backendRevision == root.backendRevision else { throw MachineUpdateRoleChallengeError.changedScope }
    }
    private static func gatewayNonce(_ root: Data) -> Data {
        Data(SHA256.hash(data: Data("Remozio/MachineUpdateInstalledGatewayNonce/v1\0".utf8) + root))
    }
    private static func authenticateReply(_ bytes: Data, challenge: Challenge) throws -> MachineUpdateAuthenticatedRoleReply {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: Self.replyLimits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
              fields[1] == .text(Self.replyName), case .bytes(let request) = fields[2],
              case .bytes(let signature) = fields[3], signature.count == 64,
              request == (try challenge.encoded) else { throw MachineUpdateRoleChallengeError.invalidMessage }
        let canonical = try Self.reply(request: request, signature: signature)
        guard canonical == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }
        let key = try P256.Signing.PublicKey(x963Representation: challenge.requirement.publicKey)
        let signed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        guard try key.isValidSignature(signed, for: challenge.signedBytes) else { throw MachineUpdateRoleChallengeError.invalidSignature }
        return .init(requirement: challenge.requirement,
            challengeDigest: MachineUpdateActivationRecord.digest(try challenge.encoded))
    }

    private struct Challenge: Sendable {
        let nonce: Data
        let requirement: Requirement
        init(nonce: Data, requirement: Requirement) throws {
            guard nonce.count == 32, [.authority, .transport, .notificationGateway].contains(requirement.role),
                  requirement.code.role == requirement.role, requirement.code.active,
                  requirement.binding.formatVersion == 2,
                  requirement.publicKey.count == 65,
                  (try? P256.Signing.PublicKey(x963Representation: requirement.publicKey)) != nil,
                  requirement.role == .authority ? requirement.executionUID == 0 :
                    requirement.executionUID > 0 && requirement.executionUID < UInt32.max else {
                throw MachineUpdateRoleChallengeError.changedScope
            }
            self.nonce = nonce; self.requirement = requirement
            _ = try encoded
        }
        private var scope: Data { get throws {
            try DeterministicCBOR.encode(.map([
                0: .bytes(requirement.binding.encoded),
                1: .bytes(ServiceAccountPlan.bytes(requirement.configurationEpoch)),
                2: .bytes(ServiceAccountPlan.bytes(requirement.configurationRevision)),
                3: .bytes(ServiceAccountPlan.bytes(requirement.backendEpoch)),
                4: .bytes(ServiceAccountPlan.bytes(requirement.backendRevision)),
                5: .unsigned(requirement.role.rawValue), 6: .unsigned(UInt64(requirement.executionUID)),
                7: .bytes(AuthorityCodePolicy(entries: [requirement.code]).bytes), 8: .bytes(requirement.publicKey)]),
                limits: Self.scopeLimits)
        } }
        var encoded: Data { get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("machine-update-role-challenge"),
                2: .bytes(nonce), 3: .bytes(scope)]), limits: Self.limits)
        } }
        var signedBytes: Data { get throws { Data("Remozio/MachineUpdateRoleReply/v1\0".utf8) + (try encoded) } }
        static func decode(_ bytes: Data, expected: Requirement) throws -> Self {
            let value = try decode(bytes)
            guard value.requirement == expected else { throw MachineUpdateRoleChallengeError.changedScope }
            return value
        }
        static func decode(_ bytes: Data) throws -> Self {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
                  fields[1] == .text("machine-update-role-challenge"), case .bytes(let nonce) = fields[2],
                  case .bytes(let scope) = fields[3],
                  case .map(let values) = try DeterministicCBOR.decode(scope, limits: scopeLimits),
                  Set(values.keys) == Set(UInt64(0)...8), case .bytes(let binding) = values[0],
                  case .unsigned(let rawRole) = values[5], let role = AuthorityCodeRole(rawValue: rawRole),
                  case .unsigned(let rawUID) = values[6], let uid = UInt32(exactly: rawUID),
                  case .bytes(let policyBytes) = values[7], case .bytes(let publicKey) = values[8] else {
                throw MachineUpdateRoleChallengeError.invalidMessage
            }
            func uuid(_ key: UInt64) throws -> UUID {
                guard case .bytes(let bytes) = values[key], bytes.count == 16 else {
                    throw MachineUpdateRoleChallengeError.invalidMessage
                }
                return bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
            }
            let policy = try AuthorityCodePolicy.decode(policyBytes)
            guard policy.entries.count == 1, let code = policy.entries.first else {
                throw MachineUpdateRoleChallengeError.invalidMessage
            }
            let requirement = try Requirement(binding: RuntimeReleaseBinding.decode(binding),
                configurationEpoch: uuid(1), configurationRevision: uuid(2), backendEpoch: uuid(3), backendRevision: uuid(4),
                role: role, executionUID: uid, code: code, publicKey: publicKey)
            let value = try Self(nonce: nonce, requirement: requirement)
            guard try value.encoded == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }
            return value
        }
        static let scopeLimits = try! CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 19)
        static let limits = try! CBORLimits(maxBytes: 16480, maxDepth: 1, maxItems: 9)
    }
    private static let replyName = "machine-update-role-reply"
    private static let replyLimits = try! CBORLimits(maxBytes: 16640, maxDepth: 1, maxItems: 9)
    private static func reply(request: Data, signature: Data) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(replyName),
            2: .bytes(request), 3: .bytes(signature)]), limits: replyLimits)
    }
}
