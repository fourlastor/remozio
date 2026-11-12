import CryptoKit
import Foundation
import RemozioProtocol

/// Checks archived signatures and scope only. It grants no freshness, peer identity, startup, or writer authority.
enum MachineUpdateRetainedSetupHealthEvidence {
    static let version: UInt64 = 1
    static let completionVersion: UInt64 = 2
    static let promotionVersion: UInt64 = 3
    struct Requirement: Equatable, Sendable {
        let binding: RuntimeRetainedSetupReleaseBinding
        let activationPlanDigest: Data
        let inventoryDigest: Data
        let role: AuthorityCodeRole
        let executionUID: UInt32
        let code: AuthorityCodeEntry
        let publicKey: Data
        let completionBoundaryDigest: Data?
        let promotionDigest: Data?
        init(binding: RuntimeRetainedSetupReleaseBinding, activationPlanDigest: Data, inventoryDigest: Data,
            role: AuthorityCodeRole, executionUID: UInt32, code: AuthorityCodeEntry, publicKey: Data,
            completionBoundaryDigest: Data? = nil, promotionDigest: Data? = nil) {
            self.binding = binding; self.activationPlanDigest = activationPlanDigest; self.inventoryDigest = inventoryDigest
            self.role = role; self.executionUID = executionUID; self.code = code; self.publicKey = publicKey
            self.completionBoundaryDigest = completionBoundaryDigest; self.promotionDigest = promotionDigest
        }
        func validate() throws {
            _ = try binding.encoded
            guard activationPlanDigest.count == 32, inventoryDigest.count == 32,
                  completionBoundaryDigest == nil || completionBoundaryDigest?.count == 32,
                  promotionDigest == nil || promotionDigest?.count == 32 && completionBoundaryDigest != nil,
                  [.authority, .transport].contains(role), code.role == role, code.active,
                  publicKey.count == 65, (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil,
                  role == .authority ? executionUID == 0 : executionUID > 0 && executionUID < UInt32.max else {
                throw MachineUpdateRoleChallengeError.changedScope
            }
        }
        var encoded: Data { get throws {
            try validate()
            let version = promotionDigest != nil ? MachineUpdateRetainedSetupHealthEvidence.promotionVersion
                : completionBoundaryDigest == nil ? MachineUpdateRetainedSetupHealthEvidence.version
                : MachineUpdateRetainedSetupHealthEvidence.completionVersion
            var fields: [UInt64: CBORValue] = [0: .unsigned(version),
                1: .text("retained-setup-health-scope"), 2: .bytes(try binding.encoded),
                3: .bytes(activationPlanDigest), 4: .bytes(inventoryDigest),
                5: .unsigned(role.rawValue), 6: .unsigned(UInt64(executionUID)),
                7: .bytes(try AuthorityCodePolicy(entries: [code]).bytes), 8: .bytes(publicKey)]
            if let completionBoundaryDigest { fields[9] = .bytes(completionBoundaryDigest) }
            if let promotionDigest { fields[10] = .bytes(promotionDigest) }
            return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
        } }
        private static let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 23)
        static func decode(_ bytes: Data) throws -> Self {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  case .unsigned(let version) = fields[0],
                  fields[1] == .text("retained-setup-health-scope"), case .bytes(let binding) = fields[2],
                  case .bytes(let plan) = fields[3], case .bytes(let inventory) = fields[4],
                  case .unsigned(let rawRole) = fields[5], let role = AuthorityCodeRole(rawValue: rawRole),
                  case .unsigned(let rawUID) = fields[6], let uid = UInt32(exactly: rawUID),
                  case .bytes(let policyBytes) = fields[7], case .bytes(let publicKey) = fields[8] else {
                throw MachineUpdateRoleChallengeError.invalidMessage
            }
            let completionBoundaryDigest: Data?, promotionDigest: Data?
            switch version {
            case MachineUpdateRetainedSetupHealthEvidence.version:
                guard Set(fields.keys) == Set(UInt64(0)...8) else { throw MachineUpdateRoleChallengeError.invalidMessage }
                completionBoundaryDigest = nil; promotionDigest = nil
            case MachineUpdateRetainedSetupHealthEvidence.completionVersion:
                guard Set(fields.keys) == Set(UInt64(0)...9), case .bytes(let digest) = fields[9], digest.count == 32 else {
                    throw MachineUpdateRoleChallengeError.invalidMessage
                }
                completionBoundaryDigest = digest; promotionDigest = nil
            case MachineUpdateRetainedSetupHealthEvidence.promotionVersion:
                guard Set(fields.keys) == Set(UInt64(0)...10), case .bytes(let digest) = fields[9], digest.count == 32,
                      case .bytes(let publication) = fields[10], publication.count == 32 else {
                    throw MachineUpdateRoleChallengeError.invalidMessage
                }
                completionBoundaryDigest = digest; promotionDigest = publication
            default: throw MachineUpdateRoleChallengeError.invalidMessage
            }
            let policy = try AuthorityCodePolicy.decode(policyBytes)
            guard policy.entries.count == 1, let code = policy.entries.first else { throw MachineUpdateRoleChallengeError.invalidMessage }
            let value = try Self(binding: .decode(binding), activationPlanDigest: plan, inventoryDigest: inventory,
                role: role, executionUID: uid, code: code, publicKey: publicKey,
                completionBoundaryDigest: completionBoundaryDigest, promotionDigest: promotionDigest)
            guard try value.encoded == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }; return value
        }
    }
    static func verifyJointRootReply(request: Data, response: Data, expected: Requirement,
        transportDigest: Data) throws {
        let challenge = try Challenge.decode(request)
        guard expected.role == .authority, challenge.requirement == expected, transportDigest.count == 32,
              case .map(let fields) = try DeterministicCBOR.decode(response, limits: jointRootLimits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              fields[1] == .text("retained-setup-joint-root-reply"), fields[2] == .bytes(request),
              fields[3] == .bytes(transportDigest), case .bytes(let signature) = fields[4], signature.count == 64,
              try jointRootReply(request: request, transportDigest: transportDigest, signature: signature) == response else {
            throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let key = try P256.Signing.PublicKey(x963Representation: expected.publicKey)
        guard try key.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature),
            for: jointRootSignedBytes(request: request, transportDigest: transportDigest)) else {
            throw MachineUpdateRoleChallengeError.invalidSignature
        }
    }
    private static func authenticateReply(_ bytes: Data, challenge: Challenge) throws {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: Self.replyLimits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
              fields[1] == .text(Self.replyName), case .bytes(let request) = fields[2],
              case .bytes(let signature) = fields[3], signature.count == 64,
              request == (try challenge.encoded), try Self.reply(request: request, signature: signature) == bytes else {
            throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let key = try P256.Signing.PublicKey(x963Representation: challenge.requirement.publicKey)
        guard try key.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: challenge.signedBytes) else {
            throw MachineUpdateRoleChallengeError.invalidSignature
        }
    }
    static func decodeRequestedRequirement(_ bytes: Data) throws -> Requirement { try Challenge.decode(bytes).requirement }
    static func verifyTransportReply(request: Data, response: Data, expected: Requirement,
        boundTo root: Data) throws {
        let child = try Challenge.decode(request), parent = try Challenge.decode(root)
        try requireTransportScope(expected, root: parent.requirement)
        guard child.requirement == expected, child.nonce == transportNonce(root) else { throw MachineUpdateRoleChallengeError.changedScope }
        try authenticateReply(response, challenge: child)
    }
    private static func requireTransportScope(_ transport: Requirement, root: Requirement) throws {
        try root.validate(); try transport.validate()
        guard root.role == .authority, root.executionUID == 0, transport.role == .transport,
              transport.binding == root.binding, transport.activationPlanDigest == root.activationPlanDigest,
              transport.inventoryDigest == root.inventoryDigest,
              transport.completionBoundaryDigest == root.completionBoundaryDigest,
              transport.promotionDigest == root.promotionDigest else { throw MachineUpdateRoleChallengeError.changedScope }
    }
    private static func transportNonce(_ root: Data) -> Data {
        MachineUpdateActivationRecord.digest(Data("Remozio/RetainedSetupTransportNonce/v1\0".utf8) + root)
    }
    private static func jointRootSignedBytes(request: Data, transportDigest: Data) -> Data {
        Data("Remozio/RetainedSetupJointRootReply/v1\0".utf8) + transportDigest + request
    }
    private static func jointRootReply(request: Data, transportDigest: Data, signature: Data) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("retained-setup-joint-root-reply"),
            2: .bytes(request), 3: .bytes(transportDigest), 4: .bytes(signature)]), limits: jointRootLimits)
    }
    private struct Challenge: Sendable {
        let nonce: Data
        let requirement: Requirement
        init(nonce: Data, requirement: Requirement) throws {
            guard nonce.count == 32 else { throw MachineUpdateRoleChallengeError.invalidMessage }
            try requirement.validate(); self.nonce = nonce; self.requirement = requirement; _ = try encoded
        }
        var encoded: Data { get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("retained-setup-health-challenge"),
                2: .bytes(nonce), 3: .bytes(requirement.encoded)]), limits: Self.limits)
        } }
        var signedBytes: Data { get throws { Data("Remozio/RetainedSetupHealthReply/v1\0".utf8) + (try encoded) } }
        static func decode(_ bytes: Data) throws -> Self {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
                  fields[1] == .text("retained-setup-health-challenge"), case .bytes(let nonce) = fields[2],
                  case .bytes(let requirement) = fields[3] else { throw MachineUpdateRoleChallengeError.invalidMessage }
            let value = try Self(nonce: nonce, requirement: .decode(requirement))
            guard try value.encoded == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }; return value
        }
        static let limits = try! CBORLimits(maxBytes: 16512, maxDepth: 1, maxItems: 9)
    }
    private static func reply(request: Data, signature: Data) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(replyName),
            2: .bytes(request), 3: .bytes(signature)]), limits: replyLimits)
    }
    private static let jointRootLimits = try! CBORLimits(maxBytes: 16768, maxDepth: 1, maxItems: 11)
    private static let replyName = "retained-setup-health-reply"
    private static let replyLimits = try! CBORLimits(maxBytes: 16704, maxDepth: 1, maxItems: 9)
}

/// Preserves a historical joint packet. Decoding authenticates no native peer.
struct MachineUpdateRetainedSetupJointHealthPacket: Sendable {
    let rootReply: Data
    let transportRequest: Data
    let transportReply: Data
    var encoded: Data { get throws {
        guard !rootReply.isEmpty, rootReply.count <= 16768 else { throw MachineUpdateRoleChallengeError.invalidMessage }
        _ = try Self.transportDigest(request: transportRequest, reply: transportReply)
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("retained-setup-joint-health"),
            2: .bytes(rootReply), 3: .bytes(transportRequest), 4: .bytes(transportReply)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              fields[1] == .text("retained-setup-joint-health"), case .bytes(let root) = fields[2],
              case .bytes(let request) = fields[3], case .bytes(let reply) = fields[4] else {
            throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let value = Self(rootReply: root, transportRequest: request, transportReply: reply)
        guard try value.encoded == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }; return value
    }
    static func transportDigest(request: Data, reply: Data) throws -> Data {
        guard !request.isEmpty, request.count <= 16512, !reply.isEmpty, reply.count <= 16704 else {
            throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("retained-setup-joint-transport-proof"),
            2: .bytes(request), 3: .bytes(reply)]), limits: .init(maxBytes: 33344, maxDepth: 1, maxItems: 9))
        return MachineUpdateActivationRecord.digest(bytes)
    }
    private static let limits = try! CBORLimits(maxBytes: 50240, maxDepth: 1, maxItems: 11)
}
