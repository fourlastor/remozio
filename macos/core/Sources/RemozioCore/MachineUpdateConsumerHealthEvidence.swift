import CryptoKit
import Foundation
import RemozioProtocol

/// Binds the existing Gateway head query to the full update challenge. It grants no peer or journal authority.
enum MachineUpdateGatewayHealthQuery {
    static func nonce(_ request: Data) -> Data {
        Data(SHA256.hash(data: Data("Remozio/MachineUpdateGatewayHeadQuery/v1\0".utf8) + request))
    }
    static func make(request: Data, registration: GatewayRegistrationIdentity, gatewayPublicKey: Data) throws -> Data {
        let requirement = try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(request)
        guard requirement.role == .notificationGateway, requirement.binding.macID == registration.macID,
              requirement.binding.accountID == registration.accountID, requirement.publicKey == gatewayPublicKey else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(0),
            2: .bytes(registration.encode()), 3: .bytes(nonce(request))]),
            limits: .init(maxBytes: 1024, maxDepth: 1, maxItems: 9))
    }
}

/// Canonical transport bytes only. Root must authenticate both signatures and reconcile the reported journal head.
struct MachineUpdateConsumerHealthPacket {
    let roleReply: Data
    let gatewayHead: GatewayHeadReply?
    var encoded: Data { get throws {
        guard !roleReply.isEmpty, roleReply.count <= 16640 else { throw MachineUpdateRoleChallengeError.invalidMessage }
        if let gatewayHead {
            guard !gatewayHead.canonicalPayload.isEmpty, gatewayHead.canonicalPayload.count <= 70000,
                  gatewayHead.signature.count == 64 else { throw MachineUpdateRoleChallengeError.invalidMessage }
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("machine-update-consumer-health"),
            2: .bytes(roleReply), 3: gatewayHead.map { .bytes($0.canonicalPayload) } ?? .null,
            4: gatewayHead.map { .bytes($0.signature) } ?? .null]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let values) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(values.keys) == Set(UInt64(0)...4), values[0] == .unsigned(1),
              values[1] == .text("machine-update-consumer-health"), case .bytes(let roleReply) = values[2] else {
            throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let head: GatewayHeadReply?
        switch (values[3], values[4]) {
        case (.null?, .null?): head = nil
        case (.bytes(let payload)?, .bytes(let signature)?): head = .init(canonicalPayload: payload, signature: signature)
        default: throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let value = Self(roleReply: roleReply, gatewayHead: head)
        guard try value.encoded == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }
        return value
    }
    private static let limits = try! CBORLimits(maxBytes: 100000, maxDepth: 1, maxItems: 11)
}

/// Fresh role and optional Gateway evidence. This value grants no floor commit or permission to reopen admission.
struct MachineUpdateConsumerHealthProof: Sendable {
    let role: MachineUpdateAuthenticatedRoleReply
    let gatewayHead: VerifiedGatewayHead?
    init(role: MachineUpdateAuthenticatedRoleReply, gatewayHead: VerifiedGatewayHead?) {
        self.role = role; self.gatewayHead = gatewayHead
    }
}

/// One issue and one verification attempt. Closing or a failed reply permanently consumes this update health attempt.
final class MachineUpdateConsumerHealthChallengeSession: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private enum State { case created, issuing, issued, verifying, consumed, closed }
    private let lock = NSLock()
    private let headLock = NSLock()
    private var state = State.created
    private let role: MachineUpdateRoleChallengeSession
    private let requirement: Requirement
    private let head: GatewayHeadQueryOwner?
    private let clock: @Sendable () throws -> AuthorityMoment
    private let verifyCurrent: @Sendable () throws -> Void

    init(requirement: Requirement, registration: GatewayRegistrationIdentity?, authorityInstalledReadiness: Bool = false, authorityReadinessRequest: Data? = nil, lifetimeMilliseconds: UInt64 = 30000,
        clock: @escaping @Sendable () throws -> AuthorityMoment, verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        let allowed = authorityInstalledReadiness
            ? requirement.role == .authority && requirement.executionUID == 0 && registration == nil
            : [.transport, .notificationGateway].contains(requirement.role)
                && (requirement.role == .notificationGateway) == (registration != nil)
        guard allowed else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        self.requirement = requirement; self.clock = clock; self.verifyCurrent = verifyCurrent
        role = try .init(requirement: requirement, authorityReadinessRequest: authorityReadinessRequest, verifyCurrent: verifyCurrent)
        if let registration {
            guard registration.macID == requirement.binding.macID, registration.accountID == requirement.binding.accountID else {
                throw MachineUpdateRoleChallengeError.changedScope
            }
            head = try .init(registration: registration, gatewayPublicKey: requirement.publicKey, clockEpoch: clock().epoch,
                lifetimeMillis: lifetimeMilliseconds, maximumQueries: 1)
        } else { head = nil }
    }
    func makeRequest() throws -> Data {
        try lock.withLock {
            guard state == .created else { throw MachineUpdateRoleChallengeError.unavailable }; state = .issuing
        }
        var issued = false
        defer {
            if !issued {
                role.close(); invalidateHead()
                lock.withLock { if state == .issuing { state = .consumed } }
            }
        }
        try verifyCurrent()
        let bytes = try role.request
        try verifyCurrent()
        if let head {
            let moment = try clock()
            _ = try headLock.withLock { try head.makeUpdateHealthQuery(request: bytes, now: moment) }
        }
        return try lock.withLock {
            guard state == .issuing else { throw MachineUpdateRoleChallengeError.unavailable }
            issued = true; state = .issued; return bytes
        }
    }
    func accept(_ bytes: Data, authenticatePeer: @Sendable (Requirement) throws -> Void) throws -> MachineUpdateConsumerHealthProof {
        try lock.withLock {
            guard state == .issued else { throw MachineUpdateRoleChallengeError.unavailable }; state = .verifying
        }
        defer {
            role.close(); invalidateHead()
            lock.withLock { if state == .verifying { state = .consumed } }
        }
        try verifyCurrent()
        try authenticatePeer(requirement)
        let received = try clock()
        let packet = try MachineUpdateConsumerHealthPacket.decode(bytes)
        let verified: VerifiedGatewayHead?
        if let head {
            guard let reply = packet.gatewayHead else { throw MachineUpdateRoleChallengeError.invalidMessage }
            verified = try headLock.withLock { try head.accept(reply, now: received) }
        } else {
            guard packet.gatewayHead == nil else { throw MachineUpdateRoleChallengeError.invalidMessage }
            verified = nil
        }
        let authenticated = try role.accept(packet.roleReply, authenticatePeer: { _ in })
        try verifyCurrent()
        return try lock.withLock {
            guard state == .verifying else { throw MachineUpdateRoleChallengeError.unavailable }
            state = .consumed; return .init(role: authenticated, gatewayHead: verified)
        }
    }
    private func invalidateHead() { headLock.withLock { head?.invalidate() } }
    func close() {
        lock.withLock { state = .closed }
        role.close(); invalidateHead()
    }
    deinit { close() }
}

final class MachineUpdateTransportHealthReply: MachineUpdateConsumerHealthAnswering, @unchecked Sendable {
    private let key: MachineUpdateTransportHealthKey
    init(key: MachineUpdateTransportHealthKey) { self.key = key }
    func answer(_ bytes: Data) throws -> Data {
        try MachineUpdateConsumerHealthPacket(roleReply: key.answer(bytes), gatewayHead: nil).encoded
    }
    func close() { key.close() }
}

final class MachineUpdateGatewayHealthReply: MachineUpdateConsumerHealthAnswering, @unchecked Sendable {
    private let owner: MachineUpdateGatewayHealthOwner
    init(owner: MachineUpdateGatewayHealthOwner) { self.owner = owner }
    func answer(_ bytes: Data) throws -> Data { try owner.answerWithHead(bytes) }
    func close() throws { try owner.close() }
}
