import Foundation
import RemozioProtocol

/// Public exchange bytes only. Native peer checks and journal reconciliation remain mandatory.
struct MachineUpdateConsumerHealthExchange: Sendable {
    let request: Data
    let response: Data
}

/// Root selects this context from protected installed state. The caller cannot select the Gateway key or registration.
struct MachineUpdateAuthorityReadinessGateway: Equatable, Sendable {
    let requirement: MachineUpdateRestartHealthPlan.Requirement
    let registration: GatewayRegistrationIdentity

    init(requirement: MachineUpdateRestartHealthPlan.Requirement, registration: GatewayRegistrationIdentity) throws {
        guard requirement.role == .notificationGateway,
              requirement.binding.macID == registration.macID,
              requirement.binding.accountID == registration.accountID else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        self.requirement = requirement; self.registration = registration
    }
}

/// The Gateway challenge derives its nonce from this fresh Root challenge. Root signs only after it reconciles both signatures.
struct MachineUpdateAuthorityReadinessRequest: Sendable {
    let challenge: Data
    let gateway: MachineUpdateConsumerHealthExchange?

    init(challenge: Data, gateway: MachineUpdateConsumerHealthExchange?) throws {
        let root = try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(challenge)
        guard root.role == .authority, root.executionUID == 0 else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        if let gateway {
            try MachineUpdateRoleChallengeSession.requireGatewayChallenge(gateway.request, boundTo: challenge)
            _ = try MachineUpdateConsumerHealthPacket.decode(gateway.response)
        }
        self.challenge = challenge; self.gateway = gateway
    }

    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("machine-update-authority-readiness"),
            2: .bytes(challenge), 3: gateway.map { .bytes($0.request) } ?? .null,
            4: gateway.map { .bytes($0.response) } ?? .null]), limits: Self.limits)
    } }

    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              fields[1] == .text("machine-update-authority-readiness"), case .bytes(let challenge) = fields[2] else {
            throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let gateway: MachineUpdateConsumerHealthExchange?
        switch (fields[3], fields[4]) {
        case (.null?, .null?): gateway = nil
        case (.bytes(let request)?, .bytes(let response)?): gateway = .init(request: request, response: response)
        default: throw MachineUpdateRoleChallengeError.invalidMessage
        }
        let value = try Self(challenge: challenge, gateway: gateway)
        guard try value.encoded == bytes else { throw MachineUpdateRoleChallengeError.invalidMessage }
        return value
    }

    /// Verifies the bound signatures. Only the live client can prove the Gateway peer and the original challenge deadline.
    func gatewayProof(expected: MachineUpdateAuthorityReadinessGateway?, now: AuthorityMoment) throws -> MachineUpdateConsumerHealthProof? {
        guard (expected != nil) == (gateway != nil) else { throw MachineUpdateRoleChallengeError.changedScope }
        guard let expected, let gateway else { return nil }
        let root = try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(challenge)
        guard expected.registration.rootPublicKey == root.publicKey else { throw MachineUpdateRoleChallengeError.changedScope }
        let role = try MachineUpdateRoleChallengeSession.verifyGatewayReply(request: gateway.request,
            response: MachineUpdateConsumerHealthPacket.decode(gateway.response).roleReply,
            expected: expected.requirement, boundTo: challenge)
        let packet = try MachineUpdateConsumerHealthPacket.decode(gateway.response)
        guard let reply = packet.gatewayHead else { throw MachineUpdateRoleChallengeError.invalidMessage }
        let query = try GatewayHeadQueryOwner(registration: expected.registration,
            gatewayPublicKey: expected.requirement.publicKey, clockEpoch: now.epoch, maximumQueries: 1)
        defer { query.invalidate() }
        _ = try query.makeUpdateHealthQuery(request: gateway.request, now: now)
        return .init(role: role, gatewayHead: try query.accept(reply, now: now))
    }

    private static let limits = try! CBORLimits(maxBytes: 140000, maxDepth: 1, maxItems: 11)
}
