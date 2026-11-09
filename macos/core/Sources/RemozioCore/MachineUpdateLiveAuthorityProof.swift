import Foundation

/// A fixed-purpose proof from the running Root owner. These inputs grant no native peer admission or machine completion authority.
enum MachineUpdateLiveAuthorityProof {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    static func answer(_ request: MachineUpdateConsumerHealthRequest, expected: Requirement,
        macID: Data, accountID: Data, keyPublicKey: Data,
        gateway: MachineUpdateAuthorityReadinessGateway? = nil, now: AuthorityMoment,
        reconcileGateway: @Sendable (MachineUpdateConsumerHealthProof, MachineUpdateAuthorityReadinessGateway) throws -> Void = { _,_ in throw MachineUpdateRoleChallengeError.unavailable },
        capture: @Sendable () throws -> AuthorityJournal.MachineUpdatePolicyBoundary,
        verifyCurrent: @Sendable () throws -> Void,
        sign: @Sendable (Data) throws -> Data) throws -> Data {
        try request.claim(); try Task.checkCancellation(); try request.validate()
        guard request.requirement == expected, expected.role == .authority, expected.executionUID == 0,
              expected.binding.macID == macID, expected.binding.accountID == accountID,
              expected.publicKey == keyPublicKey else { throw MachineUpdateRoleChallengeError.changedScope }
        func current() throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
            try Task.checkCancellation(); try request.validate(); try verifyCurrent()
            let boundary = try capture()
            guard boundary.macID == macID, boundary.accountID == accountID,
                  boundary.policy.policy.entries.first(where: { $0.role == .authority && $0.active }) == expected.code else {
                throw MachineUpdateRoleChallengeError.changedScope
            }
            try expected.binding.requireCompletionPolicy(boundary.policy.policy)
            try verifyCurrent(); try request.validate(); try Task.checkCancellation(); return boundary
        }
        guard let exchange = request.authorityReadiness, exchange.challenge == request.bytes else {
            throw MachineUpdateRoleChallengeError.changedScope
        }
        if let gateway { try gateway.requireSelection(for: expected) }
        let proof = try exchange.gatewayProof(expected: gateway, now: now)
        let before = try current()
        func requireGateway() throws {
            if let proof, let gateway { try reconcileGateway(proof, gateway) }
            guard try current() == before else { throw MachineUpdateRoleChallengeError.changedScope }
        }
        try requireGateway()
        let reply = try MachineUpdateRoleChallengeSession.answer(request.bytes, expected: expected,
            verifyCurrent: {
                try requireGateway()
            }, sign: sign)
        try requireGateway()
        return reply
    }
}
