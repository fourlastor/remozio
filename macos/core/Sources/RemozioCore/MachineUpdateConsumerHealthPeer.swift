import Foundation

/// Owns one pinned Root invocation. An accepted request does not grant startup or update completion authority.
final class MachineUpdateConsumerHealthPeer: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private let lock = NSRecursiveLock()
    private let authenticateInvocation: @Sendable () throws -> Void
    private let verifyPeer: @Sendable () throws -> Void
    private let verifyCurrent: @Sendable () throws -> Void
    private let requireScope: @Sendable (Requirement) throws -> Void
    private let authorityInstalledReadiness: Bool
    private var issued = false
    private var greeted = false
    private var closed = false

    /// Injected checks exercise local ordering only. This factory does not authenticate a native connection.
    static func owned(expected: Requirement, authorityInstalledReadiness: Bool = false, authenticateInvocation: @escaping @Sendable () throws -> Void,
        verifyPeer: @escaping @Sendable () throws -> Void, verifyCurrent: @escaping @Sendable () throws -> Void) -> Self {
        Self(authenticateInvocation: authenticateInvocation, verifyPeer: verifyPeer, verifyCurrent: verifyCurrent, authorityInstalledReadiness: authorityInstalledReadiness,
            requireScope: { guard $0 == expected else { throw MachineUpdateRoleChallengeError.changedScope } })
    }
    private init(authenticateInvocation: @escaping @Sendable () throws -> Void,
        verifyPeer: @escaping @Sendable () throws -> Void, verifyCurrent: @escaping @Sendable () throws -> Void,
        authorityInstalledReadiness: Bool = false, requireScope: @escaping @Sendable (Requirement) throws -> Void) {
        self.authenticateInvocation = authenticateInvocation; self.verifyPeer = verifyPeer
        self.verifyCurrent = verifyCurrent; self.requireScope = requireScope
        self.authorityInstalledReadiness = authorityInstalledReadiness
    }

    /// The harmless handshake authenticates its own invocation. It opens no owner and issues no request capability.
    func greet() throws {
        try lock.withLock {
            guard !closed, !greeted, !issued else { throw MachineUpdateRoleChallengeError.unavailable }
            greeted = true
            do { try authenticateInvocation(); try validate() } catch { closed = true; throw error }
        }
    }

    /// Call synchronously from the exported method. Authentication runs before parsing and before any credential or store access.
    func accept(_ bytes: Data) throws -> MachineUpdateConsumerHealthRequest {
        try lock.withLock {
            guard !closed, !issued else { throw MachineUpdateRoleChallengeError.unavailable }
            issued = true
            do {
                try authenticateInvocation(); try validate()
                let authority = try authorityInstalledReadiness ? MachineUpdateAuthorityReadinessRequest.decode(bytes) : nil
                let challenge = authority?.challenge ?? bytes
                let requirement = try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(challenge)
                try requireScope(requirement); try validate()
                return MachineUpdateConsumerHealthRequest(peer: self, bytes: challenge, requirement: requirement,
                    authorityReadiness: authority)
            } catch { closed = true; throw error }
        }
    }
    fileprivate func validate() throws {
        try lock.withLock {
            guard !closed, greeted || issued else { throw MachineUpdateRoleChallengeError.unavailable }
            do {
                try verifyPeer(); try verifyCurrent()
                guard !closed else { throw MachineUpdateRoleChallengeError.unavailable }
            } catch { closed = true; throw error }
        }
    }
    func close() { lock.withLock { closed = true } }
    deinit { close() }
}

/// One owner opening per authenticated invocation. Peer closure or a changed native scope invalidates the retained request.
final class MachineUpdateConsumerHealthRequest: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private weak var peer: MachineUpdateConsumerHealthPeer?
    let bytes: Data
    let authorityReadiness: MachineUpdateAuthorityReadinessRequest?
    let requirement: MachineUpdateRestartHealthPlan.Requirement
    private var claimed = false
    private var retired = false
    fileprivate init(peer: MachineUpdateConsumerHealthPeer, bytes: Data, requirement: MachineUpdateRestartHealthPlan.Requirement,
        authorityReadiness: MachineUpdateAuthorityReadinessRequest?) {
        self.peer = peer; self.bytes = bytes; self.requirement = requirement; self.authorityReadiness = authorityReadiness
    }
    func claim() throws {
        try lock.withLock {
            guard !claimed, !retired else { throw MachineUpdateRoleChallengeError.unavailable }
            claimed = true
            try validate()
        }
    }
    func validate() throws {
        try lock.withLock {
            guard !retired, let peer else { throw MachineUpdateRoleChallengeError.unavailable }
            do { try peer.validate() } catch { retired = true; throw error }
        }
    }
    func close() { lock.withLock { retired = true } }
    deinit { close() }
}
