import Foundation

/// Owns one pinned Root invocation. An accepted request does not grant startup or update completion authority.
final class MachineUpdateConsumerHealthPeer: @unchecked Sendable {
    typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private let lock = NSRecursiveLock()
    private let authenticateInvocation: @Sendable () throws -> Void
    private let verifyPeer: @Sendable () throws -> Void
    private let verifyCurrent: @Sendable () throws -> Void
    private let requireScope: @Sendable (Requirement) throws -> Void
    private var issued = false
    private var greeted = false
    private var closed = false

    /// Injected checks exercise local ordering only. This factory does not authenticate a native connection.
    static func owned(expected: Requirement, authenticateInvocation: @escaping @Sendable () throws -> Void,
        verifyPeer: @escaping @Sendable () throws -> Void, verifyCurrent: @escaping @Sendable () throws -> Void) -> Self {
        Self(authenticateInvocation: authenticateInvocation, verifyPeer: verifyPeer, verifyCurrent: verifyCurrent,
            requireScope: { guard $0 == expected else { throw MachineUpdateRoleChallengeError.changedScope } })
    }
    private init(authenticateInvocation: @escaping @Sendable () throws -> Void,
        verifyPeer: @escaping @Sendable () throws -> Void, verifyCurrent: @escaping @Sendable () throws -> Void,
        requireScope: @escaping @Sendable (Requirement) throws -> Void) {
        self.authenticateInvocation = authenticateInvocation; self.verifyPeer = verifyPeer
        self.verifyCurrent = verifyCurrent; self.requireScope = requireScope
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
                let requirement = try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(bytes)
                try requireScope(requirement); try validate()
                return MachineUpdateConsumerHealthRequest(peer: self, bytes: bytes, requirement: requirement)
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
    let requirement: MachineUpdateRestartHealthPlan.Requirement
    private var claimed = false
    private var retired = false
    fileprivate init(peer: MachineUpdateConsumerHealthPeer, bytes: Data, requirement: MachineUpdateRestartHealthPlan.Requirement) {
        self.peer = peer; self.bytes = bytes; self.requirement = requirement
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
