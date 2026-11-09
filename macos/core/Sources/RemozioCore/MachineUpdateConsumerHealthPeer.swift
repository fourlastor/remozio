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

    /// Configure the accepted connection before activation. The listener must apply the same pinned Root policy before activation.
    static func native(connection: NSXPCConnection, scope: GatewaySettingsConsumerNativeScope,
        release: SignedReleaseEvidence) throws -> MachineUpdateConsumerHealthPeer {
        let host = scope.configuration
        try scope.validate(); try MachineUpdateConsumerHealthReleaseValidation.validate(release, host: host)
        let pins = try GatewaySettingsRecoveryNativePolicy(host: host, release: release)
        let policy = try XPCPeerPolicy(teamID: pins.authority.teamID, componentIdentifier: pins.authority.identifier,
            approvedCodeDirectoryHashes: [pins.authority.codeDirectoryHash], expectedUserID: 0)
        policy.configure(connection)
        let native = NativeConnection(connection: connection, policy: policy)
        return Self(authenticateInvocation: { try native.authenticateInvocation() }, verifyPeer: { try native.validate() },
            verifyCurrent: { try scope.validate() }, requireScope: { requirement in
                guard requirement.binding == host.releaseBinding, requirement.role == host.role.codeRole,
                      requirement.executionUID == host.serviceUID, requirement.code == host.consumerCode else {
                    throw MachineUpdateRoleChallengeError.changedScope
                }
            })
    }

    static func native(connection: NSXPCConnection, authority scope: MachineUpdateAuthorityReadinessScope) throws -> Self {
        try scope.validate(); scope.rootPolicy.configure(connection)
        let native = NativeConnection(connection: connection, policy: scope.rootPolicy)
        return Self(authenticateInvocation: { try native.authenticateInvocation() }, verifyPeer: { try native.validate() },
            verifyCurrent: { try scope.validate() }, authorityInstalledReadiness: true,
            requireScope: { guard $0 == scope.requirement else { throw MachineUpdateRoleChallengeError.changedScope } })
    }

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
    func validate() throws {
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
    private final class NativeConnection: @unchecked Sendable {
        private let lock = NSRecursiveLock()
        private weak var connection: NSXPCConnection?
        private let policy: XPCPeerPolicy
        private let invocation: XPCInvocationGuard
        private var credentials: XPCPeerCredentials?
        init(connection: NSXPCConnection, policy: XPCPeerPolicy) {
            self.connection = connection; self.policy = policy
            invocation = XPCInvocationGuard(connection: connection, policy: policy)
        }
        func authenticateInvocation() throws {
            try lock.withLock {
                let current = try invocation.verifyInvocation()
                if let credentials {
                    guard current == credentials else { throw XPCPeerPolicyError.wrongPeer }
                } else { credentials = current }
            }
        }
        func validate() throws {
            try lock.withLock {
                guard let connection, let credentials, try policy.verifyCredentials(connection) == credentials else {
                    throw XPCPeerPolicyError.wrongPeer
                }
            }
        }
    }
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
