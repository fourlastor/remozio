import Darwin
import Foundation

/// Same accepted connection and cached credentials only. No peer liveness, fresh code approval or native authority.
/// The connection's code requirement protects messages. Worker retirement follows its asynchronous handler execution.
final class SetupRetainedInvocationContext: @unchecked Sendable {
    struct Scope {
        fileprivate let check: (NSXPCConnection?) throws -> Void
        func verify() throws { try check(nil) }
        func requireConnection(_ connection: NSXPCConnection) throws { try check(connection) }
    }
    private let process = getpid()
    private var connection: NSXPCConnection?
    private var verifyConnection: (() throws -> Void)?
    private weak var owner: SetupRetainedInvocation?
    private let lock = NSLock()
    private var active = false, used = false, retired = false
    private var thread: pthread_t?
    private init(owner: SetupRetainedInvocation, connection: NSXPCConnection, verify: @escaping () throws -> Void) {
        self.owner = owner; self.connection = connection; verifyConnection = verify
    }
    static func open(owner: SetupRetainedInvocation, invocation: XPCInvocationGuard) throws -> SetupRetainedInvocationContext {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try invocation.withRetainedConnection { connection, policy, peer in
            guard owner.peer == peer, owner.incarnation == invocation.incarnation,
                  owner.acceptedPolicy.requirement == policy.requirement,
                  owner.acceptedPolicy.expectedUserID == policy.expectedUserID,
                  owner.acceptedPolicy.expectedAuditSessionID == policy.expectedAuditSessionID else { throw XPCPeerPolicyError.wrongPeer }
            try owner.validateLifetime()
            return .init(owner: owner, connection: connection, verify: {
                try invocation.requireRetainedConnection(connection, peer: peer, policy: policy)
            })
        }
    }
    /// Ordinary-owner controls test lifetime and identity only. Root cannot create a context through this factory.
    static func openOwned(owner: SetupRetainedInvocation, connection: NSXPCConnection,
        readPeer: @escaping (NSXPCConnection) throws -> XPCPeerCredentials) throws -> SetupRetainedInvocationContext {
        try RuntimeMaintenanceOwnedControl.require(); try owner.validateLifetime()
        let peer = try readPeer(connection)
        guard peer == owner.peer else { throw XPCPeerPolicyError.wrongPeer }
        return .init(owner: owner, connection: connection, verify: {
            guard try readPeer(connection) == peer else { throw XPCPeerPolicyError.wrongPeer }
        })
    }
    /// The reservation owner calls this once from its synchronous worker. The loan fixes that worker's thread.
    func withWorker<Value>(_ body: (Scope) throws -> Value) throws -> Value {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !active, !used, !retired else { retired = true; throw JournalLeaseError.invalidated }
            used = true; active = true; thread = pthread_self()
        }
        defer { retire() }
        try check(nil); let scope = Scope(check: check)
        let result = try body(scope); try check(nil); return result
    }
    private func check(_ actual: NSXPCConnection?) throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        do {
            let verify = try lock.withLock {
                guard active, !retired, let thread, pthread_equal(thread, pthread_self()) != 0,
                      let connection, actual == nil || actual === connection,
                      let verifyConnection else { throw JournalLeaseError.invalidated }
                return verifyConnection
            }
            guard let owner else { throw JournalLeaseError.invalidated }
            try owner.validateContextLifetime(self); try verify()
            try lock.withLock { guard active, !retired else { throw JournalLeaseError.invalidated } }
        } catch { retire(); throw error }
    }
    func retire() {
        guard getpid() == process else { return }
        lock.withLock { active = false; retired = true; connection = nil; verifyConnection = nil }
    }
}
