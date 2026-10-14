import Darwin
import Foundation
import Security

/// Local pairing setup only. This protocol carries no command decision or credential release.
@objc public protocol AuthorityPairingXPCProtocol {
    func pairingHello(reply: @escaping @Sendable (UInt64) -> Void)
    func pairingContext(reply: @escaping @Sendable (Data?) -> Void)
    func stagePairing(_ proposal: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func commitPairing(_ setupID: Data, confirmedDigest: Data, biometricProof: Data, authorization: Data,
                       reply: @escaping @Sendable (Data?) -> Void)
    func cancelPairing(reply: @escaping @Sendable (Bool) -> Void)
}

/// One signed app connection retains at most one uncommitted attempt. Disconnect discards only that attempt.
final class AuthorityPairingXPCEndpoint: NSObject, AuthorityPairingXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let access: AuthorityPairingSetupAccess
    private let budget: AuthorityXPCWorkBudget
    private let verify: () throws -> Void
    private let authorize: (Data) throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private var ready = false
    private var closed = false
    private var busy = false
    private var attempt: PairingEnrollmentAttempt?

    convenience init(connection: NSXPCConnection, policy: XPCPeerPolicy, access: AuthorityPairingSetupAccess,
                     budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void,
                     onClose: @escaping @Sendable () -> Void) throws {
        guard getuid() == 0, geteuid() == 0, policy.expectedUserID > 0 else { throw JournalLeaseError.rootRequired }
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        try access.verifyCurrent()
        self.init(access: access, budget: budget, verify: { _ = try invocation.verifyInvocation() },
            authorize: { try SetupAdministratorAuthorization.validate(externalForm: $0, invocation: invocation) },
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
    }
    // Logical endpoint controls cannot establish native administrator consent or Root identity.
    init(access: AuthorityPairingSetupAccess, budget: AuthorityXPCWorkBudget, verify: @escaping () throws -> Void,
         authorize: @escaping (Data) throws -> Void, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {}) {
        self.access = access; self.budget = budget; self.verify = verify; self.authorize = authorize
        self.invalidate = invalidate; self.onHandshake = onHandshake
    }
    func close() {
        let notify = lock.withLock {
            guard !closed else { return false }
            closed = true; ready = false; attempt = nil; return true
        }
        if notify { invalidate() }
    }
    func pairingHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try work(handshake: true) { ready = true }
            onHandshake(); send { reply(1) }
        } catch { close(); reply(0) }
    }
    func pairingContext(reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) { try access.context() }
    }
    func stagePairing(_ proposal: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            guard attempt == nil, proposal.count <= 132_000,
                  authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AuthorityPairingSetupError.unavailable }
            try authorize(authorization)
            let staged = try access.stage(proposal)
            let bytes = try staged.transcript.encode()
            attempt = staged
            return bytes
        }
    }
    func commitPairing(_ setupID: Data, confirmedDigest: Data, biometricProof: Data, authorization: Data,
                       reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            guard let pending = attempt, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                throw AuthorityPairingSetupError.unavailable
            }
            // An ambiguous commit must reconcile its durable receipt. This connection cannot blindly commit again.
            attempt = nil
            return try access.commit(pending, setupID: setupID, confirmedDigest: confirmedDigest, proof: biometricProof,
                authorize: { [authorize] in try authorize(authorization) })
        }
    }
    func cancelPairing(reply: @escaping @Sendable (Bool) -> Void) {
        do { try work { attempt = nil }; send { reply(true) } }
        catch { close(); reply(false) }
    }
    private func respond(_ reply: @escaping @Sendable (Data?) -> Void, _ body: () throws -> Data) {
        do { let bytes = try work(body); send { reply(bytes) } }
        catch { close(); reply(nil) }
    }
    private func work<T>(handshake: Bool = false, _ body: () throws -> T) throws -> T {
        // Native checks stay on the original exported invocation stack.
        try verify()
        return try lock.withLock {
            guard !closed, !busy, ready != handshake, budget.acquire() else { throw AuthorityPairingSetupError.unavailable }
            busy = true; defer { busy = false; budget.release() }
            try access.verifyCurrent()
            return try body()
        }
    }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}

/// Existing presence selectors keep version 1. Pairing has an independent version handshake on the signed app channel.
@objc public protocol AuthorityAppXPCProtocol: AuthorityPresenceXPCProtocol, AuthorityPairingXPCProtocol {}

final class AuthorityAppXPCEndpoint: NSObject, AuthorityAppXPCProtocol, @unchecked Sendable {
    let presence: AuthorityPresenceXPCEndpoint
    let pairing: AuthorityPairingXPCEndpoint
    init(presence: AuthorityPresenceXPCEndpoint, pairing: AuthorityPairingXPCEndpoint) { self.presence = presence; self.pairing = pairing }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) { presence.hello(reply: reply) }
    func current(reply: @escaping @Sendable (Data?) -> Void) { presence.current(reply: reply) }
    func publish(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { presence.publish(payload, reply: reply) }
    func setMode(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { presence.setMode(payload, reply: reply) }
    func pairingHello(reply: @escaping @Sendable (UInt64) -> Void) { pairing.pairingHello(reply: reply) }
    func pairingContext(reply: @escaping @Sendable (Data?) -> Void) { pairing.pairingContext(reply: reply) }
    func stagePairing(_ proposal: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        pairing.stagePairing(proposal, authorization: authorization, reply: reply)
    }
    func commitPairing(_ setupID: Data, confirmedDigest: Data, biometricProof: Data, authorization: Data,
                       reply: @escaping @Sendable (Data?) -> Void) {
        pairing.commitPairing(setupID, confirmedDigest: confirmedDigest, biometricProof: biometricProof, authorization: authorization, reply: reply)
    }
    func cancelPairing(reply: @escaping @Sendable (Bool) -> Void) { pairing.cancelPairing(reply: reply) }
}
