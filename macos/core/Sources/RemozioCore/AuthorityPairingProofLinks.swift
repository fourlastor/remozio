import Foundation

/// The dedicated link negotiates before the proof exchange is available.
@objc protocol AuthorityPairingProofXPCProtocol {
    /// Each link can complete hello once. A repeated hello retires the link.
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
}

/// A single Transport link outside the general Authority connection registry.
final class AuthorityPairingProofLinks: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private struct Offer {
        let id: UUID
        let bootstrap: UUID
        let peer: XPCPeerCredentials
        let parentActive: @Sendable () -> Bool
        let listener: NSXPCListener
        let expires: ContinuousClock.Instant
        let timer: Task<Void, Never>
        var connection: NSXPCConnection?
        var ready = false
        var retiring = false
    }

    private let lock = NSRecursiveLock()
    private let policy: XPCPeerPolicy
    private let timeout: Duration
    private let verifyCurrent: @Sendable () throws -> Void
    private let configureListener: @Sendable (NSXPCListener) -> Void
    private let configureConnection: @Sendable (NSXPCConnection) -> Void
    private var slot: Offer?
    private var closed = false

    convenience init(policy: XPCPeerPolicy, timeout: Duration, verifyCurrent: @escaping @Sendable () throws -> Void) {
        self.init(policy: policy, timeout: timeout, verifyCurrent: verifyCurrent, configureListener: policy.configure,
                  configureConnection: policy.configure)
    }

    // Native test fixtures pin their disposable test binary without using the installed Authority configuration.
    init(policy: XPCPeerPolicy, timeout: Duration, verifyCurrent: @escaping @Sendable () throws -> Void,
         configureListener: @escaping @Sendable (NSXPCListener) -> Void,
         configureConnection: @escaping @Sendable (NSXPCConnection) -> Void) {
        self.policy = policy
        self.timeout = timeout
        self.verifyCurrent = verifyCurrent
        self.configureListener = configureListener
        self.configureConnection = configureConnection
    }

    deinit { close() }

    func offer(bootstrap: UUID, peer: XPCPeerCredentials,
               parentActive: @escaping @Sendable () -> Bool) throws -> NSXPCListenerEndpoint {
        _ = try policy.credentials(processID: peer.processID, userID: peer.userID, auditSessionID: peer.auditSessionID)
        try verifyCurrent()
        return try lock.withLock {
            guard !closed, slot == nil, parentActive() else { throw AuthorityXPCEndpointError.unavailable }
            let listener = NSXPCListener.anonymous()
            let id = UUID(), expires = ContinuousClock.now.advanced(by: timeout)
            configureListener(listener)
            listener.delegate = self
            let timer = Task { [weak self] in
                do { try await ContinuousClock().sleep(until: expires) } catch { return }
                self?.retire(id: id, onlyPending: true)
            }
            slot = Offer(id: id, bootstrap: bootstrap, peer: peer, parentActive: parentActive, listener: listener,
                         expires: expires, timer: timer)
            listener.activate()
            return listener.endpoint
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard !closed, let current = slot, current.listener === listener, current.connection == nil, !current.retiring,
                  ContinuousClock.now < current.expires, current.parentActive(),
                  (try? policy.verifyCredentials(connection)) == current.peer else { return false }
            let id = current.id
            let invocation = XPCInvocationGuard(connection: connection, policy: policy)
            connection.exportedInterface = NSXPCInterface(with: AuthorityPairingProofXPCProtocol.self)
            let peer = current.peer
            connection.exportedObject = Endpoint { [weak self] reply in
                guard let self else { reply(0); return }
                do {
                    guard try invocation.verifyInvocation() == peer else { throw XPCPeerPolicyError.wrongPeer }
                    try self.acceptHello(id: id, reply: reply)
                } catch {
                    reply(0)
                    self.retire(id: id)
                }
            }
            configureConnection(connection)
            let ended: @Sendable () -> Void = { [weak self] in self?.retire(id: id) }
            connection.interruptionHandler = ended
            connection.invalidationHandler = ended
            slot?.connection = connection
            connection.activate()
            // Invalidating this listener would also disconnect its accepted client.
            // Keeping the connection in the slot permanently closes this offer to other clients.
            return true
        }
    }

    private func acceptHello(id: UUID, reply: @Sendable (UInt64) -> Void) throws {
        try verifyCurrent()
        try lock.withLock {
            guard !closed, let current = slot, current.id == id, !current.ready, !current.retiring, current.parentActive(),
                  ContinuousClock.now < current.expires else { throw AuthorityXPCEndpointError.unavailable }
            slot?.ready = true
            current.timer.cancel()
            reply(1)
        }
    }

    func retire(bootstrap: UUID) {
        clear { $0.bootstrap == bootstrap }
    }

    private func retire(id: UUID, onlyPending: Bool = false) {
        clear { $0.id == id && (!onlyPending || !$0.ready) }
    }

    func close() {
        lock.withLock { closed = true }
        clear { _ in true }
    }

    private func clear(_ matches: (Offer) -> Bool) {
        let retired = lock.withLock { () -> Offer? in
            guard let current = slot, !current.retiring, matches(current) else { return nil }
            slot?.retiring = true
            current.timer.cancel()
            return current
        }
        guard let retired else { return }
        retired.listener.invalidate()
        retired.connection?.invalidate()
        lock.withLock { if slot?.id == retired.id { slot = nil } }
    }

    private final class Endpoint: NSObject, AuthorityPairingProofXPCProtocol {
        let sendHello: (@Sendable (UInt64) -> Void) -> Void
        init(sendHello: @escaping (@Sendable (UInt64) -> Void) -> Void) { self.sendHello = sendHello }
        func hello(reply: @escaping @Sendable (UInt64) -> Void) { sendHello(reply) }
    }
}
