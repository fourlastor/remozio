import Foundation
import Synchronization

enum AuthorityPairingProofWire {
    static let handoffVersion: UInt64 = 3
    static let lanHandoffVersion: UInt64 = 4
    static let bootstrapTimeout: Duration = .seconds(3)

    static func bytes(_ id: UUID) -> Data { withUnsafeBytes(of: id.uuid) { Data($0) } }

    static func identifier(_ data: Data) throws -> UUID {
        guard data.count == 16 else { throw AuthorityXPCError.invalidMessage }
        return data.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
}

/// The dedicated link negotiates before the proof exchange is available.
@objc protocol AuthorityPairingProofXPCProtocol {
    /// Each link can complete hello once. A repeated hello retires the link.
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func bindWindow(_ windowID: Data, reply: @escaping @Sendable (Bool) -> Void)
    @objc optional func bindLANWindow(_ windowID: Data, reply: @escaping @Sendable (Data?) -> Void)
    func finishBootstrap(reply: @escaping @Sendable (Bool) -> Void)
    func registerCandidate(_ connectionID: Data, acceptedAt: UInt64, peerPoint: Data, exporter: Data,
                           reply: @escaping @Sendable (Data?, Data?) -> Void)
    func verifyCandidate(_ candidateID: Data, proposal: Data, tag: Data, reply: @escaping @Sendable (Bool) -> Void)
    func confirmCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void)
    func retireCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void)
}

/// Serialize bootstrap closure against the transfer of one exact offer.
final class AuthorityPairingProofBootstrap: Sendable {
    private enum State { case open, closed, handedOff(UUID) }
    private let state = Mutex(State.open)

    var acceptsOffer: Bool {
        state.withLock { if case .open = $0 { return true }; return false }
    }

    func permits(_ offer: UUID) -> Bool {
        state.withLock {
            switch $0 {
            case .open: return true
            case .closed: return false
            case .handedOff(let id): return id == offer
            }
        }
    }

    func transferred(_ offer: UUID) -> Bool {
        state.withLock { if case .handedOff(let id) = $0 { return id == offer }; return false }
    }

    func transfer(_ offer: UUID) -> Bool {
        state.withLock {
            guard case .open = $0 else { return false }
            $0 = .handedOff(offer)
            return true
        }
    }

    func close() {
        state.withLock { if case .open = $0 { $0 = .closed } }
    }
}

/// A single Transport link outside the general Authority connection registry.
final class AuthorityPairingProofLinks: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    typealias BindReservations = @Sendable (Data, AuthorityPairingProofLink) throws -> AuthorityPairingProofReservations

    private struct Offer {
        let id: UUID
        let bootstrap: AuthorityPairingProofBootstrap
        let peer: XPCPeerCredentials
        let listener: NSXPCListener
        let expires: ContinuousClock.Instant
        let timer: Task<Void, Never>
        var connection: NSXPCConnection?
        let proofLink: AuthorityPairingProofLink
        let rendezvous: AuthorityPairingRendezvous?
        var reservations: AuthorityPairingProofReservations?
        var ready = false
        var retiring = false
        var activeWork = 0
        var retirementFinished = false
    }

    private let lock = NSRecursiveLock()
    private let policy: XPCPeerPolicy
    private let timeout: Duration
    private let verifyCurrent: @Sendable () throws -> Void
    private let bindReservations: BindReservations?
    private let validateTransport: @Sendable (JournalTransaction) throws -> Void
    private let lookupRendezvous: @Sendable (Data) -> AuthorityPairingRendezvous?
    private let configureListener: @Sendable (NSXPCListener) -> Void
    private let configureConnection: @Sendable (NSXPCConnection) -> Void
    private var slot: Offer?
    private var closed = false

    convenience init(policy: XPCPeerPolicy, timeout: Duration, verifyCurrent: @escaping @Sendable () throws -> Void,
                     bindReservations: BindReservations? = nil,
                     validateTransport: @escaping @Sendable (JournalTransaction) throws -> Void = { _ in },
                     lookupRendezvous: @escaping @Sendable (Data) -> AuthorityPairingRendezvous? = { _ in nil }) {
        self.init(policy: policy, timeout: timeout, verifyCurrent: verifyCurrent, configureListener: policy.configure,
                  configureConnection: policy.configure, bindReservations: bindReservations, validateTransport: validateTransport,
                  lookupRendezvous: lookupRendezvous)
    }

    // Native test fixtures pin their disposable test binary without using the installed Authority configuration.
    init(policy: XPCPeerPolicy, timeout: Duration, verifyCurrent: @escaping @Sendable () throws -> Void,
         configureListener: @escaping @Sendable (NSXPCListener) -> Void,
         configureConnection: @escaping @Sendable (NSXPCConnection) -> Void, bindReservations: BindReservations? = nil,
         validateTransport: @escaping @Sendable (JournalTransaction) throws -> Void = { _ in },
         lookupRendezvous: @escaping @Sendable (Data) -> AuthorityPairingRendezvous? = { _ in nil }) {
        self.policy = policy
        self.lookupRendezvous = lookupRendezvous
        self.bindReservations = bindReservations
        self.validateTransport = validateTransport
        self.timeout = timeout
        self.verifyCurrent = verifyCurrent
        self.configureListener = configureListener
        self.configureConnection = configureConnection
    }

    deinit { close() }

    func offer(bootstrap: AuthorityPairingProofBootstrap, peer: XPCPeerCredentials,
               rendezvousID: Data? = nil) throws -> NSXPCListenerEndpoint {
        let rendezvous: AuthorityPairingRendezvous?
        if let rendezvousID {
            guard rendezvousID.count == 16, let pending = lookupRendezvous(rendezvousID) else {
                throw AuthorityXPCEndpointError.unavailable
            }
            rendezvous = pending
        } else { rendezvous = nil }
        _ = try policy.credentials(processID: peer.processID, userID: peer.userID, auditSessionID: peer.auditSessionID)
        try verifyCurrent()
        clear { $0.rendezvous?.isRetired == true && !$0.bootstrap.transferred($0.id) }
        return try lock.withLock {
            guard !closed, slot == nil, bootstrap.acceptsOffer else { throw AuthorityXPCEndpointError.unavailable }
            let listener = NSXPCListener.anonymous()
            let id = UUID()
            let expires = ContinuousClock.now.advanced(by: timeout)
            if let rendezvous {
                guard bindReservations != nil, rendezvous.claim(offer: id) else { throw AuthorityXPCEndpointError.unavailable }
            }
            configureListener(listener)
            listener.delegate = self
            let timer = Task { [weak self] in
                do { try await ContinuousClock().sleep(until: expires) } catch { return }
                self?.retire(id: id, onlyPending: true)
            }
            let proofLink = AuthorityPairingProofLink(verifyPolicy: { [verifyCurrent] in
                guard bootstrap.permits(id) else { throw AuthorityXPCEndpointError.unavailable }
                try verifyCurrent()
            }, validatePolicy: { [validateTransport] transaction in
                guard bootstrap.permits(id) else { throw AuthorityXPCEndpointError.unavailable }
                try validateTransport(transaction)
            })
            slot = Offer(id: id, bootstrap: bootstrap, peer: peer, listener: listener,
                         expires: expires, timer: timer, proofLink: proofLink, rendezvous: rendezvous)
            listener.activate()
            return listener.endpoint
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard !closed, let current = slot, current.listener === listener, current.connection == nil, !current.retiring,
                  ContinuousClock.now < current.expires, current.bootstrap.permits(current.id),
                  (try? policy.verifyCredentials(connection)) == current.peer else { return false }
            let id = current.id
            let invocation = XPCInvocationGuard(connection: connection, policy: policy)
            connection.exportedInterface = NSXPCInterface(with: AuthorityPairingProofXPCProtocol.self)
            let peer = current.peer
            connection.exportedObject = Endpoint(owner: self, id: id) {
                guard try invocation.verifyInvocation() == peer else { throw XPCPeerPolicyError.wrongPeer }
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
            guard !closed, let current = slot, current.id == id, !current.ready, !current.retiring, current.bootstrap.permits(current.id),
                  ContinuousClock.now < current.expires else { throw AuthorityXPCEndpointError.unavailable }
            if let rendezvous = current.rendezvous {
                guard rendezvous.acceptHello(offer: id, link: current.proofLink, offerDeadline: current.expires) else { throw AuthorityXPCEndpointError.unavailable }
            }
            slot?.ready = true
            if bindReservations == nil { current.timer.cancel() }
            if current.rendezvous?.lanScope != nil { reply(AuthorityPairingProofWire.lanHandoffVersion) }
            else { reply(bindReservations == nil ? 1 : AuthorityPairingProofWire.handoffVersion) }
        }
    }

    private func perform<Value>(id: UUID, binding: Bool = false, _ operation: (Offer) throws -> Value) throws -> Value {
        let current = try lock.withLock {
            guard !closed, let current = slot, current.id == id, current.ready, !current.retiring,
                  current.bootstrap.permits(current.id), current.activeWork < 8,
                  binding ? current.reservations == nil && current.activeWork == 0 && ContinuousClock.now < current.expires
                          : current.reservations != nil && current.bootstrap.transferred(id) else {
                throw AuthorityXPCEndpointError.unavailable
            }
            slot?.activeWork += 1
            return current
        }
        defer {
            lock.withLock {
                if slot?.id == id {
                    slot?.activeWork -= 1
                    if slot?.retirementFinished == true, slot?.activeWork == 0 { slot = nil }
                }
            }
        }
        try current.proofLink.verifyCurrent()
        let result = try operation(current)
        try current.proofLink.requireActive()
        return result
    }

    private func bindWindow(id: UUID, windowID: Data, wantsLAN: Bool) throws -> Data? {
        try perform(id: id, binding: true) { current in
            let scope = current.rendezvous?.lanScope
            guard wantsLAN == (scope != nil), let bindReservations,
                  current.rendezvous?.permitsBinding(link: current.proofLink) != false else {
                throw AuthorityXPCEndpointError.unavailable
            }
            let reservations = try bindReservations(windowID, current.proofLink)
            let retained = lock.withLock {
                guard slot?.id == id, slot?.retiring == false else { return false }
                slot?.reservations = reservations
                return true
            }
            guard retained else {
                reservations.retire()
                throw AuthorityXPCEndpointError.unavailable
            }
            if let scope, let rendezvous = current.rendezvous {
                return try PairingLANBinding(windowID: windowID, revision: rendezvous.revision,
                    scope: scope, expiresAtMilliseconds: reservations.windowDeadline).encode()
            }
            return nil
        }
    }

    private func finishBootstrap(id: UUID) throws {
        try verifyCurrent()
        try lock.withLock {
            guard !closed, let current = slot, current.id == id, current.ready, !current.retiring,
                  current.reservations != nil, current.activeWork == 0, ContinuousClock.now < current.expires,
                  current.rendezvous?.permitsBinding(link: current.proofLink) != false,
                  current.bootstrap.transfer(id) else { throw AuthorityXPCEndpointError.unavailable }
            current.timer.cancel()
        }
    }

    private func withReservations<Value>(id: UUID, _ operation: (AuthorityPairingProofReservations) throws -> Value) throws -> Value {
        try perform(id: id) { current in
            guard let reservations = current.reservations else { throw AuthorityXPCEndpointError.unavailable }
            return try reservations.withXPCWork { try operation(reservations) }
        }
    }

    private func retireCandidate(id: UUID, candidate: Data) throws {
        try perform(id: id) { current in
            guard let reservations = current.reservations else { throw AuthorityXPCEndpointError.unavailable }
            reservations.retire(candidate: try AuthorityPairingProofWire.identifier(candidate))
        }
    }

    func retire(bootstrap: AuthorityPairingProofBootstrap) {
        bootstrap.close()
        clear { $0.bootstrap === bootstrap && !bootstrap.transferred($0.id) }
    }

    private func retire(id: UUID, onlyPending: Bool = false) {
        clear { offer in
            guard offer.id == id else { return false }
            if !onlyPending { return true }
            return bindReservations == nil ? !offer.ready : !offer.bootstrap.transferred(id)
        }
    }

    func close() {
        lock.withLock { closed = true }
        clear { _ in true }
    }

    private func clear(_ matches: (Offer) -> Bool) {
        let retired = lock.withLock { () -> Offer? in
            guard let current = slot, !current.retiring, matches(current) else { return nil }
            current.rendezvous?.retire()
            slot?.retiring = true
            current.timer.cancel()
            return current
        }
        guard let retired else { return }
        retired.proofLink.retire()
        retired.listener.invalidate()
        retired.connection?.invalidate()
        retired.reservations?.retire()
        lock.withLock {
            if slot?.id == retired.id {
                slot?.retirementFinished = true
                if slot?.activeWork == 0 { slot = nil }
            }
        }
    }

    private final class Endpoint: NSObject, AuthorityPairingProofXPCProtocol {
        private weak var owner: AuthorityPairingProofLinks?
        private let id: UUID
        private let verifyInvocation: () throws -> Void

        init(owner: AuthorityPairingProofLinks, id: UUID, verifyInvocation: @escaping () throws -> Void) {
            self.owner = owner; self.id = id; self.verifyInvocation = verifyInvocation
        }

        private func checkedOwner() throws -> AuthorityPairingProofLinks {
            guard let owner else { throw AuthorityXPCEndpointError.unavailable }
            do { try verifyInvocation(); return owner }
            catch { owner.retire(id: id); throw error }
        }

        func hello(reply: @escaping @Sendable (UInt64) -> Void) {
            do { try checkedOwner().acceptHello(id: id, reply: reply) }
            catch { reply(0); owner?.retire(id: id) }
        }

        func bindWindow(_ windowID: Data, reply: @escaping @Sendable (Bool) -> Void) {
            do { _ = try checkedOwner().bindWindow(id: id, windowID: windowID, wantsLAN: false); reply(true) }
            catch { reply(false); owner?.retire(id: id) }
        }

        func bindLANWindow(_ windowID: Data, reply: @escaping @Sendable (Data?) -> Void) {
            do { reply(try checkedOwner().bindWindow(id: id, windowID: windowID, wantsLAN: true)) }
            catch { reply(nil); owner?.retire(id: id) }
        }

        func finishBootstrap(reply: @escaping @Sendable (Bool) -> Void) {
            do { try checkedOwner().finishBootstrap(id: id); reply(true) }
            catch { reply(false) }
        }

        func registerCandidate(_ connectionID: Data, acceptedAt: UInt64, peerPoint: Data, exporter: Data,
                               reply: @escaping @Sendable (Data?, Data?) -> Void) {
            do {
                let candidate = try checkedOwner().withReservations(id: id) {
                    try $0.register(connection: AuthorityPairingProofWire.identifier(connectionID), acceptedAt: acceptedAt,
                                    peerPoint: peerPoint, exporter: exporter)
                }
                reply(AuthorityPairingProofWire.bytes(candidate.id), candidate.challenge)
            } catch { reply(nil, nil) }
        }

        func verifyCandidate(_ candidateID: Data, proposal: Data, tag: Data, reply: @escaping @Sendable (Bool) -> Void) {
            do {
                try checkedOwner().withReservations(id: id) {
                    try $0.verify(candidate: AuthorityPairingProofWire.identifier(candidateID), proposalBytes: proposal, tag: tag)
                }
                reply(true)
            } catch { reply(false) }
        }

        func confirmCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) {
            do {
                try checkedOwner().withReservations(id: id) {
                    try $0.confirm(candidate: AuthorityPairingProofWire.identifier(candidateID))
                }
                reply(true)
            } catch { reply(false) }
        }

        func retireCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) {
            do {
                try checkedOwner().retireCandidate(id: id, candidate: candidateID)
                reply(true)
            } catch { reply(false) }
        }
    }
}
