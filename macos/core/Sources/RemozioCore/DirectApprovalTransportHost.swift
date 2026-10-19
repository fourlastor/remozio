import Foundation
import Security

public enum DirectHostError: Error { case stopped, staleSession, authorityUnavailable, wrongScope }
public enum DirectHostState: Sendable, Equatable {
    case stopped, authorityUnavailable, noEligiblePhones, starting, ready(port: UInt16), failed
}

/// Identifies one authenticated channel incarnation. It grants no approval or execution authority.
public struct DirectApprovalSession: Sendable {
    public let peer: DirectApprovalPeer
    fileprivate let generation: UUID
    let revision: UUID
}

protocol OwnedDirectListener: Sendable {
    func start() throws
    func close()
    func closeAndWait() async
}
extension DirectApprovalListener: OwnedDirectListener { }

/// Runs in the dedicated transport service, never the root authority. It owns no journal or authority key.
/// The service supplies trust snapshots and validation through its authenticated, ordered authority IPC connection.
public actor DirectApprovalTransportHost {
    typealias Factory = (UUID, [DirectApprovalPeer], @escaping @Sendable (DirectListenerEvent) -> Void,
        @escaping @Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void) throws -> any OwnedDirectListener
    private let macID: Data
    private let accountID: Data
    private let factory: Factory
    private let validatePeer: @Sendable (DirectApprovalPeer, UUID) async throws -> Void
    private var handler: @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void
    private var handlerSealed = false
    private var authority: AuthorityTrustLease?
    private var trust: DirectApprovalTrust?
    private var listener: (generation: UUID, value: any OwnedDirectListener)?
    private let retiredListeners = OwnedTaskHandoffRegistry()
    private var enabled = false
    private var closed = false
    public private(set) var state: DirectHostState = .stopped

    /// The identity is transport-only. The validator must contact the protected authority; it must not use a cached allow result.
    public init(macID: Data, accountID: Data, identity: sending SecIdentity,
                binding: DirectApprovalListener.Binding = .localNetwork, maximumConnections: Int = 8,
                timeoutMilliseconds: UInt64 = 15_000,
                validatePeer: @escaping @Sendable (DirectApprovalPeer, UUID) async throws -> Void,
                handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void) throws {
        guard macID.count == 16, accountID.count == 16 else { throw DirectListenerError.invalidConfiguration }
        self.macID = macID; self.accountID = accountID
        self.validatePeer = validatePeer; self.handler = handler
        let connectionBudget = try AuthorityXPCWorkBudget(maximum: maximumConnections)
        factory = { _, peers, event, handler in
            try DirectApprovalListener(identity: identity, peers: peers, binding: binding,
                maximumConnections: maximumConnections, timeoutMilliseconds: timeoutMilliseconds,
                event: event, handler: handler, sharedWorkBudget: connectionBudget)
        }
    }

    init(macID: Data, accountID: Data, factory: sending @escaping Factory,
         validatePeer: @escaping @Sendable (DirectApprovalPeer, UUID) async throws -> Void,
         handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void = { _, _ in }) {
        self.macID = macID; self.accountID = accountID
        self.factory = factory; self.validatePeer = validatePeer; self.handler = handler
    }

    func configureHandler(_ value: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void) throws {
        guard !handlerSealed, !closed else { throw DirectHostError.stopped }
        handler = value
    }

    public func start() throws {
        handlerSealed = true
        guard !closed else { throw DirectHostError.stopped }
        enabled = true
        if listener == nil { try open() }
    }
    public func stop() { enabled = false; invalidate(); state = .stopped }
    public func close() { stop(); authority?.invalidate(); trust = nil; closed = true }
    public func closeAndWait() async { close(); await retiredListeners.waitAll() }
    deinit {
        if let listener {
            let work = retiredListeners.reserve(); listener.value.close()
            work.install(Task { await listener.value.closeAndWait() })
        }
    }

    /// Call for each authenticated trust or policy change. A snapshot is not a phone-provided message.
    /// The IPC owner must reject old connection incarnations and out-of-order updates before calling this method.
    public func replaceTrust(_ value: DirectApprovalTrust) throws {
        guard !closed else { throw DirectHostError.stopped }
        guard authority?.isActive != false else { throw DirectHostError.authorityUnavailable }
        invalidate(); trust = nil
        do {
            guard value.macID == macID, value.accountID == accountID,
                  value.peers.allSatisfy({ $0.scope.macID == macID && $0.scope.accountID == accountID }) else {
                throw DirectHostError.wrongScope
            }
            if !value.peers.isEmpty { _ = try DirectPeerSnapshot(value.peers) }
            trust = value
            if enabled { try open() }
        } catch { state = .failed; throw error }
    }

    /// Discard the snapshot on IPC loss. Reconnection needs a fresh authenticated snapshot before start can succeed.
    public func authorityDisconnected() {
        authority?.invalidate()
        invalidate(); trust = nil
        state = enabled ? .authorityUnavailable : .stopped
    }

    func beginAuthority(_ lease: AuthorityTrustLease) throws {
        guard !closed, lease.isActive else { throw DirectHostError.stopped }
        authority?.invalidate(); invalidate(); trust = nil; authority = lease
        state = enabled ? .authorityUnavailable : .stopped
    }
    func replaceTrust(_ value: DirectApprovalTrust, authority lease: AuthorityTrustLease) throws {
        guard authority === lease, lease.isActive else { throw DirectHostError.authorityUnavailable }
        try replaceTrust(value)
    }
    func authorityDisconnected(_ lease: AuthorityTrustLease) {
        guard authority === lease else { return }
        authorityDisconnected()
    }

    /// This is channel admission, not an execution permit. The root operation must recheck enrollment atomically with its own decision.
    public func validate(_ session: DirectApprovalSession) async throws {
        try requireCurrent(session)
        try await validatePeer(session.peer, session.revision)
        try Task.checkCancellation()
        try requireCurrent(session)
    }

    func admit(_ peer: DirectApprovalPeer, generation: UUID) async throws -> DirectApprovalSession {
        guard let trust, listener?.generation == generation else { throw DirectHostError.staleSession }
        let session = DirectApprovalSession(peer: peer, generation: generation, revision: trust.revision)
        try await validate(session)
        return session
    }
    private func requireCurrent(_ session: DirectApprovalSession) throws {
        guard enabled, !closed, authority?.isActive != false, listener?.generation == session.generation,
              trust?.revision == session.revision else { throw DirectHostError.staleSession }
    }
    private func open() throws {
        guard authority?.isActive != false, let trust else { state = .authorityUnavailable; throw DirectHostError.authorityUnavailable }
        guard !trust.peers.isEmpty else { state = .noEligiblePhones; return }
        do {
            let generation = UUID(), handler = handler
            let value = try factory(generation, trust.peers, { [weak self] event in
                Task { await self?.changed(event, generation: generation) }
            }, { [weak self] peer, channel in
                guard let self else { throw DirectHostError.stopped }
                let session = try await self.admit(peer, generation: generation)
                try await handler(session, channel)
            })
            listener = (generation, value); state = .starting
            try value.start()
        } catch { invalidate(); state = .failed; throw error }
    }
    func changed(_ event: DirectListenerEvent, generation: UUID) {
        guard enabled, listener?.generation == generation else { return }
        switch event {
        case .ready(let port): state = .ready(port: port)
        case .failed, .stopped: invalidate(); state = .failed
        }
    }
    private func invalidate() {
        let previous = listener; listener = nil
        if let previous {
            let work = retiredListeners.reserve(); previous.value.close()
            work.install(Task { await previous.value.closeAndWait() })
        }
    }
}
