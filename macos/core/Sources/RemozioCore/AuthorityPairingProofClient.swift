import Foundation

/// A native proof link. Registration and unproved cleanup can expire independently of the link.
final class AuthorityPairingProofClient: @unchecked Sendable {
    private enum Reply: Sendable {
        case version(UInt64)
        case allowed(Bool)
        case challenge(Data?, Data?)
    }

    private struct State {
        var closed = false
        var ready = false
        var pending: [UUID: AsyncStream<Reply>.Continuation] = [:]
    }

    private let connection: NSXPCConnection
    private let peerPolicy: XPCPeerPolicy
    private let onClose: @Sendable () -> Void
    private let lock = NSLock()
    private var state = State()

    init(endpoint: NSXPCListenerEndpoint, peerPolicy: XPCPeerPolicy, onClose: @escaping @Sendable () -> Void,
         configure: (NSXPCConnection) -> Void) {
        self.peerPolicy = peerPolicy; self.onClose = onClose
        connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: AuthorityPairingProofXPCProtocol.self)
        configure(connection)
    }

    struct Bootstrap {
        let channel: AuthorityXPCChannel
        let policy: XPCPeerPolicy
        let configure: @Sendable (NSXPCConnection) -> Void
    }

    static func open(configuration: ApprovalTransportConfiguration, windowID: Data,
                     onClose: @escaping @Sendable () -> Void) async throws -> AuthorityPairingProofClient {
        try await open(configuration: configuration, windowID: windowID, onClose: onClose) { supplied, ended in
            let policy = supplied.authorityPolicy
            return try Bootstrap(channel: AuthorityXPCChannel(serviceName: supplied.authorityServiceName,
                peerPolicy: policy, onClose: ended), policy: policy, configure: policy.configure)
        }
    }

    static func open(configuration: ApprovalTransportConfiguration, windowID: Data, onClose: @escaping @Sendable () -> Void,
                     bootstrap makeBootstrap: (ApprovalTransportConfiguration, @escaping @Sendable () -> Void) throws -> Bootstrap)
        async throws -> AuthorityPairingProofClient {
        guard windowID.count == 16 else { throw AuthorityXPCError.invalidMessage }
        let peer = try makeBootstrap(configuration, onClose)
        let bootstrap = peer.channel
        do {
            try await bootstrap.start()
            guard let endpoint = try await bootstrap.openPairingProof() else { throw AuthorityXPCError.failed }
            let client = AuthorityPairingProofClient(endpoint: endpoint, peerPolicy: peer.policy, onClose: {
                Task { await bootstrap.close() }
                onClose()
            }, configure: peer.configure)
            try await client.start(windowID: windowID)
            return client
        } catch {
            await bootstrap.close()
            throw error
        }
    }

    deinit { close() }

    func start(windowID: Data) async throws {
        guard windowID.count == 16 else { throw AuthorityXPCError.invalidMessage }
        let ended: @Sendable () -> Void = { [weak self] in self?.close() }
        connection.interruptionHandler = ended
        connection.invalidationHandler = ended
        connection.activate()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        guard case .version(2) = try await call(deadline: deadline, hello: true, send: { proxy, reply in
            proxy.hello { reply(.version($0)) }
        }) else { close(); throw AuthorityXPCError.failed }
        try lock.withLock {
            guard !state.closed else { throw AuthorityXPCError.closed }
            state.ready = true
        }
        guard case .allowed(true) = try await call(deadline: deadline, send: { proxy, reply in
            proxy.bindWindow(windowID) { reply(.allowed($0)) }
        }) else { close(); throw AuthorityXPCError.failed }
    }

    func register(connectionID: UUID, acceptedAt: UInt64, peerPoint: Data, exporter: Data,
                  deadline: ContinuousClock.Instant) async throws -> AuthorityPairingProofReservations.Candidate {
        let reply = try await call(deadline: deadline, candidateOnly: true) { proxy, reply in
            proxy.registerCandidate(AuthorityPairingProofWire.bytes(connectionID), acceptedAt: acceptedAt,
                peerPoint: peerPoint, exporter: exporter) { reply(.challenge($0, $1)) }
        }
        guard case let .challenge(id?, challenge?) = reply, challenge.count == 32 else {
            throw AuthorityXPCError.failed
        }
        return try .init(id: AuthorityPairingProofWire.identifier(id), challenge: challenge)
    }

    func verify(candidate: UUID, proposal: Data, tag: Data, deadline: ContinuousClock.Instant) async throws {
        let reply: Reply
        do {
            reply = try await call(deadline: deadline, candidateOnly: true) { proxy, reply in
                proxy.verifyCandidate(AuthorityPairingProofWire.bytes(candidate), proposal: proposal, tag: tag) { reply(.allowed($0)) }
            }
        } catch {
            // Authority may have accepted the proof before its reply became unavailable.
            await retire(candidate: candidate, requiresAcknowledgement: true)
            throw error
        }
        guard case .allowed(true) = reply else { throw AuthorityXPCError.failed }
    }

    func confirm(candidate: UUID, deadline: ContinuousClock.Instant) async throws {
        do {
            guard case .allowed(true) = try await call(deadline: deadline, send: { proxy, reply in
                proxy.confirmCandidate(AuthorityPairingProofWire.bytes(candidate)) { reply(.allowed($0)) }
            }) else { throw AuthorityXPCError.failed }
        } catch {
            close()
            throw error
        }
    }

    func retire(candidate: UUID, requiresAcknowledgement: Bool) async {
        let cleanup = Task {
            try await call(deadline: ContinuousClock.now.advanced(by: .seconds(1)), candidateOnly: !requiresAcknowledgement) { proxy, reply in
                proxy.retireCandidate(AuthorityPairingProofWire.bytes(candidate)) { reply(.allowed($0)) }
            }
        }
        guard case .some(.allowed(true)) = try? await cleanup.value else {
            if requiresAcknowledgement { close() }
            return
        }
    }

    func close() {
        let pending = lock.withLock {
            () -> [AsyncStream<Reply>.Continuation]? in
            guard !state.closed else { return nil }
            state.closed = true
            let values = Array(state.pending.values)
            state.pending.removeAll()
            return values
        }
        guard let pending else { return }
        for continuation in pending { continuation.finish() }
        connection.invalidate()
        onClose()
    }

    private func call(deadline: ContinuousClock.Instant, hello: Bool = false, candidateOnly: Bool = false,
                      send: (any AuthorityPairingProofXPCProtocol, @escaping @Sendable (Reply) -> Void) -> Void) async throws -> Reply {
        let id = UUID(), exchange = AsyncStream<Reply>.makeStream(bufferingPolicy: .bufferingNewest(1))
        try Task.checkCancellation()
        guard ContinuousClock.now < deadline else { throw AuthorityXPCError.timedOut }
        try lock.withLock {
            guard !state.closed, state.ready != hello, state.pending.count < 8 else { throw AuthorityXPCError.failed }
            state.pending[id] = exchange.continuation
        }
        let reply = await withTaskCancellationHandler {
            let timer = Task { [weak self] in
                do { try await ContinuousClock().sleep(until: deadline) } catch { return }
                self?.removePending(id)?.finish()
            }
            defer { timer.cancel() }
            if lock.withLock({ state.pending[id] != nil }) {
                if let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self] _ in self?.close() })
                               as? any AuthorityPairingProofXPCProtocol {
                    send(proxy) { [weak self] in self?.receive(id: id, reply: $0) }
                } else { close() }
            }
            var replies = exchange.stream.makeAsyncIterator()
            return await replies.next()
        } onCancel: { self.removePending(id)?.finish() }
        defer { removePending(id)?.finish() }
        do {
            try Task.checkCancellation()
            guard lock.withLock({ !state.closed }) else { throw AuthorityXPCError.closed }
            guard let reply, ContinuousClock.now < deadline else { throw AuthorityXPCError.timedOut }
            return reply
        } catch {
            if !candidateOnly { close() }
            throw error
        }
    }

    private func removePending(_ id: UUID) -> AsyncStream<Reply>.Continuation? {
        lock.withLock { state.pending.removeValue(forKey: id) }
    }

    private func receive(id: UUID, reply: Reply) {
        guard let continuation = removePending(id) else { return }
        defer { continuation.finish() }
        guard (try? peerPolicy.verifyCredentials(connection)) != nil else { close(); return }
        continuation.yield(reply)
    }
}
