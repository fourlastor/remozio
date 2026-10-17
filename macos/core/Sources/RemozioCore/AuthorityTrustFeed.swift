import Foundation
import RemozioProtocol

/// Invalidation is synchronous, including while actor callbacks are waiting to run.
final class AuthorityTrustLease: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true
    var isActive: Bool { lock.withLock { active } }
    func invalidate() { lock.withLock { active = false } }
}

/// One authenticated authority incarnation, owned by the dedicated transport service.
/// Keep the host alive separately. Reconnection uses a new feed and a fresh handshake.
public actor AuthorityTrustFeed {
    typealias Factory = @Sendable (@escaping @Sendable () -> Void) throws -> AuthorityXPCChannel
    private let macID: Data
    private let accountID: Data
    private let factory: Factory
    private let refreshMilliseconds: UInt64
    private let maximumWaiting: Int
    private let lease = AuthorityTrustLease()
    private weak var host: DirectApprovalTransportHost?
    private var channel: AuthorityXPCChannel?
    private var recoveryLink: (id: UUID, channel: AuthorityXPCChannel)?
    private var registrationLink: (id: UUID, channel: AuthorityXPCChannel)?
    private var timer: Task<Void, Never>?
    private var lastSnapshot: Data?
    private var started = false
    private var ready = false
    private var closed = false
    private var busy = false
    private var refreshDue = false
    private var scheduledRefresh = false
    var waitingOperationCount: Int { waiters.count }
    private var waiters: [(UUID, CheckedContinuation<Void, Error>)] = []

    public init(serviceName: String, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                timeoutMilliseconds: UInt64 = 5000, refreshMilliseconds: UInt64 = 5000,
                maximumWaiting: Int = 8) throws {
        guard macID.count == 16, accountID.count == 16, (500...60_000).contains(refreshMilliseconds),
              (0...64).contains(maximumWaiting) else { throw AuthorityXPCError.invalidConfiguration }
        self.macID = macID; self.accountID = accountID
        self.refreshMilliseconds = refreshMilliseconds; self.maximumWaiting = maximumWaiting
        factory = { onClose in try AuthorityXPCChannel(serviceName: serviceName, peerPolicy: peerPolicy,
            timeoutMilliseconds: timeoutMilliseconds, onClose: onClose) }
    }
    init(macID: Data, accountID: Data, refreshMilliseconds: UInt64 = 60_000, maximumWaiting: Int = 8,
         factory: @escaping Factory) {
        self.macID = macID; self.accountID = accountID; self.refreshMilliseconds = refreshMilliseconds
        self.maximumWaiting = maximumWaiting; self.factory = factory
    }
    deinit {
        lease.invalidate(); timer?.cancel(); channel?.abort(); registrationLink?.channel.abort(); recoveryLink?.channel.abort()
        let host = host, lease = lease
        Task { await host?.authorityDisconnected(lease) }
    }

    public func start(host: DirectApprovalTransportHost) async throws {
        guard !started, !closed else { throw AuthorityXPCError.invalidState }
        started = true; busy = true; self.host = host
        defer { release() }
        do {
            try await host.beginAuthority(lease)
            try requireActive()
            let value = try factory { [weak self, lease] in
                lease.invalidate()
                Task { await self?.close() }
            }
            channel = value
            try await value.start()
            try await update(value)
            try requireActive(); ready = true
            timer = Task { [weak self, refreshMilliseconds] in
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .milliseconds(Int64(refreshMilliseconds))) } catch { return }
                    guard let self else { return }
                    await self.scheduleRefresh()
                }
            }
        } catch { await close(); throw error }
    }
    func scheduleRefresh() {
        guard ready, !closed, !scheduledRefresh else { return }
        refreshDue = true
        if !busy { busy = true; release() }
    }
    private func runScheduledRefresh() async {
        defer { scheduledRefresh = false; release() }
        do { try await update(try activeChannel()) }
        catch { await close() }
    }
    public func refresh() async throws {
        try await acquire()
        defer { release() }
        do { try await update(try activeChannel()) }
        catch { await close(); throw error }
    }
    /// Every call reaches the authority. A previous allow result is never cached.
    public func validatePeer(_ peer: DirectApprovalPeer, revision: UUID) async throws {
        try await acquire()
        defer { release() }
        let allowed: Bool
        do {
            allowed = try await activeChannel().validatePeer(AuthorityPeerBinding(peer: peer, revision: revision))
            try requireActive()
        } catch { await close(); throw error }
        guard allowed else { throw DirectHostError.staleSession }
    }
    /// Fetch through the same ordered authority connection as trust refreshes and peer validation.
    /// The root rechecks the binding atomically with request access. Absence is not a terminal status.
    public func requestFrame(_ peer: DirectApprovalPeer, revision: UUID, requestID: Data) async throws -> Data? {
        guard peer.scope.macID == macID, peer.scope.accountID == accountID, requestID.count == 16 else {
            throw AuthorityXPCError.invalidMessage
        }
        try await acquire()
        defer { release() }
        do {
            let frame = try await activeChannel().requestFrame(binding: AuthorityPeerBinding(peer: peer, revision: revision),
                requestID: requestID)
            try requireActive()
            return frame
        } catch AuthorityXPCError.unsupportedRequestDelivery {
            try requireActive()
            throw AuthorityXPCError.unsupportedRequestDelivery
        } catch { await close(); throw error }
    }
    /// Discover through the ordered authority connection. IDs are hints, never terminal request statuses.
    public func pendingRequestIDs(_ peer: DirectApprovalPeer, revision: UUID) async throws -> [Data] {
        guard peer.scope.macID == macID, peer.scope.accountID == accountID else { throw AuthorityXPCError.invalidMessage }
        try await acquire()
        defer { release() }
        do {
            let ids = try await activeChannel().pendingRequestIDs(binding: AuthorityPeerBinding(peer: peer, revision: revision))
            try requireActive()
            return ids
        } catch AuthorityXPCError.unsupportedRequestDiscovery {
            try requireActive()
            throw AuthorityXPCError.unsupportedRequestDiscovery
        } catch { await close(); throw error }
    }
    func supportsRequestExchange() async throws -> Bool {
        try await acquire()
        defer { release() }
        do {
            let supported = try await activeChannel().supportsRequestExchange()
            try requireActive()
            return supported
        } catch { await close(); throw error }
    }
    /// Status and signed decisions share the ordered authority connection. No decision is retried after an uncertain reply.
    public func exchangeRequest(_ peer: DirectApprovalPeer, revision: UUID, requestID: Data, decisionFrame: Data? = nil) async throws -> Data? {
        guard peer.scope.macID == macID, peer.scope.accountID == accountID else { throw AuthorityXPCError.invalidMessage }
        _ = try AuthorityRequestExchange.encode(requestID: requestID, decisionFrame: decisionFrame)
        try await acquire()
        defer { release() }
        do {
            let status = try await activeChannel().exchangeRequest(binding: AuthorityPeerBinding(peer: peer, revision: revision),
                requestID: requestID, decisionFrame: decisionFrame)
            try requireActive()
            return status
        } catch AuthorityXPCError.unsupportedRequestExchange {
            try requireActive()
            throw AuthorityXPCError.unsupportedRequestExchange
        } catch { await close(); throw error }
    }
    /// Receipt recovery shares the same ordered authority connection and current trust revision.
    public func pairingReceipt(_ peer: DirectApprovalPeer, revision: UUID, setupID: Data) async throws -> Data? {
        guard peer.scope.macID == macID, peer.scope.accountID == accountID, setupID.count == 16 else {
            throw AuthorityXPCError.invalidMessage
        }
        try await acquire()
        defer { release() }
        do {
            let receipt = try await activeChannel().pairingReceipt(binding: AuthorityPeerBinding(peer: peer, revision: revision), setupID: setupID)
            try requireActive()
            return receipt
        } catch AuthorityXPCError.unsupportedPairingReceipt {
            try requireActive()
            throw AuthorityXPCError.unsupportedPairingReceipt
        } catch { await close(); throw error }
    }
    /// The transport performs this harmless preflight before accepting private recovery fields.
    public func requirePhonePushRecoverySupport() async throws {
        try await acquire(); defer { release() }
        let link = try await openRecoveryLink()
        do {
            try await link.channel.requirePhonePushRecoverySupport()
            try requireActive()
            guard recoveryLink?.id == link.id, link.channel.lifetimeActive else { throw AuthorityXPCError.closed }
        } catch AuthorityXPCError.unsupportedPhonePushRecovery {
            try requireActive(); throw AuthorityXPCError.unsupportedPhonePushRecovery
        } catch { retireRecoveryLink(link.id); try requireActive(); throw error }
    }
    public func phonePushRecovery(_ peer: DirectApprovalPeer, revision: UUID,
                                  frame: PhonePushRecoveryFrame) async throws -> PhonePushRecoveryFrame {
        guard peer.scope.macID == macID, peer.scope.accountID == accountID else { throw AuthorityXPCError.invalidMessage }
        let binding = AuthorityPeerBinding(peer: peer, revision: revision)
        try AuthorityPhonePushRecoveryExchange.request(frame, binding: binding)
        try await acquire(); defer { release() }
        let link = try await openRecoveryLink()
        do {
            let response = try await link.channel.phonePushRecovery(binding: binding, frame: frame)
            try requireActive()
            guard recoveryLink?.id == link.id, link.channel.lifetimeActive else { throw AuthorityXPCError.closed }
            return response
        } catch AuthorityXPCError.unsupportedPhonePushRecovery {
            try requireActive(); throw AuthorityXPCError.unsupportedPhonePushRecovery
        } catch { retireRecoveryLink(link.id); try requireActive(); throw error }
    }
    private func openRecoveryLink() async throws -> (id: UUID, channel: AuthorityXPCChannel) {
        try requireActive()
        if let recoveryLink { return recoveryLink }
        let id = UUID()
        let value = try factory { [weak self] in Task { await self?.retireRecoveryLink(id) } }
        recoveryLink = (id, value)
        do {
            try await value.start(); try requireActive()
            guard recoveryLink?.id == id, value.lifetimeActive else { throw AuthorityXPCError.closed }
            return (id, value)
        } catch { retireRecoveryLink(id); throw error }
    }
    private func retireRecoveryLink(_ id: UUID) {
        guard recoveryLink?.id == id else { return }
        let value = recoveryLink?.channel; recoveryLink = nil; value?.abort()
    }

    /// Serialize optional registration with this authority lease, using a separate RPC connection.
    /// An older Root can reject the optional selector without retiring ordinary approval delivery.
    public func phonePushRegistration(_ peer: DirectApprovalPeer, revision: UUID,
                                      frame: PhonePushRegistrationFrame) async throws -> PhonePushRegistrationFrame {
        guard peer.scope.macID == macID, peer.scope.accountID == accountID else { throw AuthorityXPCError.invalidMessage }
        let binding = AuthorityPeerBinding(peer: peer, revision: revision)
        try AuthorityPhonePushExchange.request(frame, binding: binding)
        try await acquire()
        defer { release() }
        let link = try await openRegistrationLink()
        do {
            let response = try await link.channel.phonePushRegistration(binding: binding, frame: frame)
            try requireActive()
            guard registrationLink?.id == link.id else { throw AuthorityXPCError.closed }
            return response
        } catch AuthorityXPCError.unsupportedPhonePushRegistration {
            try requireActive()
            throw AuthorityXPCError.unsupportedPhonePushRegistration
        } catch {
            retireRegistrationLink(link.id)
            try requireActive()
            throw error
        }
    }
    private func openRegistrationLink() async throws -> (id: UUID, channel: AuthorityXPCChannel) {
        try requireActive()
        if let registrationLink { return registrationLink }
        let id = UUID()
        let value = try factory { [weak self] in Task { await self?.retireRegistrationLink(id) } }
        registrationLink = (id, value)
        do {
            try await value.start()
            try requireActive()
            guard registrationLink?.id == id else { throw AuthorityXPCError.closed }
            return (id, value)
        } catch { retireRegistrationLink(id); throw error }
    }
    private func retireRegistrationLink(_ id: UUID) {
        guard registrationLink?.id == id else { return }
        let value = registrationLink?.channel; registrationLink = nil
        value?.abort()
    }

    public func close() async {
        if !closed {
            closed = true; ready = false; refreshDue = false; lease.invalidate(); timer?.cancel(); timer = nil
            channel?.abort(); channel = nil; lastSnapshot = nil
            if let id = registrationLink?.id { retireRegistrationLink(id) }
            if let id = recoveryLink?.id { retireRecoveryLink(id) }
            let pending = waiters; waiters.removeAll()
            for (_, waiter) in pending { waiter.resume(throwing: AuthorityXPCError.closed) }
        }
        await host?.authorityDisconnected(lease)
    }
    private func update(_ channel: AuthorityXPCChannel) async throws {
        let trust = try await channel.fetchTrust(expectedMacID: macID, expectedAccountID: accountID)
        try requireActive()
        let bytes = try AuthorityTrustCodec.encodeSnapshot(trust)
        guard bytes != lastSnapshot else { return }
        guard let host else { throw AuthorityXPCError.closed }
        try await host.replaceTrust(trust, authority: lease)
        try requireActive(); lastSnapshot = bytes
    }
    private func requireActive() throws {
        try Task.checkCancellation()
        guard !closed, lease.isActive, channel?.lifetimeActive != false else { throw AuthorityXPCError.closed }
    }
    private func activeChannel() throws -> AuthorityXPCChannel {
        try requireActive()
        guard let channel else { throw AuthorityXPCError.closed }; return channel
    }
    private func acquire() async throws {
        try requireActive()
        guard ready else { throw AuthorityXPCError.invalidState }
        if !busy { busy = true; return }
        guard waiters.count < maximumWaiting else { throw AuthorityXPCError.concurrentOperation }
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { waiters.append((id, $0)) }
        } onCancel: { Task { await self.cancel(id) } }
        do { try requireActive() } catch { release(); throw error }
    }
    private func cancel(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.0 == id }) else { return }
        waiters.remove(at: index).1.resume(throwing: CancellationError())
    }
    private func release() {
        if refreshDue, !closed {
            refreshDue = false; scheduledRefresh = true
            Task { await self.runScheduledRefresh() }
        } else if waiters.isEmpty { busy = false }
        else { waiters.removeFirst().1.resume() }
    }
}
