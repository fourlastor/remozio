import Foundation
import Security
import RemozioProtocol

/// Owns one transport incarnation. Authority reconnection requires a new service instance.
public actor DirectApprovalTransportService {
    private let feed: AuthorityTrustFeed
    private let host: DirectApprovalTransportHost
    private let useDefaultDelivery: Bool
    private let requestDeliveryTimeoutMilliseconds: UInt64
    private let requestRefreshMilliseconds: UInt64
    private var started = false
    private var closed = false

    public init(macID: Data, accountID: Data, identity: sending SecIdentity,
                authorityServiceName: String, authorityPolicy: XPCPeerPolicy,
                binding: DirectApprovalListener.Binding = .localNetwork,
                maximumConnections: Int = 8, timeoutMilliseconds: UInt64 = 15_000,
                authorityTimeoutMilliseconds: UInt64 = 5000, refreshMilliseconds: UInt64 = 5000,
                maximumWaiting: Int = 8, requestDeliveryTimeoutMilliseconds: UInt64 = 30_000,
                requestRefreshMilliseconds: UInt64 = 5000,
                handler: (@Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void)? = nil) throws {
        guard (1...60_000).contains(requestDeliveryTimeoutMilliseconds),
              (1...60_000).contains(requestRefreshMilliseconds) else { throw DirectListenerError.invalidConfiguration }
        self.requestDeliveryTimeoutMilliseconds = requestDeliveryTimeoutMilliseconds
        self.requestRefreshMilliseconds = requestRefreshMilliseconds
        let feed = try AuthorityTrustFeed(serviceName: authorityServiceName, peerPolicy: authorityPolicy,
            macID: macID, accountID: accountID, timeoutMilliseconds: authorityTimeoutMilliseconds,
            refreshMilliseconds: refreshMilliseconds, maximumWaiting: maximumWaiting)
        self.feed = feed
        useDefaultDelivery = handler == nil
        host = try DirectApprovalTransportHost(macID: macID, accountID: accountID, identity: identity,
            binding: binding, maximumConnections: maximumConnections, timeoutMilliseconds: timeoutMilliseconds,
            validatePeer: { try await feed.validatePeer($0, revision: $1) },
            handler: handler ?? { _, _ in throw DirectHostError.stopped })
    }

    init(feed: AuthorityTrustFeed, host: DirectApprovalTransportHost, useDefaultDelivery: Bool = false, requestRefreshMilliseconds: UInt64 = 5000) {
        self.feed = feed; self.host = host; self.useDefaultDelivery = useDefaultDelivery
        requestDeliveryTimeoutMilliseconds = 30_000
        self.requestRefreshMilliseconds = requestRefreshMilliseconds
    }

    deinit {
        let feed = feed, host = host
        Task { await host.close(); await feed.close() }
    }

    public var state: DirectHostState { get async { await host.state } }

    public func start() async throws {
        guard !started, !closed else { throw DirectHostError.stopped }
        started = true
        do {
            try Task.checkCancellation()
            if useDefaultDelivery {
                let timeout = requestDeliveryTimeoutMilliseconds, refresh = requestRefreshMilliseconds
                try await host.configureHandler { [weak self] session, channel in
                    guard let self else { throw DirectHostError.stopped }
                    switch channel.purpose {
                    case .approvals:
                        try await self.runRequestExchange(for: session, over: channel, timeoutMilliseconds: timeout, refreshMilliseconds: refresh)
                    case .pairingReceipt:
                        try await self.runPairingReceiptRecovery(for: session, over: channel, timeoutMilliseconds: timeout)
                    case .pendingSnapshot:
                        try await self.runPendingRequestSnapshot(for: session, over: channel, timeoutMilliseconds: timeout)
                    case .pushRegistration:
                        try await self.runPhonePushRegistration(for: session, over: channel, timeoutMilliseconds: timeout)
                    }
                }
            }
            try await feed.start(host: host)
            guard !closed else { throw DirectHostError.stopped }
            try Task.checkCancellation()
            try await host.start()
            guard !closed else { throw DirectHostError.stopped }
            try Task.checkCancellation()
        } catch { await close(); throw error }
    }

    /// Retrieves a frame for this live phone session. It neither acknowledges delivery nor grants an action.
    public func requestFrame(for session: DirectApprovalSession, requestID: Data) async throws -> Data? {
        guard started, !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        let frame = try await feed.requestFrame(session.peer, revision: session.revision, requestID: requestID)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        return frame
    }

    /// Discover requests for this live phone session. Fetch and verify each returned request separately.
    public func pendingRequestIDs(for session: DirectApprovalSession) async throws -> [Data] {
        guard started, !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        let ids = try await feed.pendingRequestIDs(session.peer, revision: session.revision)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        return ids
    }

    /// Exchange state for this live session. A lost response does not prove that a submitted decision lost.
    public func exchangeRequest(for session: DirectApprovalSession, requestID: Data, decisionFrame: Data? = nil) async throws -> Data? {
        guard started, !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        let status = try await feed.exchangeRequest(session.peer, revision: session.revision,
            requestID: requestID, decisionFrame: decisionFrame)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        return status
    }

    /// Sends one bounded discovery snapshot over the admitted channel. Writes are not phone receipts or approvals.
    /// Custom handlers may continue with other operations after this snapshot.
    /// Failure closes the channel. Missing or incompatible frames do not imply a terminal request outcome.
    public func deliverPendingRequests(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                       timeoutMilliseconds: UInt64 = 30_000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard started, !closed else { throw DirectHostError.stopped }
                guard (1...60_000).contains(timeoutMilliseconds) else { throw ApprovalChannelError.invalidInput }
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope,
                      metadata.envelopeVersion == 1,
                      session.peer.requests.contains(where: { local in
                          metadata.peer.requests.contains { $0.kind == local.kind && $0.wireVersion == local.wireVersion &&
                              $0.schemaVersion == local.schemaVersion }
                      }) else { throw ApprovalChannelError.invalidInput }
                let ids = try await pendingRequestIDs(for: session)
                for id in ids {
                    try Task.checkCancellation()
                    guard ContinuousClock.now < deadline else { throw ApprovalChannelError.timedOut }
                    guard let frame = try await requestFrame(for: session, requestID: id) else { continue }
                    guard try Self.supports(frame, maximumBytes: session.peer.maximumPayloadBytes,
                        local: session.peer.requests, remote: metadata.peer.requests) else { continue }
                    try await host.validate(session)
                    try Task.checkCancellation()
                    guard !closed else { throw DirectHostError.stopped }
                    try await Self.send(frame, over: channel, deadline: deadline)
                }
                try Task.checkCancellation()
                guard !closed else { throw DirectHostError.stopped }
                guard ContinuousClock.now < deadline else { throw ApprovalChannelError.timedOut }
            } catch {
                await channel.closeAndWait()
                throw error
            }
        } onCancel: { channel.close() }
    }

    /// Runs until EOF, cancellation, or loss of the authority session. Decisions are never retried automatically.
    public func runRequestExchange(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                   timeoutMilliseconds: UInt64 = 30_000, refreshMilliseconds: UInt64 = 5000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard (1...60_000).contains(timeoutMilliseconds), (1...60_000).contains(refreshMilliseconds) else {
                    throw ApprovalChannelError.invalidInput
                }
                try await validate(session)
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope, metadata.envelopeVersion == 1,
                      session.peer.requests.contains(where: { local in metadata.peer.requests.contains {
                          $0.kind == local.kind && $0.wireVersion == local.wireVersion && $0.schemaVersion == local.schemaVersion
                      } }) else { throw ApprovalChannelError.invalidInput }
                guard try await feed.supportsRequestExchange() else {
                    try await deliverPendingRequests(for: session, over: channel, timeoutMilliseconds: timeoutMilliseconds)
                    return
                }
                try await DirectApprovalRequestExchangeLoop(service: self, session: session, channel: channel,
                    remoteRequests: metadata.peer.requests, timeoutMilliseconds: timeoutMilliseconds,
                    refreshMilliseconds: refreshMilliseconds).run()
            } catch {
                await channel.closeAndWait()
                throw error
            }
        } onCancel: { channel.close() }
    }

    /// Returns only a bounded registration reply from the current authority. No application request is replayed.
    public func phonePushRegistration(for session: DirectApprovalSession, frame: PhonePushRegistrationFrame) async throws -> PhonePushRegistrationFrame {
        try await validate(session)
        let response: PhonePushRegistrationFrame
        do { response = try await feed.phonePushRegistration(session.peer, revision: session.revision, frame: frame) }
        catch AuthorityXPCError.unsupportedPhonePushRegistration { response = .outcome(correlationID: frame.correlationID, outcome: .incompatible) }
        try await validate(session)
        return response
    }

    /// Returns only the existing commit proof for this admitted phone and retained setup ID.
    public func pairingReceipt(for session: DirectApprovalSession, setupID: Data) async throws -> Data? {
        try await validate(session)
        let signature = try await feed.pairingReceipt(session.peer, revision: session.revision, setupID: setupID)
        try await validate(session)
        return signature
    }

    /// One bounded read-only exchange. An unavailable receipt cannot establish an absent enrollment.
    public func runPairingReceiptRecovery(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                         timeoutMilliseconds: UInt64 = 30_000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard (1...60_000).contains(timeoutMilliseconds), channel.purpose == .pairingReceipt else {
                    throw ApprovalChannelError.invalidInput
                }
                try await validate(session)
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope,
                      metadata.envelopeVersion == 1 else { throw ApprovalChannelError.invalidInput }
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        guard let bytes = try await channel.receive(maximumBytes: min(session.peer.maximumPayloadBytes, PairingReceiptFrame.maximumBytes)),
                              case .query(let setupID) = try PairingReceiptFrame.decode(bytes) else { throw ApprovalChannelError.invalidInput }
                        let signature = try await self.pairingReceipt(for: session, setupID: setupID)
                        let response = try PairingReceiptFrame.response(setupID: setupID, signature: signature).encode()
                        guard response.count <= session.peer.maximumPayloadBytes else { throw ApprovalChannelError.invalidInput }
                        try await self.validate(session)
                        try await Self.send(response, over: channel, deadline: deadline)
                    }
                    group.addTask {
                        try await ContinuousClock().sleep(until: deadline)
                        channel.close()
                        throw ApprovalChannelError.timedOut
                    }
                    defer { group.cancelAll() }
                    _ = try await group.next()
                }
                await channel.closeAndWait()
            } catch { await channel.closeAndWait(); throw error }
        } onCancel: { channel.close() }
    }

    func validate(_ session: DirectApprovalSession) async throws {
        try Task.checkCancellation()
        guard started, !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
    }

    static func supports(_ frame: Data, maximumBytes: Int,
                                 local: [ChannelRequestCapability], remote: [ChannelRequestCapability]) throws -> Bool {
        guard frame.count <= maximumBytes, maximumBytes > ApprovalMessage.overheadBytes else {
            throw ApprovalChannelError.invalidInput
        }
        let message = try ApprovalMessage.decode(frame, maximumBodyBytes: maximumBytes - ApprovalMessage.overheadBytes)
        let limits = try CBORLimits(maxBytes: maximumBytes, maxDepth: 32, maxItems: 262_144)
        guard message.type == .request, message.purpose == .issuedRequest,
              case .map(let body) = try DeterministicCBOR.decode(message.body, limits: limits),
              case .unsigned(let kind) = body[5], case .unsigned(let schema) = body[6],
              case .array(let values) = body[7], values.count <= 64 else { throw ApprovalChannelError.invalidInput }
        var features = Set<UInt64>(), previous: UInt64?
        for value in values {
            guard case .unsigned(let feature) = value, previous == nil || feature > previous! else {
                throw ApprovalChannelError.invalidInput
            }
            features.insert(feature); previous = feature
        }
        func accepts(_ capabilities: [ChannelRequestCapability]) -> Bool {
            capabilities.contains { $0.kind == kind && $0.wireVersion == message.wireVersion &&
                $0.schemaVersion == schema && features.isSubset(of: $0.features) }
        }
        return accepts(local) && accepts(remote)
    }

    static func send(_ frame: Data, over channel: NegotiatedNetworkChannel,
                             deadline: ContinuousClock.Instant) async throws {
        guard ContinuousClock.now < deadline else { throw ApprovalChannelError.timedOut }
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { try await channel.send(frame) }
                group.addTask {
                    try await ContinuousClock().sleep(until: deadline)
                    channel.close()
                    throw ApprovalChannelError.timedOut
                }
                defer { group.cancelAll() }
                _ = try await group.next()
            }
        } catch {
            if !Task.isCancelled, ContinuousClock.now >= deadline { throw ApprovalChannelError.timedOut }
            throw error
        }
    }

    public func close() async {
        closed = true
        await host.close()
        await feed.close()
    }
}
