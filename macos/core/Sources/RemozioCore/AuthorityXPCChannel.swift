import Foundation
import RemozioProtocol

@objc public protocol TransportAuthorityXPCProtocol {
    /// Harmless first call. Contains no scope, key, request, or credential material.
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    /// Optional request-delivery extension. Zero means unavailable; version one uses requestFrame.
    func requestDeliveryVersion(reply: @escaping @Sendable (UInt64) -> Void)
    /// Optional discovery extension, negotiated separately from version-one frame retrieval.
    func requestDiscoveryVersion(reply: @escaping @Sendable (UInt64) -> Void)
    func pendingRequestIDs(_ binding: Data, reply: @escaping @Sendable (Data?) -> Void)
    func requestFrame(_ binding: Data, requestID: Data, reply: @escaping @Sendable (Data?) -> Void)
    /// Optional state/decision extension. Negotiate before sending request IDs or signed decisions.
    func requestExchangeVersion(reply: @escaping @Sendable (UInt64) -> Void)
    func exchangeRequest(_ binding: Data, query: Data, reply: @escaping @Sendable (Data?) -> Void)
    /// Read-only receipt recovery. Negotiate before sending a retained setup ID or phone binding.
    func pairingReceiptVersion(reply: @escaping @Sendable (UInt64) -> Void)
    func pairingReceipt(_ binding: Data, setupID: Data, reply: @escaping @Sendable (Data?) -> Void)
    /// Optional token registration. Negotiate before sending an enrollment binding or private token.
    func phonePushRegistrationVersion(reply: @escaping @Sendable (UInt64) -> Void)
    func phonePushRegistration(_ binding: Data, frame: Data, reply: @escaping @Sendable (Data?) -> Void)
    /// Optional wake hints. Clients negotiate this extension on their own connection.
    func requestWakeVersion(reply: @escaping @Sendable (UInt64) -> Void)
    func wakeDeliveryHints(reply: @escaping @Sendable (Data?) -> Void)
    func trustSnapshot(reply: @escaping @Sendable (Data?) -> Void)
    func validatePeer(_ binding: Data, reply: @escaping @Sendable (Bool) -> Void)
}

public enum AuthorityXPCError: Error { case unsupportedPhonePushRegistration, unsupportedPairingReceipt, unsupportedRequestExchange, unsupportedRequestDiscovery, unsupportedRequestDelivery, invalidConfiguration, invalidState, concurrentOperation, closed, failed, timedOut, invalidMessage }
enum AuthorityXPCReply: Sendable { case registrationVersion(UInt64), registration(Data), receiptVersion(UInt64), receipt(Data), exchangeVersion(UInt64), exchange(Data), hello(UInt64), deliveryVersion(UInt64), discoveryVersion(UInt64), pendingRequests(Data), requestFrame(Data), snapshot(Data), validation(Bool), failed }
protocol AuthorityXPCDriver: Sendable {
    func start(invalidated: @escaping @Sendable () -> Void)
    func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func pendingRequests(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func receiptVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func receipt(_ binding: Data, setupID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func registrationVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func registration(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func close()
}

extension AuthorityXPCDriver {
    func registrationVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.registrationVersion(0)) }
    func registration(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
    func receiptVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.receiptVersion(0)) }
    func receipt(_ binding: Data, setupID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
    func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.exchangeVersion(0)) }
    func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
    func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.discoveryVersion(0)) }
    func pendingRequests(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.deliveryVersion(0)) }
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
}

private final class NativeAuthorityXPC: AuthorityXPCDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
        policy.configure(connection)
    }
    func start(invalidated: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = invalidated
        connection.invalidationHandler = invalidated
        connection.activate()
    }
    private func proxy(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) -> (any TransportAuthorityXPCProtocol)? {
        connection.remoteObjectProxyWithErrorHandler { _ in reply(.failed) } as? any TransportAuthorityXPCProtocol
    }
    private func checked(_ result: AuthorityXPCReply, _ reply: @Sendable (AuthorityXPCReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(result) }
        catch { reply(.failed) }
    }
    func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.hello { [self] version in checked(.hello(version), reply) }
    }
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.requestDeliveryVersion { [self] version in checked(.deliveryVersion(version), reply) }
    }
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.requestFrame(binding, requestID: requestID) { [self] bytes in
            checked(bytes.map(AuthorityXPCReply.requestFrame) ?? .failed, reply)
        }
    }
    func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.requestDiscoveryVersion { [self] version in checked(.discoveryVersion(version), reply) }
    }
    func pendingRequests(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.pendingRequestIDs(binding) { [self] bytes in checked(bytes.map(AuthorityXPCReply.pendingRequests) ?? .failed, reply) }
    }
    func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.requestExchangeVersion { [self] version in checked(.exchangeVersion(version), reply) }
    }
    func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.exchangeRequest(binding, query: query) { [self] bytes in checked(bytes.map(AuthorityXPCReply.exchange) ?? .failed, reply) }
    }
    func receiptVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.pairingReceiptVersion { [self] version in checked(.receiptVersion(version), reply) }
    }
    func receipt(_ binding: Data, setupID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.pairingReceipt(binding, setupID: setupID) { [self] bytes in checked(bytes.map(AuthorityXPCReply.receipt) ?? .failed, reply) }
    }
    func registrationVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.phonePushRegistrationVersion { [self] version in checked(.registrationVersion(version), reply) }
    }
    func registration(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.phonePushRegistration(binding, frame: frame) { [self] bytes in checked(bytes.map(AuthorityXPCReply.registration) ?? .failed, reply) }
    }
    func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.trustSnapshot { [self] data in checked(data.map(AuthorityXPCReply.snapshot) ?? .failed, reply) }
    }
    func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.validatePeer(binding) { [self] allowed in checked(.validation(allowed), reply) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class XPCLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var cancelled = false
    func cancel() { lock.withLock { cancelled = true } }
    func ifActive(_ body: () -> Void) -> Bool {
        lock.withLock { guard !cancelled else { return false }; body(); return true }
    }
}

/// One transport-to-root connection. A successful harmless handshake is required before any binding data is sent.
/// Interruption retires the instance. Construct a new instance and fetch fresh trust after reconnecting.
public actor AuthorityXPCChannel {
    public static let maximumSnapshotBytes = 1_048_576
    public static let maximumBindingBytes = 4096
    private enum State { case new, opening, open, closed }
    private enum Operation { case registrationVersion, registration, receiptVersion, receipt, exchangeVersion, exchange, hello, deliveryVersion, discoveryVersion, pendingRequests, requestFrame, snapshot, validation }
    private var registrationVersion: UInt64?
    private var receiptVersion: UInt64?
    private var exchangeVersion: UInt64?
    private var discoveryVersion: UInt64?
    private var deliveryVersion: UInt64?
    private let driver: any AuthorityXPCDriver
    private let cancellation = XPCLifetime()
    private let timeoutMilliseconds: UInt64
    private let onClose: @Sendable () -> Void
    private var state = State.new
    private var pending: (id: UUID, operation: Operation, continuation: CheckedContinuation<AuthorityXPCReply, Error>)?
    private var deadline: Task<Void, Never>?

    public init(serviceName: String, peerPolicy: XPCPeerPolicy, timeoutMilliseconds: UInt64 = 5000,
                onClose: @escaping @Sendable () -> Void) throws {
        guard (1...255).contains(serviceName.utf8.count), serviceName.hasPrefix("dev.remozio."),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              peerPolicy.expectedUserID == 0, (1...60_000).contains(timeoutMilliseconds) else { throw AuthorityXPCError.invalidConfiguration }
        driver = NativeAuthorityXPC(serviceName: serviceName, policy: peerPolicy)
        self.timeoutMilliseconds = timeoutMilliseconds; self.onClose = onClose
    }
    init(driver: any AuthorityXPCDriver, timeoutMilliseconds: UInt64 = 5000,
         onClose: @escaping @Sendable () -> Void = {}) {
        self.driver = driver; self.timeoutMilliseconds = timeoutMilliseconds; self.onClose = onClose
    }
    deinit { deadline?.cancel(); driver.close() }

    public func start() async throws {
        guard state == .new else { throw AuthorityXPCError.invalidState }
        state = .opening
        do {
            _ = try await perform(.hello)
            try Task.checkCancellation()
            guard cancellation.ifActive({}), state == .opening else { throw AuthorityXPCError.closed }
            state = .open
        } catch { finish(.closed); throw error }
    }
    public func trustSnapshot() async throws -> Data {
        guard case .snapshot(let data) = try await perform(.snapshot) else { throw AuthorityXPCError.invalidMessage }
        return data
    }
    /// Decode only after authenticating the authority; a malformed or wrong-scope snapshot retires the connection.
    public func fetchTrust(expectedMacID: Data, expectedAccountID: Data) async throws -> DirectApprovalTrust {
        let bytes = try await trustSnapshot()
        do { return try AuthorityTrustCodec.decodeSnapshot(bytes, expectedMacID: expectedMacID, expectedAccountID: expectedAccountID) }
        catch { finish(.invalidMessage); throw error }
    }
    public func validatePeer(_ binding: AuthorityPeerBinding) async throws -> Bool {
        try await validatePeer(binding: AuthorityTrustCodec.encodeBinding(binding))
    }
    public func validatePeer(binding: Data) async throws -> Bool {
        guard !binding.isEmpty, binding.count <= Self.maximumBindingBytes else { throw AuthorityXPCError.invalidMessage }
        guard case .validation(let allowed) = try await perform(.validation, binding: binding) else { throw AuthorityXPCError.invalidMessage }
        return allowed
    }
    /// Fetch a frame for a known request. Empty means no currently eligible frame, never a confirmed request outcome.
    /// This does not authorize an action. The root owns the queued frame and revalidates its recipient.
    public func requestFrame(binding: AuthorityPeerBinding, requestID: Data) async throws -> Data? {
        guard requestID.count == 16 else { throw AuthorityXPCError.invalidMessage }
        if deliveryVersion == nil {
            guard case .deliveryVersion(let version) = try await perform(.deliveryVersion) else { throw AuthorityXPCError.invalidMessage }
            deliveryVersion = version
        }
        guard deliveryVersion == 1 else { throw AuthorityXPCError.unsupportedRequestDelivery }
        let encoded = try AuthorityTrustCodec.encodeBinding(binding)
        guard case .requestFrame(let bytes) = try await perform(.requestFrame, binding: encoded, requestID: requestID) else {
            throw AuthorityXPCError.invalidMessage
        }
        if bytes.isEmpty { return nil }
        do { try AuthorityRequestFrame.validate(bytes, binding: binding, requestID: requestID) }
        catch { finish(.invalidMessage); throw error }
        return bytes
    }

    /// Complete bounded discovery hints for this current binding. Fetch and validate each frame separately.
    public func pendingRequestIDs(binding: AuthorityPeerBinding) async throws -> [Data] {
        if discoveryVersion == nil {
            guard case .discoveryVersion(let version) = try await perform(.discoveryVersion) else { throw AuthorityXPCError.invalidMessage }
            discoveryVersion = version
        }
        guard discoveryVersion == 1 else { throw AuthorityXPCError.unsupportedRequestDiscovery }
        let encoded = try AuthorityTrustCodec.encodeBinding(binding)
        guard case .pendingRequests(let bytes) = try await perform(.pendingRequests, binding: encoded) else {
            throw AuthorityXPCError.invalidMessage
        }
        do { return try AuthorityPendingRequests.decode(bytes, binding: binding) }
        catch { finish(.invalidMessage); throw error }
    }

    /// Negotiate the optional exchange extension without sending a request binding or decision.
    public func supportsRequestExchange() async throws -> Bool {
        if exchangeVersion == nil {
            guard case .exchangeVersion(let version) = try await perform(.exchangeVersion) else { throw AuthorityXPCError.invalidMessage }
            exchangeVersion = version
        }
        return exchangeVersion == 1
    }

    /// Returns authority-signed state. A decision can commit before a lost reply; query status to reconcile it.
    public func exchangeRequest(binding: AuthorityPeerBinding, requestID: Data, decisionFrame: Data? = nil) async throws -> Data? {
        let query = try AuthorityRequestExchange.encode(requestID: requestID, decisionFrame: decisionFrame)
        guard try await supportsRequestExchange() else { throw AuthorityXPCError.unsupportedRequestExchange }
        let encoded = try AuthorityTrustCodec.encodeBinding(binding)
        guard case .exchange(let bytes) = try await perform(.exchange, binding: encoded, query: query) else {
            throw AuthorityXPCError.invalidMessage
        }
        if bytes.isEmpty { return nil }
        do { try AuthorityRequestExchange.validateResponse(bytes, binding: binding, requestID: requestID) }
        catch { finish(.invalidMessage); throw error }
        return bytes
    }

    /// Missing receipts do not establish that enrollment was never committed.
    public func pairingReceipt(binding: AuthorityPeerBinding, setupID: Data) async throws -> Data? {
        guard setupID.count == 16 else { throw AuthorityXPCError.invalidMessage }
        if receiptVersion == nil {
            guard case .receiptVersion(let version) = try await perform(.receiptVersion) else { throw AuthorityXPCError.invalidMessage }
            receiptVersion = version
        }
        guard receiptVersion == 1 else { throw AuthorityXPCError.unsupportedPairingReceipt }
        let encoded = try AuthorityTrustCodec.encodeBinding(binding)
        guard case .receipt(let bytes) = try await perform(.receipt, binding: encoded, setupID: setupID) else {
            throw AuthorityXPCError.invalidMessage
        }
        return bytes.isEmpty ? nil : bytes
    }

    /// The optional capability is checked before any binding or token is sent. Uncertain requests are never replayed.
    public func phonePushRegistration(binding: AuthorityPeerBinding, frame: PhonePushRegistrationFrame) async throws -> PhonePushRegistrationFrame {
        try AuthorityPhonePushExchange.request(frame, binding: binding)
        if registrationVersion == nil {
            guard case .registrationVersion(let version) = try await perform(.registrationVersion) else { throw AuthorityXPCError.invalidMessage }
            registrationVersion = version
        }
        guard registrationVersion == 1 else { throw AuthorityXPCError.unsupportedPhonePushRegistration }
        let encoded = try AuthorityTrustCodec.encodeBinding(binding)
        guard case .registration(let bytes) = try await perform(.registration, binding: encoded, query: frame.encode()) else {
            throw AuthorityXPCError.invalidMessage
        }
        do {
            let result = try PhonePushRegistrationFrame.decode(bytes)
            try AuthorityPhonePushExchange.response(result, to: frame, binding: binding)
            return result
        } catch { finish(.invalidMessage); throw error }
    }

    // Synchronous driver invalidation must fence results from the optional RPC connection too.
    nonisolated var lifetimeActive: Bool { cancellation.ifActive({}) }

    public nonisolated func abort() {
        cancellation.cancel(); driver.close()
        Task { await self.close() }
    }
    public func close() { finish(.closed) }

    private func perform(_ operation: Operation, binding: Data? = nil, requestID: Data? = nil, query: Data? = nil, setupID: Data? = nil) async throws -> AuthorityXPCReply {
        guard state == .open || (state == .opening && operation == .hello) else { throw AuthorityXPCError.closed }
        guard pending == nil else { throw AuthorityXPCError.concurrentOperation }
        try Task.checkCancellation()
        let cancellation = cancellation, driver = driver
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let id = UUID()
                pending = (id, operation, continuation)
                deadline = Task { [weak self, timeoutMilliseconds] in
                    do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
                    await self?.expired(id)
                }
                let reply: @Sendable (AuthorityXPCReply) -> Void = { [weak self] result in
                    Task { await self?.received(result, id: id) }
                }
                if operation == .hello {
                    driver.start { [weak self] in
                        cancellation.cancel()
                        Task { await self?.close() }
                    }
                }
                guard cancellation.ifActive({
                    switch operation {
                    case .registrationVersion: driver.registrationVersion(reply)
                    case .registration: driver.registration(binding!, frame: query!, reply)
                    case .receiptVersion: driver.receiptVersion(reply)
                    case .receipt: driver.receipt(binding!, setupID: setupID!, reply)
                    case .exchangeVersion: driver.exchangeVersion(reply)
                    case .exchange: driver.exchange(binding!, query: query!, reply)
                    case .hello: driver.hello(reply)
                    case .discoveryVersion: driver.discoveryVersion(reply)
                    case .pendingRequests: driver.pendingRequests(binding!, reply)
                    case .deliveryVersion: driver.deliveryVersion(reply)
                    case .requestFrame: driver.requestFrame(binding!, requestID: requestID!, reply)
                    case .snapshot: driver.snapshot(reply)
                    case .validation: driver.validate(binding!, reply)
                    }
                }) else { finish(.closed); return }
            }
        } onCancel: {
            cancellation.cancel(); driver.close()
            Task { await self.close() }
        }
        try Task.checkCancellation()
        guard cancellation.ifActive({}), state != .closed else { finish(.closed); throw AuthorityXPCError.closed }
        return result
    }
    private func received(_ reply: AuthorityXPCReply, id: UUID) {
        guard let current = pending, current.id == id else { return }
        guard cancellation.ifActive({}) else { finish(.closed); return }
        if case .failed = reply { finish(.failed); return }
        switch (current.operation, reply) {
        case (.hello, .hello(1)), (.validation, .validation), (.deliveryVersion, .deliveryVersion), (.discoveryVersion, .discoveryVersion): break
        case (.registrationVersion, .registrationVersion): break
        case (.registration, .registration(let bytes)) where !bytes.isEmpty && bytes.count <= PhonePushRegistrationFrame.maximumBytes: break
        case (.receiptVersion, .receiptVersion): break
        case (.receipt, .receipt(let bytes)) where bytes.isEmpty || bytes.count == 64: break
        case (.exchangeVersion, .exchangeVersion): break
        case (.exchange, .exchange(let bytes)) where bytes.count <= AuthorityRequestExchange.maximumFrameBytes: break
        case (.pendingRequests, .pendingRequests(let bytes)) where !bytes.isEmpty && bytes.count <= AuthorityPendingRequests.maximumBytes: break
        case (.requestFrame, .requestFrame(let bytes)) where bytes.count <= AuthorityRequestFrame.maximumBytes: break
        case (.snapshot, .snapshot(let bytes)) where !bytes.isEmpty && bytes.count <= Self.maximumSnapshotBytes: break
        default: finish(.invalidMessage); return
        }
        pending = nil; deadline?.cancel(); deadline = nil
        current.continuation.resume(returning: reply)
    }
    private func expired(_ id: UUID) { if pending?.id == id { finish(.timedOut) } }
    private func finish(_ error: AuthorityXPCError) {
        guard state != .closed else { return }
        state = .closed; cancellation.cancel(); deadline?.cancel(); deadline = nil
        let current = pending; pending = nil
        driver.close(); onClose(); current?.continuation.resume(throwing: error)
    }
}
