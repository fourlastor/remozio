import Foundation
import RemozioProtocol

public enum AuthorityXPCEndpointError: Error { case invalidConfiguration, unavailable }

/// Share one budget across all authority transport endpoints. Admission never queues waiting work.
public final class AuthorityXPCWorkBudget: @unchecked Sendable {
    private let lock = NSLock()
    private let maximum: Int
    private var active = 0
    public init(maximum: Int = 8) throws {
        guard (1...64).contains(maximum) else { throw AuthorityXPCEndpointError.invalidConfiguration }
        self.maximum = maximum
    }
    func acquire() -> Bool { lock.withLock { guard active < maximum else { return false }; active += 1; return true } }
    func release() { lock.withLock { active -= 1 } }
}

/// One exported transport connection. Handlers execute synchronously and must use the root owner's serialized journal access.
/// Request-frame handlers do not expose arbitrary signing, credential release, or target execution.
public final class AuthorityXPCEndpoint: NSObject, TransportAuthorityXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let verify: () throws -> Void
    private let verifyHandshakePolicy: @Sendable () throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private let snapshot: @Sendable () throws -> DirectApprovalTrust
    private let validate: @Sendable (AuthorityPeerBinding) throws -> Bool
    private let activityJournal: AuthorityJournal?
    private let budget: AuthorityXPCWorkBudget
    private let macID: Data
    private let accountID: Data
    private let frame: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
    private let pendingRequests: (@Sendable (AuthorityPeerBinding) throws -> [Data])?
    private let exchange: (@Sendable (AuthorityPeerBinding, Data, Data?) throws -> Data?)?
    private let receipt: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
    private let pushRecovery: (@Sendable (AuthorityPeerBinding, PhonePushRecoveryFrame) throws -> PhonePushRecoveryFrame)?
    private let pushRegistration: (@Sendable (AuthorityPeerBinding, PhonePushRegistrationFrame) throws -> PhonePushRegistrationFrame)?
    private let wakeHints: (@Sendable () throws -> AuthorityWakeHints)?
    private var recoveryReady = false
    private var registrationReady = false
    private var receiptReady = false
    private var wakeReady = false
    private var exchangeReady = false
    private var discoveryReady = false
    private var deliveryReady = false
    private var ready = false
    private var closed = false
    private var busy = false

    /// The listener must enforce the same peer policy and own the accepted connection. Activate it only after this initializer succeeds.
    public convenience init(connection: NSXPCConnection, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                            budget: AuthorityXPCWorkBudget, activityJournal: AuthorityJournal? = nil,
                            verifyHandshakePolicy: @escaping @Sendable () throws -> Void = {},
                            onHandshake: @escaping @Sendable () -> Void = {}, onClose: @escaping @Sendable () -> Void = {},
                            snapshot: @escaping @Sendable () throws -> DirectApprovalTrust,
                            validate: @escaping @Sendable (AuthorityPeerBinding) throws -> Bool,
                            requestFrame: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)? = nil,
                            pendingRequestIDs: (@Sendable (AuthorityPeerBinding) throws -> [Data])? = nil,
                            exchangeRequest: (@Sendable (AuthorityPeerBinding, Data, Data?) throws -> Data?)? = nil,
                            pairingReceipt: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)? = nil,
                            phonePushRegistration: (@Sendable (AuthorityPeerBinding, PhonePushRegistrationFrame) throws -> PhonePushRegistrationFrame)? = nil,
         phonePushRecovery: (@Sendable (AuthorityPeerBinding, PhonePushRecoveryFrame) throws -> PhonePushRecoveryFrame)? = nil,
         wakeHints: (@Sendable () throws -> AuthorityWakeHints)? = nil) throws {
        guard peerPolicy.expectedUserID != 0, macID.count == 16, accountID.count == 16 else { throw AuthorityXPCEndpointError.invalidConfiguration }
        _ = try peerPolicy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: peerPolicy)
        self.init(macID: macID, accountID: accountID, budget: budget, activityJournal: activityJournal,
            verify: { _ = try invocation.verifyInvocation() }, verifyHandshakePolicy: verifyHandshakePolicy, invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake,
            snapshot: snapshot, validate: validate, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs,
            exchangeRequest: exchangeRequest, pairingReceipt: pairingReceipt, phonePushRegistration: phonePushRegistration, phonePushRecovery: phonePushRecovery, wakeHints: wakeHints)
        peerPolicy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    init(macID: Data, accountID: Data, budget: AuthorityXPCWorkBudget, activityJournal: AuthorityJournal? = nil,
         verify: @escaping () throws -> Void, verifyHandshakePolicy: @escaping @Sendable () throws -> Void = {}, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {},
         snapshot: @escaping @Sendable () throws -> DirectApprovalTrust,
         validate: @escaping @Sendable (AuthorityPeerBinding) throws -> Bool,
         requestFrame: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)? = nil,
         pendingRequestIDs: (@Sendable (AuthorityPeerBinding) throws -> [Data])? = nil,
         exchangeRequest: (@Sendable (AuthorityPeerBinding, Data, Data?) throws -> Data?)? = nil,
         pairingReceipt: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)? = nil,
         phonePushRegistration: (@Sendable (AuthorityPeerBinding, PhonePushRegistrationFrame) throws -> PhonePushRegistrationFrame)? = nil,
         phonePushRecovery: (@Sendable (AuthorityPeerBinding, PhonePushRecoveryFrame) throws -> PhonePushRecoveryFrame)? = nil,
         wakeHints: (@Sendable () throws -> AuthorityWakeHints)? = nil) {
        self.activityJournal = activityJournal
        self.macID = macID; self.accountID = accountID; self.budget = budget
        self.verify = verify; self.verifyHandshakePolicy = verifyHandshakePolicy; self.invalidate = invalidate; self.onHandshake = onHandshake; self.snapshot = snapshot; self.validate = validate; self.frame = requestFrame; self.pendingRequests = pendingRequestIDs; self.exchange = exchangeRequest
        self.wakeHints = wakeHints; self.receipt = pairingReceipt; self.pushRegistration = phonePushRegistration; self.pushRecovery = phonePushRecovery
    }
    public func close() {
        let notify = lock.withLock { if closed { return false }; closed = true; ready = false; return true }
        if notify { invalidate() }
    }
    public func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work(handshake: true) {
                try lock.withLock {
                    guard !closed else { throw AuthorityXPCEndpointError.unavailable }
                    ready = true
                }
                onHandshake()
            }
            defer { completed.activity?.close() }
            send { reply(1) }
        } catch { close(); reply(0) }
    }
    public func requestDeliveryVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                let supported = frame != nil
                lock.withLock { deliveryReady = supported }
                return supported ? UInt64(1) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func requestDiscoveryVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                let supported = pendingRequests != nil
                lock.withLock { discoveryReady = supported }
                return supported ? UInt64(1) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func pendingRequestIDs(_ binding: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                guard lock.withLock({ discoveryReady }), let pendingRequests else { throw AuthorityXPCEndpointError.unavailable }
                let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                return try AuthorityPendingRequests.encode(pendingRequests(peer), binding: peer)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func requestFrame(_ binding: Data, requestID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                guard lock.withLock({ deliveryReady }), let frame, requestID.count == 16 else {
                    throw AuthorityXPCEndpointError.unavailable
                }
                let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                // The handler rechecks enrollment and code policy inside the root's request-owner lock.
                guard let result = try frame(peer, requestID) else { return Data() }
                try AuthorityRequestFrame.validate(result, binding: peer, requestID: requestID)
                return result
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func requestExchangeVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                let supported = exchange != nil
                lock.withLock { exchangeReady = supported }
                return supported ? UInt64(1) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func pairingReceiptVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                let supported = receipt != nil
                lock.withLock { receiptReady = supported }
                return supported ? UInt64(1) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func pairingReceipt(_ binding: Data, setupID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                guard lock.withLock({ receiptReady }), let receipt, setupID.count == 16 else {
                    throw AuthorityXPCEndpointError.unavailable
                }
                let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                guard let signature = try receipt(peer, setupID) else { return Data() }
                guard signature.count == 64 else { throw AuthorityXPCError.invalidMessage }
                return signature
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func phonePushRecoveryVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                try verifyHandshakePolicy()
                let supported = pushRecovery != nil
                lock.withLock { recoveryReady = supported }
                return supported ? UInt64(2) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func phonePushRecovery(_ binding: Data, frame: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                guard lock.withLock({ recoveryReady }), let pushRecovery else { throw AuthorityXPCEndpointError.unavailable }
                let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                let request = try PhonePushRecoveryFrame.decode(frame)
                try AuthorityPhonePushRecoveryExchange.request(request, binding: peer)
                let result = try pushRecovery(peer, request)
                try AuthorityPhonePushRecoveryExchange.response(result, to: request, binding: peer)
                return try result.encode()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func phonePushRegistrationVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                try verifyHandshakePolicy()
                let supported = pushRegistration != nil
                lock.withLock { registrationReady = supported }
                return supported ? UInt64(1) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func phonePushRegistration(_ binding: Data, frame: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                guard lock.withLock({ registrationReady }), let pushRegistration else { throw AuthorityXPCEndpointError.unavailable }
                let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                let request = try PhonePushRegistrationFrame.decode(frame)
                try AuthorityPhonePushExchange.request(request, binding: peer)
                let result = try pushRegistration(peer, request)
                try AuthorityPhonePushExchange.response(result, to: request, binding: peer)
                return try result.encode()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func requestWakeVersion(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work {
                try verifyHandshakePolicy()
                let supported = wakeHints != nil
                lock.withLock { wakeReady = supported }
                return supported ? UInt64(1) : UInt64(0)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(0) }
    }
    public func wakeDeliveryHints(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                try verifyHandshakePolicy()
                guard lock.withLock({ wakeReady }), let wakeHints else { throw AuthorityXPCEndpointError.unavailable }
                let hints = try wakeHints()
                guard hints.binding.macID == macID, hints.binding.accountID == accountID else { throw AuthorityWakeHintError.invalidMessage }
                return try hints.encode()
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func exchangeRequest(_ binding: Data, query: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                guard lock.withLock({ exchangeReady }), let exchange else { throw AuthorityXPCEndpointError.unavailable }
                let peer = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                let request = try AuthorityRequestExchange.decode(query)
                guard let result = try exchange(peer, request.requestID, request.decisionFrame) else { return Data() }
                try AuthorityRequestExchange.validateResponse(result, binding: peer, requestID: request.requestID)
                return result
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func trustSnapshot(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let completed = try work {
                let trust = try snapshot()
                guard trust.macID == macID, trust.accountID == accountID else { throw AuthorityXPCEndpointError.unavailable }
                return try AuthorityTrustCodec.encodeSnapshot(trust)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(nil) }
    }
    public func validatePeer(_ binding: Data, reply: @escaping @Sendable (Bool) -> Void) {
        do {
            let completed = try work {
                let decoded = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
                return try validate(decoded)
            }
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        } catch { close(); reply(false) }
    }
    private func work<T>(handshake: Bool = false, _ body: () throws -> T) throws -> (value: T, activity: ReleaseActivityToken?) {
        try begin(handshake: handshake); defer { end() }
        let activity = try activityJournal?.acquireReleaseActivity()
        var transferred = false
        defer { if !transferred { activity?.close() } }
        if handshake { try verifyHandshakePolicy() }
        let value = try body()
        try activity?.validate()
        transferred = true
        return (value, activity)
    }
    private func begin(handshake: Bool) throws {
        try verify()
        try lock.withLock {
            guard !closed, ready != handshake, !busy, budget.acquire() else { throw AuthorityXPCEndpointError.unavailable }
            busy = true
        }
    }
    private func end() { lock.withLock { budget.release(); busy = false } }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}
