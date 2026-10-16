import Darwin
import Foundation

protocol OwnedAuthorityConnection: Sendable { func activate(); func close() }

/// Reservations cover setup and handshake, not just fully configured connections.
final class AuthorityConnectionRegistry: @unchecked Sendable {
    private struct Entry {
        var connection: (any OwnedAuthorityConnection)?
        var ready = false
        var deadline: Task<Void, Never>?
    }
    private let lock = NSRecursiveLock()
    private let maximum: Int
    private let timeoutMilliseconds: UInt64
    private var entries: [UUID: Entry] = [:]
    private var running = false
    private var closed = false
    init(maximum: Int, timeoutMilliseconds: UInt64) throws {
        guard (1...64).contains(maximum), (1...60_000).contains(timeoutMilliseconds) else { throw AuthorityXPCEndpointError.invalidConfiguration }
        self.maximum = maximum; self.timeoutMilliseconds = timeoutMilliseconds
    }
    deinit { close() }
    func start() throws {
        try lock.withLock {
            guard !running, !closed else { throw AuthorityXPCEndpointError.unavailable }; running = true
        }
    }
    func reserve() -> UUID? {
        lock.withLock {
            guard running, !closed, entries.count < maximum else { return nil }
            let id = UUID()
            let deadline = Task { [weak self, timeoutMilliseconds] in
                do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
                self?.expire(id)
            }
            entries[id] = Entry(deadline: deadline)
            return id
        }
    }
    func install(_ connection: any OwnedAuthorityConnection, id: UUID) -> Bool {
        let accepted = lock.withLock {
            guard var entry = entries[id], entry.connection == nil else { return false }
            entry.connection = connection; entries[id] = entry
            connection.activate()
            return entries[id] != nil
        }
        if !accepted { connection.close() }
        return accepted
    }
    func handshake(_ id: UUID) {
        lock.withLock {
            guard var entry = entries[id] else { return }
            entry.ready = true; entry.deadline?.cancel(); entry.deadline = nil; entries[id] = entry
        }
    }
    func remove(_ id: UUID) {
        let entry = lock.withLock { entries.removeValue(forKey: id) }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func expire(_ id: UUID) {
        let entry = lock.withLock { () -> Entry? in
            guard let entry = entries[id], !entry.ready else { return nil }
            return entries.removeValue(forKey: id)
        }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func close() {
        let removed = lock.withLock { () -> [Entry] in
            closed = true; running = false
            let removed = Array(entries.values); entries.removeAll(); return removed
        }
        for entry in removed { entry.deadline?.cancel(); entry.connection?.close() }
    }
}

private final class NativeAuthorityConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: AuthorityXPCEndpoint
    init(connection: NSXPCConnection, endpoint: AuthorityXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

/// Root Mach listener. Registration and protected installation are external prerequisites.
public final class AuthorityXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let policy: XPCPeerPolicy
    private let macID: Data
    private let accountID: Data
    private let budget: AuthorityXPCWorkBudget
    private let verifyHandshakePolicy: @Sendable () throws -> Void
    private let snapshot: @Sendable () throws -> DirectApprovalTrust
    private let validate: @Sendable (AuthorityPeerBinding) throws -> Bool
    private let frame: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
    private let pendingRequests: (@Sendable (AuthorityPeerBinding) throws -> [Data])?
    private let exchange: (@Sendable (AuthorityPeerBinding, Data, Data?) throws -> Data?)?
    private let receipt: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
    private let wakeHints: (@Sendable () throws -> AuthorityWakeHints)?
    private var running = false
    private var closed = false

    public init(serviceName: String, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000,
                maximumOperations: Int = 8,
                verifyHandshakePolicy: @escaping @Sendable () throws -> Void = {},
                snapshot: @escaping @Sendable () throws -> DirectApprovalTrust,
                validate: @escaping @Sendable (AuthorityPeerBinding) throws -> Bool,
                requestFrame: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)? = nil,
                pendingRequestIDs: (@Sendable (AuthorityPeerBinding) throws -> [Data])? = nil,
                exchangeRequest: (@Sendable (AuthorityPeerBinding, Data, Data?) throws -> Data?)? = nil,
                pairingReceipt: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)? = nil,
                wakeHints: (@Sendable () throws -> AuthorityWakeHints)? = nil) throws {
        guard serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              peerPolicy.expectedUserID != 0, macID.count == 16, accountID.count == 16 else { throw AuthorityXPCEndpointError.invalidConfiguration }
        registry = try AuthorityConnectionRegistry(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try AuthorityXPCWorkBudget(maximum: maximumOperations)
        listener = NSXPCListener(machServiceName: serviceName)
        policy = peerPolicy; self.macID = macID; self.accountID = accountID
        self.verifyHandshakePolicy = verifyHandshakePolicy; self.snapshot = snapshot; self.validate = validate; self.frame = requestFrame; self.pendingRequests = pendingRequestIDs; self.exchange = exchangeRequest
        self.wakeHints = wakeHints; self.receipt = pairingReceipt
        super.init()
        policy.configure(listener)
        listener.delegate = self
    }
    /// Bind authenticated transport RPCs to one serialized root journal owner.
    public convenience init(serviceName: String, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                            journal: AuthorityJournal, maximumPayloadBytes: Int,
                            minimumEnvelopeVersion: UInt64 = 1, auditVersions: Set<UInt64> = [],
                            maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000,
                            maximumOperations: Int = 8,
                            requestFrame: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data) throws -> Data?)? = nil,
                            pendingRequestIDs: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding) throws -> [Data])? = nil,
                            exchangeRequest: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data, Data?) throws -> Data?)? = nil,
                            pairingReceipt: AuthorityPairingReceiptProvider? = nil,
                            wakeHints: (@Sendable () throws -> AuthorityWakeHints)? = nil,
                            onCommandAuthorized: @escaping @Sendable (AuthorityCommandAuthorizationNotice) -> Void = { _ in }) throws {
        let access = try AuthorityTransportAccess(journal: journal, peerPolicy: peerPolicy, macID: macID, accountID: accountID,
            maximumPayloadBytes: maximumPayloadBytes, minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions)
        let frameHandler: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
        if let requestFrame {
            frameHandler = { binding, requestID in try access.requestFrame(binding: binding, requestID: requestID, handler: requestFrame) }
        } else { frameHandler = nil }
        let pendingHandler: (@Sendable (AuthorityPeerBinding) throws -> [Data])?
        if let pendingRequestIDs {
            pendingHandler = { binding in try access.pendingRequestIDs(binding: binding, handler: pendingRequestIDs) }
        } else { pendingHandler = nil }
        let exchangeHandler: (@Sendable (AuthorityPeerBinding, Data, Data?) throws -> Data?)?
        if let exchangeRequest {
            exchangeHandler = { binding, id, decision in
                try access.exchangeRequest(binding: binding, requestID: id, decisionFrame: decision, handler: exchangeRequest,
                    onCommandAuthorized: onCommandAuthorized)
            }
        } else { exchangeHandler = nil }
        let receiptHandler: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
        if let pairingReceipt {
            receiptHandler = { binding, setupID in try access.pairingReceipt(binding: binding, setupID: setupID, handler: pairingReceipt) }
        } else { receiptHandler = nil }
        try self.init(serviceName: serviceName, peerPolicy: peerPolicy, macID: macID, accountID: accountID,
            maximumConnections: maximumConnections, handshakeTimeoutMilliseconds: handshakeTimeoutMilliseconds,
            maximumOperations: maximumOperations, verifyHandshakePolicy: { try access.verifyCurrent() },
            snapshot: { try access.snapshot() }, validate: { try access.validate($0) },
            requestFrame: frameHandler, pendingRequestIDs: pendingHandler, exchangeRequest: exchangeHandler,
            pairingReceipt: receiptHandler, wakeHints: wakeHints)
    }
    deinit { listener.invalidate(); registry.close() }
    public func start() throws {
        try lock.withLock {
            guard geteuid() == 0, !running, !closed else { throw AuthorityXPCEndpointError.unavailable }
            try registry.start(); running = true; listener.activate()
        }
    }
    public func close() {
        lock.withLock { closed = true; running = false; listener.invalidate(); listener.delegate = nil }
        registry.close()
    }
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, running, !closed, let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                let endpoint = try AuthorityXPCEndpoint(connection: connection, peerPolicy: policy, macID: macID, accountID: accountID,
                    budget: budget, verifyHandshakePolicy: verifyHandshakePolicy, onHandshake: { [weak registry] in registry?.handshake(id) },
                    onClose: { [weak registry] in registry?.remove(id) }, snapshot: snapshot, validate: validate, requestFrame: frame,
                    pendingRequestIDs: pendingRequests, exchangeRequest: exchange, pairingReceipt: receipt, wakeHints: wakeHints)
                let owner = NativeAuthorityConnection(connection: connection, endpoint: endpoint)
                guard registry.install(owner, id: id) else { return false }
                return true
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
