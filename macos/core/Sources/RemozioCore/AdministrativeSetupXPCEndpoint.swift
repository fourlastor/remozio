import Darwin
import Foundation
import Security

/// Version 1 local administrative interface. Hello must succeed before sending an external authorization form.
@objc public protocol AdministrativeSetupXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void)
    func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                              reply: @escaping @Sendable (Data?) -> Void)
}

/// One authenticated local app connection. A shared owner serializes every machine-store operation.
/// The listener must enforce this peer policy, retain the connection and activate it only after construction succeeds.
public final class AdministrativeSetupXPCEndpoint: NSObject, AdministrativeSetupXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let owner: SetupAccountOwner
    private let verify: () throws -> uid_t
    private let authorize: (Data) throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private var ready = false
    private var closed = false
    private var busy = false

    public convenience init(connection: NSXPCConnection, peerPolicy: XPCPeerPolicy, owner: SetupAccountOwner,
                            onHandshake: @escaping @Sendable () -> Void = {}, onClose: @escaping @Sendable () -> Void = {}) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard peerPolicy.expectedUserID > 0, peerPolicy.expectedUserID < UInt32.max else {
            throw AdministrativeSetupError.invalidConfiguration
        }
        _ = try peerPolicy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: peerPolicy)
        try owner.verifyCurrent()
        self.init(owner: owner, verify: { try invocation.verifyInvocation().userID },
            authorize: { try SetupAdministratorAuthorization.validate(externalForm: $0, invocation: invocation) },
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
        peerPolicy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    // Fixtures prove sequencing and scoped storage only. Product callers cannot inject authorization or invocation checks.
    init(owner: SetupAccountOwner, verify: @escaping () throws -> uid_t,
         authorize: @escaping (Data) throws -> Void, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {}) {
        self.owner = owner; self.verify = verify; self.authorize = authorize; self.invalidate = invalidate; self.onHandshake = onHandshake
    }
    public func close() {
        let changed = lock.withLock { if closed { return false }; closed = true; ready = false; return true }
        if changed { invalidate() }
    }
    public func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try operation(handshake: true) { _ in try owner.verifyCurrent(); ready = true }
            onHandshake()
            send { reply(1) }
        } catch { close(); reply(0) }
    }
    public func accountStorageProgress(_ accountID: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard accountID.count == 16 else { throw AdministrativeSetupError.invalidConfiguration }
                return try owner.progress(accountID: accountID, callerUID: uid).map { try SetupAccountProgress($0).bytes } ?? Data()
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func resumeAccountStorage(_ accountID: Data, setupID: Data, expectedRevision: Data, authorization: Data,
                                     reply: @escaping @Sendable (Data?) -> Void) {
        do {
            let bytes = try operation { uid in
                guard accountID.count == 16, setupID.count == 16, expectedRevision.count == 16,
                      authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AdministrativeSetupError.invalidConfiguration
                }
                // Import current native rights during this exported invocation. Never retain or forward the external form.
                try authorize(authorization)
                return try SetupAccountProgress(owner.resumeAccount(accountID: accountID, setupID: setupID,
                    expectedRevision: expectedRevision, callerUID: uid)).bytes
            }
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    private func operation<T>(handshake: Bool = false, _ body: (uid_t) throws -> T) throws -> T {
        let uid = try verify()
        return try lock.withLock {
            guard !closed, !busy, ready != handshake else { throw AdministrativeSetupError.unavailable }
            busy = true; defer { busy = false }
            return try body(uid)
        }
    }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}
