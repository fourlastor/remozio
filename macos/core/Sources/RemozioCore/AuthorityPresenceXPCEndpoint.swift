import Foundation

/// Local Mac controls. This interface carries no phone approval, transport binding or credential-release operation.
@objc public protocol AuthorityPresenceXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func current(reply: @escaping @Sendable (Data?) -> Void)
    func publish(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
    func setMode(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Operations and disconnect share one lock. A closing observer cannot publish again after withdrawal.
final class AuthorityPresenceXPCEndpoint: NSObject, AuthorityPresenceXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let binding: AuthorityPresenceBinding
    private let budget: AuthorityXPCWorkBudget
    private let verify: () throws -> Void
    private let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
    private let verifyCurrent: @Sendable () throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private let withdraw: @Sendable () -> Void
    private let status: @Sendable () throws -> AuthorityPresenceStatus
    private let publishSnapshot: @Sendable (AuthorityPresencePublication) throws -> AuthorityPresenceStatus
    private let changeMode: @Sendable (AuthorityPresenceModeChange) throws -> AuthorityPresenceStatus
    private var ready = false
    private var closed = false
    private var busy = false
    private var sequence: UInt64 = 0
    private var lastTime: UInt64?
    convenience init(connection: NSXPCConnection, policy: XPCPeerPolicy, binding: AuthorityPresenceBinding,
                     budget: AuthorityXPCWorkBudget, access: AuthorityPresenceAccess,
                     onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws {
        guard policy.expectedUserID > 0 else { throw AuthorityPresenceError.invalidConfiguration }
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        self.init(binding: binding, budget: budget, verify: { _ = try invocation.verifyInvocation() },
            acquireActivity: { try access.acquireReleaseActivity() }, verifyCurrent: { try access.verifyCurrent() }, invalidate: { [weak connection] in connection?.invalidate(); onClose() },
            onHandshake: onHandshake, withdraw: { access.withdraw(observer: binding.connectionID) },
            status: { try access.status(binding: binding) }, publish: { try access.publish($0) }, setMode: { try access.setMode($0) })
        policy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: AuthorityPresenceXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    init(binding: AuthorityPresenceBinding, budget: AuthorityXPCWorkBudget, verify: @escaping () throws -> Void,
         acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken? = { nil },
         verifyCurrent: @escaping @Sendable () throws -> Void, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {}, withdraw: @escaping @Sendable () -> Void,
         status: @escaping @Sendable () throws -> AuthorityPresenceStatus,
         publish: @escaping @Sendable (AuthorityPresencePublication) throws -> AuthorityPresenceStatus,
         setMode: @escaping @Sendable (AuthorityPresenceModeChange) throws -> AuthorityPresenceStatus) {
        self.acquireActivity = acquireActivity
        self.binding = binding; self.budget = budget; self.verify = verify; self.verifyCurrent = verifyCurrent
        self.invalidate = invalidate; self.onHandshake = onHandshake; self.withdraw = withdraw
        self.status = status; publishSnapshot = publish; changeMode = setMode
    }
    deinit { withdraw() }
    func close() {
        let notify = lock.withLock {
            guard !closed else { return false }
            closed = true; ready = false; withdraw(); return true
        }
        if notify { invalidate() }
    }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work(handshake: true) { try verifyCurrent(); ready = true }
            defer { completed.activity?.close() }
            onHandshake()
            send { reply(1) }
        } catch { close(); reply(0) }
    }
    func current(reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) { try checkedStatus(status()) }
    }
    func publish(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            let value = try AuthorityPresenceCodec.decodePublication(payload)
            try consume(value.binding, sequence: value.sequence)
            return try checkedStatus(publishSnapshot(value))
        }
    }
    func setMode(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            let value = try AuthorityPresenceCodec.decodeModeChange(payload)
            try consume(value.binding, sequence: value.sequence)
            return try checkedStatus(changeMode(value))
        }
    }
    private func consume(_ received: AuthorityPresenceBinding, sequence next: UInt64) throws {
        guard received == binding else { throw AuthorityPresenceIPCError.invalidMessage }
        let expected = sequence.addingReportingOverflow(1)
        guard !expected.overflow, next == expected.partialValue else { throw AuthorityPresenceIPCError.staleOperation }
        sequence = next
    }
    private func checkedStatus(_ value: AuthorityPresenceStatus) throws -> Data {
        guard value.binding == binding, value.sampledAt.epoch == binding.clockEpoch,
              lastTime.map({ value.sampledAt.milliseconds >= $0 }) ?? true else { throw AuthorityPresenceIPCError.invalidMessage }
        lastTime = value.sampledAt.milliseconds
        return try AuthorityPresenceCodec.encodeStatus(value)
    }
    private func respond(_ reply: @escaping @Sendable (Data?) -> Void, _ body: () throws -> Data) {
        do {
            let completed = try work(body)
            defer { completed.activity?.close() }
            send { reply(completed.value) }
        }
        catch { close(); reply(nil) }
    }
    private func work<T>(handshake: Bool = false, _ body: () throws -> T) throws -> (value: T, activity: ReleaseActivityToken?) {
        // Keep OS identity validation on the original exported invocation stack.
        try verify()
        return try lock.withLock {
            guard !closed, ready != handshake, !busy, budget.acquire() else { throw AuthorityPresenceIPCError.unavailable }
            busy = true
            defer { busy = false; budget.release() }
            let activity = try acquireActivity()
            var transferred = false
            defer { if !transferred { activity?.close() } }
            let value = try body()
            try activity?.validate()
            transferred = true
            return (value, activity)
        }
    }
    private func send(_ body: () -> Void) { lock.withLock { if !closed { body() } } }
}
