import Darwin
import Foundation

@objc public protocol GatewaySettingsControlXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64, Data?) -> Void)
    func control(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// One authenticated operation per connection. This endpoint is separate from app and phone interfaces.
/// Disconnect cancels admitted work. Its budget remains held until that work actually settles.
final class GatewaySettingsControlXPCEndpoint: NSObject, GatewaySettingsControlXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let binding: GatewaySettingsControlBinding
    private let verify: () throws -> Void
    private let verifyCurrent: @Sendable () throws -> Void
    private let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
    private let budget: AuthorityXPCWorkBudget
    private let execute: @Sendable (GatewaySettingsControlRequest) async throws -> GatewaySettingsControlObservation
    private let onHandshake: @Sendable () -> Void
    private let invalidate: () -> Void
    private var ready = false
    private var closed = false
    private var consumed = false
    private var task: Task<Void, Never>?
    private var operationID: UUID?

    convenience init(connection: NSXPCConnection, setupCode: AuthorityCodeEntry, access: AuthorityGatewaySettingsAccess,
                     budget: AuthorityXPCWorkBudget,
                     acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken?,
                     onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws {
        guard getuid() == 0, geteuid() == 0, setupCode.role == .setupController, setupCode.active else {
            throw GatewayPreparationError.changedScope
        }
        let policy = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        self.init(binding: access.binding, verify: { _ = try invocation.verifyInvocation() }, verifyCurrent: access.verifyCurrent,
            acquireActivity: acquireActivity, budget: budget, onHandshake: onHandshake,
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, execute: { try await access.execute($0) })
        policy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: GatewaySettingsControlXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    // Owned invocation controls cannot prove native UID or code admission.
    init(binding: GatewaySettingsControlBinding, verify: @escaping () throws -> Void,
         verifyCurrent: @escaping @Sendable () throws -> Void,
         acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken? = { nil },
         budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void = {},
         invalidate: @escaping () -> Void,
         execute: @escaping @Sendable (GatewaySettingsControlRequest) async throws -> GatewaySettingsControlObservation) {
        self.binding = binding; self.verify = verify; self.verifyCurrent = verifyCurrent; self.acquireActivity = acquireActivity
        self.budget = budget; self.onHandshake = onHandshake; self.invalidate = invalidate; self.execute = execute
    }
    func close() {
        let result = lock.withLock { () -> (Bool, Task<Void, Never>?) in
            guard !closed else { return (false, nil) }
            closed = true; ready = false; return (true, task)
        }
        if result.0 { invalidate(); result.1?.cancel() }
    }
    /// Join admitted work before the enclosing runtime closes its journal.
    func closeAndWait() async {
        close()
        let pending = lock.withLock { task }
        await pending?.value
    }
    func hello(reply: @escaping @Sendable (UInt64, Data?) -> Void) {
        do {
            try verify(); try verifyCurrent()
            let bytes = try binding.encoded
            try lock.withLock {
                guard !closed, !ready, !consumed else { throw GatewayPreparationError.changedScope }
                ready = true; onHandshake(); reply(GatewaySettingsControlInterface.version, bytes)
            }
        } catch { close(); reply(0, nil) }
    }
    func control(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            // Authenticate on the exported invocation stack, before crossing to an asynchronous operation.
            try verify()
            let request = try GatewaySettingsControlRequest.decode(payload)
            try lock.withLock {
                guard ready, !closed, !consumed, request.binding == binding, budget.acquire() else {
                    throw GatewayPreparationError.changedScope
                }
                consumed = true
                let id = UUID(); operationID = id
                task = Task { [self] in
                    defer { finish(id) }
                    do {
                        let bytes = try await response(for: request)
                        lock.withLock { finish(id); if !closed { reply(bytes) } }
                    } catch { lock.withLock { finish(id); if !closed { reply(nil) } } }
                }
            }
        } catch { close(); reply(nil) }
    }
    /// Finish the scoped lease before releasing the operation budget or invoking a completion callback.
    private func response(for request: GatewaySettingsControlRequest) async throws -> Data {
        let activity = try acquireActivity(); defer { activity?.close() }
        try verifyCurrent(); try activity?.validate(); try Task.checkCancellation()
        let observation = try await execute(request)
        try verifyCurrent(); try activity?.validate(); try Task.checkCancellation()
        return try GatewaySettingsControlResponse(request: request, observation: observation).encoded
    }
    private func finish(_ id: UUID) {
        lock.withLock {
            guard operationID == id else { return }
            operationID = nil; task = nil; budget.release()
        }
    }
}
