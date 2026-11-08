import Foundation

final class MachineUpdateHealthConnectionInvalidator: @unchecked Sendable {
    private weak var connection: NSXPCConnection?
    init(_ connection: NSXPCConnection) { self.connection = connection }
    func invalidate() { connection?.invalidate() }
}

protocol MachineUpdateConsumerHealthAnswering: AnyObject, Sendable {
    func answer(_ bytes: Data) throws -> Data
    func close() throws
}
/// One authenticated request per connection. Disconnect retains admitted resources until the owner actually closes.
final class MachineUpdateConsumerHealthXPCEndpoint: NSObject, MachineUpdateConsumerHealthXPCProtocol, @unchecked Sendable {
    static let version = MachineUpdateConsumerHealthChannel.wireVersion
    private let lock = NSRecursiveLock()
    private let settlement = NSLock()
    private let peer: MachineUpdateConsumerHealthPeer
    private let helloBytes: Data
    private let verifyCurrent: @Sendable () throws -> Void
    private let acquireActivity: @Sendable () throws -> any OwnedReleaseActivity
    private let makeOwner: @Sendable (MachineUpdateConsumerHealthRequest) async throws -> any MachineUpdateConsumerHealthAnswering
    private let budget: AuthorityXPCWorkBudget
    private let invalidate: @Sendable () -> Void
    private let onHandshake: @Sendable () -> Void
    private var ready = false
    private var consumed = false
    private var closed = false
    private var task: Task<Void, Never>?
    private var operationID: UUID?
    private var request: MachineUpdateConsumerHealthRequest?
    private var owner: (any MachineUpdateConsumerHealthAnswering)?
    private var activity: (any OwnedReleaseActivity)?
    private var budgetHeld = false

    /// Injected callbacks test settlement. Native construction must authenticate the connection and its completed host configuration.
    convenience init(peer: MachineUpdateConsumerHealthPeer, helloBytes: Data,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity,
        budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void = {},
        invalidate: @escaping @Sendable () -> Void,
        answerInstalledReadiness: @escaping @Sendable (MachineUpdateConsumerHealthRequest) async throws -> Data) {
        self.init(peer: peer, helloBytes: helloBytes, verifyCurrent: verifyCurrent, acquireActivity: acquireActivity,
            budget: budget, onHandshake: onHandshake, invalidate: invalidate, makeOwner: { request in
                try request.validate(); try Task.checkCancellation()
                let packet = try await answerInstalledReadiness(request)
                try Task.checkCancellation(); try request.validate()
                return try MachineUpdateInstalledReadinessReply(request: request, packet: packet)
            })
    }

    /// Injected owners and activity tokens test settlement. They do not authenticate native code or open retained credentials.
    init(peer: MachineUpdateConsumerHealthPeer, helloBytes: Data,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        acquireActivity: @escaping @Sendable () throws -> any OwnedReleaseActivity,
        budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void = {},
        invalidate: @escaping @Sendable () -> Void,
        makeOwner: @escaping @Sendable (MachineUpdateConsumerHealthRequest) async throws -> any MachineUpdateConsumerHealthAnswering) {
        self.peer = peer; self.helloBytes = helloBytes; self.verifyCurrent = verifyCurrent; self.acquireActivity = acquireActivity
        self.budget = budget; self.onHandshake = onHandshake; self.invalidate = invalidate; self.makeOwner = makeOwner
        super.init()
    }

    func healthHello(reply: @escaping @Sendable (UInt64, Data?) -> Void) {
        do {
            try peer.greet(); try verifyCurrent()
            try lock.withLock {
                guard !closed, !ready, !consumed else { throw MachineUpdateRoleChallengeError.unavailable }
                ready = true; onHandshake(); reply(Self.version, helloBytes)
            }
        } catch { close(); reply(0, nil) }
    }
    func checkUpdateHealth(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            try lock.withLock {
                guard !closed, ready, !consumed else { throw MachineUpdateRoleChallengeError.unavailable }
                // Keep authentication on the exported invocation stack, before the task or any owner opening.
                let accepted = try peer.accept(payload)
                guard budget.acquire() else { accepted.close(); throw MachineUpdateRoleChallengeError.unavailable }
                consumed = true; budgetHeld = true; request = accepted
                let id = UUID(); operationID = id
                task = Task { [self] in await perform(accepted, id: id, reply: reply) }
            }
        } catch { close(); reply(nil) }
    }

    private func perform(_ accepted: MachineUpdateConsumerHealthRequest, id: UUID,
        reply: @escaping @Sendable (Data?) -> Void) async {
        var result: Data?
        do {
            try Task.checkCancellation(); try accepted.validate(); try verifyCurrent()
            let token = try acquireActivity()
            lock.withLock { activity = token }
            try token.validate(); try Task.checkCancellation(); try accepted.validate()
            let opened = try await makeOwner(accepted)
            lock.withLock { owner = opened }
            try Task.checkCancellation(); try token.validate(); try accepted.validate(); try verifyCurrent()
            let bytes = try opened.answer(accepted.bytes)
            try Task.checkCancellation(); try token.validate(); try accepted.validate(); try verifyCurrent()
            result = bytes
        } catch { result = nil }
        do { try settleResources(id) }
        catch { result = nil; close() }
        lock.withLock { if !closed { reply(result) } }
    }

    /// A failed close retains the owner, activity token and budget. A later joined close can retry settlement.
    private func settleResources(_ id: UUID) throws {
        try settlement.withLock {
            let resources = lock.withLock { () -> ((any MachineUpdateConsumerHealthAnswering)?, (any OwnedReleaseActivity)?, MachineUpdateConsumerHealthRequest?)? in
                guard operationID == id else { return nil }; return (owner, activity, request)
            }
            guard let resources else { return }
            try resources.0?.close()
            resources.1?.close(); resources.2?.close()
            lock.withLock {
                guard operationID == id else { return }
                owner = nil; activity = nil; request = nil
                if budgetHeld { budgetHeld = false; budget.release() }
            }
        }
    }
    func close() {
        let closing = lock.withLock { () -> (Bool, Task<Void, Never>?) in
            guard !closed else { return (false, task) }
            closed = true; ready = false; return (true, task)
        }
        if closing.0 { peer.close(); invalidate(); closing.1?.cancel() }
    }
    /// Wait for the admitted task before retrying any failed owner close. The enclosing host must retain its scope on an error.
    func closeAndWait() async throws {
        close()
        let pending = lock.withLock { (task, operationID) }
        await pending.0?.value
        if let id = pending.1 { try settleResources(id) }
        lock.withLock { task = nil; operationID = nil }
    }
}
