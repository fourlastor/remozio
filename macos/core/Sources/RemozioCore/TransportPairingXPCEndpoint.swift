import Darwin
import Foundation
import RemozioProtocol

/// This local protocol carries setup claims and receipts, never administrator forms or command decisions.
@objc public protocol TransportPairingXPCProtocol {
    func setupHello(reply: @escaping @Sendable (UInt64) -> Void)
    func beginSetup(_ invitation: Data, reply: @escaping @Sendable (UInt64) -> Void)
    func setupCandidates(reply: @escaping @Sendable (Data?) -> Void)
    func stageSetup(_ candidateID: Data, transcript: Data, reply: @escaping @Sendable (Bool) -> Void)
    func deliverSetupReceipt(_ candidateID: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void)
    func cancelSetupCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void)
    func stopSetup(reply: @escaping @Sendable (Bool) -> Void)
}

final class TransportPairingXPCEndpoint: NSObject, TransportPairingXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let owner: TransportPairingSetupOwner
    private let verify: () throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private var ready = false
    private var closed = false
    private var jobs: [UUID: Task<Void, Never>] = [:]
    private var busy = false
    private var cleanup: Task<Void, Never>?
    convenience init(connection: NSXPCConnection, policy: XPCPeerPolicy, owner: TransportPairingSetupOwner,
                     onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws {
        _ = try policy.verifyCredentials(connection)
        let guarder = XPCInvocationGuard(connection: connection, policy: policy)
        self.init(owner: owner, verify: { _ = try guarder.verifyInvocation() },
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
    }
    // Logical endpoint controls do not prove native code identity, UID isolation or TLS.
    init(owner: TransportPairingSetupOwner, verify: @escaping () throws -> Void, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {}) {
        self.owner = owner; self.verify = verify; self.invalidate = invalidate; self.onHandshake = onHandshake
    }
    deinit { owner.abort() }
    func close() {
        let notify = lock.withLock {
            guard !closed else { return false }; closed = true; ready = false
            owner.abort()
            let owned = Array(jobs.values), owner = owner
            for task in owned { task.cancel() }
            cleanup = Task { await owner.closeAndWait(); for task in owned { await task.value } }
            return true
        }
        if notify { invalidate() }
    }
    func closeAndWait() async { close(); let task = lock.withLock { cleanup }; await task?.value }
    func setupHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try verify()
            try lock.withLock {
                guard !closed, !ready, jobs.isEmpty else { throw TransportPairingControlError.closed }; ready = true
            }
            onHandshake(); send { reply(1) }
        } catch { close(); reply(0) }
    }
    func beginSetup(_ invitation: Data, reply: @escaping @Sendable (UInt64) -> Void) {
        launch(failed: { reply(0) }) { owner in
            guard invitation.count <= 512 else { throw TransportPairingControlError.invalidMessage }
            let port = try await owner.begin(PairingInvitation.decode(invitation))
            return { reply(UInt64(port)) }
        }
    }
    func setupCandidates(reply: @escaping @Sendable (Data?) -> Void) {
        launch(failed: { reply(nil) }) { owner in
            let bytes = try await owner.snapshot().encode(); return { reply(bytes) }
        }
    }
    func stageSetup(_ candidateID: Data, transcript: Data, reply: @escaping @Sendable (Bool) -> Void) {
        launch(failed: { reply(false) }) { owner in
            guard candidateID.count == 16, transcript.count <= 132_000 else { throw TransportPairingControlError.invalidMessage }
            try await owner.stage(candidateID: candidateID, transcript: PairingTranscript.decode(transcript)); return { reply(true) }
        }
    }
    func deliverSetupReceipt(_ candidateID: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void) {
        launch(failed: { reply(false) }) { owner in
            guard candidateID.count == 16, signature.count == 64 else { throw TransportPairingControlError.invalidMessage }
            try await owner.deliverReceipt(candidateID: candidateID, signature: signature); return { reply(true) }
        }
    }
    func cancelSetupCandidate(_ candidateID: Data, reply: @escaping @Sendable (Bool) -> Void) {
        launch(failed: { reply(false) }) { owner in
            guard candidateID.count == 16 else { throw TransportPairingControlError.invalidMessage }
            try await owner.cancel(candidateID: candidateID); return { reply(true) }
        }
    }
    func stopSetup(reply: @escaping @Sendable (Bool) -> Void) {
        launch(failed: { reply(false) }) { owner in await owner.closeAndWait(); return { reply(true) } }
    }
    private func launch(failed: @escaping @Sendable () -> Void,
                        work: @escaping @Sendable (TransportPairingSetupOwner) async throws -> @Sendable () -> Void) {
        do {
            // Keep the invocation guard on the original NSXPC exported-method stack.
            try verify()
            try lock.withLock {
                guard !closed, ready, !busy, jobs.count < 4 else { throw TransportPairingControlError.busy }
                let id = UUID(), owner = owner
                busy = true
                let job = Task { [weak self] in
                    do {
                        try Task.checkCancellation(); let result = try await work(owner); try Task.checkCancellation()
                        self?.completed(id, reply: result)
                    } catch { self?.close(); failed() }
                }
                jobs[id] = job
                Task { [weak self] in await job.value; self?.reaped(id) }
            }
        } catch { close(); failed() }
    }
    private func completed(_ id: UUID, reply: @Sendable () -> Void) {
        lock.withLock { busy = false; if !closed { reply() } }
    }
    private func reaped(_ id: UUID) { lock.withLock { jobs[id] = nil } }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}
