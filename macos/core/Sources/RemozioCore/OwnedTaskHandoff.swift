import Foundation
import Synchronization

/// Publishes one owned task after a synchronous reservation. An empty reservation is never completion proof.
final class OwnedTaskHandoff: Sendable {
    private struct State {
        var task: Task<Void, Never>?
        var cancelled = false
        var waiters: [CheckedContinuation<Task<Void, Never>, Never>] = []
    }
    private let state = Mutex(State())
    private let onCancel: @Sendable () -> Void
    init(onCancel: @escaping @Sendable () -> Void = {}) { self.onCancel = onCancel }
    func install(_ task: Task<Void, Never>) {
        let pending = state.withLock { value in
            precondition(value.task == nil)
            value.task = task
            let waiters = value.waiters; value.waiters = []
            return (value.cancelled, waiters)
        }
        if pending.0 { task.cancel() }
        for waiter in pending.1 { waiter.resume(returning: task) }
    }
    func cancel() {
        let pending = state.withLock { value in
            let first = !value.cancelled; value.cancelled = true; return (first, value.task)
        }
        if pending.0 { onCancel() }
        pending.1?.cancel()
    }
    /// A cancelled waiter still joins the installed task's terminal result.
    func wait() async {
        let task = await withCheckedContinuation { waiter in
            let task: Task<Void, Never>? = state.withLock { value in
                if let task = value.task { return task }
                value.waiters.append(waiter); return nil
            }
            if let task { waiter.resume(returning: task) }
        }
        await task.value
    }
}

/// Keeps reservations until their actual tasks finish. Reaping does not need a callback onto the owning actor.
final class OwnedTaskHandoffRegistry: Sendable {
    private let values = Mutex([UUID: OwnedTaskHandoff]())
    func reserve() -> OwnedTaskHandoff {
        let id = UUID(), work = OwnedTaskHandoff()
        values.withLock { $0[id] = work }
        Task { [self] in await work.wait(); values.withLock { $0[id] = nil } }
        return work
    }
    func cancelAll() { for value in values.withLock({ Array($0.values) }) { value.cancel() } }
    /// The owner closes admission before joining. Late synchronous handoffs remain represented by their reservations.
    func waitAll() async {
        while true {
            let pending = values.withLock { Array($0) }
            if pending.isEmpty { return }
            for (id, work) in pending {
                await work.wait()
                values.withLock { if $0[id] === work { $0[id] = nil } }
            }
        }
    }
}
