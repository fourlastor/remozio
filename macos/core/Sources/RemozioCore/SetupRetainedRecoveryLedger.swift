import Darwin
import Foundation

/// Actual owners and monotonic facts only. Joined resources grant no restoration or admission-release authority.
final class SetupRetainedRecoveryLedger: @unchecked Sendable {
    struct Evidence: Equatable, Sendable {
        let neverEntered: Bool, stopNeverPossible: Bool, windowWriteNeverPossible: Bool
        let workersRegistered: Int, workersJoined: Int, contextLoansStarted: Int, contextLoansReturned: Int
        let cleanupRegistered: Int, cleanupReturned: Int, invocationCleanupReturned: Bool
    }
    private struct Worker { let id: UUID, task: Task<Void, Never> }
    private struct Cleanup { let id: UUID, close: () throws -> Void }
    private let process = getpid(), lock = NSLock()
    private var entered = false, stopPossible = false, windowWritePossible = false, sealed = false
    private var closingCleanup = false
    private let executor: SetupAuditUpgradeWorkExecutor?
    private var workers: [Worker] = [], workersJoined: Set<UUID> = []
    private var activeLoans: Set<UUID> = [], loansStarted = 0, loansReturned = 0
    private var cleanup: [Cleanup] = [], cleanupRegistered = 0, cleanupReturned = 0
    private var deinitReturned = false
    private var deinitWaiters: [CheckedContinuation<Void, Never>] = []
    private var joinTask: Task<Void, any Error>?
    private var joinFailed = false, joined = false
    private static let maximumOwners = 128

    init(executor: SetupAuditUpgradeWorkExecutor?) { self.executor = executor }
    /// Every path that produces a writable window for this invocation must pass this latch before returning metadata.
    /// authorizedMaintenanceWindow is currently the only such path. Never clear this fact.
    func windowMayBeWritten() throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock { guard !sealed else { throw JournalLeaseError.invalidated }; windowWritePossible = true }
    }
    func beginWorker() throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !sealed else { throw JournalLeaseError.invalidated }
            entered = true; stopPossible = true
        }
    }
    /// Register the actual task before any loan. Registration conservatively forbids a never-entered proof.
    func retainWorker(_ task: Task<Void, Never>) throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !sealed, workers.count < Self.maximumOwners else { throw AdministrativeSetupError.unavailable }
            entered = true; stopPossible = true; workers.append(.init(id: UUID(), task: task))
        }
    }
    /// This ledger records the synchronous context loan's return, not a substitute proof that a native store closed.
    func withContextLoan<Value>(_ body: () throws -> Value) throws -> Value {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        let id = try lock.withLock {
            guard !sealed, entered, loansStarted < Self.maximumOwners else { throw JournalLeaseError.invalidated }
            let id = UUID(); activeLoans.insert(id); loansStarted += 1; return id
        }
        defer { lock.withLock { if activeLoans.remove(id) != nil { loansReturned += 1 } } }
        return try body()
    }
    /// Register the real cleanup owner before borrowing. Its close must be idempotent after a known cleanup failure.
    func retainCleanup(_ close: @escaping () throws -> Void) throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !sealed, cleanupRegistered < Self.maximumOwners else { throw AdministrativeSetupError.unavailable }
            cleanup.append(.init(id: UUID(), close: close)); cleanupRegistered += 1
        }
    }
    func invocationCleanupReturned() {
        guard getpid() == process else { return }
        let waiting = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            deinitReturned = true; let waiting = deinitWaiters; deinitWaiters = []; return waiting
        }
        for waiter in waiting { waiter.resume() }
    }
    private func waitForInvocationCleanup() async {
        await withCheckedContinuation { continuation in
            let ready = lock.withLock {
                if deinitReturned { return true }; deinitWaiters.append(continuation); return false
            }
            if ready { continuation.resume() }
        }
    }
    func sealForClaim() throws -> Task<Void, any Error>? {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        let completed = lock.withLock { () -> Task<Void, any Error>? in
            sealed = true
            guard joinFailed else { return nil }
            joinFailed = false; let old = joinTask; joinTask = nil; return old
        }
        // The caller must retain this task until both owner and record locks have been released.
        return completed
    }
    func joinWorkers() async throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        let actual = lock.withLock { workers }
        for worker in actual { worker.task.cancel() }
        for worker in actual {
            await worker.task.value
            lock.withLock { _ = workersJoined.insert(worker.id) }
        }
    }
    func closeSynchronousCleanup() throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !closingCleanup, activeLoans.isEmpty, workers.allSatisfy({ workersJoined.contains($0.id) }) else {
                throw AdministrativeSetupError.unavailable
            }
            closingCleanup = true
        }
        defer { lock.withLock { closingCleanup = false } }
        while let owner = lock.withLock({ cleanup.last }) {
            try owner.close()
            let removed = lock.withLock { () -> Cleanup? in
                guard cleanup.last?.id == owner.id else { return nil }
                cleanupReturned += 1; return cleanup.popLast()
            }
            withExtendedLifetime((owner, removed)) {}
        }
    }
    /// The task survives its caller. Cancellation cannot turn a pending actual join into a completed resource.
    func joinSealed() throws -> Task<Void, any Error> {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            guard sealed else { throw JournalLeaseError.invalidated }
            if let joinTask { return joinTask }
            let task = Self.launchJoin(self); joinTask = task; return task
        }
    }
    private nonisolated static func launchJoin(_ ledger: SetupRetainedRecoveryLedger) -> Task<Void, any Error> {
        Task {
            do {
                await ledger.waitForInvocationCleanup()
                try await ledger.joinWorkers()
                guard let executor = ledger.executor else { throw AdministrativeSetupError.unavailable }
                try await executor.run { _ in try ledger.closeSynchronousCleanup() }
                try ledger.lock.withLock {
                    guard ledger.activeLoans.isEmpty, ledger.deinitReturned,
                          ledger.workersJoined.count == ledger.workers.count,
                          ledger.cleanupReturned == ledger.cleanupRegistered else { throw JournalLeaseError.invalidated }
                    ledger.joined = true
                }
            } catch { ledger.lock.withLock { ledger.joinFailed = true }; throw error }
        }
    }
    func snapshot() -> Evidence {
        lock.withLock { .init(neverEntered: !entered, stopNeverPossible: !stopPossible, windowWriteNeverPossible: !windowWritePossible,
            workersRegistered: workers.count, workersJoined: workersJoined.count,
            contextLoansStarted: loansStarted, contextLoansReturned: loansReturned,
            cleanupRegistered: cleanupRegistered, cleanupReturned: cleanupReturned,
            invocationCleanupReturned: deinitReturned) }
    }
    func requireJoined() throws -> Evidence {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard sealed, joined, !closingCleanup, deinitReturned, activeLoans.isEmpty,
                  workersJoined.count == workers.count, cleanupReturned == cleanupRegistered else {
                throw JournalLeaseError.invalidated
            }
        }
        return snapshot()
    }
    func workerStatus(synchronous: Bool) -> SetupRetainedInvocationStatus.Fact<SetupRetainedInvocationStatus.Worker> {
        guard getpid() == process, lock.try() else { return .unavailable }; defer { lock.unlock() }
        return .observed(synchronous ? .running : (workersJoined.count == workers.count ? .idle : .registered))
    }
    func status() -> SetupRetainedInvocationStatus.Fact<SetupRetainedInvocationStatus.Cleanup> {
        guard getpid() == process, lock.try() else { return .unavailable }; defer { lock.unlock() }
        if joined { return .observed(.joined) }
        if joinTask != nil && !joinFailed { return .observed(.joining) }
        if !cleanup.isEmpty { return .observed(.pending) }
        return .observed(.noneRegistered)
    }
}
