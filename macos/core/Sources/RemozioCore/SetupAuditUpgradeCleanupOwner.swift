import Darwin
import Foundation

/// Keeps failed cleanup alive after connection disposal. Pending scope ownership also keeps daemon shutdown waiting.
final class SetupAuditUpgradeCleanupOwner: @unchecked Sendable {
    private let lock = NSLock()
    private let processID = getpid()
    private var pending: [ObjectIdentifier: SetupAuditUpgradeInvocation] = [:]
    private var settling: Set<ObjectIdentifier> = []

    /// Transfers retention before attempting cleanup. No lock is held while closing a possibly active invocation.
    func settle(_ invocation: SetupAuditUpgradeInvocation) -> Bool {
        guard getpid() == processID else { return false }
        let key = ObjectIdentifier(invocation)
        let admitted = lock.withLock { () -> Bool in
            pending[key] = invocation
            return settling.insert(key).inserted
        }
        guard admitted else { return false }
        let closed: Bool
        do { try invocation.close(); closed = true } catch { closed = false }
        lock.withLock {
            settling.remove(key)
            if closed { pending.removeValue(forKey: key) }
        }
        return closed
    }
    /// Attempts each retained cleanup once. This never resumes an upgrade, imports rights or starts services.
    func retry() -> Bool {
        guard getpid() == processID else { return false }
        let values = lock.withLock { Array(pending.values) }
        for invocation in values { _ = settle(invocation) }
        return lock.withLock { pending.isEmpty }
    }
}
