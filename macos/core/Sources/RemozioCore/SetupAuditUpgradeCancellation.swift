import Darwin
import Foundation

/// Cancellation for a maintenance worker outside the Swift executor. Cancellation never grants rights or releases resources.
final class SetupAuditUpgradeCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private let processID = getpid()
    private var cancelled = false
    func cancel() {
        guard getpid() == processID else { return }
        lock.withLock { cancelled = true }
    }
    func check() throws {
        guard getpid() == processID else { throw CancellationError() }
        try lock.withLock { if cancelled { throw CancellationError() } }
    }
}
