import Darwin
import Foundation

/// One active blocking maintenance worker. Large configuration values must not exhaust the Swift executor's small stack.
final class SetupAuditUpgradeWorkExecutor: @unchecked Sendable {
    static let stackBytes = 8 * 1024 * 1024
    private let lock = NSLock()
    private let processID = getpid()
    private var running = false
    private var ownedAttempts: OwnedAttempts?
    final class OwnedAttempts: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func countOwned() throws -> Int {
            try RuntimeMaintenanceOwnedControl.require(); return lock.withLock { count }
        }
        fileprivate func record() throws {
            try RuntimeMaintenanceOwnedControl.require(); lock.withLock { count += 1 }
        }
    }
    func observeAttemptsOwned() throws -> OwnedAttempts {
        try RuntimeMaintenanceOwnedControl.require()
        return lock.withLock {
            if let ownedAttempts { return ownedAttempts }
            let probe = OwnedAttempts(); ownedAttempts = probe; return probe
        }
    }
    private let name: String
    init(name: String = "Remozio audit upgrade") { self.name = name }

    /// Only this executor can mint the retryable result, before it starts any body.
    final class BusyBeforeBody: Error, @unchecked Sendable { fileprivate init() {} }
    /// The hook runs once after the body returns, or before a refusal resumes the caller.
    func runRestorationPhase<Value: Sendable>(cancellation: SetupAuditUpgradeCancellation = .init(),
        afterReturn: (@Sendable () -> Void)? = nil,
        _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
        try await execute(cancellation: cancellation, busy: BusyBeforeBody(), afterReturn: afterReturn ?? {}, body)
    }
    func run<Value: Sendable>(cancellation: SetupAuditUpgradeCancellation = .init(), afterReturn: (@Sendable () -> Void)? = nil,
                              _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
        try await execute(cancellation: cancellation, busy: AdministrativeSetupError.unavailable, afterReturn: afterReturn ?? {}, body)
    }
    private func execute<Value: Sendable>(cancellation: SetupAuditUpgradeCancellation, busy: any Error,
        afterReturn: @escaping @Sendable () -> Void,
        _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
        guard getpid() == processID else { afterReturn(); throw AdministrativeSetupError.unavailable }
        let probe = lock.withLock { ownedAttempts }
        do { try probe?.record() } catch { afterReturn(); throw error }
        return try await withTaskCancellationHandler {
            do { try Task.checkCancellation(); try cancellation.check() } catch { afterReturn(); throw error }
            return try await withCheckedThrowingContinuation { continuation in
                let admitted = lock.withLock { () -> Bool in
                    guard !running else { return false }; running = true; return true
                }
                guard admitted else { afterReturn(); continuation.resume(throwing: busy); return }
                let thread = Thread { [self, cancellation] in
                    let result: Result<Value, any Error> = Result {
                        try cancellation.check()
                        guard pthread_get_stacksize_np(pthread_self()) >= Self.stackBytes else { throw AdministrativeSetupError.unavailable }
                        return try body(cancellation)
                    }
                    lock.withLock { running = false }
                    afterReturn()
                    continuation.resume(with: result)
                }
                thread.name = self.name
                thread.qualityOfService = .userInitiated
                thread.stackSize = Self.stackBytes
                thread.start()
            }
        } onCancel: { cancellation.cancel() }
    }
}
