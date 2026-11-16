import Darwin
import Foundation

/// One active blocking maintenance worker. Large configuration values must not exhaust the Swift executor's small stack.
final class SetupAuditUpgradeWorkExecutor: @unchecked Sendable {
    static let stackBytes = 8 * 1024 * 1024
    private let lock = NSLock()
    private let processID = getpid()
    private var running = false
    private let name: String
    init(name: String = "Remozio audit upgrade") { self.name = name }

    /// Only this executor can mint the retryable result, before it starts any body.
    final class BusyBeforeBody: Error, @unchecked Sendable { fileprivate init() {} }
    func runRestorationPhase<Value: Sendable>(
        _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
        try await execute(cancellation: .init(), busy: BusyBeforeBody(), body)
    }
    func run<Value: Sendable>(cancellation: SetupAuditUpgradeCancellation = .init(),
                              _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
        try await execute(cancellation: cancellation, busy: AdministrativeSetupError.unavailable, body)
    }
    private func execute<Value: Sendable>(cancellation: SetupAuditUpgradeCancellation, busy: any Error,
        _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation(); try cancellation.check()
            return try await withCheckedThrowingContinuation { continuation in
                let admitted = lock.withLock { () -> Bool in
                    guard !running else { return false }; running = true; return true
                }
                guard admitted else { continuation.resume(throwing: busy); return }
                let thread = Thread { [self, cancellation] in
                    let result: Result<Value, any Error> = Result {
                        try cancellation.check()
                        guard pthread_get_stacksize_np(pthread_self()) >= Self.stackBytes else { throw AdministrativeSetupError.unavailable }
                        return try body(cancellation)
                    }
                    lock.withLock { running = false }
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
