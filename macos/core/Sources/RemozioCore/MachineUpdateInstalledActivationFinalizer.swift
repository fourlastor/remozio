import Foundation

/// Joins the activation owner before a fresh outcome check. Only a completed outcome can release its admission drain.
final class MachineUpdateInstalledActivationFinalizer: @unchecked Sendable {
    enum Outcome: Equatable, Sendable { case finishing, completed }
    enum Failure: Error, Equatable { case busy }
    struct Operations: Sendable {
        let join: @Sendable () async throws -> Void
        let observe: @Sendable () throws -> Outcome
        let release: @Sendable () -> Void
    }
    private let operations: Operations
    private let lock = NSLock()
    private var busy = false, joined = false, released = false
    init(operations: Operations) { self.operations = operations }

    /// A failed read or cancelled caller retains admission. A retry joins cleanup and reads the current outcome again.
    func finish() async throws -> Outcome {
        try Task.checkCancellation()
        let alreadyReleased = try lock.withLock { () throws -> Bool in
            guard !busy else { throw Failure.busy }
            if released { return true }
            busy = true; return false
        }
        if alreadyReleased { return .completed }
        defer { lock.withLock { busy = false } }
        if !lock.withLock({ joined }) {
            try await operations.join()
            lock.withLock { joined = true }
        }
        try Task.checkCancellation()
        let outcome = try operations.observe()
        try Task.checkCancellation()
        guard outcome == .completed else { return .finishing }
        operations.release()
        lock.withLock { released = true }
        return .completed
    }
}
