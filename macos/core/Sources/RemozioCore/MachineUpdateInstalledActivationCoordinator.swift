import Foundation

/// Joins registration and readiness owners. It never owns a callback that can release the original admission drain.
final class MachineUpdateInstalledActivationCoordinator<Commit: Sendable>: @unchecked Sendable {
    enum Failure: Error, Equatable { case busy, closed, changedScope, recoveryRequired }
    enum RegistrationProgress: Sendable { case pending(Set<Data>), confirmed(Set<Data>) }
    struct RegistrationCheckpoint: Sendable {
        let expected: Set<Data>
        let progress: RegistrationProgress
    }
    enum Progress: Sendable { case pending(Set<Data>), committed(Commit) }
    struct Operations: Sendable {
        let validate: @Sendable () throws -> Void
        let pollRegistrations: @Sendable () throws -> RegistrationCheckpoint
        let closeRegistrations: @Sendable () throws -> Void
        let commitReadiness: @Sendable () async throws -> Commit
        let closeReadiness: @Sendable () async throws -> Void
    }
    private enum Phase { case registrations, closingRegistrations, committing, closingReadiness(Commit), committed(Commit), recoveryRequired }
    private let lock = NSLock()
    private let operations: Operations
    private var phase = Phase.registrations
    private var expected: Set<Data>?
    private var operation: Task<Progress, Error>?
    private var settlement: Task<Void, Error>?
    private var closed = false, cleanupComplete = false
    var isClosed: Bool { lock.withLock { closed } }

    /// Owned operations test sequencing. Only the native adapter can return the actual store's commit receipt.
    init(operations: Operations) { self.operations = operations }
    func advance() async throws -> Progress {
        try Task.checkCancellation()
        let task = try lock.withLock { () throws -> Task<Progress, Error> in
            guard !closed else { throw Failure.closed }
            guard operation == nil else { throw Failure.busy }
            let task = Task { [self] in
                defer { lock.withLock { operation = nil } }
                return try await perform()
            }
            operation = task; return task
        }
        let progress = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        try Task.checkCancellation(); return progress
    }
    private func requireOpen() throws {
        try Task.checkCancellation()
        try lock.withLock { guard !closed else { throw Failure.closed } }
        try operations.validate()
    }
    private func check(_ checkpoint: RegistrationCheckpoint) throws -> Set<Data>? {
        guard checkpoint.expected.count <= 128, checkpoint.expected.allSatisfy({ $0.count == 16 }) else { throw Failure.changedScope }
        try lock.withLock {
            if let expected { guard expected == checkpoint.expected else { throw Failure.changedScope } }
            else { expected = checkpoint.expected }
        }
        switch checkpoint.progress {
        case .pending(let pending):
            guard !pending.isEmpty, pending.isSubset(of: checkpoint.expected) else { throw Failure.changedScope }
            return pending
        case .confirmed(let confirmed):
            guard confirmed == checkpoint.expected else { throw Failure.changedScope }
            return nil
        }
    }
    private func perform() async throws -> Progress {
        var cleanupAttempted = false
        do {
            while true {
                try requireOpen()
                switch lock.withLock({ phase }) {
                case .registrations:
                    let checkpoint = try operations.pollRegistrations()
                    try requireOpen()
                    if let pending = try check(checkpoint) { return .pending(pending) }
                    lock.withLock { phase = .closingRegistrations }
                case .closingRegistrations:
                    try operations.closeRegistrations(); try requireOpen()
                    lock.withLock { phase = .committing }
                case .committing:
                    do {
                        let receipt = try await operations.commitReadiness()
                        lock.withLock { phase = .closingReadiness(receipt) }
                    } catch {
                        lock.withLock { phase = .recoveryRequired }
                        throw error
                    }
                case .closingReadiness(let receipt):
                    cleanupAttempted = true; try await operations.closeReadiness()
                    try requireOpen()
                    lock.withLock { phase = .committed(receipt) }
                    return .committed(receipt)
                case .committed(let receipt): return .committed(receipt)
                case .recoveryRequired: throw Failure.recoveryRequired
                }
            }
        } catch {
            let failure = error
            if !cleanupAttempted { try await operations.closeReadiness() }
            throw failure
        }
    }
    /// Cancellation joins the current operation before resource cleanup. Closing this owner cannot release admission.
    func close() async throws {
        let task = lock.withLock { () -> Task<Void, Error>? in
            guard !cleanupComplete else { return nil }
            closed = true
            if let settlement { return settlement }
            let operation = operation, operations = operations
            operation?.cancel()
            let task = Task {
                _ = try? await operation?.value
                try operations.closeRegistrations(); try await operations.closeReadiness()
            }
            settlement = task; return task
        }
        guard let task else { return }
        do { try await task.value; lock.withLock { cleanupComplete = true; settlement = nil } }
        catch { lock.withLock { settlement = nil }; throw error }
    }
    deinit {
        guard !cleanupComplete else { return }
        let operation = operation, settlement = settlement, operations = operations
        Task {
            if let settlement, (try? await settlement.value) != nil { return }
            operation?.cancel(); _ = try? await operation?.value
            while true {
                do { try operations.closeRegistrations(); try await operations.closeReadiness(); return }
                catch { try? await Task.sleep(for: .milliseconds(100)) }
            }
        }
    }
}
