import Foundation

/// Dispatch ready TLS slots in arrival order. Admission allows just one pending slot per source.
final class PairingSetupV2RegistrationLane: @unchecked Sendable {
    private struct Request {
        let id: UUID
        let deadline: ContinuousClock.Instant
        let continuation: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var active: UUID?
    private var waiting: [Request] = []

    var waitingCount: Int { lock.withLock { waiting.count } }

    func withTurn<Value>(until deadline: ContinuousClock.Instant,
                         _ work: () async throws -> Value) async throws -> Value {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.withLock {
                    guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                    guard ContinuousClock.now < deadline, waiting.count < PairingSetupV2Admissions.maximumPending else {
                        continuation.resume(throwing: PairingSetupChannelError.rejected)
                        return
                    }
                    waiting.append(.init(id: id, deadline: deadline, continuation: continuation))
                    grantNext()
                }
            }
        } onCancel: { self.cancel(id) }

        defer {
            lock.withLock {
                active = nil
                grantNext()
            }
        }
        try Task.checkCancellation()
        guard ContinuousClock.now < deadline else { throw PairingSetupChannelError.rejected }
        return try await work()
    }

    private func cancel(_ id: UUID) {
        lock.withLock {
            guard let index = waiting.firstIndex(where: { $0.id == id }) else { return }
            waiting.remove(at: index).continuation.resume(throwing: CancellationError())
        }
    }

    private func grantNext() {
        guard active == nil else { return }
        while !waiting.isEmpty {
            let next = waiting.removeFirst()
            guard ContinuousClock.now < next.deadline else {
                next.continuation.resume(throwing: PairingSetupChannelError.rejected)
                continue
            }
            active = next.id
            next.continuation.resume()
            return
        }
    }
}
