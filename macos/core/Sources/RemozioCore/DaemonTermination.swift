import Dispatch
import RemozioMach
import Synchronization

/// Process-wide termination capture for one daemon worker. Install before opening any service.
public final class DaemonTermination: Sendable {
    public enum Failure: Error { case installation(Int32) }

    private let source: any DispatchSourceRead
    private let worker = Mutex<Task<Void, any Error>?>(nil)

    public init() throws {
        var descriptor: Int32 = -1
        let result = remozio_daemon_termination_install(&descriptor)
        guard result == 0 else { throw Failure.installation(result) }
        source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: .global())
        source.setEventHandler { [weak self] in
            self?.cancelWorker()
        }
        source.activate()
    }

    var requested: Bool { remozio_daemon_termination_requested() }

    public func checkCancellation() throws {
        if requested { throw CancellationError() }
        try Task.checkCancellation()
    }

    public func run(_ operation: @escaping @Sendable () async throws -> Void) async throws {
        try checkCancellation()
        let task = Task {
            try checkCancellation()
            try await operation()
        }
        worker.withLock { $0 = task }
        defer { worker.withLock { $0 = nil }; source.cancel() }
        if requested { task.cancel() }
        try await withTaskCancellationHandler {
            try await task.value
        } onCancel: { task.cancel() }
    }

    private func cancelWorker() {
        let task = worker.withLock { $0 }
        task?.cancel()
        source.cancel()
    }
}
