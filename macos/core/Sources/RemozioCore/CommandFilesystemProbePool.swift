import Foundation

enum CommandFilesystemProbeError: Error, Equatable {
    case atCapacity, expired
}

/// A result belongs to one phase and can be consumed once. The pool owns the slot until the work returns.
final class CommandFilesystemProbe<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private let completed = DispatchSemaphore(value: 0)
    let deadline: ContinuousClock.Instant
    private var result: Result<Value, Error>?
    private var retired = false

    init(deadline: ContinuousClock.Instant) {
        self.deadline = deadline
    }

    func complete(_ result: Result<Value, Error>) {
        lock.withLock {
            if !retired, ContinuousClock.now < deadline { self.result = result }
        }
        completed.signal()
    }

    func cancel() {
        lock.withLock {
            retired = true
            result = nil
        }
    }

    func consumeIfReady() throws -> Value? {
        let ready: Result<Value, Error>? = try lock.withLock {
            guard !retired, ContinuousClock.now < deadline else {
                retired = true
                result = nil
                throw CommandFilesystemProbeError.expired
            }
            guard let result else { return nil }
            retired = true
            self.result = nil
            return result
        }
        return try ready?.get()
    }

    /// Call only on a thread that holds no authority lock.
    func wait() throws -> Value {
        do {
            while true {
                if let result = try consumeIfReady() { return result }
                _ = completed.wait(timeout: .now() + .milliseconds(20))
            }
        } catch {
            cancel()
            throw error
        }
    }
}

/// Bound the number of filesystem calls in flight, including calls whose owner has already timed out.
final class CommandFilesystemProbePool: Sendable {
    private let slots: DispatchSemaphore
    private let queue = DispatchQueue(label: "dev.remozio.authority.command-filesystem", attributes: .concurrent)
    private let timeout: Duration
    private let beforeWork: @Sendable () -> Void

    init(maximumActive: Int = 4, timeout: Duration = CommandFilesystemCapture.phaseTimeout,
         beforeWork: @escaping @Sendable () -> Void = {}) {
        slots = DispatchSemaphore(value: maximumActive)
        self.timeout = timeout
        self.beforeWork = beforeWork
    }

    func start<Value>(_ work: @escaping @Sendable (ContinuousClock.Instant) throws -> Value) throws -> CommandFilesystemProbe<Value> {
        guard slots.wait(timeout: .now()) == .success else { throw CommandFilesystemProbeError.atCapacity }
        let probe = CommandFilesystemProbe<Value>(deadline: ContinuousClock.now + timeout)
        queue.async {
            let result = Result {
                self.beforeWork()
                guard ContinuousClock.now < probe.deadline else { throw CommandFilesystemProbeError.expired }
                return try work(probe.deadline)
            }
            self.slots.signal()
            probe.complete(result)
        }
        return probe
    }
}
