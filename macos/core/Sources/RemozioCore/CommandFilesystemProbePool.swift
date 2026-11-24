import Darwin
import Foundation

enum CommandFilesystemProbeError: Error, Equatable {
    case atCapacity, expired

    static func isCapacityFailure(_ error: Error) -> Bool {
        error is Self || error as? CommandFilesystemCaptureError == .timedOut
    }
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

    func checkActive() throws {
        try lock.withLock {
            guard !retired, ContinuousClock.now < deadline else {
                throw CommandFilesystemProbeError.expired
            }
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
    func waitForProgress() {
        _ = completed.wait(timeout: .now() + .milliseconds(20))
    }

    /// Call only on a thread that holds no authority lock.
    func wait() throws -> Value {
        do {
            while true {
                if let result = try consumeIfReady() { return result }
                waitForProgress()
            }
        } catch {
            cancel()
            throw error
        }
    }
}

/// Bound the number of filesystem calls in flight, including calls whose owner has already timed out.
final class CommandFilesystemProbePool: @unchecked Sendable {
    enum Phase: Sendable {
        case admission(uid_t)
        case execution
    }

    private let lock = NSLock()
    private var admissions = Set<uid_t>()
    private var executions = 0
    private let admissionSlots: Int
    private let executionSlots: Int
    private let queue = DispatchQueue(label: "dev.remozio.authority.command-filesystem", attributes: .concurrent)
    private let timeout: Duration
    private let beforeWork: @Sendable () -> Void
    private let onCapacity: @Sendable (Phase) -> Void

    init(admissionSlots: Int = 2, executionSlots: Int = 2, timeout: Duration = CommandFilesystemCapture.phaseTimeout,
         beforeWork: @escaping @Sendable () -> Void = {}, onCapacity: @escaping @Sendable (Phase) -> Void = { _ in }) {
        self.admissionSlots = admissionSlots
        self.executionSlots = executionSlots
        self.timeout = timeout
        self.beforeWork = beforeWork
        self.onCapacity = onCapacity
    }

    func start<Value>(_ phase: Phase, _ work: @escaping @Sendable
                      (ContinuousClock.Instant, @Sendable () throws -> Void) throws -> Value) throws -> CommandFilesystemProbe<Value> {
        do {
            try lock.withLock {
                switch phase {
                case .admission(let caller):
                    guard admissions.count < admissionSlots, admissions.insert(caller).inserted else {
                        throw CommandFilesystemProbeError.atCapacity
                    }
                case .execution:
                    guard executions < executionSlots else { throw CommandFilesystemProbeError.atCapacity }
                    executions += 1
                }
            }
        } catch {
            onCapacity(phase)
            throw error
        }
        let probe = CommandFilesystemProbe<Value>(deadline: ContinuousClock.now + timeout)
        queue.async {
            let result = Result {
                try CommandFilesystemCaller.requireProcessIdentity()
                try probe.checkActive()
                self.beforeWork()
                try probe.checkActive()
                return try work(probe.deadline, { try probe.checkActive() })
            }
            self.lock.withLock {
                switch phase {
                case .admission(let caller): self.admissions.remove(caller)
                case .execution: self.executions -= 1
                }
            }
            probe.complete(result)
        }
        return probe
    }
}
