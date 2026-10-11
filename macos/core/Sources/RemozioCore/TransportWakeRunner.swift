import Foundation
import Synchronization

/// A fresh pair of authenticated channels. Factory failures release their resources before throwing.
struct TransportWakeAttempt: Sendable {
    let id = UUID()
    let start: @Sendable () async throws -> Void
    let poll: @Sendable () async throws -> Void
    let close: @Sendable () async -> Void
}

private final class TransportWakeOwnership: Sendable {
    private struct State {
        var stopping = false
        var attempt: TransportWakeAttempt?
        var status = TransportWakeRunner.Status.idle
    }
    private let state = Mutex(State())
    private let report: @Sendable (TransportWakeRunner.Status) -> Void
    init(report: @escaping @Sendable (TransportWakeRunner.Status) -> Void) { self.report = report }
    var stopping: Bool { state.withLock { $0.stopping } }
    var status: TransportWakeRunner.Status { state.withLock { $0.status } }
    func stop() { state.withLock { $0.stopping = true } }
    func retain(_ attempt: TransportWakeAttempt) throws -> Bool {
        try state.withLock {
            guard $0.attempt == nil else { throw TransportWakeRuntimeError.busy }
            $0.attempt = attempt
            return !$0.stopping
        }
    }
    func update(_ status: TransportWakeRunner.Status) {
        let changed = state.withLock {
            guard (!$0.stopping || status == .closed), $0.status != status else { return false }
            $0.status = status
            return true
        }
        if changed { report(status) }
    }
    func closeCurrent() async {
        guard let attempt = state.withLock({ $0.attempt }) else { return }
        await attempt.close()
        state.withLock { if $0.attempt?.id == attempt.id { $0.attempt = nil } }
    }
}

/// Recovers optional wake delivery without owning the direct approval service.
/// Report callbacks are diagnostic. They must return promptly and must not reenter this runner.
public actor TransportWakeRunner {
    public enum Status: Sendable, Equatable {
        case idle, starting, ready, waiting(retryMilliseconds: UInt64), failed, closed
    }
    private let ownership: TransportWakeOwnership
    private let makeAttempt: @Sendable () async throws -> TransportWakeAttempt
    private let interval: UInt64
    private let initialRetry: UInt64
    private let maximumRetry: UInt64
    private var worker: Task<Void, Never>?
    private var closing: Task<Void, Never>?
    private var started = false
    private var cleanupComplete = false
    public nonisolated var status: Status { ownership.status }

    /// Every attempt restores the provisioned signer and creates fresh hint and gateway channels with the same protected scope.
    /// Lookup never creates or replaces a key, changes custody, or weakens peer authentication.
    public init(configuration: TransportWakeStartupConfiguration, initialRetryMilliseconds: UInt64 = 1000,
                maximumRetryMilliseconds: UInt64 = 30_000,
                report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(intervalMilliseconds: configuration.pollMilliseconds, initialRetryMilliseconds: initialRetryMilliseconds,
            maximumRetryMilliseconds: maximumRetryMilliseconds, makeAttempt: {
                let runtime = try configuration.makeRuntime()
                return TransportWakeAttempt(start: { try await runtime.start() }, poll: { try await runtime.poll() },
                    close: { await runtime.close() })
            }, report: report)
    }
    init(intervalMilliseconds: UInt64 = 1000, initialRetryMilliseconds: UInt64 = 1000,
         maximumRetryMilliseconds: UInt64 = 30_000,
         makeAttempt: @escaping @Sendable () async throws -> TransportWakeAttempt,
         report: @escaping @Sendable (Status) -> Void) throws {
        guard (10...60_000).contains(intervalMilliseconds), (100...60_000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300_000).contains(maximumRetryMilliseconds) else {
            throw TransportWakeRuntimeError.invalidConfiguration
        }
        ownership = TransportWakeOwnership(report: report)
        self.makeAttempt = makeAttempt
        interval = intervalMilliseconds
        initialRetry = initialRetryMilliseconds
        maximumRetry = maximumRetryMilliseconds
    }
    deinit {
        ownership.stop()
        worker?.cancel()
        let worker = worker, pending = closing, ownership = ownership
        if !cleanupComplete {
            Task {
                if let pending { await pending.value }
                else { await worker?.value; await ownership.closeCurrent() }
            }
        }
    }
    public func start() throws {
        guard !started, !ownership.stopping else { throw TransportWakeRuntimeError.closed }
        started = true
        worker = Task { [ownership, makeAttempt, interval, initialRetry, maximumRetry] in
            await Self.run(ownership: ownership, makeAttempt: makeAttempt, interval: interval,
                initialRetry: initialRetry, maximumRetry: maximumRetry)
        }
    }
    /// Stops future attempts and awaits the active attempt before releasing its channels and signer.
    public func close() async {
        ownership.stop()
        worker?.cancel()
        guard !cleanupComplete else { return }
        if let closing { await closing.value; return }
        let previous = worker, ownership = ownership
        worker = nil
        let cleanup = Task { await previous?.value; await ownership.closeCurrent() }
        closing = cleanup
        await cleanup.value
        cleanupComplete = true
        closing = nil
        ownership.update(.closed)
    }
    static func isRetryable(_ error: any Error) -> Bool {
        switch error {
        case AuthorityWakeHintChannelError.closed, AuthorityWakeHintChannelError.timedOut,
             AuthorityWakeHintChannelError.unsupportedVersion, AuthorityWakeHintChannelError.invalidMessage,
             GatewayWakeChannelError.closed, GatewayWakeChannelError.timedOut, GatewayWakeChannelError.rejected,
             GatewayWakeChannelError.unsupportedVersion, GatewayWakeChannelError.invalidMessage,
             TransportWakeRuntimeError.closed, GatewayWakeSignerError.unavailable: true
        default: false
        }
    }
    private static func run(ownership: TransportWakeOwnership,
                            makeAttempt: @Sendable () async throws -> TransportWakeAttempt,
                            interval: UInt64, initialRetry: UInt64, maximumRetry: UInt64) async {
        var retry = initialRetry
        while !ownership.stopping, !Task.isCancelled {
            ownership.update(.starting)
            do {
                let attempt = try await makeAttempt()
                guard try ownership.retain(attempt) else { return }
                try Task.checkCancellation()
                try await attempt.start()
                guard !ownership.stopping, !Task.isCancelled else { return }
                ownership.update(.ready)
                while !ownership.stopping, !Task.isCancelled {
                    try await attempt.poll()
                    retry = initialRetry
                    try await Task.sleep(for: .milliseconds(interval))
                }
                return
            } catch {
                await ownership.closeCurrent()
                guard !ownership.stopping, !Task.isCancelled else { return }
                guard isRetryable(error) else { ownership.update(.failed); return }
                ownership.update(.waiting(retryMilliseconds: retry))
                do { try await Task.sleep(for: .milliseconds(retry)) } catch { return }
                retry = min(retry * 2, maximumRetry)
            }
        }
    }
}
