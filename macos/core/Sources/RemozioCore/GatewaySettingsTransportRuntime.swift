import Foundation
import Synchronization

/// Owns only optional wake work. Direct approval, pairing and relay services have separate owners.
actor GatewaySettingsTransportRuntime: OwnedGatewaySettingsConsumerRuntime {
    private final class State: Sendable {
        struct Value {
            var retired = false
            var attempt: TransportWakeAttempt?
            var opening: Task<Void, Error>?
            var worker: Task<Void, Never>?
            var status = TransportWakeRunner.Status.idle
        }
        let value = Mutex(Value())
        let report: @Sendable (TransportWakeRunner.Status) -> Void
        init(report: @escaping @Sendable (TransportWakeRunner.Status) -> Void) { self.report = report }
        func requireLive() throws {
            try Task.checkCancellation()
            guard !value.withLock({ $0.retired }) else { throw TransportWakeRuntimeError.closed }
        }
        func retain(_ attempt: TransportWakeAttempt) throws {
            let live = try value.withLock { value in
                guard value.attempt == nil else { throw TransportWakeRuntimeError.busy }
                value.attempt = attempt
                return !value.retired
            }
            guard live else { throw TransportWakeRuntimeError.closed }
        }
        func retire() {
            let tasks = value.withLock { value in value.retired = true; return (value.opening, value.worker) }
            tasks.0?.cancel(); tasks.1?.cancel()
        }
        func opening(_ task: Task<Void, Error>?) {
            let retired = value.withLock { $0.opening = task; return $0.retired }
            if retired { task?.cancel() }
        }
        func worker(_ task: Task<Void, Never>?) {
            let retired = value.withLock { $0.worker = task; return $0.retired }
            if retired { task?.cancel() }
        }
        func update(_ status: TransportWakeRunner.Status) {
            let changed = value.withLock {
                guard (!$0.retired || status == .closed), $0.status != status else { return false }
                $0.status = status; return true
            }
            if changed { report(status) }
        }
        func closeCurrent() async {
            guard let attempt = value.withLock({ $0.attempt }) else { return }
            await attempt.close()
            value.withLock { if $0.attempt?.id == attempt.id { $0.attempt = nil } }
        }
    }
    private nonisolated let state: State
    private let verifyCurrent: @Sendable () throws -> Void
    private let makeAttempt: @Sendable () async throws -> TransportWakeAttempt
    private let interval: UInt64
    private let initialRetry: UInt64
    private let maximumRetry: UInt64
    private var opening: Task<Void, Error>?
    private var worker: Task<Void, Never>?
    private var closing: Task<Void, Never>?
    private var started = false
    private var settled = false

    init(selection: GatewaySettingsConsumerSelection, permit: GatewaySettingsConsumerPermit,
         initialRetryMilliseconds: UInt64 = 1000, maximumRetryMilliseconds: UInt64 = 30000,
         report: @escaping @Sendable (TransportWakeRunner.Status) -> Void = { _ in }) throws {
        guard selection.binding.role == .transport else { throw GatewayPreparationError.changedScope }
        let role = try GatewayRuntimeExtension.decode(selection.configuration)
        try selection.commit.validate(role)
        guard role.target == .transport, let wake = role.wake else { throw GatewayPreparationError.changedScope }
        try self.init(wake: wake, initialRetryMilliseconds: initialRetryMilliseconds,
            maximumRetryMilliseconds: maximumRetryMilliseconds, verifyCurrent: {
                try permit.requireValid(binding: selection.binding, fence: selection.fence,
                    configuration: selection.configuration, commit: selection.commit)
            }, report: report)
    }
    init(initial: TransportSettingsInitialPublication, verifyCurrent: @escaping @Sendable () throws -> Void,
         initialRetryMilliseconds: UInt64 = 1000, maximumRetryMilliseconds: UInt64 = 30000,
         report: @escaping @Sendable (TransportWakeRunner.Status) -> Void = { _ in }) throws {
        guard initial.configuration.target == .transport, let wake = initial.configuration.wake else { throw GatewayPreparationError.changedScope }
        try self.init(wake: wake, initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            verifyCurrent: verifyCurrent, report: report)
    }
    private init(wake: TransportWakeStartupConfiguration, initialRetryMilliseconds: UInt64, maximumRetryMilliseconds: UInt64,
                 verifyCurrent: @escaping @Sendable () throws -> Void,
                 report: @escaping @Sendable (TransportWakeRunner.Status) -> Void) throws {
        try self.init(intervalMilliseconds: wake.pollMilliseconds, initialRetryMilliseconds: initialRetryMilliseconds,
            maximumRetryMilliseconds: maximumRetryMilliseconds, verifyCurrent: verifyCurrent, makeAttempt: { verify in
                let runtime = try wake.makeRuntime(verifyCurrent: verify)
                return .init(start: { try await runtime.start() }, poll: { try await runtime.poll() },
                    close: { await runtime.close() }, intervalMilliseconds: wake.pollMilliseconds)
            }, report: report)
    }
    /// Owned attempts exercise lifetime races. This constructor does not perform native admission.
    init(intervalMilliseconds: UInt64 = 1000, initialRetryMilliseconds: UInt64 = 1000,
         maximumRetryMilliseconds: UInt64 = 30000, verifyCurrent: @escaping @Sendable () throws -> Void,
         makeAttempt: @escaping @Sendable (@escaping @Sendable () throws -> Void) async throws -> TransportWakeAttempt,
         report: @escaping @Sendable (TransportWakeRunner.Status) -> Void = { _ in }) throws {
        guard (10...60000).contains(intervalMilliseconds), (100...60000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300000).contains(maximumRetryMilliseconds) else { throw TransportWakeRuntimeError.invalidConfiguration }
        let state = State(report: report)
        let verify: @Sendable () throws -> Void = { try state.requireLive(); try verifyCurrent(); try state.requireLive() }
        self.state = state; self.verifyCurrent = verify; self.makeAttempt = { try await makeAttempt(verify) }
        interval = intervalMilliseconds; initialRetry = initialRetryMilliseconds; maximumRetry = maximumRetryMilliseconds
    }
    nonisolated var status: TransportWakeRunner.Status { state.value.withLock { $0.status } }
    nonisolated func retire() { state.retire() }
    /// A returned start has completed the actual channel handshake, rather than only queuing a retry worker.
    func start() async throws {
        guard !started else { throw TransportWakeRuntimeError.closed }
        try state.requireLive(); started = true
        let state = state, verify = verifyCurrent, make = makeAttempt, interval = interval
        state.update(.starting)
        let attempt = Task {
            try verify()
            let backend = try await make()
            try state.retain(backend)
            try verify(); try Self.validateInterval(backend.intervalMilliseconds ?? interval)
            try await backend.start(); try verify()
        }
        opening = attempt; state.opening(attempt)
        do {
            try await attempt.value; try verify()
            state.update(.ready); opening = nil; state.opening(nil)
            let initialRetry = initialRetry, maximumRetry = maximumRetry
            let polling = Task {
                await Self.run(state: state, make: make, verify: verify, interval: interval,
                    initialRetry: initialRetry, maximumRetry: maximumRetry)
            }
            worker = polling; state.worker(polling)
        } catch { retire(); throw error }
    }
    private static func validateInterval(_ milliseconds: UInt64) throws {
        guard (10...60000).contains(milliseconds) else { throw TransportWakeRuntimeError.invalidConfiguration }
    }
    private static func run(state: State, make: @escaping @Sendable () async throws -> TransportWakeAttempt,
                            verify: @escaping @Sendable () throws -> Void, interval: UInt64,
                            initialRetry: UInt64, maximumRetry: UInt64) async {
        var retry = initialRetry
        while true {
            do {
                try verify()
                if state.value.withLock({ $0.attempt == nil }) {
                    state.update(.starting)
                    let backend = try await make()
                    try state.retain(backend)
                    try verify(); try validateInterval(backend.intervalMilliseconds ?? interval)
                    try await backend.start(); try verify(); state.update(.ready)
                }
                guard let backend = state.value.withLock({ $0.attempt }) else { throw TransportWakeRuntimeError.closed }
                try verify(); try await backend.poll(); try verify()
                retry = initialRetry
                try await Task.sleep(for: .milliseconds(backend.intervalMilliseconds ?? interval))
            } catch {
                await state.closeCurrent()
                do { try verify() } catch { state.update(.failed); return }
                guard TransportWakeRunner.isRetryable(error) else { state.update(.failed); return }
                state.update(.waiting(retryMilliseconds: retry))
                do { try await Task.sleep(for: .milliseconds(retry)) } catch { return }
                retry = min(retry * 2, maximumRetry)
            }
        }
    }
    /// Cancellation stops admission immediately. Every closer joins factory, handshake, polling and channel cleanup.
    func closeAndWait() async throws {
        retire()
        if settled { return }
        let cleanup: Task<Void, Never>
        if let closing { cleanup = closing }
        else {
            let opening = opening, worker = worker, state = state
            cleanup = Task {
                _ = await opening?.result; await worker?.value; await state.closeCurrent()
                state.opening(nil); state.worker(nil); state.update(.closed)
            }
            closing = cleanup
        }
        await cleanup.value
        settled = true; opening = nil; worker = nil; closing = nil
    }
    deinit {
        state.retire()
        if settled { return }
        let state = state, pending = closing, opening = opening, worker = worker
        Task {
            if let pending { await pending.value }
            else {
                _ = await opening?.result; await worker?.value; await state.closeCurrent()
                state.opening(nil); state.worker(nil); state.update(.closed)
            }
        }
    }
}
