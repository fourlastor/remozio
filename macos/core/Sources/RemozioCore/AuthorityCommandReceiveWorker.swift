import Darwin
import Foundation
import RemozioProtocol
import Synchronization

/// Trusted composition hook. Reuse this journal and clock; do not open another writer or epoch.
public typealias AuthorityCommandReceiveFactory = @Sendable (AuthorityJournal, AuthorityClock) throws -> AuthorityCommandReceiveWorker

private final class CommandReceiveWorkerOwnership: Sendable {
    private struct State {
        var started = false
        var stopping = false
        var failed = false
        var stop: CommandReceiveStop?
        var status = AuthorityCommandReceiveWorker.Status.idle
    }
    private let state = Mutex(State())
    private let completion = DispatchGroup()
    private let retirement = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
    var retirementStream: AsyncStream<Void> { retirement.stream }
    private let report: @Sendable (AuthorityCommandReceiveWorker.Status) -> Void
    init(report: @escaping @Sendable (AuthorityCommandReceiveWorker.Status) -> Void) { self.report = report }
    var stopping: Bool { state.withLock { $0.stopping } }
    var failed: Bool { state.withLock { $0.failed } }
    var status: AuthorityCommandReceiveWorker.Status { state.withLock { $0.status } }
    func begin() throws {
        try state.withLock {
            guard !$0.stopping else { throw CommandReceiveHostError.stopped }
            guard !$0.started else { throw CommandReceiveHostError.operationActive }
            completion.enter(); $0.started = true; $0.status = .starting
        }
        report(.starting)
    }
    func install(_ stop: CommandReceiveStop) -> Bool {
        let running = state.withLock { $0.stop = stop; return !$0.stopping }
        if !running { stop.requestStop() }
        return running
    }
    func ready() -> Bool {
        let running = state.withLock {
            guard !$0.stopping else { return false }
            $0.status = .running; return true
        }
        if running { report(.running) }
        return running
    }
    func requestStop() {
        let result = state.withLock { state -> (CommandReceiveStop?, AuthorityCommandReceiveWorker.Status?) in
            guard !state.stopping else { return (nil, nil) }
            state.stopping = true
            let next: AuthorityCommandReceiveWorker.Status = state.started ? .stopping : .closed
            let changed = state.status != next
            state.status = next
            return (state.stop, changed ? next : nil)
        }
        result.0?.requestStop()
        if let next = result.1 {
            if next == .closed { retirement.continuation.finish() }
            report(next)
        }
    }
    func fail() {
        let changed = state.withLock {
            guard !$0.stopping else { return false }
            $0.failed = true; $0.status = .failed; return true
        }
        if changed {
            retirement.continuation.yield(())
            retirement.continuation.finish()
            report(.failed)
        }
    }
    func finish() {
        let changed = state.withLock {
            $0.stop = nil
            guard $0.stopping else { return false }
            let changed = $0.status != .closed
            $0.status = .closed; return changed
        }
        if changed { report(.closed) }
        retirement.continuation.finish()
        completion.leave()
    }
    func wait() async {
        await withCheckedContinuation { continuation in
            completion.notify(queue: .global(qos: .utility)) { continuation.resume() }
        }
        let changed = state.withLock {
            let changed = $0.status != .closed
            $0.status = .closed; return changed
        }
        if changed { report(.closed) }
    }
    func check() throws { if stopping { throw CommandReceiveHostError.stopped } }
}

/// Owns one serial command receiver. The host factory must transfer a protected installation's receive right.
/// Resolve and draft callbacks run under the shared journal lock. They must not reenter the journal.
/// Admission notifications run after journal work. They grant no execution authority.
/// Status callbacks must return promptly and must not start or stop this worker.
public final class AuthorityCommandReceiveWorker: Sendable {
    public enum Status: Equatable, Sendable { case idle, starting, running, stopping, failed, closed }
    /// Fixture observations omit the handshake profile and all request data.
    enum ReceiveObservation: Sendable, Equatable {
        case idle, hello, inputHandled, rejected(CommandReceiveRejection)
        init(_ event: CommandReceiveEvent) {
            switch event {
            case .idle: self = .idle
            case .hello: self = .hello
            case .inputHandled: self = .inputHandled
            case .rejected(let reason): self = .rejected(reason)
            }
        }
    }
    private let ownership: CommandReceiveWorkerOwnership
    private let queue = DispatchQueue(label: "dev.remozio.authority.command-receive", qos: .utility)
    private let makeHost: @Sendable () throws -> CommandReceiveHost
    private let limits: CBORLimits
    private let admit: @Sendable (sending RetainedCommandAdmissionAttempt, UInt64?, CommandReceiveStop) throws -> IssuedRequestPayload
    private let receiptTime: @Sendable () -> UInt64?
    private let onAdmission: @Sendable (Result<IssuedRequestPayload, any Error>) -> Void
    private let observeReceive: (@Sendable (ReceiveObservation) -> Void)?
    public var status: Status { ownership.status }
    public var isRetired: Bool { ownership.failed }
    /// One enclosing service observes the buffered failure. Normal shutdown ends without a failure event.
    var retirement: AsyncStream<Void> { ownership.retirementStream }

    /// The factory creates a fresh host on this worker's queue. It must clean up before throwing.
    /// It must not infer protected registration from successful bootstrap check-in alone.
    public convenience init(journal: AuthorityJournal, submissionLimits: CBORLimits,
                            makeHost: @escaping @Sendable () throws -> CommandReceiveHost,
                            resolve: @escaping @Sendable (CommandSubmission) throws -> CommandAdmissionResolution,
                            draft: @escaping @Sendable (CommandCapture) throws -> ApprovalRequestDraft,
                            clock: @escaping @Sendable () throws -> AuthorityMoment,
                            receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                            onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
                            report: @escaping @Sendable (Status) -> Void = { _ in }) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try self.init(ownedJournal: journal, submissionLimits: submissionLimits, makeHost: makeHost,
            resolve: resolve, draft: draft, clock: clock, receiptTime: receiptTime, onAdmission: onAdmission, report: report)
    }
    /// Fixture account seam. Queue ownership, policy checks, and admission use the same worker path.
    convenience init(ownedJournal: AuthorityJournal, submissionLimits: CBORLimits,
         makeHost: @escaping @Sendable () throws -> CommandReceiveHost,
         resolve: @escaping @Sendable (CommandSubmission) throws -> CommandAdmissionResolution,
         draft: @escaping @Sendable (CommandCapture) throws -> ApprovalRequestDraft,
         clock: @escaping @Sendable () throws -> AuthorityMoment,
         receiptTime: @escaping @Sendable () -> UInt64? = { nil },
         onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
         report: @escaping @Sendable (Status) -> Void = { _ in }) throws {
        try self.init(submissionLimits: submissionLimits, makeHost: makeHost, admit: { attempt, time, stop in
            try ownedJournal.admitCommandAttempt(attempt, resolve: resolve, draft: draft, now: clock,
                receiptTimeMs: time, checkCancellation: { try stop.check() })
        }, receiptTime: receiptTime, onAdmission: onAdmission, report: report)
    }

    /// Reads current grants for each original attempt. The binding factory supplies fresh host-owned stream metadata.
    public convenience init(journal: AuthorityJournal, submissionLimits: CBORLimits,
                            makeHost: @escaping @Sendable () throws -> CommandReceiveHost,
                            elevationPolicy: CurrentCommandElevationPolicy, captureSchemaVersion: UInt64,
                            minimalEnvironment: [CapturedEnvironmentEntry], captureLimits: CBORLimits,
                            maximumAncestryEntries: Int = 16,
                            streamBinding: @escaping @Sendable () throws -> Data,
                            draft: @escaping @Sendable (CommandCapture) throws -> ApprovalRequestDraft,
                            clock: @escaping @Sendable () throws -> AuthorityMoment,
                            receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                            onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
                            report: @escaping @Sendable (Status) -> Void = { _ in }) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try self.init(submissionLimits: submissionLimits, makeHost: makeHost, admit: { attempt, time, stop in
            try journal.admitCommandAttempt(attempt, elevationPolicy: elevationPolicy,
                captureSchemaVersion: captureSchemaVersion, minimalEnvironment: minimalEnvironment,
                streamBinding: streamBinding, captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
                draft: draft, now: clock, receiptTimeMs: time, checkCancellation: { try stop.check() })
        }, receiptTime: receiptTime, onAdmission: onAdmission, report: report)
    }

    /// Fixture admission seam. Product construction uses a Root-validated journal operation.
    /// The optional observer runs on the receive queue and must return promptly without reentry.
    init(submissionLimits: CBORLimits, makeHost: @escaping @Sendable () throws -> CommandReceiveHost,
         admit: @escaping @Sendable (sending RetainedCommandAdmissionAttempt, UInt64?, CommandReceiveStop) throws -> IssuedRequestPayload,
         receiptTime: @escaping @Sendable () -> UInt64? = { nil },
         onAdmission: @escaping @Sendable (Result<IssuedRequestPayload, any Error>) -> Void = { _ in },
         report: @escaping @Sendable (Status) -> Void = { _ in },
         observeReceive: (@Sendable (ReceiveObservation) -> Void)? = nil) throws {
        guard submissionLimits.maxBytes <= 16_777_216 else { throw CommandReceiveHostError.invalidConfiguration }
        ownership = CommandReceiveWorkerOwnership(report: report); limits = submissionLimits
        self.makeHost = makeHost; self.admit = admit
        self.receiptTime = receiptTime; self.onAdmission = onAdmission; self.observeReceive = observeReceive
    }
    deinit { ownership.requestStop() }

    /// Ready means that the fresh host passed its current policy read. It does not authorize a command.
    public func start() async throws {
        try Task.checkCancellation()
        let ownership = ownership, queue = queue, makeHost = makeHost, limits = limits
        let admit = admit, receiptTime = receiptTime, onAdmission = onAdmission, observeReceive = observeReceive
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    do { try ownership.begin() }
                    catch { continuation.resume(throwing: error); return }
                    queue.async {
                        var ready = false
                        do {
                            try ownership.check()
                            let host = try makeHost()
                            defer { host.close() }
                            guard ownership.install(host.stop) else { throw CommandReceiveHostError.stopped }
                            try host.validateStartupContext()
                            guard ownership.ready() else { throw CommandReceiveHostError.stopped }
                            ready = true; continuation.resume()
                            while !ownership.stopping {
                                let event = try host.pollAdmission(submissionLimits: limits, receiptTime: receiptTime,
                                    admit: admit, onResult: onAdmission)
                                observeReceive?(ReceiveObservation(event))
                            }
                        } catch {
                            ownership.fail()
                            if !ready { continuation.resume(throwing: error) }
                        }
                        ownership.finish()
                    }
                }
                try Task.checkCancellation()
            } onCancel: { ownership.requestStop() }
        } catch {
            if Task.isCancelled { ownership.requestStop(); throw CancellationError() }
            throw error
        }
    }
    /// Signals without disposing objects from the calling thread.
    public func requestStop() { ownership.requestStop() }
    /// Awaits the active factory and receive turn. The shared journal remains owned by the enclosing service.
    public func close() async { ownership.requestStop(); await ownership.wait() }
}
