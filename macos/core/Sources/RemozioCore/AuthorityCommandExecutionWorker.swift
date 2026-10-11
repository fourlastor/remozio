import Darwin
import Foundation
import Synchronization

public enum AuthorityCommandExecutionWorkerError: Error, Equatable {
    case invalidConfiguration, alreadyStarted, closed, capacity
}

private final class CommandExecutionWorkerOwnership: Sendable {
    struct State {
        var started = false
        var stopping = false
        var failed = false
        var pending: [Data: AuthorityCommandAuthorizationNotice] = [:]
    }
    let state = Mutex(State())
    let completion = DispatchGroup()
    let retirement = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
    func requestStop() { state.withLock { $0.stopping = true } }
    func fail() {
        let changed = state.withLock { state in
            guard !state.failed else { return false }
            state.failed = true; state.stopping = true; return true
        }
        if changed { retirement.continuation.yield(()); retirement.continuation.finish() }
    }
    var stopping: Bool { state.withLock { $0.stopping } }
}

/// Serializes start attempts after the approval lock releases. A notice grants no execution authority.
/// Completion reports describe attempts, not dispatch or target outcomes. Callbacks must return promptly.
public final class AuthorityCommandExecutionWorker: Sendable {
    public enum EnqueueResult: Equatable, Sendable { case queued, duplicate, closed, capacity }
    private let ownership = CommandExecutionWorkerOwnership()
    private let queue = DispatchQueue(label: "dev.remozio.authority.command-execution", qos: .utility)
    private let maximumPending: Int
    private let begin: @Sendable (AuthorityCommandAuthorizationNotice, @escaping @Sendable () throws -> Void) throws -> Void
    private let rejectUnowned: @Sendable (AuthorityCommandAuthorizationNotice) throws -> Void
    private let report: @Sendable (AuthorityCommandAuthorizationNotice, Result<Void, any Error>) -> Void
    var retirement: AsyncStream<Void> { ownership.retirement.stream }
    public var isRetired: Bool { ownership.state.withLock { $0.failed } }

    /// Fixture scheduling seam. Production construction must bind the same journal, clock and current grants.
    init(maximumPending: Int = 1024,
         begin: @escaping @Sendable (AuthorityCommandAuthorizationNotice, @escaping @Sendable () throws -> Void) throws -> Void,
         rejectUnowned: @escaping @Sendable (AuthorityCommandAuthorizationNotice) throws -> Void,
         report: @escaping @Sendable (AuthorityCommandAuthorizationNotice, Result<Void, any Error>) -> Void = { _, _ in }) throws {
        guard (1...4096).contains(maximumPending) else { throw AuthorityCommandExecutionWorkerError.invalidConfiguration }
        self.maximumPending = maximumPending; self.begin = begin; self.rejectUnowned = rejectUnowned; self.report = report
    }
    deinit { ownership.requestStop() }

    /// Start before enabling request listeners. The enclosing runtime owns shutdown and the journal.
    public func start() throws {
        try ownership.state.withLock {
            guard !$0.stopping else { throw AuthorityCommandExecutionWorkerError.closed }
            guard !$0.started else { throw AuthorityCommandExecutionWorkerError.alreadyStarted }
            $0.started = true
        }
    }

    /// Queue once while pending. Reject nonqueued approvals through the journal before returning.
    /// Call after the approval lock releases. Original state prevents duplicate release or replay.
    public func enqueue(_ notice: AuthorityCommandAuthorizationNotice) -> EnqueueResult {
        let ownership = self.ownership
        let admitted: EnqueueResult = ownership.state.withLock { state in
            guard state.pending[notice.requestID] == nil else { return .duplicate }
            ownership.completion.enter()
            guard state.started, !state.stopping else { return .closed }
            guard state.pending.count < maximumPending else { state.stopping = true; return .capacity }
            state.pending[notice.requestID] = notice; return .queued
        }
        guard admitted == .queued else {
            guard admitted != .duplicate else { return admitted }
            defer { ownership.completion.leave() }
            // The journal must settle this exact unowned approval before capacity retirement.
            do {
                try rejectUnowned(notice)
                report(notice, .failure(admitted == .capacity ? AuthorityCommandExecutionWorkerError.capacity : .closed))
            } catch { ownership.fail(); report(notice, .failure(error)) }
            if admitted == .capacity { ownership.fail() }
            return admitted
        }
        let begin = begin, rejectUnowned = rejectUnowned, report = report
        queue.async {
            defer {
                _ = ownership.state.withLock { $0.pending.removeValue(forKey: notice.requestID) }
                ownership.completion.leave()
            }
            do {
                guard !ownership.stopping else { throw AuthorityCommandExecutionWorkerError.closed }
                try begin(notice, {
                    guard !ownership.stopping else { throw AuthorityCommandExecutionWorkerError.closed }
                })
                report(notice, .success(()))
            } catch {
                do { try rejectUnowned(notice) }
                catch { ownership.fail(); report(notice, .failure(error)); return }
                report(notice, .failure(error))
            }
        }
        return .queued
    }

    public func requestStop() { ownership.requestStop() }

    /// Prevent new attempts and await every queued turn. Only the journal may dispose native owners.
    public func close() async {
        ownership.requestStop()
        let ownership = ownership
        await withCheckedContinuation { continuation in
            ownership.completion.notify(queue: .global(qos: .utility)) { continuation.resume() }
        }
        ownership.retirement.continuation.finish()
    }
}
