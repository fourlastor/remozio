import Darwin
import Foundation
import Synchronization

/// One trusted account owner shares this guard with every command connection and shutdown path.
/// Acquire ownership before registration, runner, marker, hold or pairing locks. Never wait while holding those locks.
/// A command may do bounded local work. It cannot await XPC, network work or an owner that shutdown must close.
/// Stop reserves admission before waiting for the actual command return. Cleanup never refuses because it is busy.
final class AuthorityMaintenanceCommandExclusion: Sendable {
    enum AcquisitionError: Error, Equatable { case busy, stopping }
    private enum Pending {
        case registering, cancelled
        case waiting(CheckedContinuation<Command, any Error>)
    }
    private struct State {
        var command: UUID?
        var stopping = false
        var publicationClaimed = false
        var waiters: [CheckedContinuation<Void, Never>] = []
        var pending: [UUID: Pending] = [:]
        var queue: [UUID] = []
    }
    private let state = Mutex(State())
    private let processID = getpid(), ownerUID = getuid()

    var isStopping: Bool { state.withLock { $0.stopping } }
    var waitingCommands: Int { state.withLock { $0.queue.count } }
    var waitingStops: Int { state.withLock { $0.waiters.count } }

    func acquire() throws -> Command {
        try requireIdentity()
        return try state.withLock {
            guard !$0.stopping else { throw AcquisitionError.stopping }
            guard $0.command == nil else { throw AcquisitionError.busy }
            let id = UUID(); $0.command = id
            return Command(owner: self, id: id)
        }
    }
    /// Waiting commands retain their existing endpoint budget. Cancellation removes only their own reservation.
    func acquireWhenAvailable() async throws -> Command {
        try requireIdentity()
        let id = UUID()
        state.withLock { $0.pending[id] = .registering }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let result: Result<Command, any Error>? = state.withLock { value in
                    if case .cancelled? = value.pending[id] {
                        value.pending[id] = nil; return .failure(CancellationError())
                    }
                    guard !value.stopping else {
                        value.pending[id] = nil; return .failure(AcquisitionError.stopping)
                    }
                    if value.command == nil {
                        value.pending[id] = nil; value.command = id
                        return .success(Command(owner: self, id: id))
                    }
                    value.pending[id] = .waiting(continuation); value.queue.append(id)
                    return nil
                }
                if let result { continuation.resume(with: result) }
            }
        } onCancel: { self.cancelWaitingCommand(id) }
    }
    private func cancelWaitingCommand(_ id: UUID) {
        let continuation: CheckedContinuation<Command, any Error>? = state.withLock { value in
            switch value.pending[id] {
            case .registering?: value.pending[id] = .cancelled; return nil
            case .waiting(let continuation)?:
                value.pending[id] = nil; value.queue.removeAll { $0 == id }; return continuation
            case .cancelled?, nil: return nil
            }
        }
        continuation?.resume(throwing: CancellationError())
    }
    /// Existing close owners can join the same stop. No second ownership acquisition or new deadline is introduced.
    /// Cancellation cannot replace an actual command return, so cleanup still joins that command.
    func beginStop() async throws -> Stop {
        try requireIdentity()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let (ready, rejected) = state.withLock { value in
                value.stopping = true
                let rejected = value.queue.compactMap { id -> CheckedContinuation<Command, any Error>? in
                    guard case .waiting(let waiter)? = value.pending.removeValue(forKey: id) else { return nil }
                    return waiter
                }
                value.queue.removeAll()
                if value.command == nil { return (true, rejected) }
                value.waiters.append(continuation); return (false, rejected)
            }
            for waiter in rejected { waiter.resume(throwing: AcquisitionError.stopping) }
            if ready { continuation.resume() }
        }
        try requireIdentity()
        return Stop(owner: self)
    }
    private func requireIdentity() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else {
            throw JournalLeaseError.invalidated
        }
    }
    private func release(_ id: UUID) {
        let (waiters, next) = state.withLock { value -> ([CheckedContinuation<Void, Never>], (UUID, CheckedContinuation<Command, any Error>)?) in
            guard value.command == id else { return ([], nil) }
            value.command = nil
            if !value.stopping, !value.queue.isEmpty {
                let nextID = value.queue.removeFirst()
                if case .waiting(let next)? = value.pending.removeValue(forKey: nextID) {
                    value.command = nextID
                    return ([], (nextID, next))
                }
            }
            let waiting = value.waiters; value.waiters.removeAll(); return (waiting, nil)
        }
        if let next {
            // The next command already owns the reservation before its continuation resumes.
            next.1.resume(returning: Command(owner: self, id: next.0))
        }
        for waiter in waiters { waiter.resume() }
    }

    private func requireCommand(_ id: UUID) throws {
        try requireIdentity()
        try state.withLock { guard $0.command == id else { throw JournalLeaseError.invalidated } }
    }
    private func requireStop() throws {
        try requireIdentity()
        try state.withLock { guard $0.stopping, $0.command == nil else { throw JournalLeaseError.invalidated } }
    }
    private func claimPublication() throws -> Bool {
        try requireIdentity()
        return try state.withLock {
            guard $0.stopping, $0.command == nil else { throw JournalLeaseError.invalidated }
            guard !$0.publicationClaimed else { return false }
            $0.publicationClaimed = true; return true
        }
    }
    final class Command: Sendable {
        private let owner: AuthorityMaintenanceCommandExclusion, id: UUID
        private let closed = Mutex(false)
        fileprivate init(owner: AuthorityMaintenanceCommandExclusion, id: UUID) { self.owner = owner; self.id = id }
        func validate() throws {
            guard !closed.withLock({ $0 }) else { throw JournalLeaseError.invalidated }
            try owner.requireCommand(id)
        }
        func close() {
            let release = closed.withLock { value in guard !value else { return false }; value = true; return true }
            if release { owner.release(id) }
        }
        deinit { close() }
    }
    /// Stop ownership remains valid through actual cleanup and marker publication. It never reopens commands.
    final class Stop: Sendable {
        private let owner: AuthorityMaintenanceCommandExclusion
        fileprivate init(owner: AuthorityMaintenanceCommandExclusion) { self.owner = owner }
        func validate() throws { try owner.requireStop() }
        func claimClosePublication() throws -> Bool { try owner.claimPublication() }
    }
}
