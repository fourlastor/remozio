import Foundation
import Synchronization

public enum FCMTokenSourceError: Error, Equatable {
    case invalidConfiguration, capacityExceeded, credentialsChanged, stopped, insufficientLifetime, invalidated
}

/// A token reference scoped to one source and credential generation. Obtain its token through that source.
public struct FCMTokenGrant: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    fileprivate let owner: UUID
    fileprivate let generation: UUID
    fileprivate let identifier: UUID
    fileprivate let lease: FCMTokenLease
    fileprivate let invalidation = Invalidation()
    fileprivate final class Invalidation: Sendable { let value = Mutex(false) }
    public var expiresAt: ContinuousClock.Instant { lease.expiresAt }
    public var description: String { "FCMTokenGrant(redacted)" }
    public var debugDescription: String { description }
}

/// Owns one provider's process-local token cache. This is not an enrollment or gateway submission endpoint.
public actor FCMTokenSource {
    private let owner = UUID()
    private var generation = UUID()
    private let minimumValidity: Duration
    private let maximumWaiters: Int
    private let now: @Sendable () -> ContinuousClock.Instant
    private var refresh: (@Sendable () async throws -> FCMTokenLease)?
    private var cached: FCMTokenGrant?
    private var flight: Flight?
    private var retiredRefreshes: [UUID: Task<Void, Never>] = [:]

    private struct Flight {
        let identifier: UUID
        let task: Task<Void, Never>
        var waiters: [UUID: CheckedContinuation<FCMTokenGrant, any Error>]
    }

    public init(client: FCMOAuthClient, minimumValiditySeconds: TimeInterval = 60, maximumWaiters: Int = 64) throws {
        try self.init(minimumValiditySeconds: minimumValiditySeconds, maximumWaiters: maximumWaiters,
                      now: { .now }, refresh: { try await client.acquireToken() })
    }
    init(minimumValiditySeconds: TimeInterval = 60, maximumWaiters: Int = 64,
         now: @escaping @Sendable () -> ContinuousClock.Instant,
         refresh: @escaping @Sendable () async throws -> FCMTokenLease) throws {
        guard minimumValiditySeconds.isFinite, (0...3599).contains(minimumValiditySeconds),
              (1...1024).contains(maximumWaiters) else { throw FCMTokenSourceError.invalidConfiguration }
        self.minimumValidity = .seconds(minimumValiditySeconds); self.maximumWaiters = maximumWaiters
        self.now = now; self.refresh = refresh
    }

    public func token() async throws -> FCMTokenGrant {
        try Task.checkCancellation()
        guard refresh != nil else { throw FCMTokenSourceError.stopped }
        if let cached, usable(cached.lease) { return cached }
        let waiter = UUID()
        let grant: FCMTokenGrant = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<FCMTokenGrant, any Error>) in
                guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                guard pendingCallerCount < maximumWaiters else {
                    continuation.resume(throwing: FCMTokenSourceError.capacityExceeded); return
                }
                if flight == nil {
                    guard retiredRefreshes.count < maximumWaiters else {
                        continuation.resume(throwing: FCMTokenSourceError.capacityExceeded); return
                    }
                    startRefresh()
                }
                flight!.waiters[waiter] = continuation
            }
        } onCancel: {
            Task { await self.cancel(waiter) }
        }
        try Task.checkCancellation()
        return grant
    }

    /// Recheck immediately before sending. A previously extracted bearer token cannot be revoked locally.
    public func accessToken(for grant: FCMTokenGrant) throws -> FCMAccessToken {
        guard refresh != nil else { throw FCMTokenSourceError.stopped }
        guard grant.owner == owner, grant.generation == generation else { throw FCMTokenSourceError.credentialsChanged }
        guard !grant.invalidation.value.withLock({ $0 }) else { throw FCMTokenSourceError.invalidated }
        return try grant.lease.accessToken(at: now())
    }

    /// An old request's 401 must not evict a newer token or interrupt its refresh.
    public func invalidate(_ grant: FCMTokenGrant) {
        guard grant.owner == owner, grant.generation == generation else { return }
        grant.invalidation.value.withLock { $0 = true }
        if cached?.identifier == grant.identifier { cached = nil }
    }

    public func replace(client: FCMOAuthClient) throws {
        try replace(refresh: { try await client.acquireToken() })
    }
    func replace(refresh: @escaping @Sendable () async throws -> FCMTokenLease) throws {
        guard self.refresh != nil else { throw FCMTokenSourceError.stopped }
        generation = UUID(); cached = nil; self.refresh = refresh
        abandon(throwing: FCMTokenSourceError.credentialsChanged)
    }

    public func shutdown() {
        refresh = nil; cached = nil
        abandon(throwing: FCMTokenSourceError.stopped)
    }

    /// Joins provider refresh work after terminal cancellation.
    public func shutdownAndWait() async {
        shutdown()
        let pending = Array(retiredRefreshes.values)
        for task in pending { await task.value }
    }

    var pendingCallerCount: Int { flight?.waiters.count ?? 0 }
    private(set) var finishedAttemptCount: UInt64 = 0

    private func usable(_ lease: FCMTokenLease) -> Bool {
        now().advanced(by: minimumValidity) < lease.expiresAt
    }
    private func startRefresh() {
        let identifier = UUID(), refresh = refresh!
        let task = Task { [weak self] in
            let result: Result<FCMTokenLease, any Error>
            do { result = .success(try await refresh()) }
            catch { result = .failure(error) }
            await self?.finish(identifier, result: result)
        }
        flight = Flight(identifier: identifier, task: task, waiters: [:])
    }
    private func finish(_ identifier: UUID, result: Result<FCMTokenLease, any Error>) {
        retiredRefreshes.removeValue(forKey: identifier)
        finishedAttemptCount &+= 1
        guard let active = flight, active.identifier == identifier else { return }
        flight = nil
        let result = result.flatMap { lease -> Result<FCMTokenGrant, any Error> in
            guard usable(lease) else { return .failure(FCMTokenSourceError.insufficientLifetime) }
            let grant = FCMTokenGrant(owner: owner, generation: generation, identifier: UUID(), lease: lease)
            cached = grant
            return .success(grant)
        }
        for continuation in active.waiters.values { continuation.resume(with: result) }
    }
    private func cancel(_ waiter: UUID) {
        guard let continuation = flight?.waiters.removeValue(forKey: waiter) else { return }
        continuation.resume(throwing: CancellationError())
        if flight?.waiters.isEmpty == true {
            let active = flight
            flight = nil
            if let active { retiredRefreshes[active.identifier] = active.task; active.task.cancel() }
        }
    }
    private func abandon(throwing error: any Error) {
        let active = flight
        flight = nil
        if let active { retiredRefreshes[active.identifier] = active.task; active.task.cancel() }
        for continuation in active?.waiters.values ?? [:].values { continuation.resume(throwing: error) }
    }
}
