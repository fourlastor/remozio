import Foundation
import Synchronization
@testable import RemozioCore
import XCTest

final class FCMTokenSourceTests: XCTestCase, @unchecked Sendable {
    private final class Counter: Sendable { let value = Mutex(0) }
    private enum FixtureError: Error { case timeout, missingAttempt }
    private final class Clock: Sendable {
        let value = Mutex(ContinuousClock.now)
        func now() -> ContinuousClock.Instant { value.withLock { $0 } }
        func advance(_ seconds: Int) { value.withLock { $0 = $0.advanced(by: .seconds(seconds)) } }
    }
    private actor Refresh {
        private(set) var calls = 0
        private(set) var cancellations = Set<Int>()
        private var pending: [Int: CheckedContinuation<FCMTokenLease, any Error>] = [:]
        let honorCancellation: Bool
        init(honorCancellation: Bool = true) { self.honorCancellation = honorCancellation }
        func next() async throws -> FCMTokenLease {
            calls += 1
            let id = calls
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { pending[id] = $0 }
            } onCancel: { Task { await self.cancel(id) } }
        }
        private func cancel(_ id: Int) {
            cancellations.insert(id)
            if honorCancellation { pending.removeValue(forKey: id)?.resume(throwing: CancellationError()) }
        }
        func complete(_ id: Int, _ result: Result<FCMTokenLease, any Error>) throws {
            guard let continuation = pending.removeValue(forKey: id) else { throw FixtureError.missingAttempt }
            continuation.resume(with: result)
        }
        func close() {
            let waiting = pending; pending = [:]
            for continuation in waiting.values { continuation.resume(throwing: CancellationError()) }
        }
    }
    private func lease(_ clock: Clock, seconds: Int = 3600) throws -> FCMTokenLease {
        FCMTokenLease(value: try FCMAccessToken("synthetic-token"), expiresAt: clock.now().advanced(by: .seconds(seconds)))
    }
    private func source(_ refresh: Refresh, _ clock: Clock, margin: Double = 60, maximum: Int = 64) throws -> FCMTokenSource {
        try FCMTokenSource(minimumValiditySeconds: margin, maximumWaiters: maximum, now: { clock.now() }, refresh: { try await refresh.next() })
    }
    private func until(_ predicate: @Sendable () async -> Bool) async throws {
        for _ in 0..<200 {
            if await predicate() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw FixtureError.timeout
    }
    private func expect(_ error: FCMTokenSourceError, _ operation: () async throws -> Void) async {
        do { try await operation(); XCTFail("Expected \(error)") }
        catch let actual { XCTAssertEqual(actual as? FCMTokenSourceError, error) }
    }

    func testJoinedShutdownRetainsCancelledAndReplacedProviderAttempts() async throws {
        let clock = Clock(), old = Refresh(honorCancellation: false), new = Refresh(honorCancellation: false)
        let source = try source(old, clock)
        defer { Task { await old.close(); await new.close(); await source.shutdownAndWait() } }
        let first = Task { try await source.token() }
        try await until { await old.calls == 1 }
        first.cancel()
        _ = await first.result
        try await until { await old.cancellations.contains(1) }
        let second = Task { try await source.token() }
        try await until { await old.calls == 2 }
        try await source.replace(refresh: { try await new.next() })
        _ = await second.result
        let third = Task { try await source.token() }
        try await until { await new.calls == 1 }
        let completed = Counter()
        let closing = Task { await source.shutdownAndWait(); completed.value.withLock { $0 += 1 } }
        let otherClose = Task { await source.shutdownAndWait(); completed.value.withLock { $0 += 1 } }
        closing.cancel()
        await expect(.stopped) { _ = try await third.value }
        try await until { await new.cancellations.contains(1) }
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertEqual(completed.value.withLock { $0 }, 0)
        try await new.complete(1, .success(lease(clock)))
        try await old.complete(2, .success(lease(clock)))
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertEqual(completed.value.withLock { $0 }, 0)
        try await old.complete(1, .success(lease(clock)))
        await closing.value; await otherClose.value
        XCTAssertEqual(completed.value.withLock { $0 }, 2)
        await expect(.stopped) { _ = try await source.token() }
    }

    func testUnsettledCancelledRefreshesRemainBoundedUntilActualCompletion() async throws {
        let clock = Clock(), refresh = Refresh(honorCancellation: false), source = try source(refresh, clock, maximum: 1)
        defer { Task { await refresh.close(); await source.shutdownAndWait() } }
        let abandoned = Task { try await source.token() }
        try await until { await refresh.calls == 1 }
        abandoned.cancel(); _ = await abandoned.result
        try await until { await refresh.cancellations.contains(1) }
        await expect(.capacityExceeded) { _ = try await source.token() }
        try await refresh.complete(1, .success(lease(clock)))
        try await until { await source.finishedAttemptCount == 1 }
        let next = Task { try await source.token() }
        try await until { await refresh.calls == 2 }
        try await refresh.complete(2, .success(lease(clock)))
        _ = try await next.value
        await source.shutdownAndWait()
    }

    func testConcurrentCallersShareRefreshAndThenReuseCache() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let tasks = (0..<20).map { _ in Task { try await source.token() } }
        defer { for task in tasks { task.cancel() } }
        try await until {
            let waiting = await source.pendingCallerCount, started = await refresh.calls
            return waiting == 20 && started == 1
        }
        let calls = await refresh.calls
        XCTAssertEqual(calls, 1)
        let token = try lease(clock)
        try await refresh.complete(1, .success(token))
        for task in tasks {
            let grant = try await task.value
            XCTAssertEqual(grant.expiresAt, token.expiresAt)
            _ = try await source.accessToken(for: grant)
            XCTAssertEqual(String(reflecting: grant), "FCMTokenGrant(redacted)")
        }
        _ = try await source.token()
        let cachedCalls = await refresh.calls
        XCTAssertEqual(cachedCalls, 1)
    }

    func testCapacityRejectsNewCallerWithoutDisturbingWaiters() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock, maximum: 2)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let first = Task { try await source.token() }, second = Task { try await source.token() }
        defer { first.cancel(); second.cancel() }
        try await until {
            let waiting = await source.pendingCallerCount, started = await refresh.calls
            return waiting == 2 && started == 1
        }
        await expect(.capacityExceeded) { _ = try await source.token() }
        try await refresh.complete(1, .success(lease(clock)))
        _ = try await first.value; _ = try await second.value
        let calls = await refresh.calls
        XCTAssertEqual(calls, 1)
    }

    func testCancellingOneWaiterPreservesOthersRefresh() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let cancelled = Task { try await source.token() }, keeper = Task { try await source.token() }
        defer { cancelled.cancel(); keeper.cancel() }
        try await until {
            let waiting = await source.pendingCallerCount, started = await refresh.calls
            return waiting == 2 && started == 1
        }
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Expected cancellation") } catch { XCTAssertTrue(error is CancellationError) }
        let pending = await source.pendingCallerCount, cancellations = await refresh.cancellations
        XCTAssertEqual(pending, 1); XCTAssertTrue(cancellations.isEmpty)
        try await refresh.complete(1, .success(lease(clock)))
        _ = try await keeper.value
    }

    func testLastCancellationCancelsRefreshAndIgnoresItsLateSuccess() async throws {
        let clock = Clock(), refresh = Refresh(honorCancellation: false), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let abandoned = Task { try await source.token() }
        defer { abandoned.cancel() }
        try await until { await refresh.calls == 1 }
        abandoned.cancel()
        do { _ = try await abandoned.value; XCTFail("Expected cancellation") } catch { XCTAssertTrue(error is CancellationError) }
        try await until { await refresh.cancellations.contains(1) }
        let current = Task { try await source.token() }
        defer { current.cancel() }
        try await until { await refresh.calls == 2 }
        try await refresh.complete(1, .success(lease(clock, seconds: 1000)))
        try await until { await source.finishedAttemptCount == 1 }
        let pending = await source.pendingCallerCount
        XCTAssertEqual(pending, 1)
        let fresh = try lease(clock)
        try await refresh.complete(2, .success(fresh))
        let result = try await current.value
        XCTAssertEqual(result.expiresAt, fresh.expiresAt)
    }

    func testRefreshMarginAndOldInvalidationDoNotEvictNewToken() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let initial = Task { try await source.token() }
        defer { initial.cancel() }
        try await until { await refresh.calls == 1 }
        try await refresh.complete(1, .success(lease(clock)))
        let old = try await initial.value
        clock.advance(3540)
        let renewed = Task { try await source.token() }
        defer { renewed.cancel() }
        try await until { await refresh.calls == 2 }
        let next = try lease(clock)
        try await refresh.complete(2, .success(next))
        let fresh = try await renewed.value
        await source.invalidate(old)
        await expect(.invalidated) { _ = try await source.accessToken(for: old) }
        _ = try await source.accessToken(for: fresh)
        let cached = try await source.token(), calls = await refresh.calls
        XCTAssertEqual(cached.expiresAt, next.expiresAt); XCTAssertEqual(calls, 2)
    }

    func testCredentialReplacementRejectsOldGrantsAndPendingWaiters() async throws {
        let clock = Clock(), oldProvider = Refresh(honorCancellation: false), newProvider = Refresh()
        let source = try source(oldProvider, clock)
        defer { Task { await source.shutdown(); await oldProvider.close(); await newProvider.close() } }
        let initial = Task { try await source.token() }
        defer { initial.cancel() }
        try await until { await oldProvider.calls == 1 }
        try await oldProvider.complete(1, .success(lease(clock)))
        let oldGrant = try await initial.value
        await source.invalidate(oldGrant)
        let pending = Task { try await source.token() }
        defer { pending.cancel() }
        try await until { await oldProvider.calls == 2 }
        try await source.replace(refresh: { try await newProvider.next() })
        await expect(.credentialsChanged) { _ = try await pending.value }
        await expect(.credentialsChanged) { _ = try await source.accessToken(for: oldGrant) }
        try await oldProvider.complete(2, .success(lease(clock, seconds: 1000)))
        try await until { await source.finishedAttemptCount == 2 }
        let current = Task { try await source.token() }
        defer { current.cancel() }
        try await until { await newProvider.calls == 1 }
        let token = try lease(clock)
        try await newProvider.complete(1, .success(token))
        let result = try await current.value
        XCTAssertEqual(result.expiresAt, token.expiresAt)
    }

    func testShutdownIsTerminalAndRejectsAlreadyIssuedGrants() async throws {
        let clock = Clock(), refresh = Refresh(honorCancellation: false), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let initial = Task { try await source.token() }
        defer { initial.cancel() }
        try await until { await refresh.calls == 1 }
        try await refresh.complete(1, .success(lease(clock)))
        let grant = try await initial.value
        await source.invalidate(grant)
        let pending = Task { try await source.token() }
        defer { pending.cancel() }
        try await until { await refresh.calls == 2 }
        await source.shutdown()
        await expect(.stopped) { _ = try await pending.value }
        await expect(.stopped) { _ = try await source.token() }
        await expect(.stopped) { _ = try await source.accessToken(for: grant) }
        await expect(.stopped) { try await source.replace(refresh: { try await refresh.next() }) }
        try await refresh.complete(2, .success(lease(clock)))
        try await until { await source.finishedAttemptCount == 2 }
        await expect(.stopped) { _ = try await source.token() }
    }

    func testProviderFailureAndShortLifetimeDoNotRetryAutomatically() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let failed = Task { try await source.token() }
        defer { failed.cancel() }
        try await until { await refresh.calls == 1 }
        try await refresh.complete(1, .failure(FCMError.network))
        do { _ = try await failed.value; XCTFail("Expected provider failure") }
        catch { XCTAssertEqual(error as? FCMError, .network) }
        let calls = await refresh.calls
        XCTAssertEqual(calls, 1)
        let short = Task { try await source.token() }
        defer { short.cancel() }
        try await until { await refresh.calls == 2 }
        try await refresh.complete(2, .success(lease(clock, seconds: 60)))
        await expect(.insufficientLifetime) { _ = try await short.value }
        let finalCalls = await refresh.calls
        XCTAssertEqual(finalCalls, 2)
    }

    func testGrantsCannotCrossSourcesAndExpireAtUse() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock)
        let other = try FCMTokenSource(now: { clock.now() }, refresh: { try await refresh.next() })
        defer { Task { await source.shutdown(); await other.shutdown(); await refresh.close() } }
        let task = Task { try await source.token() }
        defer { task.cancel() }
        try await until { await refresh.calls == 1 }
        try await refresh.complete(1, .success(lease(clock)))
        let grant = try await task.value
        await expect(.credentialsChanged) { _ = try await other.accessToken(for: grant) }
        await other.invalidate(grant)
        _ = try await source.accessToken(for: grant)
        clock.advance(3600)
        do { _ = try await source.accessToken(for: grant); XCTFail("Expected expiry") }
        catch { XCTAssertEqual(error as? FCMError, .tokenExpired) }
    }

    func testAlreadyCancelledCallerDoesNotStartRefresh() async throws {
        let clock = Clock(), refresh = Refresh(), source = try source(refresh, clock)
        defer { Task { await source.shutdown(); await refresh.close() } }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await source.token()
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        let calls = await refresh.calls, pending = await source.pendingCallerCount
        XCTAssertEqual(calls, 0); XCTAssertEqual(pending, 0)
    }

    func testConfigurationBounds() throws {
        let clock = Clock(), refresh = Refresh()
        for margin in [-1.0, .nan, .infinity, 3600] { XCTAssertThrowsError(try source(refresh, clock, margin: margin)) }
        for count in [0, -1, 1025] { XCTAssertThrowsError(try source(refresh, clock, maximum: count)) }
    }
}
