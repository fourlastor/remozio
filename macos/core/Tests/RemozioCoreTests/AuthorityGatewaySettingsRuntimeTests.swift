import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityGatewaySettingsRuntimeTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private final class Listener: OwnedGatewaySettingsControlListener, @unchecked Sendable {
        let starts = Mutex(0)
        let closes = Mutex(0)
        let settled = Mutex(0)
        let gates = Mutex<[CheckedContinuation<Void, Never>]>([])
        let rejectStart: Bool
        let blockClose: Bool
        init(rejectStart: Bool = false, blockClose: Bool = false) {
            self.rejectStart = rejectStart; self.blockClose = blockClose
        }
        func start() throws { starts.withLock { $0 += 1 }; if rejectStart { throw Failed() } }
        func closeAndWait() async {
            closes.withLock { $0 += 1 }
            if blockClose { await withCheckedContinuation { pending in gates.withLock { $0.append(pending) } } }
            settled.withLock { $0 += 1 }
        }
        func release() {
            let pending = gates.withLock { let old = $0; $0 = []; return old }
            for continuation in pending { continuation.resume() }
        }
    }
    private func waitUntil(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(4))
        while !condition() {
            guard ContinuousClock.now < deadline else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testAnOlderHostCanRunWithoutConstructingANativeListener() async throws {
        let factories = Mutex(0)
        let owner = AuthorityGatewaySettingsRuntime { factories.withLock { $0 += 1 }; return nil }
        try await owner.start(); await owner.close(); await owner.close()
        XCTAssertEqual(factories.withLock { $0 }, 1)
    }
    func testStartupFailureRetainsTheConstructedListenerUntilCleanupSettles() async throws {
        let listener = Listener(rejectStart: true)
        let owner = AuthorityGatewaySettingsRuntime { listener }
        do { try await owner.start(); XCTFail() } catch { XCTAssertTrue(error is Failed) }
        XCTAssertEqual(listener.closes.withLock { $0 }, 0)
        await owner.close(); await owner.close()
        XCTAssertEqual(listener.starts.withLock { $0 }, 1); XCTAssertEqual(listener.closes.withLock { $0 }, 1)
        XCTAssertEqual(listener.settled.withLock { $0 }, 1)
    }
    func testConcurrentAndCancelledClosesJoinTheSameWorkBeforeReturning() async throws {
        let listener = Listener(blockClose: true), completed = Mutex(0)
        let owner = AuthorityGatewaySettingsRuntime { listener }; try await owner.start()
        let first = Task { @Sendable in await owner.close(); completed.withLock { $0 += 1 } }
        defer { listener.release() }
        try await waitUntil { listener.gates.withLock { !$0.isEmpty } }
        let second = Task { @Sendable in await owner.close(); completed.withLock { $0 += 1 } }
        first.cancel(); try await Task.sleep(for: .milliseconds(25))
        XCTAssertEqual(completed.withLock { $0 }, 0); XCTAssertEqual(listener.closes.withLock { $0 }, 1)
        listener.release(); await first.value; await second.value
        XCTAssertEqual(completed.withLock { $0 }, 2); XCTAssertEqual(listener.settled.withLock { $0 }, 1)
    }
    func testClosingBeforeStartupPreventsTheFactoryAndAllFutureStarts() async throws {
        let calls = Mutex(0)
        let owner = AuthorityGatewaySettingsRuntime { calls.withLock { $0 += 1 }; return nil }
        await owner.close()
        do { try await owner.start(); XCTFail() } catch {}
        XCTAssertEqual(calls.withLock { $0 }, 0)
    }
    func testAFactoryFailureCannotBeRepeatedByAnotherStart() async throws {
        let calls = Mutex(0)
        let owner = AuthorityGatewaySettingsRuntime { calls.withLock { $0 += 1 }; throw Failed() }
        for _ in 0..<2 { do { try await owner.start(); XCTFail() } catch {} }
        await owner.close(); XCTAssertEqual(calls.withLock { $0 }, 1)
    }
    func testDeinitDoesNotAbandonAnUnclosedListener() async throws {
        let listener = Listener(blockClose: true)
        var owner: AuthorityGatewaySettingsRuntime? = AuthorityGatewaySettingsRuntime { listener }
        final class WeakOwner { weak var value: AuthorityGatewaySettingsRuntime?; init(_ owner: AuthorityGatewaySettingsRuntime?) { value = owner } }
        let released = WeakOwner(owner); try await owner?.start(); owner = nil
        defer { listener.release() }
        XCTAssertNil(released.value)
        try await waitUntil { listener.gates.withLock { !$0.isEmpty } }
        XCTAssertEqual(listener.settled.withLock { $0 }, 0)
        listener.release(); try await waitUntil { listener.settled.withLock { $0 == 1 } }
    }
}
