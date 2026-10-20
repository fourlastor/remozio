import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityGatewaySettingsListenerSupervisorTests: XCTestCase, @unchecked Sendable {
    private struct Failed: Error {}
    private typealias Supervisor = AuthorityGatewaySettingsListenerSupervisor
    private final class Listener: OwnedGatewaySettingsControlListener, @unchecked Sendable {
        let starts = Mutex(0), closes = Mutex(0), settled = Mutex(0)
        let gates = Mutex<[CheckedContinuation<Void, Never>]>([])
        let fail: Bool, hold: Bool
        init(fail: Bool = false, hold: Bool = false) { self.fail = fail; self.hold = hold }
        func start() throws { starts.withLock { $0 += 1 }; if fail { throw Failed() } }
        func closeAndWait() async {
            closes.withLock { $0 += 1 }
            if hold { await withCheckedContinuation { pending in gates.withLock { $0.append(pending) } } }
            settled.withLock { $0 += 1 }
        }
        func release() {
            let previous = gates.withLock { let pending = $0; $0 = []; return pending }
            for pending in previous { pending.resume() }
        }
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(4))
        while !(await condition()) {
            guard ContinuousClock.now < end else { throw Failed() }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func testFailedStartDrainsBeforeRetryWithoutClosingTheForegroundOwner() async throws {
        let f = try AuthorityWakeSettingsTests.Fixture(), service = try f.service([AuthorityWakeSettingsTests.Driver()])
        let failed = Listener(fail: true, hold: true), healthy = Listener(), attempts = Mutex(0)
        let owner = try Supervisor(retryMilliseconds: 100) {
            let index = attempts.withLock { let old = $0; $0 += 1; return old }
            return AuthorityGatewaySettingsRuntime { index == 0 ? failed : healthy }
        }
        try await service.start(); let before = try f.state(); try await owner.start()
        defer { failed.release() }
        try await waitUntil { failed.gates.withLock { !$0.isEmpty } }
        XCTAssertEqual(attempts.withLock { $0 }, 1); XCTAssertEqual(healthy.starts.withLock { $0 }, 0)
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        XCTAssertEqual(try f.state(), before); XCTAssertEqual(before.deadlineMilliseconds, 5000)
        failed.release(); try await waitUntil { await owner.status == .listening }
        XCTAssertEqual(failed.settled.withLock { $0 }, 1); XCTAssertEqual(healthy.starts.withLock { $0 }, 1)
        XCTAssertEqual(f.closes.withLock { $0 }, 0); XCTAssertEqual(try f.state(), before)
        await owner.close(); XCTAssertEqual(healthy.closes.withLock { $0 }, 1)
        XCTAssertEqual(f.closes.withLock { $0 }, 0); try await service.close(); XCTAssertEqual(f.closes.withLock { $0 }, 1)
    }
    func testFactoryFailureRetriesWithFreshValidationAndNoLeakedListener() async throws {
        let attempts = Mutex(0), healthy = Listener()
        let owner = try Supervisor(retryMilliseconds: 100) {
            let index = attempts.withLock { let old = $0; $0 += 1; return old }
            return AuthorityGatewaySettingsRuntime { if index == 0 { throw Failed() }; return healthy }
        }
        try await owner.start(); try await waitUntil { await owner.status == .listening }
        XCTAssertEqual(attempts.withLock { $0 }, 2); XCTAssertEqual(healthy.starts.withLock { $0 }, 1)
        await owner.close(); XCTAssertEqual(healthy.closes.withLock { $0 }, 1)
    }
    func testCloseInterruptsTheRetryDelayWithoutStartingAnotherAttempt() async throws {
        let attempts = Mutex(0)
        let owner = try Supervisor(retryMilliseconds: 60_000) {
            attempts.withLock { $0 += 1 }; return AuthorityGatewaySettingsRuntime { throw Failed() }
        }
        try await owner.start(); try await waitUntil { await owner.status == .waiting }
        await owner.close(); let status = await owner.status; XCTAssertEqual(status, .closed)
        XCTAssertEqual(attempts.withLock { $0 }, 1)
    }
    func testConcurrentCancelledClosesJoinTheActiveListenerCleanup() async throws {
        let listener = Listener(hold: true), completed = Mutex(0)
        let owner = try Supervisor { AuthorityGatewaySettingsRuntime { listener } }
        try await owner.start(); try await waitUntil { await owner.status == .listening }
        let first = Task { await owner.close(); completed.withLock { $0 += 1 } }
        defer { listener.release() }
        try await waitUntil { listener.gates.withLock { !$0.isEmpty } }
        let second = Task { await owner.close(); completed.withLock { $0 += 1 } }
        first.cancel(); XCTAssertEqual(completed.withLock { $0 }, 0); XCTAssertEqual(listener.closes.withLock { $0 }, 1)
        listener.release(); await first.value; await second.value
        XCTAssertEqual(completed.withLock { $0 }, 2); XCTAssertEqual(listener.settled.withLock { $0 }, 1)
    }
    func testLegacyAbsenceCreatesNoListenerAndDoesNotRetry() async throws {
        let calls = Mutex(0)
        let owner = try Supervisor { calls.withLock { $0 += 1 }; return nil }
        try await owner.start(); try await waitUntil { await owner.status == .absent }
        await owner.close(); await owner.close(); XCTAssertEqual(calls.withLock { $0 }, 1)
    }
    func testCloseBeforeStartPreventsFactoriesAndInvalidRetryBoundsAreRejected() async throws {
        let calls = Mutex(0), owner = try Supervisor { calls.withLock { $0 += 1 }; return nil }
        await owner.close()
        do { try await owner.start(); XCTFail() } catch {}
        XCTAssertEqual(calls.withLock { $0 }, 0)
        for delay in [0, 99, 60_001] { XCTAssertThrowsError(try Supervisor(retryMilliseconds: delay) { XCTFail(); return nil }) }
    }
    func testDeinitWaitsForFailedListenerWorkAndCannotStartASuccessor() async throws {
        let listener = Listener(fail: true, hold: true), calls = Mutex(0)
        var owner: Supervisor? = try Supervisor(retryMilliseconds: 100) {
            calls.withLock { $0 += 1 }; return AuthorityGatewaySettingsRuntime { listener }
        }
        final class Weak { weak var value: Supervisor?; init(_ value: Supervisor?) { self.value = value } }
        let weak = Weak(owner); try await owner?.start()
        defer { listener.release() }
        try await waitUntil { listener.gates.withLock { !$0.isEmpty } }
        owner = nil; XCTAssertNil(weak.value); XCTAssertEqual(listener.settled.withLock { $0 }, 0)
        listener.release(); try await waitUntil { listener.settled.withLock { $0 == 1 } }
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(listener.closes.withLock { $0 }, 1)
    }
}
