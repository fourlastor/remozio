import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class ApprovalRelayCoordinatorTests: XCTestCase, @unchecked Sendable {
    private final class Relay: OwnedApprovalRelay, Sendable {
        let counts = Mutex((started: 0, closed: 0))
        let event: @Sendable (DirectListenerEvent) -> Void
        init(_ event: @escaping @Sendable (DirectListenerEvent) -> Void) { self.event = event }
        func start() { counts.withLock { $0.started += 1 } }
        func closeAndWait() async { counts.withLock { $0.closed += 1 } }
    }
    private final class Factory: Sendable {
        struct Attempt: Sendable { let port: UInt16; let relay: Relay }
        let attempts = Mutex([Attempt]())
        let failures = Mutex(0)
        func make(_ port: UInt16, _ event: @escaping @Sendable (DirectListenerEvent) -> Void) throws -> any OwnedApprovalRelay {
            if failures.withLock({ remaining in
                guard remaining > 0 else { return false }
                remaining -= 1; return true
            }) { throw ApprovalRelayError.stopped }
            let relay = Relay(event)
            attempts.withLock { $0.append(.init(port: port, relay: relay)) }
            return relay
        }
    }
    private func wait(_ owner: ApprovalRelayCoordinator, for value: ApprovalRelayCoordinator.Status) async throws {
        for _ in 0..<100 {
            if await owner.status == value { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("Relay did not report the expected state")
    }
    func testMeasuredReadinessStableTargetAndReplacementCleanup() async throws {
        let factory = Factory()
        let owner = try ApprovalRelayCoordinator(factory: factory.make)
        try await owner.update(.noEligiblePhones)
        XCTAssertTrue(factory.attempts.withLock { $0.isEmpty })
        try await owner.update(.ready(port: 10001))
        let first = factory.attempts.withLock { $0[0].relay }
        let starting = await owner.status
        XCTAssertEqual(starting, .starting)
        first.event(.ready(port: 9090))
        try await wait(owner, for: .ready)
        try await owner.update(.ready(port: 10001))
        XCTAssertEqual(factory.attempts.withLock { $0.count }, 1)
        try await owner.update(.ready(port: 10002))
        XCTAssertEqual(first.counts.withLock { $0.closed }, 1)
        XCTAssertEqual(factory.attempts.withLock { $0.map(\.port) }, [10001, 10002])
        // An old endpoint callback cannot make its replacement appear ready.
        first.event(.ready(port: 9090))
        try await Task.sleep(for: .milliseconds(20))
        let replacement = await owner.status
        XCTAssertEqual(replacement, .starting)
        await owner.close()
        XCTAssertEqual(factory.attempts.withLock { $0.last!.relay.counts.withLock { $0.closed } }, 1)
    }
    func testAuthorityLossClosesEndpointAndNoLateCallbackReopensIt() async throws {
        let factory = Factory()
        let owner = try ApprovalRelayCoordinator(factory: factory.make)
        try await owner.update(.ready(port: 10001))
        let relay = factory.attempts.withLock { $0[0].relay }
        try await owner.update(.authorityUnavailable)
        XCTAssertEqual(relay.counts.withLock { $0.closed }, 1)
        relay.event(.ready(port: 9090))
        try await Task.sleep(for: .milliseconds(20))
        let idle = await owner.status
        XCTAssertEqual(idle, .idle)
        await owner.close()
        do { try await owner.update(.ready(port: 10002)); XCTFail("Closed owner reopened") }
        catch { }
        let closed = await owner.status
        XCTAssertEqual(closed, .closed)
    }
    func testConstructorFailureObeysRetryDelayAndNewTargetCanRecoverPromptly() async throws {
        let factory = Factory()
        factory.failures.withLock { $0 = 1 }
        let owner = try ApprovalRelayCoordinator(retryMilliseconds: 200, factory: factory.make)
        try await owner.update(.ready(port: 10001))
        let failed = await owner.status
        XCTAssertEqual(failed, .failed)
        try await owner.update(.ready(port: 10001))
        XCTAssertTrue(factory.attempts.withLock { $0.isEmpty })
        try await Task.sleep(for: .milliseconds(220))
        try await owner.update(.ready(port: 10001))
        XCTAssertEqual(factory.attempts.withLock { $0.count }, 1)
        let relay = factory.attempts.withLock { $0[0].relay }
        relay.event(.failed)
        try await wait(owner, for: .failed)
        try await owner.update(.ready(port: 10001))
        XCTAssertEqual(factory.attempts.withLock { $0.count }, 1)
        try await owner.update(.ready(port: 10002))
        XCTAssertEqual(relay.counts.withLock { $0.closed }, 1)
        XCTAssertEqual(factory.attempts.withLock { $0.count }, 2)
        await owner.close()
    }
    func testFailureIsTerminalForAnIncarnationEvenWhenReadyCallbackArrivesLate() async throws {
        let factory = Factory()
        let owner = try ApprovalRelayCoordinator(factory: factory.make)
        try await owner.update(.ready(port: 10001))
        let relay = factory.attempts.withLock { $0[0].relay }
        relay.event(.failed)
        try await wait(owner, for: .failed)
        relay.event(.ready(port: 9090))
        try await Task.sleep(for: .milliseconds(20))
        let failed = await owner.status
        XCTAssertEqual(failed, .failed)
        await owner.close()
    }
    private final class DrainGate: @unchecked Sendable {
        private struct State { var open = false; var waiters: [CheckedContinuation<Void, Never>] = [] }
        private let state = Mutex(State())
        func wait() async {
            await withCheckedContinuation { continuation in
                let done = state.withLock { value in
                    if value.open { return true }
                    value.waiters.append(continuation); return false
                }
                if done { continuation.resume() }
            }
        }
        func release() {
            let waiters = state.withLock { value in
                value.open = true
                let waiters = value.waiters; value.waiters.removeAll(); return waiters
            }
            for waiter in waiters { waiter.resume() }
        }
    }
    private final class DrainingRelay: OwnedApprovalRelay, @unchecked Sendable {
        let gate = DrainGate()
        let firstClose = XCTestExpectation(description: "replacement starts draining")
        let calls = Mutex(0)
        let closing = XCTestExpectation(description: "both callers drain the old relay")
        init() { closing.expectedFulfillmentCount = 2 }
        func start() { }
        func closeAndWait() async {
            let first = calls.withLock { value in value += 1; return value == 1 }
            if first { firstClose.fulfill() }
            closing.fulfill(); await gate.wait()
        }
    }
    func testShutdownDuringReplacementDrainsOldRelayAndCreatesNoNewEndpoint() async throws {
        let old = DrainingRelay(), ports = Mutex([UInt16]())
        let owner = try ApprovalRelayCoordinator(factory: { port, event in
            ports.withLock { $0.append(port) }
            return old
        })
        try await owner.update(.ready(port: 10001))
        let replacement = Task { try await owner.update(.ready(port: 10002)) }
        await fulfillment(of: [old.firstClose], timeout: 2)
        let shutdown = Task { await owner.close() }
        await fulfillment(of: [old.closing], timeout: 2)
        old.gate.release()
        await shutdown.value
        try await replacement.value
        XCTAssertEqual(ports.withLock { $0 }, [10001])
        let closed = await owner.status
        XCTAssertEqual(closed, .closed)
    }

    func testInvalidBoundsRejectBeforeListenerConstruction() {
        XCTAssertThrowsError(try ApprovalRelayCoordinator(listenPort: 0, report: { _ in }))
        XCTAssertThrowsError(try ApprovalRelayCoordinator(listenPort: 9090, maximumConnections: 0, report: { _ in }))
        XCTAssertThrowsError(try ApprovalRelayCoordinator(listenPort: 9090, timeoutMilliseconds: 0, report: { _ in }))
        XCTAssertThrowsError(try ApprovalWebSocketRelay(listenPort: 9090, targetPort: 9090, event: { _ in }))
        XCTAssertThrowsError(try ApprovalWebSocketRelay(listenPort: 9090, targetPort: 0, event: { _ in }))
    }
}
