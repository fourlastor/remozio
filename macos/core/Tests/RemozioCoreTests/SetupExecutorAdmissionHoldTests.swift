import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

enum SetupExecutorAdmissionTestPhases {
    static func owned(executor: SetupAuditUpgradeWorkExecutor,
        deadline: ContinuousClock.Instant? = nil, cancellation: SetupAuditUpgradeCancellation? = nil) throws
        -> SetupRetainedInvocationReservation.RestorationPhases {
        let work = try SetupOwnerAsyncWork.fixtureOwned(), reply = try SetupOwnerAsyncWork.fixtureOwned()
        let hold = try SetupAccountOwner.ExecutorAdmission.durableOwned(admission: work.admit(), reply: reply.admit(), activity: nil)
        return try .owned(executor: executor, hold: hold, deadline: deadline, cancellation: cancellation)
    }
}

final class SetupExecutorAdmissionHoldTests: XCTestCase {
    private typealias Admission = SetupAccountOwner.ExecutorAdmission
    private typealias Phases = SetupRetainedInvocationReservation.RestorationPhases
    private enum Failure: Error { case expected, timeout }
    private final class Gate: @unchecked Sendable {
        let entered = Mutex(false)
        private let resume = DispatchSemaphore(value: 0)
        func wait() throws {
            entered.withLock { $0 = true }
            guard resume.wait(timeout: .now() + 15) == .success else { throw Failure.timeout }
        }
        func open() { resume.signal() }
    }
    private final class Probe<Value: Sendable>: @unchecked Sendable {
        let task: Task<Value, any Error>
        let finished = Mutex(false)
        init(_ operation: @escaping @Sendable () async throws -> Value) {
            let actual = Task { try await operation() }; task = actual
            Task { [self] in _ = await actual.result; finished.withLock { $0 = true } }
        }
        func value() async throws -> Value { try await task.value }
    }
    private final class Fixture: @unchecked Sendable {
        let work: SetupOwnerAsyncWork, reply: SetupOwnerAsyncWork
        let activity: ReleaseActivityFixture, installer: ReleaseActivityBarrier
        let held: Admission
        init() throws {
            work = try .fixtureOwned(); reply = try .fixtureOwned()
            activity = try .init(); installer = try activity.open()
            held = try .durableOwned(admission: work.admit(), reply: reply.admit(), activity: installer.acquireShared())
        }
        func phases(_ executor: SetupAuditUpgradeWorkExecutor = .init()) throws -> Phases {
            try .owned(executor: executor, hold: held)
        }
        func assertHeld() {
            XCTAssertFalse(work.isIdle); XCTAssertFalse(reply.isIdle)
            XCTAssertThrowsError(try installer.acquireExclusive())
        }
        func assertReleased() throws {
            XCTAssertTrue(work.isIdle); XCTAssertTrue(reply.isIdle)
            let exclusive = try installer.acquireExclusive(); exclusive.close()
        }
        deinit { held.releaseRecord() }
    }
    private static func eventually(until timeout: Duration = .seconds(5), _ predicate: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failure.timeout }
            try await ContinuousClock().sleep(for: .milliseconds(1))
        }
    }
    private static func invalidated<Value>(_ operation: () async throws -> Value) async {
        do { _ = try await operation(); XCTFail("A released hold entered its body") }
        catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
    }

    // DESIGN14.
    func testBodyKeepsTokensUntilActualReturnAndLaterBodyIsRefused() async throws {
        let f = try Fixture(), writes = Mutex(0)
        try await f.held.runRestorationPhase(on: .init()) { _ in
            f.held.releaseRecord(); f.assertHeld(); writes.withLock { $0 += 1 }
        }
        try f.assertReleased()
        do {
            try await f.held.runRestorationPhase(on: .init()) { _ in writes.withLock { $0 += 1 } }
            XCTFail("A released admission accepted work")
        } catch { XCTAssertTrue(error is Admission.Released) }
        XCTAssertEqual(writes.withLock { $0 }, 1)
    }
    // DESIGN16.
    func testRefusedPhaseWaitsForEarlierBodyWithoutEnteringAnotherExecutor() async throws {
        let f = try Fixture(), gate = Gate(), writes = Mutex(0)
        let p1 = try f.phases(), p2 = try f.phases()
        let first = Probe { try await p1.cleanup { f.held.releaseRecord(); try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let second = Probe { try await p2.run { writes.withLock { $0 += 1 } } }
        try await ContinuousClock().sleep(for: .milliseconds(200))
        XCTAssertFalse(second.finished.withLock { $0 }); XCTAssertEqual(writes.withLock { $0 }, 0); f.assertHeld()
        gate.open(); try await first.value()
        await Self.invalidated { try await second.value() }
        try f.assertReleased()
    }
    // DESIGN17, including the direct wait form.
    func testReleasingPhaseAndDirectWaitJoinEarlierBodyBeforeReturning() async throws {
        let f = try Fixture(), gate = Gate(), released = Mutex(false)
        let p1 = try f.phases(), p2 = try f.phases()
        let prior = Probe { try await p2.cleanup { try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let releasing = Probe { try await p1.cleanup { f.held.releaseRecord(); released.withLock { $0 = true }; return 7 } }
        try await Self.eventually { released.withLock { $0 } }
        let direct = Probe { await f.held.waitForReleaseAfterRecord(until: nil) }
        try await ContinuousClock().sleep(for: .milliseconds(200))
        XCTAssertFalse(releasing.finished.withLock { $0 }); XCTAssertFalse(direct.finished.withLock { $0 }); f.assertHeld()
        gate.open(); try await prior.value()
        let result = try await releasing.value(); XCTAssertEqual(result, 7)
        try await direct.value(); try f.assertReleased()
    }
    // DESIGN19. Join failure is a status fact, not a field of the evidence snapshot.
    func testLedgerJoinAfterReleaseReportsJoinFailedAndSkipsCleanup() async throws {
        let f = try Fixture(), calls = Mutex(0)
        let ledger = SetupRetainedRecoveryLedger(executor: .init(), hold: f.held)
        try ledger.retainCleanup { calls.withLock { $0 += 1 } }
        ledger.invocationCleanupReturned(); _ = try ledger.sealForClaim(); f.held.releaseRecord()
        let joined = try ledger.joinSealed()
        await Self.invalidated { try await joined.value }
        XCTAssertEqual(ledger.status(), .observed(.joinFailed))
        XCTAssertEqual(calls.withLock { $0 }, 0); try f.assertReleased()
    }
    // DESIGN21, with a real release activity barrier.
    func testActivityRemainsSharedInsideBodyAfterRecordRelease() async throws {
        let f = try Fixture(), phases = try f.phases()
        try await phases.cleanup { f.held.releaseRecord(); f.assertHeld() }
        try f.assertReleased()
    }
    // DESIGN23: cancellation stops the waiter, never the earlier body or its admission.
    func testCancelledReleaseWaiterReturnsTheBodyResultAndKeepsEarlierHold() async throws {
        let f = try Fixture(), gate = Gate(), released = Mutex(false)
        let p1 = try f.phases(), p2 = try f.phases()
        let prior = Probe { try await p2.cleanup { try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let waiter = Probe { try await p1.cleanup { f.held.releaseRecord(); released.withLock { $0 = true }; return 7 } }
        try await Self.eventually { released.withLock { $0 } }
        waiter.task.cancel()
        try await Self.eventually(until: .milliseconds(100)) { waiter.finished.withLock { $0 } }
        let result = try await waiter.value(); XCTAssertEqual(result, 7); f.assertHeld()
        XCTAssertFalse(prior.finished.withLock { $0 })
        gate.open(); try await prior.value(); try f.assertReleased()
    }
    // DESIGN23: the attempt deadline stops only the release wait after a successful body.
    func testAttemptDeadlineStopsReleaseWaitWithoutClosingEarlierHold() async throws {
        let f = try Fixture(), gate = Gate(), released = Mutex(false)
        let original = try f.phases(), p2 = try f.phases()
        let prior = Probe { try await p2.cleanup { try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(50))
        let p1 = try original.forAttempt(until: deadline)
        let waiter = Probe { try await p1.run { f.held.releaseRecord(); released.withLock { $0 = true }; return 7 } }
        try await Self.eventually { released.withLock { $0 } }
        try await Self.eventually(until: .milliseconds(100)) { waiter.finished.withLock { $0 } }
        let result = try await waiter.value(); XCTAssertEqual(result, 7); f.assertHeld()
        XCTAssertFalse(prior.finished.withLock { $0 })
        gate.open(); try await prior.value(); try f.assertReleased()
    }
    func testMarkedReleaseRefusesPhaseBeforeTheOutsideLockCloseRuns() async throws {
        let f = try Fixture(), phases = try f.phases(), writes = Mutex(0)
        let finish = f.held.markRecordReleased(); f.assertHeld()
        let refused = Probe { try await phases.cleanup { writes.withLock { $0 += 1 } } }
        try await ContinuousClock().sleep(for: .milliseconds(200))
        XCTAssertFalse(refused.finished.withLock { $0 }); XCTAssertEqual(writes.withLock { $0 }, 0)
        finish(); finish()
        await Self.invalidated { try await refused.value() }
        try f.assertReleased()
    }
    func testOwnedFactoryRefusesAReleasedOrAlreadyRunningFixtureHold() async throws {
        let f = try Fixture(), gate = Gate(), phases = try f.phases()
        let running = Probe { try await phases.cleanup { try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        XCTAssertThrowsError(try f.phases())
        gate.open(); try await running.value(); f.held.releaseRecord()
        XCTAssertThrowsError(try f.phases()); try f.assertReleased()
    }
    func testDurableOwnedRefusesOrdinaryAdmissionTokensWithoutClosingThem() throws {
        let work = SetupOwnerAsyncWork(), reply = SetupOwnerAsyncWork()
        let a = try work.admit(), b = try reply.admit()
        defer { a.close(); b.close() }
        XCTAssertThrowsError(try Admission.durableOwned(admission: a, reply: b, activity: nil))
        XCTAssertTrue(work.permits(a)); XCTAssertTrue(reply.permits(b))
    }
    func testDurableOwnedRefusesClosedFixtureTokens() throws {
        let work = try SetupOwnerAsyncWork.fixtureOwned(), reply = try SetupOwnerAsyncWork.fixtureOwned()
        let a = try work.admit(), b = try reply.admit(); defer { b.close() }
        a.close()
        XCTAssertThrowsError(try Admission.durableOwned(admission: a, reply: b, activity: nil))
        XCTAssertTrue(work.isIdle); XCTAssertTrue(reply.permits(b))
    }
    func testDurableOwnedRefusesMixedFixtureAndOrdinaryTokens() throws {
        let work = try SetupOwnerAsyncWork.fixtureOwned(), reply = SetupOwnerAsyncWork()
        let a = try work.admit(), b = try reply.admit(); defer { a.close(); b.close() }
        XCTAssertThrowsError(try Admission.durableOwned(admission: a, reply: b, activity: nil))
        XCTAssertTrue(work.permits(a)); XCTAssertTrue(reply.permits(b))
    }

}
