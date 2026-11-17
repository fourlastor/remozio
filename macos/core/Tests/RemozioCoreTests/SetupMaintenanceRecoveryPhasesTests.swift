import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

private struct RecoveryPhaseThreadFrame: Sendable {
    let stackBytes: Int
    let hasTask: Bool
}
private actor RecoveryPhaseAsyncProbe {
    func hasCurrentTask() -> Bool { withUnsafeCurrentTask { $0 != nil } }
}
private enum RecoveryPhaseTestFailure: Error { case timeout }
private final class RecoveryPhaseValue<Value: Sendable>: Sendable {
    let value: Mutex<Value>
    init(_ value: Value) { self.value = Mutex(value) }
}

@MainActor
final class SetupMaintenanceRecoveryPhasesTests: XCTestCase {
    private typealias Phases = SetupRetainedInvocationReservation.RestorationPhases
    private nonisolated static func frame() -> RecoveryPhaseThreadFrame {
        .init(stackBytes: pthread_get_stacksize_np(pthread_self()), hasTask: withUnsafeCurrentTask { $0 != nil })
    }
    private static func eventually(_ check: @escaping @Sendable () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !check() {
            guard ContinuousClock.now < deadline else { throw RecoveryPhaseTestFailure.timeout }
            try await ContinuousClock().sleep(for: .milliseconds(1))
        }
    }
    func testSharedPhaseBodiesUseTheOriginalEightMiBStackWithoutASwiftTask() async throws {
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor())
        let running = try await phases.run { Self.frame() }
        let cleanup = try await phases.cleanup { Self.frame() }
        let acquisition = try await phases.acquire { Self.frame() }
        for frame in [running, cleanup, acquisition] {
            XCTAssertGreaterThanOrEqual(frame.stackBytes, SetupAuditUpgradeWorkExecutor.stackBytes)
            XCTAssertFalse(frame.hasTask)
        }
        XCTAssertTrue(withUnsafeCurrentTask { $0 != nil })
    }
    func testAsyncProbeRemainsOnItsTaskBetweenBlockingPhases() async throws {
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor()), probe = RecoveryPhaseAsyncProbe()
        let before = await probe.hasCurrentTask(); XCTAssertTrue(before)
        let body = try await phases.run { Self.frame() }; XCTAssertFalse(body.hasTask)
        let after = await probe.hasCurrentTask(); XCTAssertTrue(after)
    }
    func testOccupiedExecutorReturnsTypedBusyWithoutStartingTheSecondBody() async throws {
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor())
        let started = RecoveryPhaseValue(false), bodyWrites = Mutex(0), resume = DispatchSemaphore(value: 0)
        let first = Task { @Sendable [phases, started, resume] in
            try await phases.run {
                started.value.withLock { $0 = true }
                guard resume.wait(timeout: .now() + 5) == .success else { throw RecoveryPhaseTestFailure.timeout }
            }
        }
        defer { resume.signal(); first.cancel() }
        try await Self.eventually { started.value.withLock { $0 } }
        do {
            try await phases.acquire { bodyWrites.withLock { $0 += 1 } }
            XCTFail("A busy executor started another body")
        } catch { XCTAssertTrue(error is SetupAuditUpgradeWorkExecutor.BusyBeforeBody) }
        XCTAssertEqual(bodyWrites.withLock { $0 }, 0)
        resume.signal(); try await first.value
    }
    func testCancellationReachesTheWorkTokenInsideTheRunningThreadBeforeAWrite() async throws {
        let cancellation = SetupAuditUpgradeCancellation()
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor(), cancellation: cancellation)
        let started = RecoveryPhaseValue(false), bodyHasTask = RecoveryPhaseValue<Bool?>(nil), writes = RecoveryPhaseValue(0), resume = DispatchSemaphore(value: 0)
        let work = Task { @Sendable [phases, cancellation, started, bodyHasTask, writes, resume] in
            try await phases.run {
                bodyHasTask.value.withLock { $0 = withUnsafeCurrentTask { $0 != nil } }
                started.value.withLock { $0 = true }
                guard resume.wait(timeout: .now() + 5) == .success else { throw RecoveryPhaseTestFailure.timeout }
                try Task.checkCancellation()
                try cancellation.check()
                writes.value.withLock { $0 += 1 }
            }
        }
        defer { resume.signal(); work.cancel() }
        try await Self.eventually { started.value.withLock { $0 } }; work.cancel()
        try await Self.eventually {
            do { try cancellation.check(); return false } catch { return true }
        }
        resume.signal()
        do { try await work.value; XCTFail("The cancelled worker wrote") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(bodyHasTask.value.withLock { $0 }, false); XCTAssertEqual(writes.value.withLock { $0 }, 0)
    }
    func testCleanupIgnoresTheCancelledWorkTokenAndClosesExactlyOnce() async throws {
        let cancellation = SetupAuditUpgradeCancellation(), writes = Mutex(0), closes = Mutex(0)
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor(), cancellation: cancellation)
        cancellation.cancel()
        do { try await phases.run { writes.withLock { $0 += 1 } }; XCTFail("Cancelled work entered its body") }
        catch { XCTAssertTrue(error is CancellationError) }
        try await phases.closeActual { closes.withLock { $0 += 1 } }
        XCTAssertEqual(writes.withLock { $0 }, 0); XCTAssertEqual(closes.withLock { $0 }, 1)
    }
    func testExpiredAcquisitionNeverStartsItsBody() async throws {
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor(), deadline: .now.advanced(by: .milliseconds(-1)))
        let starts = Mutex(0)
        do { try await phases.acquire { starts.withLock { $0 += 1 } }; XCTFail("An expired attempt started") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(starts.withLock { $0 }, 0)
    }
    func testNativeDeadlineHasADistinctErrorAndDoesNotCancelTheWorkToken() async throws {
        let cancellation = SetupAuditUpgradeCancellation(), writes = Mutex(0)
        let phases = try Phases.owned(executor: SetupAuditUpgradeWorkExecutor(), deadline: .now.advanced(by: .milliseconds(-1)),
            cancellation: cancellation)
        do { try await phases.acquire { writes.withLock { $0 += 1 } }; XCTFail("Expired native work entered its body") }
        catch { XCTAssertEqual(error as? RuntimeMaintenanceStartupAttemptError, .deadlineExpired) }
        XCTAssertNoThrow(try cancellation.check()); XCTAssertEqual(writes.withLock { $0 }, 0)
    }

}
