import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupAuditUpgradeWorkExecutorTests: XCTestCase {
    private struct Refused: Error {}
    private final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Void, any Error>?
        func set(_ result: Result<Void, any Error>) { lock.withLock { self.result = result } }
        func check() throws { try lock.withLock { try XCTUnwrap(result).get() } }
    }
    private func asynchronous(_ body: @escaping @Sendable () async throws -> Void) throws {
        let done = expectation(description: "Worker result"), result = ResultBox()
        Task.detached {
            do { try await body(); result.set(.success(())) } catch { result.set(.failure(error)) }
            done.fulfill()
        }
        wait(for: [done], timeout: 30); try result.check()
    }
    func testThrowingWorkReleasesTheSlotAndTheNextWorkerHasTheRequiredStack() throws {
        try asynchronous {
            let executor = SetupAuditUpgradeWorkExecutor()
            do { let _: Void = try await executor.run { _ in throw Refused() }; XCTFail("Failed work") }
            catch is Refused {}
            let stack = try await executor.run { _ in
                XCTAssertEqual(pthread_main_np(), 0)
                return pthread_get_stacksize_np(pthread_self())
            }
            XCTAssertGreaterThanOrEqual(stack, SetupAuditUpgradeWorkExecutor.stackBytes)
        }
    }
    func testCancelledBeforeAdmissionDoesNotRunTheBodyOrConsumeTheWorkerSlot() throws {
        try asynchronous {
            let executor = SetupAuditUpgradeWorkExecutor(), cancellation = SetupAuditUpgradeCancellation()
            cancellation.cancel()
            do {
                try await executor.run(cancellation: cancellation) { _ in XCTFail("Cancelled body") }
                XCTFail("Cancelled result")
            } catch is CancellationError {}
            let value = try await executor.run { _ in 42 }
            XCTAssertEqual(value, 42)
        }
    }
    func testConcurrentWorkIsRefusedWithoutStartingAnotherBody() throws {
        let executor = SetupAuditUpgradeWorkExecutor(), gate = DispatchSemaphore(value: 0)
        let started = expectation(description: "First worker started"), firstDone = expectation(description: "First worker settled")
        Task.detached {
            do {
                try await executor.run { _ in
                    started.fulfill()
                    guard gate.wait(timeout: .now() + 15) == .success else { throw Refused() }
                }
            } catch { XCTFail("First worker: \(error)") }
            firstDone.fulfill()
        }
        wait(for: [started], timeout: 5)
        let secondDone = expectation(description: "Second request refused")
        Task.detached {
            do { try await executor.run { _ in XCTFail("Concurrent body") }; XCTFail("Concurrent admission") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            secondDone.fulfill()
        }
        wait(for: [secondDone], timeout: 5); gate.signal(); wait(for: [firstDone], timeout: 5)
    }
    func testTaskCancellationReachesPreimportedAuthorizationOnTheBlockingWorker() throws {
        let h = try RuntimeAuditUpgradeOperationTests.Harness(), owner = try h.owner(); defer { try? owner.close() }
        let cancellation = SetupAuditUpgradeCancellation()
        let grant = try SetupAuditUpgradeAuthorization.openOwned(cancellation: cancellation, verifyRights: {})
        let gate = DispatchSemaphore(value: 0), started = expectation(description: "Authorized worker started")
        let done = expectation(description: "Cancelled worker settled")
        let task = Task.detached {
            do {
                try await owner.performAuditUpgradeWork(authorization: grant) { token, admission in
                    XCTAssertTrue(token === cancellation); XCTAssertFalse(Task.isCancelled)
                    let scope = try owner.acquireAuditUpgradeScope(authorization: grant, admission: admission)
                    defer { do { try scope.close() } catch { XCTFail("Cleanup: \(error)") } }
                    started.fulfill()
                    guard gate.wait(timeout: .now() + 15) == .success else { throw Refused() }
                    try scope.validateLifetime()
                    XCTFail("Cancelled authorization")
                }
                XCTFail("Cancelled result")
            } catch is CancellationError {} catch { XCTFail("Unexpected worker error: \(error)") }
            done.fulfill()
        }
        wait(for: [started], timeout: 5); task.cancel(); gate.signal(); wait(for: [done], timeout: 5)
        XCTAssertThrowsError(try grant.validate()); try owner.verifyCurrent(); try h.machine { _ in () }
    }
    func testAfterReturnRunsOnceOnSuccessErrorCancellationAndBusyRefusal() throws {
        try asynchronous {
            let executor = SetupAuditUpgradeWorkExecutor(), ended = Mutex(0)
            let after: @Sendable () -> Void = { ended.withLock { $0 += 1 } }
            let value = try await executor.run(afterReturn: after) { _ in XCTAssertEqual(ended.withLock { $0 }, 0); return 7 }
            XCTAssertEqual(value, 7); XCTAssertEqual(ended.withLock { $0 }, 1)
            do { try await executor.run(afterReturn: after) { _ in throw Refused() }; XCTFail("Expected worker failure") }
            catch is Refused {}
            XCTAssertEqual(ended.withLock { $0 }, 2)
            let cancelled = SetupAuditUpgradeCancellation(); cancelled.cancel()
            do { try await executor.run(cancellation: cancelled, afterReturn: after) { _ in XCTFail("Cancelled body") }; XCTFail("Expected cancellation") }
            catch is CancellationError {}
            XCTAssertEqual(ended.withLock { $0 }, 3)
            let entered = Mutex(false), resume = DispatchSemaphore(value: 0)
            let actual = Task {
                try await executor.run(afterReturn: after) { token in
                    entered.withLock { $0 = true }
                    guard resume.wait(timeout: .now() + 10) == .success else { throw Refused() }
                    try token.check()
                }
            }
            defer { resume.signal() }
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            while !entered.withLock({ $0 }) {
                guard ContinuousClock.now < deadline else { throw Refused() }
                try await ContinuousClock().sleep(for: .milliseconds(1))
            }
            do { try await executor.run(afterReturn: after) { _ in XCTFail("Busy audit body") }; XCTFail("Expected busy audit") }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            XCTAssertEqual(ended.withLock { $0 }, 4)
            do { try await executor.runRestorationPhase(afterReturn: after) { _ in XCTFail("Busy phase body") }; XCTFail("Expected busy phase") }
            catch { XCTAssertTrue(error is SetupAuditUpgradeWorkExecutor.BusyBeforeBody) }
            XCTAssertEqual(ended.withLock { $0 }, 5)
            actual.cancel(); XCTAssertEqual(ended.withLock { $0 }, 5)
            resume.signal()
            do { try await actual.value; XCTFail("Cancelled worker returned success") } catch { XCTAssertTrue(error is CancellationError) }
            XCTAssertEqual(ended.withLock { $0 }, 6)
        }
    }

}
