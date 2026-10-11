import Foundation
import XCTest
import Synchronization
import RemozioProtocol
@testable import RemozioCore

final class AuthorityCommandExecutionWorkerTests: XCTestCase {
    private func notice(_ byte: UInt8) -> AuthorityCommandAuthorizationNotice {
        .init(state: .init(requestKind: .command, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            requestDigest: Data(repeating: byte, count: 32), challenge: Data(repeating: byte, count: 32),
            reason: .none, terminalAt: nil, decisionPhoneID: nil, requestID: Data(repeating: byte, count: 16), phase: .authorized,
            revision: 1, firstObservedAt: .init(epoch: UUID(), milliseconds: 100), deadlineMilliseconds: 200))
    }

    @MainActor func testPendingDuplicateDoesNotStartAnotherAttempt() async throws {
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let calls = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, check in
            calls.withLock { $0 += 1 }; entered.signal()
            guard resume.wait(timeout: .now() + 3) == .success else { throw AuthorityCommandExecutionWorkerError.closed }
            try check()
        }, rejectUnowned: { _ in }, report: { _, _ in completed.signal() })
        try worker.start()
        let original = notice(3)
        XCTAssertEqual(worker.enqueue(original), .queued)
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(worker.enqueue(original), .duplicate)
        resume.signal()
        XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        await worker.close()
        XCTAssertEqual(calls.withLock { $0 }, 1)
        XCTAssertEqual(worker.enqueue(original), .closed)
    }

    @MainActor func testStopCancelsQueuedTurnsAndChecksTheActiveAttempt() async throws {
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
        let completed = DispatchSemaphore(value: 0), calls = Mutex([Data]()), rejections = Mutex([Data]())
        let worker = try AuthorityCommandExecutionWorker(begin: { request, check in
            calls.withLock { $0.append(request.requestID) }; entered.signal()
            guard resume.wait(timeout: .now() + 3) == .success else { throw AuthorityCommandExecutionWorkerError.closed }
            try check()
        }, rejectUnowned: { request in rejections.withLock { $0.append(request.requestID) } },
            report: { _, result in if case .success = result { XCTFail("A stopped turn must not succeed") }; completed.signal() })
        try worker.start()
        let first = notice(3), second = notice(4)
        XCTAssertEqual(worker.enqueue(first), .queued)
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(worker.enqueue(second), .queued)
        worker.requestStop(); resume.signal()
        await worker.close()
        XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(calls.withLock { $0 }, [first.requestID])
        XCTAssertEqual(rejections.withLock { $0 }, [first.requestID, second.requestID])
    }

    @MainActor func testCapacityRetiresRatherThanDroppingAnApprovalWhileStayingHealthy() async throws {
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), rejected = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(maximumPending: 1, begin: { _, check in
            entered.signal()
            guard resume.wait(timeout: .now() + 3) == .success else { throw AuthorityCommandExecutionWorkerError.closed }
            try check()
        }, rejectUnowned: { _ in rejected.withLock { $0 += 1 } })
        try worker.start()
        var events = worker.retirement.makeAsyncIterator()
        XCTAssertEqual(worker.enqueue(notice(3)), .queued)
        XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(worker.enqueue(notice(4)), .capacity)
        XCTAssertTrue(worker.isRetired)
        let retired = await events.next()
        XCTAssertNotNil(retired)
        XCTAssertEqual(worker.enqueue(notice(5)), .closed)
        resume.signal(); await worker.close()
        XCTAssertEqual(rejected.withLock { $0 }, 3)
    }

    @MainActor func testStartFailureUsesOnlyTheJournalRejectionCallbackWithoutRetry() async throws {
        let completed = DispatchSemaphore(value: 0), starts = Mutex(0), rejections = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, _ in
            starts.withLock { $0 += 1 }; throw AuthorityCommandExecutionWorkerError.invalidConfiguration
        }, rejectUnowned: { _ in rejections.withLock { $0 += 1 } }, report: { _, result in
            if case .success = result { XCTFail("A failed start attempt must not be reported as success") }
            completed.signal()
        })
        try worker.start(); XCTAssertEqual(worker.enqueue(notice(3)), .queued)
        XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        await worker.close()
        XCTAssertEqual(starts.withLock { $0 }, 1); XCTAssertEqual(rejections.withLock { $0 }, 1)
        XCTAssertFalse(worker.isRetired)
    }

    @MainActor func testRejectionFailureRetiresTheRuntime() async throws {
        let completed = DispatchSemaphore(value: 0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, _ in throw AuthorityCommandExecutionWorkerError.closed },
            rejectUnowned: { _ in throw AuthorityCommandExecutionWorkerError.invalidConfiguration }, report: { _, result in
                guard case .failure(let error) = result else { return XCTFail("The rejection failure must be retained") }
                XCTAssertEqual(error as? AuthorityCommandExecutionWorkerError, .invalidConfiguration); completed.signal()
            })
        try worker.start(); XCTAssertEqual(worker.enqueue(notice(3)), .queued)
        XCTAssertEqual(completed.wait(timeout: .now() + 3), .success)
        XCTAssertTrue(worker.isRetired); await worker.close()
    }

    @MainActor func testCloseBeforeStartAndInvalidBoundsNeverCallBegin() async throws {
        let rejections = Mutex(0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, _ in XCTFail("A closed worker must not start") },
            rejectUnowned: { _ in rejections.withLock { $0 += 1 } })
        XCTAssertEqual(worker.enqueue(notice(3)), .closed)
        await worker.close(); await worker.close()
        XCTAssertThrowsError(try worker.start())
        XCTAssertEqual(worker.enqueue(notice(3)), .closed)
        XCTAssertEqual(rejections.withLock { $0 }, 2)
        for maximum in [0, 4097] {
            XCTAssertThrowsError(try AuthorityCommandExecutionWorker(maximumPending: maximum, begin: { _, _ in }, rejectUnowned: { _ in }))
        }
    }
    func testCloseJoinsAnInFlightNonqueuedRejection() async throws {
        let entered = Mutex(false), returned = Mutex(false), closed = Mutex(false)
        let resume = DispatchSemaphore(value: 0)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, _ in XCTFail("A stopped worker must not begin") },
            rejectUnowned: { _ in
                entered.withLock { $0 = true }
                XCTAssertEqual(resume.wait(timeout: .now() + 3), .success)
            })
        try worker.start(); worker.requestStop()
        let original = notice(3)
        let rejection = Task.detached { XCTAssertEqual(worker.enqueue(original), .closed); returned.withLock { $0 = true } }
        defer { resume.signal() }
        for _ in 0..<300 where !entered.withLock({ $0 }) { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertTrue(entered.withLock { $0 })
        let cleanup = Task { await worker.close(); closed.withLock { $0 = true } }
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertFalse(returned.withLock { $0 })
        resume.signal(); await rejection.value; await cleanup.value
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertTrue(returned.withLock { $0 })
    }

    @MainActor func testNonqueuedRejectionFailureRetiresWithoutTryingExecution() async throws {
        let reported = Mutex(false)
        let worker = try AuthorityCommandExecutionWorker(begin: { _, _ in XCTFail("No execution may start") },
            rejectUnowned: { _ in throw AuthorityCommandExecutionWorkerError.invalidConfiguration }, report: { _, result in
                guard case .failure(let error) = result else { return XCTFail("A rejection failure must be reported") }
                XCTAssertEqual(error as? AuthorityCommandExecutionWorkerError, .invalidConfiguration)
                reported.withLock { $0 = true }
            })
        try worker.start(); worker.requestStop()
        XCTAssertEqual(worker.enqueue(notice(3)), .closed)
        XCTAssertTrue(reported.withLock { $0 }); XCTAssertTrue(worker.isRetired)
        await worker.close()
    }

}
