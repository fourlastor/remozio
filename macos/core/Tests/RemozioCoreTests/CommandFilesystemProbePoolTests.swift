import Foundation
import XCTest
@testable import RemozioCore

final class CommandFilesystemProbePoolTests: XCTestCase {
    func testRetiredProbeKeepsItsSlotUntilTheCallReturns() throws {
        let pool = CommandFilesystemProbePool(executionSlots: 2)
        let entered = DispatchSemaphore(value: 0), unblock = DispatchSemaphore(value: 0)
        let held = try pool.start(.execution) { _, _ -> Int in
            entered.signal()
            _ = unblock.wait(timeout: .now() + .seconds(5))
            return 1
        }
        defer { unblock.signal() }
        XCTAssertEqual(entered.wait(timeout: .now() + .seconds(2)), .success)
        held.cancel()
        XCTAssertThrowsError(try held.consumeIfReady()) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .expired)
        }
        let otherEntered = DispatchSemaphore(value: 0), otherUnblock = DispatchSemaphore(value: 0)
        let other = try pool.start(.execution) { _, _ -> Int in
            otherEntered.signal()
            _ = otherUnblock.wait(timeout: .now() + .seconds(5))
            return 2
        }
        defer { otherUnblock.signal() }
        XCTAssertEqual(otherEntered.wait(timeout: .now() + .seconds(2)), .success)
        XCTAssertThrowsError(try pool.start(.execution) { _, _ in 3 }) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .atCapacity)
        }
        otherUnblock.signal()
        XCTAssertEqual(try other.wait(), 2)
    }

    func testExpiredOrConsumedResultCanNeverBeReused() throws {
        let expired = CommandFilesystemProbe<Int>(deadline: ContinuousClock.now - .seconds(1))
        expired.complete(.success(1))
        XCTAssertThrowsError(try expired.consumeIfReady()) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .expired)
        }
        let probe = try CommandFilesystemProbePool().start(.execution) { _, _ in 2 }
        XCTAssertEqual(try probe.wait(), 2)
        XCTAssertThrowsError(try probe.consumeIfReady()) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .expired)
        }
    }

    func testAdmissionsHaveTwoSlotsAndOneOperationPerUID() throws {
        let pool = CommandFilesystemProbePool()
        let unblock = DispatchSemaphore(value: 0)
        let first = try pool.start(.admission(501)) { _, _ in _ = unblock.wait(timeout: .now() + .seconds(4)) }
        defer { first.cancel(); unblock.signal() }
        XCTAssertThrowsError(try pool.start(.admission(501)) { _, _ in 0 }) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .atCapacity)
        }
        let second = try pool.start(.admission(502)) { _, _ in _ = unblock.wait(timeout: .now() + .seconds(4)) }
        defer { second.cancel(); unblock.signal() }
        XCTAssertThrowsError(try pool.start(.admission(503)) { _, _ in 0 }) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .atCapacity)
        }
        let firstExecution = try pool.start(.execution) { _, _ in 1 }
        let secondExecution = try pool.start(.execution) { _, _ in 2 }
        XCTAssertEqual(try firstExecution.wait(), 1)
        XCTAssertEqual(try secondExecution.wait(), 2)
    }

    func testCancelledWorkerStopsAtTheNextCheckpoint() throws {
        let pool = CommandFilesystemProbePool()
        let entered = DispatchSemaphore(value: 0), unblock = DispatchSemaphore(value: 0)
        let cancelled = DispatchSemaphore(value: 0)
        let probe = try pool.start(.execution) { _, checkActive -> Int in
            entered.signal()
            _ = unblock.wait(timeout: .now() + .seconds(4))
            do { try checkActive() }
            catch { cancelled.signal(); throw error }
            XCTFail("A cancelled worker continued after its checkpoint")
            return 1
        }
        defer { unblock.signal() }
        XCTAssertEqual(entered.wait(timeout: .now() + .seconds(2)), .success)
        probe.cancel()
        unblock.signal()
        XCTAssertEqual(cancelled.wait(timeout: .now() + .seconds(2)), .success)
        XCTAssertThrowsError(try probe.consumeIfReady()) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .expired)
        }
    }
}
