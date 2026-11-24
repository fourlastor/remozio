import Foundation
import XCTest
@testable import RemozioCore

final class CommandFilesystemProbePoolTests: XCTestCase {
    func testRetiredProbeKeepsItsSlotUntilTheCallReturns() throws {
        let pool = CommandFilesystemProbePool(maximumActive: 2)
        let entered = DispatchSemaphore(value: 0), unblock = DispatchSemaphore(value: 0)
        let held = try pool.start { _ -> Int in
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
        let other = try pool.start { _ -> Int in
            otherEntered.signal()
            _ = otherUnblock.wait(timeout: .now() + .seconds(5))
            return 2
        }
        defer { otherUnblock.signal() }
        XCTAssertEqual(otherEntered.wait(timeout: .now() + .seconds(2)), .success)
        XCTAssertThrowsError(try pool.start { _ in 3 }) {
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
        let probe = try CommandFilesystemProbePool().start { _ in 2 }
        XCTAssertEqual(try probe.wait(), 2)
        XCTAssertThrowsError(try probe.consumeIfReady()) {
            XCTAssertEqual($0 as? CommandFilesystemProbeError, .expired)
        }
    }
}
