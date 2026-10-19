import XCTest
@testable import RemozioCore

final class AuthorityClockTests: XCTestCase {
    func testLiveClockPreservesEpochAcrossCopiesAndMovesForward() throws {
        let clock = try AuthorityClock(), copy = clock, replacement = try AuthorityClock()
        let first = try clock.now(), second = try copy.now()
        XCTAssertEqual(first.epoch, clock.epoch)
        XCTAssertEqual(second.epoch, first.epoch)
        XCTAssertGreaterThanOrEqual(second.milliseconds, first.milliseconds)
        XCTAssertNotEqual(replacement.epoch, clock.epoch)
    }

    func testInternalConstructionPreservesSuppliedEpoch() throws {
        let epoch = UUID(), clock = try AuthorityClock(epoch: epoch)
        XCTAssertEqual(clock.epoch, epoch)
        XCTAssertEqual(try clock.now().epoch, epoch)
    }
}
