import XCTest
@testable import RemozioCore

final class AcceptedInputMemoTests: XCTestCase {
    private struct Refused: Error {}

    func testAcceptedInputRunsOnce() {
        let memo = AcceptedInputMemo<Int>(); var runs = 0
        for _ in 0..<3 { memo.check(1) { runs += 1 } }
        XCTAssertEqual(runs, 1)
        memo.check(2) { runs += 1 }
        XCTAssertEqual(runs, 2)
    }
    func testRefusedInputRunsEveryTimeAndLaterAcceptanceIsRemembered() throws {
        let memo = AcceptedInputMemo<Int>(); var runs = 0
        for _ in 0..<2 {
            XCTAssertThrowsError(try memo.check(1) { runs += 1; throw Refused() }) { XCTAssertTrue($0 is Refused) }
        }
        XCTAssertEqual(runs, 2)
        try memo.check(1) { runs += 1 }
        try memo.check(1) { runs += 1 }
        XCTAssertEqual(runs, 3)
    }
    func testCapacityForgetsOlderInputsInsteadOfGrowing() {
        let memo = AcceptedInputMemo<Int>(capacity: 2); var runs = 0
        for key in [1, 2, 3, 1] { memo.check(key) { runs += 1 } }
        XCTAssertEqual(runs, 4)
    }
}
