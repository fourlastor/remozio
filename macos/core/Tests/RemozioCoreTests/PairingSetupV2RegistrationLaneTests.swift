import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class PairingSetupV2RegistrationLaneTests: XCTestCase, @unchecked Sendable {
    private func reaches(_ count: Int, on lane: PairingSetupV2RegistrationLane) async throws -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while lane.waitingCount != count && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        return lane.waitingCount == count
    }

    func testReadySlotsTakeTurnsUntilTheActualRegistrationReturns() async throws {
        let lane = PairingSetupV2RegistrationLane()
        let firstEntered = expectation(description: "First registration owns the lane")
        let release = AsyncStream<Void>.makeStream()
        defer { release.continuation.finish() }
        let timeline = Mutex<[Int]>([])
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        let first = Task {
            try await lane.withTurn(until: deadline) {
                timeline.withLock { $0.append(1) }
                firstEntered.fulfill()
                for await _ in release.stream {}
            }
        }
        await fulfillment(of: [firstEntered], timeout: 2)
        let second = Task { try await lane.withTurn(until: deadline) { timeline.withLock { $0.append(2) } } }
        let secondQueued = try await reaches(1, on: lane)
        XCTAssertTrue(secondQueued)
        let third = Task { try await lane.withTurn(until: deadline) { timeline.withLock { $0.append(3) } } }
        let thirdQueued = try await reaches(2, on: lane)
        XCTAssertTrue(thirdQueued)
        XCTAssertEqual(timeline.withLock { $0 }, [1])
        release.continuation.finish()
        try await first.value
        try await second.value
        try await third.value
        XCTAssertEqual(timeline.withLock { $0 }, [1, 2, 3])
    }

    func testCancelledAndExpiredWaitersDoNotUseTheLane() async throws {
        let lane = PairingSetupV2RegistrationLane()
        let firstEntered = expectation(description: "First registration owns the lane")
        let release = AsyncStream<Void>.makeStream()
        defer { release.continuation.finish() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        let first = Task {
            try await lane.withTurn(until: deadline) {
                firstEntered.fulfill()
                for await _ in release.stream {}
            }
        }
        await fulfillment(of: [firstEntered], timeout: 2)
        let cancelled = Task { try await lane.withTurn(until: deadline) { XCTFail("Cancelled waiter ran") } }
        let queued = try await reaches(1, on: lane)
        XCTAssertTrue(queued)
        cancelled.cancel()
        do { try await cancelled.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}

        let expiry = ContinuousClock.now.advanced(by: .milliseconds(250))
        let expired = Task { try await lane.withTurn(until: expiry) { XCTFail("Expired waiter ran") } }
        let expiryQueued = try await reaches(1, on: lane)
        XCTAssertTrue(expiryQueued)
        let next = Task { try await lane.withTurn(until: deadline) { true } }
        try await ContinuousClock().sleep(until: expiry)
        release.continuation.finish()
        try await first.value
        do { try await expired.value; XCTFail("Expected deadline rejection") }
        catch PairingSetupChannelError.rejected {}
        let advanced = try await next.value
        XCTAssertTrue(advanced)
    }
}
