import Foundation
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupWorkTests: XCTestCase, @unchecked Sendable {
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        func run(started: XCTestExpectation) async {
            await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        }
        func release() { continuation?.resume(); continuation = nil }
    }
    func testRetiredEndpointCannotReportDrainedWhileItsInitializerStillOwnsTheBudget() async throws {
        let work = try GatewayJournalSetupWork(), gate = Gate(), started = expectation(description: "initializer active")
        let late = expectation(description: "late reply"); late.isInverted = true
        let id = Data(repeating: 1, count: 16), digest = Data(repeating: 2, count: 32)
        let endpoint = try GatewayJournalSetupXPCEndpoint(intentID: id, scopeDigest: digest, verify: {}, budget: work.budget,
            invalidate: {}, execute: {
                await gate.run(started: started)
                return try GatewayJournalSetupReport(intentID: id, scopeDigest: digest, created: true).encoded
            })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.prepare(digest, challenge: Data(repeating: 3, count: 32)) { _ in late.fulfill() }
        await fulfillment(of: [started], timeout: 2); endpoint.close()
        do { try await work.waitForIdle(timeoutMilliseconds: 20); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayServiceError, .unavailable) }
        XCTAssertFalse(work.budget.acquire()); await gate.release()
        try await work.waitForIdle(timeoutMilliseconds: 2000)
        await fulfillment(of: [late], timeout: 0.1)
        XCTAssertTrue(work.budget.acquire()); work.budget.release()
    }
    func testCancelledDrainCannotReleaseOrHideActiveWork() async throws {
        let work = try GatewayJournalSetupWork(); XCTAssertTrue(work.budget.acquire())
        let task = Task { try await work.waitForIdle(timeoutMilliseconds: 2000) }
        task.cancel()
        do { try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertFalse(work.budget.acquire()); work.budget.release()
        try await work.waitForIdle(timeoutMilliseconds: 100)
    }
    func testIdleDrainAndInvalidBoundsDoNotConsumeAWorkSlot() async throws {
        let work = try GatewayJournalSetupWork()
        try await work.waitForIdle(timeoutMilliseconds: 1)
        for timeout: UInt64 in [0, 120001, UInt64.max] {
            do { try await work.waitForIdle(timeoutMilliseconds: timeout); XCTFail() }
            catch { XCTAssertEqual(error as? GatewayPreparationError, .invalidRecord) }
        }
        XCTAssertTrue(work.budget.acquire()); work.budget.release()
    }
}
