import Foundation
import XCTest
@testable import RemozioCore

@MainActor
final class MacAccountSetupControlsTests: XCTestCase {
    private enum Failure: Error { case lostReply }
    private actor Driver: MacAccountSetupDriver {
        var reads = 0, writes = 0
        let cancelled: Bool
        init(cancelled: Bool = false) { self.cancelled = cancelled }
        func progress() -> SetupAccountEnrollmentProgress? { reads += 1; return nil }
        func prepare(_ request: AccountEnrollmentRequest) throws -> SetupAccountEnrollmentProgress {
            writes += 1
            if cancelled { throw SetupAdministratorAuthorizationError.cancelled }
            throw Failure.lostReply
        }
        func counts() -> [Int] { [reads, writes] }
    }
    func testRefreshNeverAuthorizesOrMutatesAndPrepareRequiresAnInitialRead() async throws {
        let driver = Driver(), controls = MacAccountSetupControls(driver: driver)
        let request = try AccountEnrollmentRequest(allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
        await controls.prepare(request)
        var counts = await driver.counts(); XCTAssertEqual(counts, [0, 0])
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertFalse(controls.working); XCTAssertFalse(controls.failed)
        counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
    }
    func testLostResponseRequiresAReadBeforeAnotherMutationWithoutAutomaticRetry() async throws {
        let driver = Driver(), controls = MacAccountSetupControls(driver: driver)
        let request = try AccountEnrollmentRequest(allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true)
        await controls.refresh(); await controls.prepare(request)
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed); XCTAssertFalse(controls.working)
        await controls.prepare(request)
        var counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh()
        counts = await driver.counts(); XCTAssertEqual(counts, [2, 1])
        XCTAssertTrue(controls.loaded); XCTAssertFalse(controls.failed)
    }
    func testCancellingAdministratorConsentDoesNotReportAnUncertainFailureOrRetry() async throws {
        let driver = Driver(cancelled: true), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh()
        try await controls.prepare(.init(allowedTargetUIDs: [0], independentPolicyDisclosureAccepted: true))
        XCTAssertFalse(controls.loaded); XCTAssertFalse(controls.failed); XCTAssertFalse(controls.working)
        let counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
    }
}
