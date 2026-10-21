import Foundation
import XCTest
@testable import RemozioCore

@MainActor
final class MacPortableSetupImportControlsTests: XCTestCase {
    private enum Failure: Error { case expected }
    private actor Driver: MacPortableSetupImportDriver {
        let expected: SetupPortableImportProgress
        var fails = false
        var reads = 0
        var actions: [SetupPortableImportOperation.Action] = []
        init(_ expected: SetupPortableImportProgress) { self.expected = expected }
        func setFails() { fails = true }
        func progress() throws -> SetupPortableImportProgress? { reads += 1; return expected }
        func perform(_ request: SetupPortableImportOperation) throws -> SetupPortableImportOperationResult {
            actions.append(request.action)
            if fails { throw Failure.expected }
            return try .init(request: request, progress: expected, status: .applied)
        }
    }
    func testRefreshDoesNotApplyAndOnlyAnExplicitStepCanSendTheReviewedRequest() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let expected = try fixture.progress(owner), driver = Driver(expected)
        let controls = MacPortableSetupImportControls(reviewed: ReviewedSetupFile(proposal: try fixture.f.proposal()), driver: driver)
        defer { controls.close() }
        await controls.perform(.retain)
        let before = await driver.actions
        XCTAssertTrue(before.isEmpty)
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertEqual(controls.progress, expected)
        let refreshed = await driver.actions
        XCTAssertTrue(refreshed.isEmpty)
        await controls.perform(.retain)
        XCTAssertEqual(controls.lastResult?.status, .applied)
        let actions = await driver.actions
        XCTAssertEqual(actions, [.retain])
        XCTAssertFalse(controls.working); XCTAssertNil(controls.notice)
    }
    func testUnknownOutcomeDisablesAnotherStepUntilTheUserExplicitlyRefreshes() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let expected = try fixture.progress(owner), driver = Driver(expected)
        let controls = MacPortableSetupImportControls(reviewed: ReviewedSetupFile(proposal: try fixture.f.proposal()), driver: driver)
        defer { controls.close() }
        await controls.refresh(); await driver.setFails(); await controls.perform(.retain)
        XCTAssertFalse(controls.loaded); XCTAssertNil(controls.progress); XCTAssertNil(controls.lastResult)
        XCTAssertEqual(controls.notice, .operationOutcomeUnknown)
        await controls.perform(.retain)
        let actions = await driver.actions, reads = await driver.reads
        XCTAssertEqual(actions, [.retain]); XCTAssertEqual(reads, 1)
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertNil(controls.notice)
        let refreshed = await driver.reads
        XCTAssertEqual(refreshed, 2)
    }
    func testClosingReleasesTheReviewAndCannotRefreshOrApplyAnotherStep() async throws {
        let fixture = try RelayProvisioningFixture(), owner = try fixture.owner()
        defer { try? owner.close() }
        let expected = try fixture.progress(owner), driver = Driver(expected)
        let reviewed = ReviewedSetupFile(proposal: try fixture.f.proposal())
        let controls = MacPortableSetupImportControls(reviewed: reviewed, driver: driver)
        await controls.refresh(); controls.close(); await controls.refresh(); await controls.perform(.retain)
        XCTAssertFalse(controls.loaded); XCTAssertNil(controls.progress); XCTAssertNil(controls.lastResult)
        XCTAssertThrowsError(try reviewed.operation(action: .retain, expected: expected))
        let actions = await driver.actions, reads = await driver.reads
        XCTAssertTrue(actions.isEmpty); XCTAssertEqual(reads, 1)
    }
}
