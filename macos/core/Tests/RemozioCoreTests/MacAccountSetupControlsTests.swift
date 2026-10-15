import Darwin
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
        func serviceAccountsProgress() -> SetupServiceAccountProgress? { nil }
        func prepareServiceAccounts(_ expected: SetupServiceAccountProgress) throws -> SetupServiceAccountProgress {
            XCTFail("No service write without prepared storage and current progress"); throw Failure.lostReply
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
    private actor ServicesDriver: MacAccountSetupDriver {
        let enrollment: SetupAccountEnrollmentProgress
        var services: SetupServiceAccountProgress?
        let completed: SetupServiceAccountProgress
        var reads = 0, writes = 0
        let loseReply: Bool
        init(account: AccountPreparationIntent, plan: ServiceAccountPlan, missing: Bool = false, loseReply: Bool = false) throws {
            enrollment = try .init(account)
            services = missing ? nil : try .init(account: account, state: .init(plan: nil, complete: false))
            completed = try .init(account: account, state: .init(plan: plan, complete: true)); self.loseReply = loseReply
        }
        func progress() -> SetupAccountEnrollmentProgress? { enrollment }
        func prepare(_ request: AccountEnrollmentRequest) throws -> SetupAccountEnrollmentProgress {
            XCTFail("Do not repeat completed account preparation"); throw Failure.lostReply
        }
        func serviceAccountsProgress() -> SetupServiceAccountProgress? { reads += 1; return services }
        func prepareServiceAccounts(_ expected: SetupServiceAccountProgress) throws -> SetupServiceAccountProgress {
            writes += 1; services = completed
            if loseReply { throw Failure.lostReply }; return completed
        }
        func counts() -> [Int] { [reads, writes] }
    }
    private func servicesDriver(missing: Bool = false, loseReply: Bool = false) throws -> ServicesDriver {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup fixture") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        var candidate: UInt32 = 19999
        let plan = try ServiceAccountAllocator.plan(account: account, reserved: [], candidate: { candidate += 1; return candidate },
            available: { _ in true })
        return try .init(account: account, plan: plan, missing: missing, loseReply: loseReply)
    }
    func testServiceCreationRequiresAReadAndAnExplicitActionAndCannotRepeatCompletion() async throws {
        let driver = try servicesDriver(), controls = MacAccountSetupControls(driver: driver)
        await controls.prepareServiceAccounts()
        var counts = await driver.counts(); XCTAssertEqual(counts, [0, 0])
        await controls.refresh()
        counts = await driver.counts(); XCTAssertEqual(counts, [1, 0]); XCTAssertFalse(try XCTUnwrap(controls.services).complete)
        await controls.prepareServiceAccounts()
        XCTAssertTrue(try XCTUnwrap(controls.services).complete); XCTAssertFalse(controls.working)
        await controls.prepareServiceAccounts()
        counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
    }
    func testLostServiceReplyRequiresRefreshWhichReadsCompletionWithoutAnotherWrite() async throws {
        let driver = try servicesDriver(loseReply: true), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh(); await controls.prepareServiceAccounts()
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed)
        await controls.prepareServiceAccounts()
        var counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertTrue(try XCTUnwrap(controls.services).complete)
        await controls.prepareServiceAccounts()
        counts = await driver.counts(); XCTAssertEqual(counts, [2, 1])
    }
    func testMissingServiceProgressAfterPreparedEnrollmentDisablesMutationAndReportsFailure() async throws {
        let driver = try servicesDriver(missing: true), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh()
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed)
        await controls.prepareServiceAccounts()
        let counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
    }

}
