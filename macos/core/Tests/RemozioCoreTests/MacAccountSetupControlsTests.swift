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
        func runtimeProgress() -> SetupRuntimeProgress? { nil }
        func prepareRuntime(_ expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) throws -> SetupRuntimeProgress {
            XCTFail("No runtime write without completed services"); throw Failure.lostReply
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
        let pendingRuntime: SetupRuntimeProgress
        let completedRuntime: SetupRuntimeProgress
        var runtimeState: SetupRuntimeProgress?
        var runtimeReads = 0, runtimeWrites = 0
        let runtimeLoseReply: Bool
        var reads = 0, writes = 0
        let loseReply: Bool
        init(account: AccountPreparationIntent, plan: ServiceAccountPlan, missing: Bool = false, loseReply: Bool = false, runtimeLoseReply: Bool = false) throws {
            enrollment = try .init(account)
            services = missing ? nil : try .init(account: account, state: .init(plan: nil, complete: false))
            completed = try .init(account: account, state: .init(plan: plan, complete: true)); self.loseReply = loseReply
            pendingRuntime = try .init(account: account, services: .init(plan: plan, complete: true), state: .init(reference: nil, configurationPublished: false))
            runtimeState = pendingRuntime; self.runtimeLoseReply = runtimeLoseReply
            let now = Date(), material = try RuntimePreparationMaterial.create(services: plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
            completedRuntime = try .init(account: account, services: .init(plan: plan, complete: true),
                state: .init(reference: material.reference, configurationPublished: true))
        }
        func progress() -> SetupAccountEnrollmentProgress? { enrollment }
        func prepare(_ request: AccountEnrollmentRequest) throws -> SetupAccountEnrollmentProgress {
            XCTFail("Do not repeat completed account preparation"); throw Failure.lostReply
        }
        func runtimeProgress() -> SetupRuntimeProgress? { runtimeReads += 1; return runtimeState }
        func prepareRuntime(_ expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) throws -> SetupRuntimeProgress {
            XCTAssertTrue(fileCustodyAccepted); XCTAssertEqual(expected, pendingRuntime)
            runtimeWrites += 1; runtimeState = completedRuntime
            if runtimeLoseReply { throw Failure.lostReply }; return completedRuntime
        }
        func runtimeCounts() -> [Int] { [runtimeReads, runtimeWrites] }
        func clearRuntime() { runtimeState = nil }
        func serviceAccountsProgress() -> SetupServiceAccountProgress? { reads += 1; return services }
        func prepareServiceAccounts(_ expected: SetupServiceAccountProgress) throws -> SetupServiceAccountProgress {
            writes += 1; services = completed
            if loseReply { throw Failure.lostReply }; return completed
        }
        func counts() -> [Int] { [reads, writes] }
    }
    private func servicesDriver(missing: Bool = false, loseReply: Bool = false, runtimeLoseReply: Bool = false) throws -> ServicesDriver {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup fixture") }
        let f = try AccountPreparationFixture(), machine = try f.open(initialize: true); defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        var candidate: UInt32 = 19999
        let plan = try ServiceAccountAllocator.plan(account: account, reserved: [], candidate: { candidate += 1; return candidate },
            available: { _ in true })
        return try .init(account: account, plan: plan, missing: missing, loseReply: loseReply, runtimeLoseReply: runtimeLoseReply)
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

    func testRuntimePreparationRequiresCompletedServicesAReadAndExplicitCustodyConsent() async throws {
        let driver = try servicesDriver(), controls = MacAccountSetupControls(driver: driver)
        await controls.prepareRuntime(fileCustodyAccepted: true)
        await controls.refresh()
        await controls.prepareRuntime(fileCustodyAccepted: true)
        var counts = await driver.runtimeCounts(); XCTAssertEqual(counts, [0, 0])
        await controls.prepareServiceAccounts()
        XCTAssertNotNil(controls.runtime)
        await controls.prepareRuntime(fileCustodyAccepted: false)
        counts = await driver.runtimeCounts(); XCTAssertEqual(counts, [1, 0])
        await controls.prepareRuntime(fileCustodyAccepted: true)
        XCTAssertTrue(try XCTUnwrap(controls.runtime).configurationPublished)
        await controls.prepareRuntime(fileCustodyAccepted: true)
        counts = await driver.runtimeCounts(); XCTAssertEqual(counts, [1, 1])
    }
    func testLostRuntimeReplyRequiresRefreshWithoutAutomaticWriteRetry() async throws {
        let driver = try servicesDriver(runtimeLoseReply: true), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh(); await controls.prepareServiceAccounts(); await controls.prepareRuntime(fileCustodyAccepted: true)
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed)
        await controls.prepareRuntime(fileCustodyAccepted: true)
        var counts = await driver.runtimeCounts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertTrue(try XCTUnwrap(controls.runtime).configurationPublished)
        await controls.prepareRuntime(fileCustodyAccepted: true)
        counts = await driver.runtimeCounts(); XCTAssertEqual(counts, [2, 1])
    }
    func testMissingRuntimeProgressCannotLeaveTheAppReadyToMutate() async throws {
        let driver = try servicesDriver(), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh(); await controls.prepareServiceAccounts(); await driver.clearRuntime(); await controls.refresh()
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed)
        await controls.prepareRuntime(fileCustodyAccepted: true)
        let counts = await driver.runtimeCounts(); XCTAssertEqual(counts, [2, 0])
    }
}
