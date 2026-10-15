import Darwin
import Foundation
import XCTest
@testable import RemozioCore

@MainActor
final class MacActivationControlsTests: XCTestCase {
    private struct LostReply: Error {}
    private actor Driver: MacAccountSetupDriver {
        let enrollment: SetupAccountEnrollmentProgress
        let services: SetupServiceAccountProgress
        let runtime: SetupRuntimeProgress
        let completed: SetupActivationProgress
        var current: SetupActivationProgress?
        var reads = 0, writes = 0
        let loseReply: Bool
        init(_ f: RuntimeActivationFixture, loseReply: Bool = false) throws {
            enrollment = try .init(f.account)
            services = try .init(account: f.account, state: .init(plan: f.services, complete: true))
            let runtimeState = RuntimePreparationState(reference: try f.material.reference, configurationPublished: true)
            runtime = try .init(account: f.account, services: .init(plan: f.services, complete: true), state: runtimeState)
            current = try .init(account: f.account, runtime: runtimeState, state: .init(plan: nil, jobsRegistered: false))
            completed = try .init(account: f.account, runtime: runtimeState, state: .init(plan: f.plan, jobsRegistered: true))
            self.loseReply = loseReply
        }
        func progress() -> SetupAccountEnrollmentProgress? { enrollment }
        func serviceAccountsProgress() -> SetupServiceAccountProgress? { services }
        func runtimeProgress() -> SetupRuntimeProgress? { runtime }
        func activationProgress() -> SetupActivationProgress? { reads += 1; return current }
        func activateRuntime(_ expected: SetupActivationProgress) throws -> SetupActivationProgress {
            writes += 1; current = completed
            if loseReply { throw LostReply() }; return completed
        }
        func prepare(_ request: AccountEnrollmentRequest) throws -> SetupAccountEnrollmentProgress { throw LostReply() }
        func prepareServiceAccounts(_ expected: SetupServiceAccountProgress) throws -> SetupServiceAccountProgress { throw LostReply() }
        func prepareRuntime(_ expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) throws -> SetupRuntimeProgress { throw LostReply() }
        func counts() -> [Int] { [reads, writes] }
        func clearProgress() { current = nil }
    }
    private func driver(loseReply: Bool = false) throws -> Driver {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner setup fixture") }
        return try .init(RuntimeActivationFixture(), loseReply: loseReply)
    }
    func testRefreshNeverStartsServicesAndExplicitRestorePreservesTheRetainedScope() async throws {
        let driver = try driver(), controls = MacAccountSetupControls(driver: driver)
        await controls.activateRuntime()
        var counts = await driver.counts(); XCTAssertEqual(counts, [0, 0])
        await controls.refresh()
        counts = await driver.counts(); XCTAssertEqual(counts, [1, 0]); XCTAssertTrue(controls.loaded)
        await controls.activateRuntime()
        XCTAssertTrue(try XCTUnwrap(controls.activation).jobsRegistered)
        let digest = controls.activation?.planDigest, material = controls.activation?.materialID
        await controls.activateRuntime() // An explicit restore is allowed; no automatic action occurs.
        XCTAssertEqual(controls.activation?.planDigest, digest); XCTAssertEqual(controls.activation?.materialID, material)
        counts = await driver.counts(); XCTAssertEqual(counts, [1, 2])
    }
    func testLostReplyRequiresRefreshAndDoesNotAutomaticallyRetryActivation() async throws {
        let driver = try driver(loseReply: true), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh(); await controls.activateRuntime()
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed)
        await controls.activateRuntime()
        var counts = await driver.counts(); XCTAssertEqual(counts, [1, 1])
        await controls.refresh()
        XCTAssertTrue(controls.loaded); XCTAssertTrue(try XCTUnwrap(controls.activation).jobsRegistered)
        counts = await driver.counts(); XCTAssertEqual(counts, [2, 1])
    }
    func testMissingActivationProgressCannotLeaveTheAppReadyToMutate() async throws {
        let driver = try driver(), controls = MacAccountSetupControls(driver: driver)
        await controls.refresh(); await driver.clearProgress(); await controls.refresh()
        XCTAssertFalse(controls.loaded); XCTAssertTrue(controls.failed)
        await controls.activateRuntime()
        let counts = await driver.counts(); XCTAssertEqual(counts, [2, 0])
    }
}
