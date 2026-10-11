import XCTest
@testable import RemozioCore

@MainActor
private final class LoginDriver: MacLoginItemDriver {
    enum Failure: Error { case refused }
    var value = MacLoginItemState.notRegistered
    var reads = 0, registrations = 0, removals = 0, settings = 0
    var registration: (() throws -> Void)?
    var removal: (() async throws -> Void)?
    func status() -> MacLoginItemState { reads += 1; return value }
    func register() throws { registrations += 1; try registration?() }
    func unregister() async throws { removals += 1; try await removal?() }
    func openSettings() { settings += 1 }
}
final class MacLoginItemControlsTests: XCTestCase {
    @MainActor func testPendingApprovalDoesNotBecomeEnabledOrRetryAutomatically() async {
        let driver = LoginDriver()
        let subject = MacLoginItemControls(driver: driver)
        driver.registration = { driver.value = .requiresApproval }
        await subject.setEnabled(true)
        XCTAssertEqual(subject.state, .requiresApproval)
        XCTAssertTrue(subject.state.registered)
        await subject.setEnabled(true)
        XCTAssertEqual(driver.registrations, 1)
        XCTAssertEqual(driver.settings, 0)
        driver.value = .enabled; subject.refresh()
        XCTAssertEqual(subject.state, .enabled)
        driver.value = .requiresApproval; subject.refresh()
        XCTAssertEqual(subject.state, .requiresApproval)
        XCTAssertEqual(driver.registrations, 1)
    }
    @MainActor func testRegistrationFailureUsesCurrentSystemState() async {
        let driver = LoginDriver()
        let controls = MacLoginItemControls(driver: driver)
        driver.registration = { driver.value = .requiresApproval; throw LoginDriver.Failure.refused }
        await controls.setEnabled(true)
        XCTAssertEqual(controls.state, .requiresApproval)
        XCTAssertEqual(controls.notice, .enableFailed)
        XCTAssertFalse(controls.changing)
    }
    @MainActor func testFailedRemovalDoesNotClaimDisabled() async {
        let driver = LoginDriver(); driver.value = .enabled
        let controls = MacLoginItemControls(driver: driver)
        driver.removal = { throw LoginDriver.Failure.refused }
        await controls.setEnabled(false)
        XCTAssertEqual(controls.state, .enabled)
        XCTAssertEqual(controls.notice, .disableFailed)
        XCTAssertFalse(controls.changing)
    }
    @MainActor func testRemovalRefreshesAfterCompletionWithoutDuplicateMutation() async {
        let driver = LoginDriver(); driver.value = .requiresApproval
        let controls = MacLoginItemControls(driver: driver)
        var resume: CheckedContinuation<Void, Never>?
        driver.removal = { await withCheckedContinuation { resume = $0 }; driver.value = .notRegistered }
        let operation = Task { await controls.setEnabled(false) }
        while resume == nil { await Task.yield() }
        XCTAssertTrue(controls.changing)
        let reads = driver.reads
        controls.refresh()
        await controls.setEnabled(true)
        XCTAssertEqual(driver.reads, reads)
        XCTAssertEqual(driver.registrations, 0)
        XCTAssertEqual(driver.removals, 1)
        resume?.resume(); await operation.value
        XCTAssertEqual(controls.state, .notRegistered)
        XCTAssertFalse(controls.changing)
    }
    @MainActor func testUnavailableAndUnknownStateNeverClaimRegistration() async {
        let driver = LoginDriver()
        let subject = MacLoginItemControls(driver: driver)
        for value in [MacLoginItemState.notFound, .unknown, .notRegistered] {
            driver.value = value; subject.refresh()
            XCTAssertEqual(subject.state, value)
            XCTAssertFalse(subject.state.registered)
        }
        XCTAssertEqual(driver.registrations, 0)
        XCTAssertEqual(driver.removals, 0)
    }
    @MainActor func testSettingsOpenOnlyOnExplicitAction() async {
        let driver = LoginDriver(); driver.value = .requiresApproval
        let controls = MacLoginItemControls(driver: driver)
        controls.refresh(); await controls.setEnabled(true)
        XCTAssertEqual(driver.settings, 0)
        controls.openSettings()
        XCTAssertEqual(driver.settings, 1)
    }
    @MainActor func testRegistrationNoticeSurvivesUnknownStateThenClearsOnEnabledRefresh() async {
        let driver = LoginDriver()
        let subject = MacLoginItemControls(driver: driver)
        driver.registration = { throw LoginDriver.Failure.refused }
        await subject.setEnabled(true)
        XCTAssertEqual(subject.notice, .enableFailed)
        for state in [MacLoginItemState.unknown, .requiresApproval] {
            driver.value = state; subject.refresh()
            XCTAssertEqual(subject.notice, .enableFailed)
        }
        driver.value = .enabled; subject.refresh()
        XCTAssertEqual(subject.state, .enabled)
        XCTAssertNil(subject.notice)
        await subject.setEnabled(true)
        XCTAssertEqual(driver.registrations, 1)
        XCTAssertEqual(driver.removals, 0)
    }
    @MainActor func testRemovalNoticeSurvivesUnknownStateThenClearsOnConfirmedUnregistration() async {
        let driver = LoginDriver(); driver.value = .enabled
        let controls = MacLoginItemControls(driver: driver)
        driver.removal = { throw LoginDriver.Failure.refused }
        await controls.setEnabled(false)
        XCTAssertEqual(controls.notice, .disableFailed)
        for state in [MacLoginItemState.unknown, .requiresApproval] {
            driver.value = state; controls.refresh()
            XCTAssertEqual(controls.notice, .disableFailed)
        }
        driver.value = .notRegistered; controls.refresh()
        XCTAssertEqual(controls.state, .notRegistered)
        XCTAssertNil(controls.notice)
        await controls.setEnabled(false)
        XCTAssertEqual(driver.registrations, 0)
        XCTAssertEqual(driver.removals, 1)
    }

}
