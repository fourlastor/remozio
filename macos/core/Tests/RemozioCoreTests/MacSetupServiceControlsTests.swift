import XCTest
@testable import RemozioCore

@MainActor private final class SetupRegistrationDriver: MacSetupServiceDriver {
    enum Failure: Error { case refused }
    var value = MacSetupServiceState.notRegistered
    var inspections = 0, registrations = 0
    var inspection: (() async throws -> MacSetupServiceState)?
    var registration: (() async throws -> MacSetupServiceState)?
    func inspect() async throws -> MacSetupServiceState {
        inspections += 1
        return try await inspection?() ?? value
    }
    func register() async throws -> MacSetupServiceState {
        registrations += 1
        return try await registration?() ?? value
    }
}

final class MacSetupServiceControlsTests: XCTestCase {
    @MainActor func testRefreshNeverRegistersOrPromotesUnknownHealth() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        XCTAssertEqual(subject.state, .unavailable)
        for state in [MacSetupServiceState.notRegistered, .requiresApproval, .enabled, .notFound, .requiresInstallation, .unavailable] {
            driver.value = state; await subject.refresh()
            XCTAssertEqual(subject.state, state)
        }
        XCTAssertEqual(driver.registrations, 0)
        XCTAssertNil(subject.operation)
    }
    @MainActor func testApprovalPendingIsRetainedWithoutRepeatedRegistration() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.registration = { driver.value = .requiresApproval; return driver.value }
        await subject.enable()
        XCTAssertEqual(subject.state, .requiresApproval)
        await subject.enable(); await subject.refresh()
        XCTAssertEqual(driver.registrations, 1)
        XCTAssertNil(subject.notice)
    }
    @MainActor func testAlreadyEnabledDoesNotRegisterAgain() async {
        let driver = SetupRegistrationDriver(); driver.value = .enabled
        let subject = MacSetupServiceControls(driver: driver)
        await subject.enable()
        XCTAssertEqual(subject.state, .enabled)
        XCTAssertEqual(driver.registrations, 0)
    }
    @MainActor func testUnavailableAndUninstalledStatesCannotRegister() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        for state in [MacSetupServiceState.requiresInstallation, .notFound, .unavailable] {
            driver.value = state; await subject.enable()
            XCTAssertEqual(subject.state, state)
            XCTAssertEqual(subject.notice, .registrationFailed)
        }
        XCTAssertEqual(driver.registrations, 0)
    }
    @MainActor func testLostReplyReconcilesCurrentStateWithoutAnotherMutation() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.registration = { driver.value = .requiresApproval; throw SetupRegistrationDriver.Failure.refused }
        await subject.enable()
        XCTAssertEqual(subject.state, .requiresApproval)
        XCTAssertNil(subject.notice)
        XCTAssertEqual(driver.registrations, 1)
        driver.value = .enabled; await subject.refresh()
        XCTAssertEqual(subject.state, .enabled)
        XCTAssertNil(subject.notice)
        XCTAssertEqual(driver.registrations, 1)
    }
    @MainActor func testInspectionFailureDoesNotAttemptRegistration() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.inspection = { throw SetupRegistrationDriver.Failure.refused }
        await subject.refresh()
        XCTAssertEqual(subject.state, .unavailable)
        XCTAssertEqual(subject.notice, .inspectionFailed)
        await subject.enable()
        XCTAssertEqual(subject.state, .unavailable)
        XCTAssertEqual(subject.notice, .registrationFailed)
        XCTAssertEqual(driver.registrations, 0)
        driver.inspection = nil; await subject.refresh()
        XCTAssertEqual(subject.state, .notRegistered)
        XCTAssertEqual(subject.notice, .registrationFailed)
    }
    @MainActor func testRepeatedActionsCannotOverlapRegistration() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        var resume: CheckedContinuation<Void, Never>?
        driver.registration = {
            await withCheckedContinuation { resume = $0 }
            driver.value = .enabled; return driver.value
        }
        let work = Task { await subject.enable() }
        while resume == nil { await Task.yield() }
        XCTAssertEqual(subject.operation, .registering)
        let reads = driver.inspections
        await subject.enable(); await subject.refresh()
        XCTAssertEqual(driver.inspections, reads)
        XCTAssertEqual(driver.registrations, 1)
        resume?.resume(); await work.value
        XCTAssertEqual(subject.state, .enabled)
        XCTAssertNil(subject.operation)
    }
    @MainActor func testFailedRegistrationCannotClaimEnabledFromPreviousState() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.registration = { driver.value = .unavailable; throw SetupRegistrationDriver.Failure.refused }
        await subject.enable()
        XCTAssertEqual(subject.state, .unavailable)
        XCTAssertEqual(subject.notice, .registrationFailed)
        XCTAssertNil(subject.operation)
    }
    @MainActor func testUnexpectedRegistrationResultDoesNotClaimSuccess() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.registration = { .notRegistered }
        await subject.enable()
        XCTAssertEqual(subject.state, .notRegistered)
        XCTAssertEqual(subject.notice, .registrationFailed)
    }
    @MainActor func testNativeTestProcessRequiresInstalledAppWithoutRegistration() async {
        let subject = MacSetupServiceControls()
        await subject.refresh()
        XCTAssertEqual(subject.state, .requiresInstallation)
        XCTAssertNil(subject.notice)
        await subject.enable()
        XCTAssertEqual(subject.state, .requiresInstallation)
        XCTAssertEqual(subject.notice, .registrationFailed)
    }
    func testLocationAcceptsOnlyTheInstalledAppBundleOrItsExecutable() {
        let path = MachineBootstrap.bundlePath
        XCTAssertTrue(MacSetupServiceLocation.matches(bundlePath: path, codePath: path))
        XCTAssertTrue(MacSetupServiceLocation.matches(bundlePath: path, codePath: path + "/Contents/MacOS/Remozio"))
    }
    func testLocationRejectsCopiesAndOtherNestedCode() {
        let path = MachineBootstrap.bundlePath
        XCTAssertFalse(MacSetupServiceLocation.matches(bundlePath: "/private/tmp/Remozio.app", codePath: path))
        for code in [path + "/Contents/Library/LaunchServices/RemozioSetup", "/private/tmp/Remozio", path + "/Other"] {
            XCTAssertFalse(MacSetupServiceLocation.matches(bundlePath: path, codePath: code))
        }
    }

    @MainActor func testEnabledRegistrationReconcilesAnErrorWithoutFailureOrRetry() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.registration = { driver.value = .enabled; throw SetupRegistrationDriver.Failure.refused }
        await subject.enable()
        XCTAssertEqual(subject.state, .enabled)
        XCTAssertNil(subject.notice)
        XCTAssertEqual(driver.registrations, 1)
        await subject.enable()
        XCTAssertEqual(driver.registrations, 1)
    }
    @MainActor func testRegistrationErrorRemainsVisibleWhenRegistrationIsStillAbsent() async {
        let driver = SetupRegistrationDriver(), subject: MacSetupServiceControls
        subject = MacSetupServiceControls(driver: driver)
        driver.registration = { throw SetupRegistrationDriver.Failure.refused }
        await subject.enable()
        XCTAssertEqual(subject.state, .notRegistered)
        XCTAssertEqual(subject.notice, .registrationFailed)
        await subject.refresh()
        XCTAssertEqual(subject.state, .notRegistered)
        XCTAssertEqual(subject.notice, .registrationFailed)
        XCTAssertEqual(driver.registrations, 1)
        driver.value = .requiresApproval
        await subject.refresh()
        XCTAssertEqual(subject.state, .requiresApproval)
        XCTAssertNil(subject.notice)
        XCTAssertEqual(driver.registrations, 1)
    }

}
