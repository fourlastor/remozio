import Foundation
import XCTest
@testable import RemozioCore

@MainActor
final class MacGatewaySettingsActionTests: XCTestCase {
    private struct LostReply: Error {}
    private actor Driver: MacGatewaySetupDriver {
        let h: GatewaySettingsSetupOwnerTests.Harness
        var writes = 0, reads = 0, restores = 0
        var loseAfterRetain = false, cancelConsent = false, wrongResult = false
        init(_ h: GatewaySettingsSetupOwnerTests.Harness) { self.h = h }
        func progress() throws -> SetupGatewayActivationProgress? { reads += 1; return try h.read().activation }
        func settingsProgress() throws -> SetupGatewaySettingsProgress? { try h.read() }
        func configure(lose: Bool = false, cancelled: Bool = false, wrong: Bool = false) {
            loseAfterRetain = lose; cancelConsent = cancelled; wrongResult = wrong
        }
        func applySettings(_ expected: SetupGatewaySettingsProgress, selection: GatewayRuntimeSettingsSelection) async throws -> SetupGatewaySettingsProgress {
            writes += 1
            if cancelConsent { throw SetupAdministratorAuthorizationError.cancelled }
            let pending = try expected.pendingDigest == nil
                ? h.owner.retainGatewaySettings(callerUID: expected.activation.setup.ownerUID, expected: expected, selection: selection) : expected
            if loseAfterRetain { throw LostReply() }
            let result = try await h.owner.resumeGatewaySettings(callerUID: expected.activation.setup.ownerUID, expected: pending)
            return wrongResult ? expected : result
        }
        func counts() -> [Int] { [reads, writes] }
        func restoreCount() -> Int { restores }
        func prepare(_ expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices) throws -> SetupGatewayProgress { throw LostReply() }
        func initializeJournal(_ expected: SetupGatewayProgress) throws -> SetupGatewayJournalResult { throw LostReply() }
        func activate(_ expected: SetupGatewayActivationProgress, settings: GatewayRuntimeActivationSettings) throws -> SetupGatewayActivationProgress { restores += 1; return expected }
    }
    func testLegacySettingsStayReadableAndRestorableWithoutCallingTheMutationDriver() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(native: false), driver = Driver(h)
        let controls = MacGatewaySetupControls(driver: driver), before = try h.read()
        await controls.refresh(); XCTAssertTrue(controls.loaded)
        XCTAssertFalse(try XCTUnwrap(controls.settingsProgress).supportsSettingsChanges)
        await controls.applySettings(h.selection)
        XCTAssertEqual(controls.notice, .settingsUnavailable); XCTAssertTrue(controls.loaded)
        var counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
        await controls.activate(settings: try XCTUnwrap(before.activation.settings))
        let restores = await driver.restoreCount(); XCTAssertEqual(restores, 1)
        counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
        XCTAssertTrue(controls.loaded); XCTAssertNil(controls.notice); XCTAssertEqual(try h.read(), before)
    }
    func testUnsupportedLegacySelectionRefusesBeforeNativeConnectionOrConsent() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(native: false), driver = try NativeMacGatewaySetupDriver()
        do { _ = try await driver.applySettings(h.read(), selection: h.selection); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupChannelError, .unsupportedVersion) }
        XCTAssertNil(try h.read().pendingDigest)
    }
    func testRefreshRestoresTheOriginalServiceSettingsWithoutStartingAChange() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), driver = Driver(h), controls = MacGatewaySetupControls(driver: driver)
        await controls.applySettings(h.selection)
        var counts = await driver.counts(); XCTAssertEqual(counts, [0, 0])
        await controls.refresh(); counts = await driver.counts(); XCTAssertEqual(counts, [1, 0])
        let settings = try XCTUnwrap(controls.settingsProgress)
        XCTAssertEqual(try settings.currentSelection.service.setupBytes, try h.ready.fixture.intent.configuration.settings.setupBytes)
        XCTAssertNil(settings.stage); XCTAssertTrue(controls.loaded)
    }
    func testApplyChangesOnlyAfterAnExplicitActionAndReturnsTheExactSelectedSettings() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), driver = Driver(h), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh(); await controls.applySettings(h.selection)
        XCTAssertTrue(controls.loaded); XCTAssertNil(controls.notice); XCTAssertFalse(controls.working)
        XCTAssertEqual(try controls.settingsProgress?.currentSelection.bytes, try h.selection.bytes)
        await controls.refresh(); let counts = await driver.counts(); XCTAssertEqual(counts, [2, 1])
    }
    func testLostRetentionReplyNeedsRefreshAndExplicitResumeWithoutCreatingAnotherRevision() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), driver = Driver(h), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh(); await driver.configure(lose: true); await controls.applySettings(h.selection)
        XCTAssertFalse(controls.loaded); XCTAssertEqual(controls.notice, .operationFailed)
        let retained = try h.read(); XCTAssertEqual(retained.stage, .retained)
        await controls.applySettings(h.selection); var counts = await driver.counts(); XCTAssertEqual(counts[1], 1)
        await driver.configure(); await controls.refresh()
        XCTAssertEqual(try controls.settingsProgress?.pendingDigest, try retained.pendingDigest)
        counts = await driver.counts(); XCTAssertEqual(counts[1], 1)
        await controls.applySettings(h.selection)
        XCTAssertEqual(try controls.settingsProgress?.activeDigest, try retained.pendingDigest)
        counts = await driver.counts(); XCTAssertEqual(counts[1], 2)
    }
    func testAPendingChangeCannotBeReplacedWithAnotherFormSelection() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(); _ = try h.retain()
        let driver = Driver(h), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh()
        let different = try GatewayRuntimeSettingsSelection(service: h.selection.service,
            activation: .init(wakePollMilliseconds: 3333, wakeTimeoutMilliseconds: 4444))
        await controls.applySettings(different)
        let counts = await driver.counts(); XCTAssertEqual(counts[1], 0)
        XCTAssertEqual(try h.read().pendingSelection?.bytes, try h.selection.bytes)
    }
    func testCancelledConsentDoesNotRetainAnIntentOrShowAnOperationFailure() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), driver = Driver(h), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh(); await driver.configure(cancelled: true); await controls.applySettings(h.selection)
        XCTAssertFalse(controls.loaded); XCTAssertNil(controls.notice); XCTAssertNil(try h.read().pendingDigest)
    }
    func testUncommittedCompletionCannotBeDisplayedAsSuccess() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), driver = Driver(h), controls = MacGatewaySetupControls(driver: driver)
        await controls.refresh(); await driver.configure(wrong: true); await controls.applySettings(h.selection)
        XCTAssertFalse(controls.loaded); XCTAssertEqual(controls.notice, .operationFailed); XCTAssertNil(controls.settingsProgress)
        await controls.refresh(); XCTAssertNotNil(try controls.settingsProgress?.activeDigest)
    }
    func testNativePendingSelectionMismatchRefusesBeforeConnectionOrConsent() async throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), pending = try h.retain(), driver = try NativeMacGatewaySetupDriver()
        let different = try GatewayRuntimeSettingsSelection(service: h.selection.service, activation: .init(wakePollMilliseconds: 3333))
        do { _ = try await driver.applySettings(pending, selection: different); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayPreparationError, .conflictingMaterial) }
    }
}
