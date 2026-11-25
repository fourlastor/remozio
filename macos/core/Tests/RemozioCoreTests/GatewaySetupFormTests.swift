import Foundation
import XCTest
@testable import RemozioCore

final class GatewaySetupFormTests: XCTestCase, @unchecked Sendable {
    func testDefaultsAndCustomValuesReachEveryServiceSetting() throws {
        var form = GatewaySetupForm()
        _ = try form.serviceSettings(); _ = try form.activationSettings()
        for field in GatewaySetupField.allCases { form[field] = "7" }
        form[.wakePoll] = "700"
        let settings = try form.serviceSettings(), activation = try form.activationSettings()
        XCTAssertEqual(activation.wakePollMilliseconds, 700); XCTAssertEqual(activation.wakeTimeoutMilliseconds, 7)
        XCTAssertEqual(settings.maximumOperations, 7); XCTAssertEqual(settings.handshakeTimeoutMillis, 7)
        XCTAssertEqual(settings.authorityLeaseMillis, 7); XCTAssertEqual(settings.providerTimeoutSeconds, 7)
        XCTAssertEqual(settings.schedulerRetryMillis, 7); XCTAssertEqual(settings.maximumStoredControls, 7)
        XCTAssertEqual(settings.maximumPendingPerEnrollment, 7); XCTAssertEqual(settings.maximumCandidateLifetimeMillis, 7)
        XCTAssertEqual(settings.databaseBusyMillis, 7)
        XCTAssertEqual(settings.delivery.maximumFlights, 7); XCTAssertEqual(settings.delivery.minimumSendIntervalMillis, 7)
        XCTAssertEqual(settings.delivery.retryBaseDelayMillis, 7); XCTAssertEqual(settings.delivery.maximumRetryBackoffMillis, 7)
        XCTAssertEqual(settings.probe.maximumAttempts, 7); XCTAssertEqual(settings.probe.minimumRetryDelayMillis, 7)
        XCTAssertEqual(settings.probe.maximumTTLSeconds, 7); XCTAssertEqual(settings.wake.maximumEntries, 7)
        XCTAssertEqual(settings.wake.maximumAttempts, 7); XCTAssertEqual(settings.wake.minimumEnrollmentIntervalMillis, 7)
        XCTAssertEqual(settings.wake.maximumLifetimeMillis, 7); XCTAssertEqual(settings.wake.maximumTTLSeconds, 7)
    }
    func testMalformedNumbersAndCrossFieldLimitsRefuse() throws {
        for field in GatewaySetupField.allCases {
            for text in ["", "-1", " 1", "1.5", "١", "18446744073709551616"] {
                var form = GatewaySetupForm(); form[field] = text
                if field == .wakePoll || field == .wakeTimeout { XCTAssertThrowsError(try form.activationSettings()) }
                else if [.wakeConnections, .wakeOperations, .wakeChallenge].contains(field) { XCTAssertThrowsError(try form.settingsSelection()) }
                else { XCTAssertThrowsError(try form.serviceSettings()) }
            }
        }
        var form = GatewaySetupForm(); form[.storedControls] = "1"; form[.pendingPerEnrollment] = "2"
        XCTAssertThrowsError(try form.serviceSettings())
        form = .init(); form[.retryBase] = "200"; form[.retryMaximum] = "100"
        XCTAssertThrowsError(try form.serviceSettings())
        form = .init(); form[.probeTTL] = "4294967296"
        XCTAssertThrowsError(try form.serviceSettings())
    }
    func testRetainedWakeSelectionChangesOnlyTheSelectedTimings() throws {
        var form = GatewaySetupForm(); form.senderID = "123"; form[.operations] = "3"
        form.selectRetained(try .init(wakePollMilliseconds: 1234, wakeTimeoutMilliseconds: 2345))
        XCTAssertEqual(try form.activationSettings().wakePollMilliseconds, 1234)
        XCTAssertEqual(try form.activationSettings().wakeTimeoutMilliseconds, 2345)
        XCTAssertEqual(form.senderID, "123"); XCTAssertEqual(form[.operations], "3")
    }
    func testImportedFirebaseCredentialAndConsentReachValidatedChoices() async throws {
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let key = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let fields = ["type": "service_account", "token_uri": FCMServiceAccount.tokenEndpoint, "project_id": "fixture-project",
            "client_email": "fixture@fixture.iam.gserviceaccount.com", "private_key_id": "fixture", "private_key": String(decoding: key, as: UTF8.self),
            "client_id": "extra-provider-metadata"]
        let directory = try importDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("account.json")
        var bytes = try JSONSerialization.data(withJSONObject: fields)
        bytes.append(Data(repeating: 32, count: 65_536 - bytes.count))
        try bytes.write(to: file)
        let provider = try await SetupFCMConfiguration.importServiceAccount(from: file)
        XCTAssertEqual(provider.project, "fixture-project"); XCTAssertEqual(String(describing: provider), "SetupFCMConfiguration(redacted)")
        var form = GatewaySetupForm(); form.senderID = "123"
        XCTAssertThrowsError(try form.choices(provider: provider))
        form.fileWakeCustodyAccepted = true; form[.operations] = "3"
        let choices = try form.choices(provider: provider)
        XCTAssertEqual(choices.senderID, "123"); XCTAssertEqual(choices.packageName, "dev.sebastiano.remozio.android")
        XCTAssertTrue(choices.fileWakeCustodyAccepted); XCTAssertEqual(choices.settings.maximumOperations, 3)
        form.senderID = "invalid sender"; XCTAssertThrowsError(try form.choices(provider: provider))
        form.senderID = "123"; form.packageName = "invalid package"; XCTAssertThrowsError(try form.choices(provider: provider))
    }
    func testCredentialImportRejectsMalformedOversizeAndForeignEndpoints() throws {
        for bytes in [Data(), Data("{}".utf8), Data(repeating: 32, count: 65537)] {
            XCTAssertThrowsError(try SetupFCMConfiguration(serviceAccountJSON: bytes))
        }
        let fields = ["type": "service_account", "token_uri": "https://example.invalid/token", "project_id": "fixture",
            "client_email": "fixture@example.invalid", "private_key_id": "fixture", "private_key": "not-a-key"]
        XCTAssertThrowsError(try SetupFCMConfiguration(serviceAccountJSON: JSONSerialization.data(withJSONObject: fields)))
    }
    func testCredentialFileImportRejectsUnsupportedSourcesBeforeParsing() async throws {
        let directory = try importDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let empty = directory.appendingPathComponent("empty.json")
        let large = directory.appendingPathComponent("large.json")
        let malformed = directory.appendingPathComponent("malformed.json")
        let link = directory.appendingPathComponent("link.json")
        try Data().write(to: empty)
        try Data(repeating: 0, count: 65_537).write(to: large)
        try Data("{}".utf8).write(to: malformed)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: malformed)
        for file in [directory, empty, large, link, directory.appendingPathComponent("missing.json")] {
            do {
                _ = try await SetupFCMConfiguration.importServiceAccount(from: file)
                XCTFail("Accepted an unreadable or unsupported file")
            } catch SetupPreviewReadError.unreadable { }
        }
        do {
            _ = try await SetupFCMConfiguration.importServiceAccount(from: malformed)
            XCTFail("Accepted an invalid credential")
        } catch PortableSetupError.rejected { }
    }
    func testCancelledCredentialFileImportStopsBeforeReading() async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await SetupFCMConfiguration.importServiceAccount(from: URL(fileURLWithPath: "/"))
        }
        do { _ = try await task.value; XCTFail("Accepted cancelled import") }
        catch { XCTAssertTrue(error is CancellationError) }
    }
    private func importDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        return directory
    }
    func testRetainedSelectionRestoresEveryKnobWithoutChangingProviderInputs() throws {
        let ready = try GatewayRuntimeSettingsStoreTests.Ready()
        let saved = try GatewayRuntimeSettingsSelection(service: ready.fixture.intent.configuration.settings,
            activation: .init(wakePollMilliseconds: 4321, wakeTimeoutMilliseconds: 8765),
            maximumWakeConnections: 13, maximumWakeOperations: 17, wakeChallengeLifetimeMilliseconds: 7999)
        var form = GatewaySetupForm(); form.senderID = "123"; form.packageName = "example.retained"
        form.selectRetained(saved)
        XCTAssertEqual(try form.settingsSelection().bytes, try saved.bytes)
        XCTAssertEqual(form.senderID, "123"); XCTAssertEqual(form.packageName, "example.retained")
        form[.wakePoll] = "5000"
        let changed = try form.settingsSelection()
        XCTAssertEqual(try changed.service.setupBytes, try saved.service.setupBytes)
        XCTAssertEqual(changed.maximumWakeConnections, 13); XCTAssertEqual(changed.maximumWakeOperations, 17)
        XCTAssertEqual(changed.wakeChallengeLifetimeMilliseconds, 7999)
        XCTAssertEqual(changed.activation.wakePollMilliseconds, 5000)
    }

    func testRefreshPreservesEditsOnlyForTheSameRetainedAccountAndForegroundScope() throws {
        let first = try GatewaySettingsSetupOwnerTests.Harness(), second = try GatewaySettingsSetupOwnerTests.Harness()
        let left = try first.read(), right = try second.read()
        XCTAssertNotEqual(left.activation.setup.accountID, right.activation.setup.accountID)
        var form = GatewaySetupForm(), selection = GatewaySetupFormSelection()
        selection.update(form: &form, activation: left.activation, settings: left, initial: nil)
        form[.sendInterval] = "777"
        selection.update(form: &form, activation: left.activation, settings: left, initial: nil)
        XCTAssertEqual(form[.sendInterval], "777")
        selection.update(form: &form, activation: right.activation, settings: right, initial: nil)
        XCTAssertEqual(form[.sendInterval], String(try right.currentSelection.service.delivery.minimumSendIntervalMillis))
    }

}
