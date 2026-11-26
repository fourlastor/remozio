import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandFrontendCallerSettingsTests: XCTestCase {
    private func settings(_ preferences: [String: Any]) throws -> CommandFrontendCallerSettings {
        try .init(preferences: preferences, defaultIOMode: .pipes, defaultDisconnectBehavior: .continueRunning,
            defaultReadiness: .init(timeoutMilliseconds: 98765, initialBackoffMilliseconds: 125,
                maximumBackoffMilliseconds: 3000, controlTimeoutMilliseconds: 6000))
    }
    func testAbsentPreferencesUseInstallationDefaultsWithoutTerminalGuesses() throws {
        let value = try settings([:])
        XCTAssertEqual(value.ioMode, .pipes); XCTAssertEqual(value.disconnectBehavior, .continueRunning)
        XCTAssertEqual(value.readiness.timeoutMilliseconds, 98765)
        XCTAssertEqual(value.readiness.initialBackoffMilliseconds, 125)
        XCTAssertEqual(value.readiness.maximumBackoffMilliseconds, 3000)
        XCTAssertEqual(value.readiness.controlTimeoutMilliseconds, 6000)
        XCTAssertEqual(value.controlRetryMilliseconds, 50); XCTAssertEqual(value.foregroundRetryMilliseconds, 250)
    }
    func testPreferencesChangeCallerSettingsAndCannotSupplyTrustFields() throws {
        let value = try settings([
            CommandFrontendCallerSettings.modeKey: "pty", CommandFrontendCallerSettings.disconnectKey: "terminate",
            CommandFrontendCallerSettings.timeoutKey: String(UInt64.max),
            CommandFrontendCallerSettings.initialBackoffKey: "1", CommandFrontendCallerSettings.maximumBackoffKey: "60000",
            CommandFrontendCallerSettings.controlTimeoutKey: "12000", CommandFrontendCallerSettings.controlRetryKey: "7",
            CommandFrontendCallerSettings.foregroundRetryKey: "123", "authorityPolicy": "false", "serviceName": "untrusted"])
        XCTAssertEqual(value.ioMode, .pty); XCTAssertEqual(value.disconnectBehavior, .terminate)
        XCTAssertEqual(value.readiness.timeoutMilliseconds, UInt64.max)
        XCTAssertEqual(value.readiness.initialBackoffMilliseconds, 1); XCTAssertEqual(value.readiness.maximumBackoffMilliseconds, 60000)
        XCTAssertEqual(value.readiness.controlTimeoutMilliseconds, 12000)
        XCTAssertEqual(value.controlRetryMilliseconds, 7); XCTAssertEqual(value.foregroundRetryMilliseconds, 123)
    }
    func testMalformedAndContradictoryPreferencesDoNotSilentlyFallback() throws {
        for key in [CommandFrontendCallerSettings.timeoutKey, CommandFrontendCallerSettings.initialBackoffKey,
                    CommandFrontendCallerSettings.maximumBackoffKey, CommandFrontendCallerSettings.controlTimeoutKey,
                    CommandFrontendCallerSettings.controlRetryKey, CommandFrontendCallerSettings.foregroundRetryKey] {
            for value: Any in ["", "0", "-1", "1.5", " 50", "50 ", "18446744073709551616", NSNumber(value: 50), true] {
                XCTAssertThrowsError(try settings([key: value]), "\(key): \(value)")
            }
            if key != CommandFrontendCallerSettings.timeoutKey { XCTAssertThrowsError(try settings([key: "60001"])) }
        }
        XCTAssertThrowsError(try settings([CommandFrontendCallerSettings.initialBackoffKey: "4000"])) {
            XCTAssertEqual($0 as? CommandFrontendCallerSettingsError, .invalidValue(.maximumBackoff, .maximumBackoff))
        }
        XCTAssertThrowsError(try settings([CommandFrontendCallerSettings.modeKey: "automatic"]))
        XCTAssertThrowsError(try settings([CommandFrontendCallerSettings.disconnectKey: "ignore"]))
    }

    func testValidationIdentifiesTheInvalidFieldAndRule() throws {
        typealias Field = CommandFrontendCallerSettings.Field
        typealias Rule = CommandFrontendCallerSettingsError.Rule
        let invalid: [(Field, Any, Rule)] = [
            (.ioMode, "automatic", .ioMode), (.disconnectBehavior, "ignore", .disconnectBehavior),
            (.readinessWait, "", .readinessWait), (.initialBackoff, "0", .interval),
            (.maximumBackoff, "60001", .interval), (.controlTimeout, " 50", .interval),
            (.controlRetry, 50, .text), (.foregroundRetry, "18446744073709551616", .interval),
        ]
        for (field, value, rule) in invalid {
            XCTAssertThrowsError(try settings([field.rawValue: value])) { error in
                let failure = error as? CommandFrontendCallerSettingsError
                XCTAssertEqual(failure, .invalidValue(field, rule))
                XCTAssertEqual(failure?.field, field)
            }
        }
        let value = try settings([Field.initialBackoff.rawValue: "060000", Field.maximumBackoff.rawValue: "60000"])
        XCTAssertEqual(value.readiness.initialBackoffMilliseconds, 60_000)
        XCTAssertEqual(value.readiness.maximumBackoffMilliseconds, 60_000)
    }

    func testDraftValidatesSparseEditsAgainstInstalledDefaults() throws {
        typealias Field = CommandFrontendCallerSettings.Field
        let installed = try CommandFrontendCallerSettings(preferences: [:], defaultIOMode: .pipes,
            defaultDisconnectBehavior: .terminate, defaultReadiness: .init(timeoutMilliseconds: 40_000,
                initialBackoffMilliseconds: 4000, maximumBackoffMilliseconds: 5000))
        XCTAssertThrowsError(try installed.applying([.maximumBackoff: "3000"], to: [:])) {
            XCTAssertEqual($0 as? CommandFrontendCallerSettingsError, .invalidValue(.maximumBackoff, .maximumBackoff))
        }
        let snapshot = try installed.applying([.initialBackoff: "3000"], to: [:])
        XCTAssertEqual(snapshot[Field.initialBackoff.rawValue] as? String, "3000")
        XCTAssertNil(snapshot[Field.maximumBackoff.rawValue])
        XCTAssertNil(snapshot[Field.ioMode.rawValue])
        let read = try CommandFrontendCallerSettings(preferences: snapshot, defaultIOMode: installed.ioMode,
            defaultDisconnectBehavior: installed.disconnectBehavior, defaultReadiness: installed.readiness)
        XCTAssertEqual(read.readiness.initialBackoffMilliseconds, 3000)
        XCTAssertEqual(read.readiness.maximumBackoffMilliseconds, 5000)
    }

    func testValidatedDraftPreservesUnrelatedPreferencesAndKeepsThePairTogether() throws {
        typealias Field = CommandFrontendCallerSettings.Field
        let name = "dev.sebastiano.remozio.tests.\(UUID().uuidString)"
        let store = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { store.removePersistentDomain(forName: name) }
        store.setPersistentDomain([Field.readinessWait.rawValue: "30000", "unrelated": true], forName: name)
        let saved = try XCTUnwrap(store.persistentDomain(forName: name))
        let installed = try settings([:])
        XCTAssertThrowsError(try installed.applying([.readinessWait: ""], to: saved))
        XCTAssertEqual(store.persistentDomain(forName: name)?[Field.readinessWait.rawValue] as? String, "30000")

        let proposed = try installed.applying([.initialBackoff: "4500", .maximumBackoff: "4500"], to: saved)
        store.setPersistentDomain(proposed, forName: name)
        let reloaded = try XCTUnwrap(store.persistentDomain(forName: name))
        XCTAssertEqual(reloaded["unrelated"] as? Bool, true)
        XCTAssertNil(reloaded[Field.ioMode.rawValue])
        let read = try settings(reloaded)
        XCTAssertEqual(read.readiness.initialBackoffMilliseconds, 4500)
        XCTAssertEqual(read.readiness.maximumBackoffMilliseconds, 4500)
    }

    func testLegacyInvalidDomainReportsCLIErrorAndCanBeReset() throws {
        typealias Field = CommandFrontendCallerSettings.Field
        let legacy: [String: Any] = [Field.readinessWait.rawValue: "", "unrelated": true]
        XCTAssertThrowsError(try settings(legacy)) { error in
            guard let failure = error as? CommandFrontendCallerSettingsError else {
                return XCTFail("Expected a command caller settings error")
            }
            var messages: [String] = []
            let exit = CommandFrontendMain.settingsExit(failure) { messages.append($0) }
            guard case .status(let status) = exit else { return XCTFail("Expected an exit status") }
            XCTAssertEqual(status, EX_CONFIG)
            XCTAssertEqual(messages, ["Readiness wait (ms) must be a valid positive whole number. Review Command Caller in Remozio Settings."])
        }
        let everyOverride = Dictionary(uniqueKeysWithValues: Field.allCases.map { ($0.rawValue, "" as Any) })
        let reset = CommandFrontendCallerSettings.resettingOverrides(in: everyOverride.merging(legacy) { _, value in value })
        XCTAssertEqual(Set(reset.keys), ["unrelated"])
        let restored = try settings(reset)
        XCTAssertEqual(restored.readiness.timeoutMilliseconds, 98_765)
    }
}
