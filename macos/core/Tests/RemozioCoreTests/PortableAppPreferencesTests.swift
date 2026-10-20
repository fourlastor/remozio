import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PortableAppPreferencesTests: XCTestCase {
    func testNoStoredPreferencesRemainAbsentRatherThanClaimingSourceDefaults() throws {
        let value = try PortableAppPreferences(preferences: [:])
        XCTAssertNil(value.menuBarVisible); XCTAssertTrue(value.commandOverrides.isEmpty); XCTAssertTrue(value.valuesToApply.isEmpty)
        XCTAssertEqual(try PortableAppPreferences.decode(value.bytes), value)
    }
    func testCaptureDropsLocalAuthorityAndRegistrationFields() throws {
        let value = try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: false,
            CommandFrontendCallerSettings.modeKey: "pipes", "authorityPublicKey": "local-only", "macID": "local-only",
            "presenceMode": "away", "launchAtLogin": true, "pairings": ["phone"]])
        XCTAssertEqual(value.menuBarVisible, false); XCTAssertEqual(Set(value.valuesToApply.keys), Set([PortableAppPreferences.menuBarKey, CommandFrontendCallerSettings.modeKey]))
        XCTAssertEqual(value.commandOverrides, [CommandFrontendCallerSettings.modeKey: "pipes"])
        XCTAssertNil(try value.bytes.range(of: Data("local-only".utf8)))
    }
    func testCaptureReadsOnlyAllowlistedKeysWithoutInspectingOtherStoredState() throws {
        var readKeys: [String] = []
        let value = try PortableAppPreferences.capture { key in
            readKeys.append(key)
            if key == CommandFrontendCallerSettings.modeKey { return "pipes" }
            return nil
        }
        XCTAssertEqual(readKeys, [PortableAppPreferences.menuBarKey] + PortableAppPreferences.commandKeys)
        XCTAssertEqual(value.commandOverrides, [CommandFrontendCallerSettings.modeKey: "pipes"])
        XCTAssertNil(value.menuBarVisible)
    }
    func testSparseValuesRoundTripWithoutAddingOtherPreferences() throws {
        let value = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.controlRetryKey: "7"])
        let decoded = try PortableAppPreferences.decode(value.bytes)
        XCTAssertNil(decoded.menuBarVisible); XCTAssertEqual(decoded.commandOverrides, [CommandFrontendCallerSettings.controlRetryKey: "7"])
        XCTAssertEqual(try decoded.bytes, try value.bytes)
    }
    func testAllCallerPreferencesKeepTheirExistingValidationAndMaximumTimeout() throws {
        let overrides = [CommandFrontendCallerSettings.modeKey: "pty", CommandFrontendCallerSettings.disconnectKey: "continue",
            CommandFrontendCallerSettings.timeoutKey: String(UInt64.max), CommandFrontendCallerSettings.initialBackoffKey: "1",
            CommandFrontendCallerSettings.maximumBackoffKey: "60000", CommandFrontendCallerSettings.controlTimeoutKey: "12000",
            CommandFrontendCallerSettings.controlRetryKey: "7", CommandFrontendCallerSettings.foregroundRetryKey: "123"]
        let value = try PortableAppPreferences(preferences: overrides)
        XCTAssertEqual(value.commandOverrides, overrides); XCTAssertEqual(try PortableAppPreferences.decode(value.bytes), value)
    }
    func testValidLeadingZerosAreNormalizedWithoutChangingTheEffectiveSetting() throws {
        let text = String(repeating: "0", count: 50) + "50"
        let value = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.controlRetryKey: text])
        XCTAssertEqual(value.commandOverrides[CommandFrontendCallerSettings.controlRetryKey], "50")
        XCTAssertEqual(try PortableAppPreferences.decode(value.bytes), value)
    }
    func testMalformedOrContradictoryCallerPreferencesFailInsteadOfFallingBack() throws {
        for key in PortableAppPreferences.commandKeys {
            for value: Any in ["", "-1", "unexpected", true, NSNumber(value: 5)] {
                XCTAssertThrowsError(try PortableAppPreferences(preferences: [key: value]))
            }
        }
        XCTAssertThrowsError(try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.initialBackoffKey: "5000"]))
        XCTAssertThrowsError(try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.timeoutKey: String(repeating: "0", count: 21)]))
    }
    func testMenuBarSettingRequiresABooleanAndDoesNotCoerceNumbersOrText() throws {
        for raw: Any in [NSNumber(value: 1), NSNumber(value: 0), "true", "false"] {
            XCTAssertThrowsError(try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: raw]))
        }
        for value in [false, true] {
            XCTAssertEqual(try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: value]).menuBarVisible, value)
        }
    }
    func testUnknownVersionsFieldsAndTypesAreRejected() throws {
        let limits = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 32)
        let base: [UInt64: CBORValue] = [0: .unsigned(1), 1: .text("remozio-shared-app-preferences"), 2: .map([:])]
        var version = base; version[0] = .unsigned(2)
        var extra = base; extra[3] = .null
        var key = base; key[2] = .map([9: .text("injected")])
        var boolean = base; boolean[2] = .map([0: .unsigned(1)])
        var command = base; command[2] = .map([1: .boolean(true)])
        var purpose = base; purpose[1] = .text("another-purpose")
        for fields in [version,extra,key,boolean,command,purpose] {
            XCTAssertThrowsError(try PortableAppPreferences.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        XCTAssertThrowsError(try PortableAppPreferences.decode(Data(repeating: 0, count: 2049)))
    }
}
