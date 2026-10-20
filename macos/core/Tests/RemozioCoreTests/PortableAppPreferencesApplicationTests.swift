import Foundation
import XCTest
@testable import RemozioCore

final class PortableAppPreferencesApplicationTests: XCTestCase {
    func testValidSourceMaximumCannotInvalidateTheDestinationInitialBackoff() throws {
        let proposal = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.maximumBackoffKey: "500"])
        let existing: [String: Any] = [CommandFrontendCallerSettings.initialBackoffKey: "1000",
            CommandFrontendCallerSettings.maximumBackoffKey: "2000"]
        XCTAssertThrowsError(try proposal.applicationValues { existing[$0] })
        XCTAssertEqual(existing[CommandFrontendCallerSettings.initialBackoffKey] as? String, "1000")
        XCTAssertEqual(existing[CommandFrontendCallerSettings.maximumBackoffKey] as? String, "2000")
    }

    func testValidSourceInitialCannotInvalidateTheDestinationMaximumBackoff() throws {
        let proposal = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.initialBackoffKey: "1500"])
        let existing: [String: Any] = [CommandFrontendCallerSettings.maximumBackoffKey: "1000"]
        XCTAssertThrowsError(try proposal.applicationValues { existing[$0] })
    }

    func testCompatibleSparseImportReturnsOnlyTheReviewedKeys() throws {
        let proposal = try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: false,
            CommandFrontendCallerSettings.maximumBackoffKey: "5000"])
        let existing: [String: Any] = [CommandFrontendCallerSettings.initialBackoffKey: "1500",
            CommandFrontendCallerSettings.modeKey: "pipes", "installationID": "local-only"]
        var readKeys: [String] = []
        let values = try proposal.applicationValues { key in readKeys.append(key); return existing[key] }
        XCTAssertEqual(Set(readKeys), Set(PortableAppPreferences.commandKeys))
        XCTAssertEqual(Set(values.keys), [PortableAppPreferences.menuBarKey, CommandFrontendCallerSettings.maximumBackoffKey])
        XCTAssertEqual(values[PortableAppPreferences.menuBarKey] as? Bool, false)
        XCTAssertEqual(values[CommandFrontendCallerSettings.maximumBackoffKey] as? String, "5000")
        XCTAssertNil(values[CommandFrontendCallerSettings.initialBackoffKey])
        XCTAssertNil(values[CommandFrontendCallerSettings.modeKey]); XCTAssertNil(values["installationID"])
    }

    func testImportedPairCanReplaceIncompatibleDestinationValuesTogether() throws {
        let proposal = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.initialBackoffKey: "1500",
            CommandFrontendCallerSettings.maximumBackoffKey: "5000"])
        let existing: [String: Any] = [CommandFrontendCallerSettings.initialBackoffKey: "250",
            CommandFrontendCallerSettings.maximumBackoffKey: "1000"]
        let values = try proposal.applicationValues { existing[$0] }
        XCTAssertEqual(values[CommandFrontendCallerSettings.initialBackoffKey] as? String, "1500")
        XCTAssertEqual(values[CommandFrontendCallerSettings.maximumBackoffKey] as? String, "5000")
        XCTAssertEqual(values.count, 2)
    }

    func testOverriddenInvalidDestinationValueDoesNotBlockAValidReplacement() throws {
        let proposal = try PortableAppPreferences(preferences: [CommandFrontendCallerSettings.modeKey: "pipes"])
        let existing: [String: Any] = [CommandFrontendCallerSettings.modeKey: 7]
        let values = try proposal.applicationValues { existing[$0] }
        XCTAssertEqual(values[CommandFrontendCallerSettings.modeKey] as? String, "pipes")
        XCTAssertEqual(values.count, 1)
    }

    func testMenuBarOnlyImportDoesNotReadUnchangedCommandSettings() throws {
        let proposal = try PortableAppPreferences(preferences: [PortableAppPreferences.menuBarKey: true])
        let values = try proposal.applicationValues { _ in XCTFail("No command setting changes"); return 7 }
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[PortableAppPreferences.menuBarKey] as? Bool, true)
    }

    func testEmptyPreferenceImportDoesNotReadOrInventDestinationValues() throws {
        let proposal = try PortableAppPreferences(preferences: [:])
        let values = try proposal.applicationValues { _ in XCTFail("No selected preferences"); return 7 }
        XCTAssertTrue(values.isEmpty)
    }
}
