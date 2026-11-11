import Foundation
import XCTest
@testable import RemozioCore

/// Uses synthetic archive facts to check the decoder. The fixture proves no native runtime state.
final class RuntimeRetainedSetupCompletionBindingTests: XCTestCase {
    private let digestFields = ["recordedCompletionDigest", "activationPlanDigest", "recordedInventoryDigest",
        "completionPolicySnapshotDigest", "completionCheckpointDigest"]

    private func encoded(_ fields: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func fixture() -> [String: Any] {
        let digest = Data(repeating: 1, count: 32).base64EncodedString()
        let identity = Data(repeating: 2, count: 16).base64EncodedString()
        var startup: [String: Any] = ["formatVersion": 1, "macID": identity, "installationID": identity,
            "accountID": identity, "ownerUID": 501, "activationAttempt": UUID().uuidString]
        for name in ["candidateDigest", "admissionDigest", "updateID", "stableSealDigest", "installedEpochDigest",
                     "sealedInventoryDigest", "sourceAccountDigest", "preparationDigest", "initializationDigest",
                     "provisioningInventoryDigest", "provisioningReleaseDigest", "previousInstalledReleaseDigest",
                     "installedReleaseDigest", "runtimeReferenceDigest", "retainedSourceDigest", "policyIntentDigest",
                     "sourcePolicyDigest", "sourceCheckpointDigest", "startupPolicyDigest", "startupPolicySnapshotDigest",
                     "startupCheckpointDigest", "completionPolicyDigest"] {
            startup[name] = digest
        }
        startup["installedReleaseDigest"] = Data(repeating: 3, count: 32).base64EncodedString()
        var fields: [String: Any] = ["formatVersion": 1, "startupBinding": startup,
            "completionPolicyRevision": UUID().uuidString]
        for name in digestFields { fields[name] = digest }
        return fields
    }
    private func rejects(_ fields: [String: Any], file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionBinding.decode(encoded(fields)), file: file, line: line) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan, file: file, line: line)
        }
    }

    func testRoundTripsCanonicalArchiveFactsAndRedactsDescriptions() throws {
        let bytes = try encoded(fixture())
        let binding = try RuntimeRetainedSetupCompletionBinding.decode(bytes)
        XCTAssertEqual(try binding.encoded, bytes)
        XCTAssertEqual(try RuntimeRetainedSetupCompletionBinding.decode(binding.encoded), binding)
        XCTAssertEqual(binding.description, "RuntimeRetainedSetupCompletionBinding(redacted)")
        XCTAssertEqual(binding.debugDescription, binding.description)
    }
    func testRejectsEveryInvalidCompletionDigestLength() throws {
        for name in digestFields {
            for count in [0, 31, 33] {
                var fields = fixture()
                fields[name] = Data(repeating: 7, count: count).base64EncodedString()
                try rejects(fields)
            }
        }
    }
    func testRejectsUnsupportedVersionsAndMissingOrInvalidRevisions() throws {
        for version in [0, 2] {
            var fields = fixture(); fields["formatVersion"] = version
            try rejects(fields)
        }
        var fields = fixture(); fields.removeValue(forKey: "completionPolicyRevision")
        try rejects(fields)
        fields["completionPolicyRevision"] = "invalid"
        try rejects(fields)
    }
    func testRejectsInvalidNestedStartupBindings() throws {
        for value in [0, 2] {
            var fields = fixture()
            var startup = try XCTUnwrap(fields["startupBinding"] as? [String: Any])
            startup["formatVersion"] = value; fields["startupBinding"] = startup
            try rejects(fields)
        }
        var fields = fixture()
        var startup = try XCTUnwrap(fields["startupBinding"] as? [String: Any])
        startup["installedReleaseDigest"] = startup["provisioningReleaseDigest"]
        fields["startupBinding"] = startup
        try rejects(fields)
        fields = fixture()
        startup = try XCTUnwrap(fields["startupBinding"] as? [String: Any])
        startup["ownerUID"] = 0; fields["startupBinding"] = startup
        try rejects(fields)
    }
    func testRejectsUnknownFieldsAndNoncanonicalOrOversizedBytes() throws {
        var fields = fixture(); fields["unknown"] = true
        try rejects(fields)
        let bytes = try encoded(fixture())
        for invalid in [Data(), bytes + Data(" ".utf8),
                        Data(repeating: 32, count: RuntimeRetainedSetupCompletionBinding.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionBinding.decode(invalid)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
            }
        }
        fields = fixture()
        var startup = try XCTUnwrap(fields["startupBinding"] as? [String: Any])
        startup["unknown"] = true; fields["startupBinding"] = startup
        try rejects(fields)
    }
}
