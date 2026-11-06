import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateConfigurationAccountOperandTests: XCTestCase {
    private struct Fixture {
        let accountID: Data
        let history: MachineUpdateProvisioningHistory
        let emptyHistory: MachineUpdateProvisioningHistory
        let policy: AuthorityCodePolicySnapshot
        init() throws {
            let files = try AccountPreparationFixture(), machine = try files.open(initialize: true)
            defer { try? machine.close() }
            let preparation = try files.begin(machine), inventory = try XCTUnwrap(machine.inventory())
            accountID = preparation.accountID
            history = try .capture(current: inventory, preparations: [preparation])
            emptyHistory = try .capture(current: inventory, preparations: [])
            let codePolicy = try preparation.initialAuthority.codePolicy
            let revision = UUID()
            policy = .init(revision: revision, policy: codePolicy,
                roleRevisions: Dictionary(uniqueKeysWithValues: codePolicy.entries.map { ($0.role, revision) }))
        }
    }
    private let limits = try! CBORLimits(maxBytes: RuntimeReleaseConfigurationSource.maximumBytes + 1024,
        maxDepth: 1, maxItems: 32)
    private func fields(_ operand: MachineUpdateConfigurationAccountOperand) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(operand.encoded, limits: limits) else {
            throw PreparationStoreError.corruptRecord
        }
        return fields
    }
    private func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    private func value(_ f: Fixture) throws -> MachineUpdateConfigurationAccountOperand {
        try .init(policy: f.policy, history: f.history, accountID: f.accountID)
    }
    func testPolicyOnlyRoundTripRetainsExactStoredPolicyBytes() throws {
        let f = try Fixture()
        let value = try MachineUpdateConfigurationAccountOperand(policy: f.policy, history: nil, accountID: f.accountID)
        let decoded = try MachineUpdateConfigurationAccountOperand.decode(value.encoded, accountID: f.accountID)
        XCTAssertEqual(decoded.policy, try f.policy.storedBytes)
        XCTAssertNil(decoded.history)
        XCTAssertEqual(try decoded.encoded, try value.encoded)
        XCTAssertEqual(try AuthorityCodePolicySnapshot.decodeStored(XCTUnwrap(decoded.policy),
            revision: f.policy.revision), f.policy)
    }
    func testHistoryOnlyRoundTripRetainsTheExactOriginalHistory() throws {
        let f = try Fixture()
        let value = try MachineUpdateConfigurationAccountOperand(policy: nil, history: f.history, accountID: f.accountID)
        let decoded = try MachineUpdateConfigurationAccountOperand.decode(value.encoded, accountID: f.accountID)
        XCTAssertNil(decoded.policy)
        XCTAssertEqual(decoded.history, f.history)
        XCTAssertEqual(try decoded.history?.encoded, try f.history.encoded)
        XCTAssertEqual(try decoded.encoded, try value.encoded)
    }
    func testCombinedRoundTripRetainsBothIndependentOperands() throws {
        let f = try Fixture(), original = try value(f)
        let decoded = try MachineUpdateConfigurationAccountOperand.decode(original.encoded, accountID: f.accountID)
        XCTAssertEqual(decoded.policy, try f.policy.storedBytes)
        XCTAssertEqual(decoded.history, f.history)
        XCTAssertEqual(try decoded.encoded, try original.encoded)
    }
    func testAnOperandCannotOmitBothPolicyAndHistory() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand(policy: nil, history: nil, accountID: f.accountID))
        var changed = try fields(value(f)); changed[2] = .null; changed[3] = .null
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
    }
    func testTheExternalAccountKeyMustHaveTheExactLength() throws {
        let f = try Fixture(), bytes = try value(f).encoded
        for length in [0, 15, 17] {
            let id = Data(repeating: 1, count: length)
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand(policy: f.policy, history: nil, accountID: id))
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(bytes, accountID: id))
        }
    }
    func testHistoryCannotBeReboundToAnotherAccount() throws {
        let f = try Fixture(), other = try Fixture(), bytes = try value(f).encoded
        XCTAssertNotEqual(f.accountID, other.accountID)
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand(policy: f.policy, history: f.history,
            accountID: other.accountID))
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(bytes, accountID: other.accountID))
    }
    func testHistoryMustCarryExactlyOneSelectedAccount() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand(policy: f.policy, history: f.emptyHistory,
            accountID: f.accountID))
        var changed = try fields(value(f)); changed[3] = .bytes(try f.emptyHistory.encoded)
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
    }
    func testMissingAndUnknownFieldsAreRejected() throws {
        let f = try Fixture(), original = try fields(value(f))
        for key in original.keys {
            var changed = original; changed.removeValue(forKey: key)
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
        }
        var changed = original; changed[4] = .null
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
    }
    func testWrongVersionsAndDomainNamesAreRejected() throws {
        let f = try Fixture(), original = try fields(value(f))
        for version in [UInt64(0), 2, UInt64.max] {
            var changed = original; changed[0] = .unsigned(version)
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
        }
        var changed = original; changed[1] = .text("remozio/provisioning-history/v1")
        XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
    }
    func testPolicyAndHistoryFieldsRejectNonBytePayloads() throws {
        let f = try Fixture(), original = try fields(value(f))
        for key in [UInt64(2), 3] {
            for replacement in [CBORValue.unsigned(1), .text("operand"), .map([:])] {
                var changed = original; changed[key] = replacement
                XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
            }
        }
    }
    func testEmptyAndOversizedPolicyBytesAreRejected() throws {
        let f = try Fixture(), original = try fields(value(f))
        for bytes in [Data(), Data(repeating: 0, count: RuntimeReleaseConfigurationSource.maximumBytes + 1)] {
            var changed = original; changed[2] = .bytes(bytes)
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
        }
    }
    func testMalformedHistoryBytesAreRejected() throws {
        let f = try Fixture(), original = try fields(value(f))
        for bytes in [Data(), Data([0xff]), Data([1])] {
            var changed = original; changed[3] = .bytes(bytes)
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID))
        }
    }
    func testTrailingAndOversizedRecordsAreRejected() throws {
        let f = try Fixture()
        for bytes in [try value(f).encoded + Data([0]), Data(repeating: 0,
            count: MachineUpdateConfigurationAccountOperand.maximumBytes + 1)] {
            XCTAssertThrowsError(try MachineUpdateConfigurationAccountOperand.decode(bytes, accountID: f.accountID))
        }
    }
    func testPolicyPayloadStillNeedsTheEnclosingArchiveValidation() throws {
        let f = try Fixture()
        var changed = try fields(value(f)); changed[2] = .bytes(Data([1])); changed[3] = .null
        let decoded = try MachineUpdateConfigurationAccountOperand.decode(encode(changed), accountID: f.accountID)
        XCTAssertEqual(decoded.policy, Data([1]))
        XCTAssertThrowsError(try AuthorityCodePolicySnapshot.decodeStored(XCTUnwrap(decoded.policy),
            revision: f.policy.revision))
    }
    func testDescriptionsRedactThePolicyAndProvisioningHistory() throws {
        let f = try Fixture(), operand = try value(f)
        XCTAssertEqual(String(describing: operand), "MachineUpdateConfigurationAccountOperand(redacted)")
        XCTAssertEqual(String(reflecting: operand), "MachineUpdateConfigurationAccountOperand(redacted)")
    }
    func testReadsAndRoundTripsDoNotChangeRetainedBytes() throws {
        let f = try Fixture(), operand = try value(f), before = try operand.encoded
        for _ in 0..<3 {
            _ = try MachineUpdateConfigurationAccountOperand.decode(operand.encoded, accountID: f.accountID)
            XCTAssertEqual(try operand.encoded, before)
            XCTAssertEqual(operand.policy, try f.policy.storedBytes)
            XCTAssertEqual(operand.history, f.history)
        }
    }
}
