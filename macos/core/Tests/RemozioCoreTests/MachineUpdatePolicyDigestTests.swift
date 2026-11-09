import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdatePolicyDigestTests: XCTestCase {
    private typealias Account = MachineUpdatePolicyDigest.Account
    /// A JSON value re-encoded with JSONEncoder, so its key order matches the record's canonical encoding.
    /// JSONSerialization sorts keys differently, so its output is never canonical.
    private enum JSONValue: Encodable {
        case string(String), number(Int64), bool(Bool), object([String: JSONValue])

        init(_ value: Any) throws {
            switch value {
            case let value as String: self = .string(value)
            case let value as NSNumber where CFGetTypeID(value) == CFBooleanGetTypeID(): self = .bool(value.boolValue)
            case let value as NSNumber: self = .number(value.int64Value)
            case let value as [String: Any]: self = .object(try value.mapValues(JSONValue.init))
            default: throw PreparationStoreError.corruptRecord
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value): try container.encode(value)
            case .number(let value): try container.encode(value)
            case .bool(let value): try container.encode(value)
            case .object(let value): try container.encode(value)
            }
        }
    }
    private func canonicalJSON(_ object: [String: Any]) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(object.mapValues(JSONValue.init))
    }
    private func activation() throws -> MachineUpdateActivationRecord {
        let value: [String: Any] = [
            "formatVersion": 1, "attemptID": "00000000-0000-4000-8000-000000000001",
            "revision": "00000000-0000-4000-8000-000000000002", "macID": Data(repeating: 1, count: 16).base64EncodedString(),
            "installationID": Data(repeating: 2, count: 16).base64EncodedString(),
            "updateID": Data(repeating: 3, count: 32).base64EncodedString(), "generation": 3,
            "candidateDigest": Data(repeating: 4, count: 32).base64EncodedString(),
            "inventoryDigest": Data(repeating: 5, count: 32).base64EncodedString(),
            "admissionDigest": Data(repeating: 6, count: 32).base64EncodedString(),
            "machineAdmission": ["device": 1, "inode": 10], "phase": 1]
        return try MachineUpdateActivationRecord.decode(canonicalJSON(value))
    }
    private func changed(_ activation: MachineUpdateActivationRecord, key: String, value: Any) throws -> MachineUpdateActivationRecord {
        let canonical = try activation.encoded
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
        XCTAssertEqual(try canonicalJSON(object), canonical)
        object[key] = value
        return try .decode(canonicalJSON(object))
    }
    private func account(id: UInt8 = 8, uid: UInt32 = 501, digest: UInt8 = 9,
        policy: AuthorityCodePolicySnapshot? = nil) -> Account {
        .init(accountID: Data(repeating: id, count: 16), ownerUID: uid,
            sourceDigest: Data(repeating: digest, count: 32), policy: policy)
    }
    private func policy(revision: UUID = UUID(), roleRevision: UUID = UUID(), generation: UInt64 = 1) throws -> AuthorityCodePolicySnapshot {
        let entry = try AuthorityCodeEntry(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.test.authority",
            installedGeneration: generation, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 1, count: 20), active: true)
        return .init(revision: revision, policy: try .init(entries: [entry]), roleRevisions: [.authority: roleRevision])
    }
    func testDigestMatchesTheRetainedVersionOneDomainAndIndependentCBORVector() throws {
        let digest = try MachineUpdatePolicyDigest.make(activation: activation(), accounts: [account()])
        XCTAssertEqual(digest, Data([0xfe, 0x05, 0xf1, 0x5e, 0xe4, 0xbf, 0x5e, 0x56, 0xe1, 0x7d, 0xdb, 0x50, 0x8b, 0xf6, 0x95, 0x07, 0x91, 0xe1, 0x76, 0xcc, 0xd9, 0xf4, 0x0c, 0x26, 0xff, 0xf1, 0x20, 0xc6, 0x2b, 0xd9, 0xf5, 0xa3]))
    }
    /// A configured account (two roles, one inactive, each with its own token) beside an unconfigured one.
    /// Both expected values come from an independent CBOR encoder, so they also check DeterministicCBOR and the stored encoding.
    func testAConfiguredPolicyMatchesAnIndependentCBORVector() throws {
        func uuid(_ text: String) throws -> UUID { try XCTUnwrap(UUID(uuidString: text)) }
        let team = "ABCDEFGHIJ", prefix = "dev.sebastiano.remozio.test."
        let authority = try AuthorityCodeEntry(role: .authority, teamID: team, identifier: prefix + "authority",
            installedGeneration: 300, minimumGeneration: 24, codeDirectoryHash: Data(repeating: 0x11, count: 20), active: true)
        let guiAgent = try AuthorityCodeEntry(role: .guiAgent, teamID: team, identifier: prefix + "gui-agent",
            installedGeneration: 2, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 0x12, count: 20), active: false)
        let snapshot = AuthorityCodePolicySnapshot(revision: try uuid("00000000-0000-4000-8000-000000000010"),
            policy: try .init(entries: [guiAgent, authority]),
            roleRevisions: [.authority: try uuid("00000000-0000-4000-8000-000000000011"),
                .guiAgent: try uuid("00000000-0000-4000-8000-000000000012")])
        XCTAssertEqual(MachineUpdateActivationRecord.digest(try snapshot.storedBytes), Data([0xec, 0xfd, 0x0c, 0x0e, 0xa5, 0xc3, 0x1a, 0xaf, 0x9f, 0x4d, 0x75, 0xcb, 0x55, 0x88, 0x11, 0x8b, 0xbd, 0x48, 0x30, 0x55, 0x63, 0x27, 0x32, 0x24, 0x37, 0x43, 0x9f, 0xf3, 0x4d, 0x42, 0x50, 0x34]))
        let digest = try MachineUpdatePolicyDigest.make(activation: activation(),
            accounts: [account(id: 10, uid: 502, digest: 11, policy: snapshot), account()])
        XCTAssertEqual(digest, Data([0xff, 0xae, 0xeb, 0xad, 0x51, 0x84, 0xe9, 0xf1, 0x3c, 0x08, 0x23, 0x28, 0x90, 0x49, 0xea, 0xa4, 0xe3, 0x61, 0x1b, 0x94, 0xb4, 0x5f, 0x5a, 0xaa, 0x4b, 0x1f, 0xfb, 0x37, 0x2f, 0x9e, 0x04, 0x52]))
    }
    func testAccountOrderDoesNotChangeTheDigest() throws {
        let a = try activation(), one = account(), two = account(id: 10)
        XCTAssertEqual(try MachineUpdatePolicyDigest.make(activation: a, accounts: [one, two]),
            try MachineUpdatePolicyDigest.make(activation: a, accounts: [two, one]))
    }
    func testAdvancingTheSameAttemptRetainsItsPreflightDigest() throws {
        let a = try activation(), started = try a.starting(policyPreflightDigest: Data(repeating: 7, count: 32))
        let checking = try started.advancing(to: .restartChecking)
        XCTAssertNotEqual(a.revision, started.revision)
        for value in [started, checking] {
            XCTAssertEqual(try MachineUpdatePolicyDigest.make(activation: a, accounts: [account()]),
                try MachineUpdatePolicyDigest.make(activation: value, accounts: [account()]))
        }
    }
    func testAnotherAttemptOrMachineOperandChangesTheDigest() throws {
        let a = try activation(), expected = try MachineUpdatePolicyDigest.make(activation: a, accounts: [account()])
        var changes: [(String, Any)] = [("attemptID", "00000000-0000-4000-8000-000000000003")]
        for key in ["macID", "installationID"] { changes.append((key, Data(repeating: 20, count: 16).base64EncodedString())) }
        for key in ["updateID", "candidateDigest", "inventoryDigest", "admissionDigest"] {
            changes.append((key, Data(repeating: 21, count: 32).base64EncodedString()))
        }
        for (key, value) in changes {
            XCTAssertNotEqual(expected, try MachineUpdatePolicyDigest.make(activation: changed(a, key: key, value: value), accounts: [account()]))
        }
    }
    func testAccountIdentityOwnerAndRetainedSourceEachChangeTheDigest() throws {
        let a = try activation(), expected = try MachineUpdatePolicyDigest.make(activation: a, accounts: [account()])
        for value in [account(id: 10), account(uid: 502), account(digest: 11)] {
            XCTAssertNotEqual(expected, try MachineUpdatePolicyDigest.make(activation: a, accounts: [value]))
        }
    }
    func testAddingOrRemovingAnUnconfiguredAccountChangesTheDigest() throws {
        let a = try activation(), one = account(), two = account(id: 10)
        let expected = try MachineUpdatePolicyDigest.make(activation: a, accounts: [one, two])
        XCTAssertNotEqual(expected, try MachineUpdatePolicyDigest.make(activation: a, accounts: [one]))
        XCTAssertNotEqual(expected, try MachineUpdatePolicyDigest.make(activation: a, accounts: []))
    }
    func testTheGlobalPolicyRevisionIsBoundEvenWhenStoredBytesAreEqual() throws {
        let a = try activation(), token = UUID(), one = try policy(roleRevision: token), two = try policy(roleRevision: token)
        XCTAssertEqual(try one.storedBytes, try two.storedBytes)
        XCTAssertNotEqual(try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: one)]),
            try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: two)]))
    }
    func testEveryRoleTokenIsBoundEvenWhenTheGlobalRevisionIsEqual() throws {
        let a = try activation(), revision = UUID(), one = try policy(revision: revision), two = try policy(revision: revision)
        XCTAssertEqual(one.policy, two.policy)
        XCTAssertNotEqual(try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: one)]),
            try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: two)]))
    }
    func testPolicyContentsAreBoundEvenWhenAllRevisionTokensAreEqual() throws {
        let a = try activation(), revision = UUID(), token = UUID()
        let one = try policy(revision: revision, roleRevision: token), two = try policy(revision: revision, roleRevision: token, generation: 2)
        XCTAssertNotEqual(try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: one)]),
            try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: two)]))
    }
    func testDuplicateAccountsAndMalformedIdentityOrSourceLengthsAreRejected() throws {
        let a = try activation()
        for values in [[account(), account()],
            [Account(accountID: Data(repeating: 8, count: 15), ownerUID: 501, sourceDigest: Data(repeating: 9, count: 32), policy: nil)],
            [Account(accountID: Data(repeating: 8, count: 16), ownerUID: 501, sourceDigest: Data(repeating: 9, count: 31), policy: nil)]] {
            XCTAssertThrowsError(try MachineUpdatePolicyDigest.make(activation: a, accounts: values)) {
                XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
            }
        }
    }
    func testTheAccountBoundAccepts128AndRejects129DistinctAccounts() throws {
        let a = try activation(), accounts = (0..<129).map { account(id: UInt8($0)) }
        XCTAssertEqual(try MachineUpdatePolicyDigest.make(activation: a, accounts: Array(accounts.prefix(128))).count, 32)
        XCTAssertThrowsError(try MachineUpdatePolicyDigest.make(activation: a, accounts: accounts)) {
            XCTAssertEqual($0 as? MachineUpdateActivationError, .changedScope)
        }
    }
    func testAConfiguredPolicyWithMissingRoleTokensCannotProduceADigest() throws {
        let a = try activation(), valid = try policy()
        let invalid = AuthorityCodePolicySnapshot(revision: valid.revision, policy: valid.policy, roleRevisions: [:])
        XCTAssertThrowsError(try MachineUpdatePolicyDigest.make(activation: a, accounts: [account(policy: invalid)])) {
            XCTAssertEqual($0 as? AuthorityCodePolicyError, .corruptData)
        }
    }
}
