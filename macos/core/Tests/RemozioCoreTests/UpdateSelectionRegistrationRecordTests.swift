import Foundation
import XCTest
@testable import RemozioCore

/// Synthetic records test codec boundaries. They do not grant live admission or installed authority.
final class UpdateSelectionRegistrationRecordTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16)
    private let installation = Data(repeating: 2, count: 16)
    private let account = Data(repeating: 3, count: 16)
    private func preparation(_ phase: PreparationRecordPhase = .copyRecorded) throws -> PreparationIntentRecord {
        try .init(id: UUID(), revision: UUID(), parent: "/synthetic", ancestry: [.init(device: 1, inode: 1)],
            phase: phase, copyIdentity: phase == .intent ? nil : .init(device: 1, inode: 2),
            copyDigest: phase == .intent ? nil : Data(repeating: 4, count: 32))
    }
    private func candidate(generation: UInt64 = 1, selected: Bool = true) throws -> UpdateSchedulingCandidateRecord {
        try .init(macID: mac, installationID: installation, inventoryRevision: Data(repeating: 5, count: 16),
            preparation: preparation(), generation: generation, selected: selected)
    }
    private func registration(accounts: [UpdateAdmissionRegistrationRecord.Account]? = nil,
        machine: PreparationFileIdentity = .init(device: 1, inode: 10), owner: Data? = nil) throws -> UpdateAdmissionRegistrationRecord {
        try .init(macID: mac, installationID: installation, machine: machine,
            accounts: accounts ?? [.init(accountID: account, identity: .init(device: 1, inode: 11))], designatedOwner: owner)
    }
    private func mutate(_ bytes: Data, _ body: (inout [String: Any]) -> Void) throws -> Data {
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        body(&fields)
        return try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    func testSelectionRoundTripsWithoutRecreatingAWithdrawnGeneration() throws {
        for generation in [UInt64(1), .max] {
            for selected in [false, true] {
                let value = try candidate(generation: generation, selected: selected)
                XCTAssertEqual(try UpdateSchedulingCandidateRecord.decode(value.encoded), value)
                XCTAssertEqual(value.updateID, value.preparation.copyDigest)
                XCTAssertEqual(value.description, "UpdateSchedulingCandidateRecord(redacted)")
                XCTAssertEqual(value.debugDescription, value.description)
            }
        }
    }
    func testSelectionRejectsAnIntentOrAbandonedCopy() throws {
        for phase in [PreparationRecordPhase.intent, .abandoned] {
            XCTAssertThrowsError(try UpdateSchedulingCandidateRecord(macID: mac, installationID: installation,
                inventoryRevision: Data(repeating: 5, count: 16), preparation: preparation(phase), generation: 1))
        }
    }
    func testSelectionRejectsMissingScopeAndZeroGeneration() throws {
        XCTAssertThrowsError(try candidate(generation: 0))
        for index in 0..<3 {
            var scopes = [mac, installation, Data(repeating: 5, count: 16)]
            scopes[index] = Data(repeating: 9, count: 15)
            XCTAssertThrowsError(try UpdateSchedulingCandidateRecord(macID: scopes[0], installationID: scopes[1],
                inventoryRevision: scopes[2], preparation: preparation(), generation: 1))
        }
    }
    func testSelectionDecodeRejectsUnknownNoncanonicalAndInvalidRecords() throws {
        let bytes = try candidate().encoded
        for invalid in [Data(), bytes + Data(" ".utf8), Data(repeating: 0, count: 32769),
            try mutate(bytes) { $0["unknown"] = 1 }, try mutate(bytes) { $0["generation"] = 0 },
            try mutate(bytes) { $0["formatVersion"] = 2 }] {
            XCTAssertThrowsError(try UpdateSchedulingCandidateRecord.decode(invalid))
        }
    }
    func testRegistrationSortsAccountsAndPreservesExplicitOwnerSelection() throws {
        let other = UpdateAdmissionRegistrationRecord.Account(accountID: Data(repeating: 8, count: 16), identity: .init(device: 1, inode: 12))
        let first = UpdateAdmissionRegistrationRecord.Account(accountID: account, identity: .init(device: 1, inode: 11))
        for owner in [nil, account, other.accountID] {
            let value = try registration(accounts: [other, first], owner: owner)
            XCTAssertEqual(value.accounts.map(\.accountID), [account, other.accountID])
            XCTAssertEqual(value.designatedOwner, owner)
            XCTAssertEqual(try UpdateAdmissionRegistrationRecord.decode(value.encoded), value)
            XCTAssertEqual(value.description, "UpdateAdmissionRegistrationRecord(redacted)")
            XCTAssertEqual(value.debugDescription, value.description)
        }
        XCTAssertNil(try registration().designatedOwner)
    }
    func testRegistrationRejectsAliasedFilesDuplicateAccountsAndAnUnknownOwner() throws {
        let first = UpdateAdmissionRegistrationRecord.Account(accountID: account, identity: .init(device: 1, inode: 11))
        let alias = UpdateAdmissionRegistrationRecord.Account(accountID: Data(repeating: 8, count: 16), identity: first.identity)
        XCTAssertThrowsError(try registration(accounts: [first, first]))
        XCTAssertThrowsError(try registration(accounts: [first, alias]))
        XCTAssertThrowsError(try registration(machine: first.identity))
        XCTAssertThrowsError(try registration(owner: Data(repeating: 99, count: 16)))
    }
    func testRegistrationBoundsAccountsAndRejectsInvalidIdentities() throws {
        let accounts = (1...64).map { value in
            UpdateAdmissionRegistrationRecord.Account(accountID: Data(repeating: UInt8(value), count: 16),
                identity: .init(device: 1, inode: UInt64(value + 100)))
        }
        XCTAssertEqual(try registration(accounts: accounts).accounts.count, 64)
        XCTAssertThrowsError(try registration(accounts: []))
        XCTAssertThrowsError(try registration(accounts: accounts + [.init(accountID: Data(repeating: 65, count: 16), identity: .init(device: 1, inode: 165))]))
        XCTAssertThrowsError(try registration(machine: .init(device: 1, inode: 0)))
        XCTAssertThrowsError(try registration(accounts: [.init(accountID: Data(repeating: 1, count: 15), identity: .init(device: 1, inode: 11))]))
        XCTAssertThrowsError(try registration(accounts: [.init(accountID: account, identity: .init(device: 1, inode: 0))]))
    }
    func testRegistrationDecodeRejectsUnknownNoncanonicalAndUnsortedRecords() throws {
        let first = UpdateAdmissionRegistrationRecord.Account(accountID: account, identity: .init(device: 1, inode: 11))
        let other = UpdateAdmissionRegistrationRecord.Account(accountID: Data(repeating: 8, count: 16), identity: .init(device: 1, inode: 12))
        let bytes = try registration(accounts: [first, other]).encoded
        let reversed = try mutate(bytes) { fields in
            fields["accounts"] = (fields["accounts"] as! [Any]).reversed().map { $0 }
        }
        for invalid in [Data(), bytes + Data(" ".utf8), Data(repeating: 0, count: 32769), reversed,
            try mutate(bytes) { $0["unknown"] = 1 }, try mutate(bytes) { $0["formatVersion"] = 2 }] {
            XCTAssertThrowsError(try UpdateAdmissionRegistrationRecord.decode(invalid))
        }
    }
}
