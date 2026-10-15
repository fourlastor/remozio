import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ServiceAccountDirectoryTests: XCTestCase {
    private func claim() throws -> ServiceAccountClaim {
        try .init(accountID: Data(repeating: 1, count: 16), role: .transport, number: 20000, userID: UUID(), groupID: UUID())
    }
    private func record(_ claim: ServiceAccountClaim, kind: ServiceDirectoryKind = .user) -> ServiceDirectoryRecord {
        .init(number: claim.number, id: kind == .user ? claim.userID : claim.groupID, names: [claim.name])
    }
    func testAllIndexesMustBeAbsentBeforeReportingLocalAbsence() throws {
        let claim = try claim()
        XCTAssertEqual(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: .user, byName: [], byNumber: [], byID: []), .absent)
        let row = record(claim)
        for values in [[[row], [], []], [[], [row], []], [[], [], [row]]] {
            XCTAssertThrowsError(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: .user,
                byName: values[0], byNumber: values[1], byID: values[2]))
        }
    }
    func testEveryIndexMustMatchTheRetainedUUIDNumberAndName() throws {
        let claim = try claim()
        for kind in [ServiceDirectoryKind.user, .group] {
            let row = record(claim, kind: kind)
            XCTAssertEqual(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: kind, byName: [row], byNumber: [row], byID: [row]), .retained)
        }
    }
    func testNamesAloneCannotAdoptARecordAndAliasesCannotBroadenTheClaim() throws {
        let claim = try claim(), exact = record(claim)
        let records = [ServiceDirectoryRecord(number: claim.number, id: UUID(), names: [claim.name]),
            .init(number: claim.number + 1, id: claim.userID, names: [claim.name]),
            .init(number: claim.number, id: claim.userID, names: ["foreign"]),
            .init(number: claim.number, id: claim.userID, names: [claim.name, "alias"])]
        for row in records {
            XCTAssertThrowsError(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: .user, byName: [row], byNumber: [row], byID: [row]))
            XCTAssertThrowsError(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: .user, byName: [exact], byNumber: [row], byID: [exact]))
        }
    }
    func testDuplicateRecordsOrDifferentRecordKindsAreConflicts() throws {
        let claim = try claim(), row = record(claim)
        XCTAssertThrowsError(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: .user, byName: [row, row], byNumber: [row], byID: [row]))
        XCTAssertThrowsError(try ServiceDirectoryPreflight.evaluate(claim: claim, kind: .group, byName: [row], byNumber: [row], byID: [row]))
    }
    func testMalformedMetadataCannotBeTreatedAsAnAbsentRecord() throws {
        let id = UUID().uuidString
        for numbers in [[], ["1", "1"], ["+1"], ["01"], ["-1"], [String(UInt32.max)], ["18446744073709551616"]] {
            XCTAssertThrowsError(try ServiceDirectoryRecord.decode(numbers: numbers, ids: [id], names: ["valid"]))
        }
        for ids in [[], [id, id], ["invalid"]] {
            XCTAssertThrowsError(try ServiceDirectoryRecord.decode(numbers: ["1"], ids: ids, names: ["valid"]))
        }
        for names in [[], [""], ["same", "same"], ["bad\0name"]] {
            XCTAssertThrowsError(try ServiceDirectoryRecord.decode(numbers: ["1"], ids: [id], names: names))
        }
        XCTAssertEqual(try ServiceDirectoryRecord.decode(numbers: ["1"], ids: [id], names: ["valid"]).description, "ServiceDirectoryRecord(redacted)")
    }
    func testNativeReadOnlyIndexesAgreeForTheCurrentCallerAndPrimaryGroup() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary account metadata") }
        let reader = try ServiceAccountDirectoryReader()
        for (kind, number) in [(ServiceDirectoryKind.user, getuid()), (.group, getgid())] {
            let records = try reader.lookup(kind: kind, index: .number(number))
            XCTAssertEqual(records.count, 1)
            let row = try XCTUnwrap(records.first), name = try XCTUnwrap(row.names.first)
            XCTAssertEqual(row.number, number)
            XCTAssertEqual(try reader.lookup(kind: kind, index: .name(name)), records)
            XCTAssertEqual(try reader.lookup(kind: kind, index: .id(row.id)), records)
        }
        XCTAssertTrue(try reader.lookup(kind: .user, index: .id(UUID())).isEmpty)
    }
    func testNativeMutationDriverRequiresBothRootIdentitiesBeforeOpeningTheNode() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary account guard") }
        for account in [Data(), Data(repeating: 1, count: 16)] {
            XCTAssertThrowsError(try NativeServiceAccountDirectory(accountID: account, ownerUID: getuid())) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
    func testNativeExistingCallerCannotBeAdoptedUsingItsUIDAndUUID() throws {
        guard getuid() > 0, getuid() == geteuid(), getuid() != 80 else { throw XCTSkip("Ordinary account metadata") }
        let reader = try ServiceAccountDirectoryReader(), rows = try reader.lookup(kind: .user, index: .number(getuid()))
        let row = try XCTUnwrap(rows.first)
        let claim = try ServiceAccountClaim(accountID: Data(repeating: 2, count: 16), role: .transport,
            number: getuid(), userID: row.id, groupID: UUID())
        XCTAssertThrowsError(try reader.state(claim: claim, kind: .user)) {
            XCTAssertEqual($0 as? ServiceAccountProvisioningError, .conflictingRecord)
        }
    }
}
