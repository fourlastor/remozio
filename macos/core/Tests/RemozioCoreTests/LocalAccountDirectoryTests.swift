import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class LocalAccountDirectoryTests: XCTestCase {
    private let id = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    private func fields(_ uids: [String] = ["501"], _ groups: [String] = ["20"], _ ids: [String]? = nil) -> LocalAccountFields {
        .init(uids: uids, groups: groups, ids: ids ?? [id.uuidString])
    }
    func testCompleteRecordRetainsItsDirectoryIdentity() throws {
        let result = try LocalAccountDirectory.decode(uid: 501, records: [fields()])
        XCTAssertEqual(result, LocalAccountIdentity(uid: 501, primaryGroupID: 20, directoryID: id))
    }
    func testInvalidOwnerScopeIsRejectedBeforeRecordInterpretation() {
        for uid in [UInt32(0), UInt32.max] {
            XCTAssertThrowsError(try LocalAccountDirectory.decode(uid: uid, records: [])) {
                XCTAssertEqual($0 as? LocalAccountLookupError, .invalidScope)
            }
        }
    }
    func testMissingAndAmbiguousAccountsCannotProduceAnIdentity() {
        XCTAssertThrowsError(try LocalAccountDirectory.decode(uid: 501, records: [])) {
            XCTAssertEqual($0 as? LocalAccountLookupError, .missing)
        }
        XCTAssertThrowsError(try LocalAccountDirectory.decode(uid: 501, records: [fields(), fields()])) {
            XCTAssertEqual($0 as? LocalAccountLookupError, .ambiguous)
        }
    }
    func testForeignUIDAndMalformedAttributesAreRejected() {
        let records = [fields(["502"]), fields(["501", "501"]), fields([]), fields(["+501"]),
            fields(["501"], []), fields(["501"], ["-1"]), fields(["501"], [String(UInt32.max)]),
            fields(["501"], ["20"], []), fields(["501"], ["20"], ["invalid"]),
            fields(["501"], ["20"], [id.uuidString, id.uuidString])]
        for record in records {
            XCTAssertThrowsError(try LocalAccountDirectory.decode(uid: 501, records: [record])) {
                XCTAssertEqual($0 as? LocalAccountLookupError, .malformed)
            }
        }
    }
    func testOwnershipRejectsAChangedRecordWithTheSameUID() throws {
        let current = try LocalAccountDirectory.decode(uid: 501, records: [fields()])
        XCTAssertNoThrow(try LocalAccountDirectory.validateOwnership(current, uid: 501, directoryID: id))
        XCTAssertThrowsError(try LocalAccountDirectory.validateOwnership(current, uid: 501, directoryID: UUID())) {
            XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged)
        }
        XCTAssertThrowsError(try LocalAccountDirectory.validateOwnership(current, uid: 502, directoryID: id)) {
            XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged)
        }
    }
    func testOwnerGroupChangesDoNotSilentlyChangeTheAccountBinding() throws {
        let current = try LocalAccountDirectory.decode(uid: 501, records: [fields(["501"], ["0"])])
        XCTAssertEqual(current.primaryGroupID, 0)
        XCTAssertNoThrow(try LocalAccountDirectory.validateOwnership(current, uid: 501, directoryID: id))
    }
    func testDescriptionDoesNotExposeDirectoryIdentity() throws {
        let current = try LocalAccountDirectory.decode(uid: 501, records: [fields()])
        XCTAssertEqual(current.description, "LocalAccountIdentity(redacted)")
    }
    func testNativeCurrentAccountLookupIsReadOnlyAndMatchesThePOSIXRecord() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary account") }
        let current = try LocalAccountDirectory.lookup(uid: getuid())
        var entry = passwd(), result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 65536)
        let status = buffer.withUnsafeMutableBufferPointer {
            getpwuid_r(getuid(), &entry, $0.baseAddress!, $0.count, &result)
        }
        XCTAssertEqual(status, 0)
        XCTAssertNotNil(result)
        XCTAssertEqual(current.uid, getuid())
        XCTAssertEqual(current.primaryGroupID, entry.pw_gid)
    }
}
