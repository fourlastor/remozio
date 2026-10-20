import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsFenceReaderTests: XCTestCase {
    private struct Denied: Error {}
    private func fence() throws -> GatewayRuntimeSettingsFence {
        let r = try GatewayRuntimeSettingsStoreTests.Ready()
        return try .init(.init(revision: r.revision(), previous: nil, activation: r.activation,
            journal: r.fixture.state(), foreground: r.fixture.runtime.plan, inventory: XCTUnwrap(r.fixture.runtime.machine.inventory())))
    }
    func testVerifiedAbsenceAndExactPendingScopeHaveDistinctResults() throws {
        let value = try fence(), bytes = try value.encoded
        XCTAssertNil(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID, read: { nil }, verifyCurrent: {}))
        let read = try XCTUnwrap(GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID, read: { bytes }, verifyCurrent: {}))
        XCTAssertEqual(try read.encoded, bytes)
    }
    func testEveryReadErrorPropagatesInsteadOfGrantingAbsence() throws {
        let value = try fence()
        for code in [ENOENT, EACCES, EIO, ELOOP] {
            XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID,
                read: { throw JournalLeaseError.system(code) }, verifyCurrent: {})) {
                XCTAssertEqual($0 as? JournalLeaseError, .system(code))
            }
        }
    }
    func testMalformedOrCrossedScopeCannotBecomeAnOptionalAbsence() throws {
        let value = try fence(), bytes = try value.encoded
        XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID, read: { Data([0xff]) }, verifyCurrent: {}))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: Data(repeating: 0, count: 16), accountID: value.accountID, read: { bytes }, verifyCurrent: {}))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: Data(repeating: 0, count: 16), read: { bytes }, verifyCurrent: {}))
    }
    func testCreationOrRemovalDuringObservationCannotReturnAStableSnapshot() throws {
        let value = try fence(), bytes = try value.encoded
        for firstMissing in [true, false] {
            var count = 0
            XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID, read: {
                count += 1; return (count == 1) == firstMissing ? nil : bytes
            }, verifyCurrent: {}))
            XCTAssertEqual(count, 2)
        }
    }
    func testFailedScopeChecksAndMalformedIDsCannotReadTheNamespace() throws {
        let value = try fence()
        XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: Data(), accountID: value.accountID,
            read: { XCTFail(); return nil }, verifyCurrent: { XCTFail() }))
        XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID,
            read: { XCTFail(); return nil }, verifyCurrent: { throw Denied() }))
        var checks = 0
        XCTAssertThrowsError(try GatewayRuntimeSettingsFenceReader.load(macID: value.macID, accountID: value.accountID, read: { nil }, verifyCurrent: {
            checks += 1; if checks == 2 { throw Denied() }
        }))
    }
}
