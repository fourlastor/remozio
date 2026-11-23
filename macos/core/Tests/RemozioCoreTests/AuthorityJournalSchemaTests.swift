import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityJournalSchemaTests: XCTestCase {
    func testLegacyTierMatchesPersistedFormatAcrossPromotionsAndRollback() throws {
        try withDatabase { db in
            XCTAssertEqual(try AuthorityJournalSchema.formatVersion(on: db), 0)
            for tier in Int64(12)...18 {
                try execute("BEGIN IMMEDIATE", on: db)
                try AuthorityJournalSchema.setFeatureTier(tier, on: db)
                XCTAssertEqual(try AuthorityJournalSchema.featureTier(on: db), tier)
                try execute("COMMIT", on: db)
                XCTAssertEqual(try AuthorityJournalSchema.formatVersion(on: db), tier)
            }
            try execute("BEGIN IMMEDIATE", on: db)
            try AuthorityJournalSchema.setFeatureTier(17, on: db)
            try execute("ROLLBACK", on: db)
            XCTAssertEqual(try AuthorityJournalSchema.formatVersion(on: db), 18)
        }
    }

    func testFeatureTierRequiresATransactionAndRejectsUninstalledFormats() throws {
        try withDatabase { db in
            XCTAssertThrowsError(try AuthorityJournalSchema.featureTier(on: db)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction)
            }
            XCTAssertThrowsError(try AuthorityJournalSchema.setFeatureTier(12, on: db)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
            }
            try execute("BEGIN IMMEDIATE", on: db)
            try AuthorityJournalSchema.setFeatureTier(13, on: db)
            XCTAssertThrowsError(try AuthorityJournalSchema.setFeatureTier(19, on: db)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .incompatibleStore)
            }
            XCTAssertEqual(try AuthorityJournalSchema.featureTier(on: db), 13)
            try execute("COMMIT", on: db)
        }
    }

    private func withDatabase(_ body: (OpaquePointer) throws -> Void) throws {
        var connection: OpaquePointer?
        let result = sqlite3_open(":memory:", &connection)
        defer { sqlite3_close(connection) }
        XCTAssertEqual(result, SQLITE_OK)
        try body(XCTUnwrap(connection))
    }

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
}
