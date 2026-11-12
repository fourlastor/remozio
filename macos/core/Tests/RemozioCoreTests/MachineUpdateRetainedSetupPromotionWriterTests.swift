import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Tests the private SQL primitive on owned SQLite only. These fixtures have no completed registration or native proof.
final class MachineUpdateRetainedSetupPromotionWriterTests: XCTestCase {
    private typealias Record = MachineUpdateRetainedSetupPromotionIntentRecord
    private enum Fault: Error { case injected }

    private func wrongRevision(_ record: Record) throws -> Record {
        let limits = try CBORLimits(maxBytes: Record.maximumBytes, maxDepth: 1, maxItems: 13)
        guard case .map(var fields) = try DeterministicCBOR.decode(record.encoded, limits: limits) else {
            throw Fault.injected
        }
        var uuid = UUID().uuid
        fields[3] = .bytes(withUnsafeBytes(of: &uuid) { Data($0) })
        return try .decode(DeterministicCBOR.encode(.map(fields), limits: limits))
    }

    func testOwnedSQLWritesExactCanonicalRecordsAndRestoresTheOrdinaryLimit() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionSchema26SQLFixture { _, machine, prepared, publishing, published in
            let account = try prepared.publication().configuration.archive.binding.startupBinding.accountID
            try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                let ordinary = try sql.limit()
                XCTAssertEqual(ordinary, 278_528)
                XCTAssertLessThanOrEqual(try prepared.encoded.count, Int(ordinary))
                print("G6b canonical fixture: recordBytes=\(try prepared.encoded.count), ordinaryLimit=\(ordinary)")
                let changes: [(Record, Record?)] = [(prepared, nil), (publishing, prepared), (published, publishing)]
                for (record, previous) in changes {
                    XCTAssertEqual(try Record.decode(record.encoded).encoded, try record.encoded)
                    try sql.write(record, replacing: previous)
                    XCTAssertEqual(try sql.read(accountID: account), record)
                    XCTAssertEqual(try sql.limit(), ordinary)
                }
            }
            // The fixture entry rolled back. A second insertion must find no retained row.
            try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                try sql.write(prepared)
                XCTAssertEqual(try sql.read(accountID: account), prepared)
            }
        }
    }

    func testOwnedSQLRejectsStaleRevisionsAndNonadjacentPhasesWithoutChangingTheRow() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionSchema26SQLFixture { _, machine, prepared, publishing, published in
            let account = try prepared.publication().configuration.archive.binding.startupBinding.accountID
            try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                try sql.write(prepared)
                let ordinary = try sql.limit()
                XCTAssertThrowsError(try sql.write(published, replacing: prepared)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
                let stale = try wrongRevision(prepared)
                try publishing.requireTransition(from: stale)
                XCTAssertThrowsError(try sql.write(publishing, replacing: stale)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(try sql.read(accountID: account), prepared)
                XCTAssertEqual(try sql.limit(), ordinary)
            }
        }
    }

    func testOwnedSQLRejectsDuplicateIDsAndRestoresTheLimitAfterFailure() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionSchema26SQLFixture { _, machine, prepared, _, _ in
            let account = try prepared.publication().configuration.archive.binding.startupBinding.accountID
            try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                try sql.write(prepared)
                let ordinary = try sql.limit()
                XCTAssertThrowsError(try sql.write(prepared)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(try sql.read(accountID: account), prepared)
                XCTAssertEqual(try sql.limit(), ordinary)
            }
        }
    }

    func testSyntheticUpperBoundsRejectAtTheCHECKAndConnectionLimit() throws {
        // Caps: 16384 + 2*262144 + 65536 + 9*65536 + 4*4096 = 1212416 bytes.
        // The four envelope allowances exceed their fixed CBOR fields and headers.
        // This excludes a near-3149824-byte canonical control. It does not exclude a canonical control above 278528 bytes.
        // These synthetic bytes test rejection only. They are not valid promotion records.
        try MachineUpdateReplacementTests.withRetainedPromotionSchema26SQLFixture { _, machine, prepared, _, _ in
            let account = try prepared.publication().configuration.archive.binding.startupBinding.accountID
            try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                try sql.write(prepared)
                let ordinary = try sql.limit()
                for (count, expected) in [(Record.maximumBytes + 1, SQLITE_CONSTRAINT), (Record.maximumBytes + 4097, SQLITE_TOOBIG)] {
                    let bytes = Data(repeating: 0xA5, count: count)
                    XCTAssertThrowsError(try sql.replaceSyntheticBytesForBoundsTest(bytes, accountID: account)) { error in
                        guard let failure = error as? PreparationStoreError, case .storage(let code) = failure else {
                            return XCTFail("Expected a SQLite bound refusal")
                        }
                        XCTAssertEqual(code & 0xff, expected)
                    }
                    XCTAssertEqual(try sql.limit(), ordinary)
                    XCTAssertEqual(try sql.read(accountID: account), prepared)
                }
            }
        }
    }

    func testOwnedSQLRollsBackAnInjectedFailureAndExpiresBothTokens() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionSchema26SQLFixture { _, machine, prepared, _, _ in
            var expired: PreparationIntentStore.OwnedRetainedSetupPromotionSQLFixture?
            XCTAssertThrowsError(try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                expired = sql
                try sql.write(prepared)
                throw Fault.injected
            }) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try XCTUnwrap(expired).limit()) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            let result = try machine.withOwnedRetainedSetupPromotionSQLFixture { sql in
                expired = sql
                try sql.write(prepared)
                return 42
            }
            XCTAssertEqual(result, 42)
            XCTAssertThrowsError(try XCTUnwrap(expired).write(prepared)) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }

    func testTheActualSchema26MachineCatalogFitsTheDeclaredBounds() throws {
        try MachineUpdateReplacementTests.withRetainedPromotionSchema26SQLFixture { path, _, _, _, _ in
            // This is the actual machine database with an empty completion table. It is not a completed native store.
            var connection: OpaquePointer?
            XCTAssertEqual(sqlite3_open_v2(path, &connection, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
            let db = try XCTUnwrap(connection)
            defer { XCTAssertEqual(sqlite3_close(db), SQLITE_OK) }
            XCTAssertEqual(sqlite3_exec(db, "BEGIN", nil, nil, nil), SQLITE_OK)
            var row: OpaquePointer?
            XCTAssertEqual(sqlite3_prepare_v2(db, "SELECT type,name,tbl_name,sql FROM sqlite_schema", -1, &row, nil), SQLITE_OK)
            let statement = try XCTUnwrap(row)
            defer { XCTAssertEqual(sqlite3_finalize(statement), SQLITE_OK) }
            var rows = 0, maximumBytes = 0
            while true {
                let result = sqlite3_step(statement)
                if result == SQLITE_DONE { break }
                guard result == SQLITE_ROW else { throw PreparationStoreError.storage(result) }
                rows += 1
                for column in Int32(0)..<4 where sqlite3_column_type(statement, column) != SQLITE_NULL {
                    XCTAssertNotNil(sqlite3_column_blob(statement, column))
                    maximumBytes = max(maximumBytes, Int(sqlite3_column_bytes(statement, column)))
                }
            }
            let frame = try MachineUpdateRetainedSetupPromotionCatalog.capture(db)
            XCTAssertEqual(frame.schemaVersion, 26)
            XCTAssertNil(frame.promotionDigest)
            XCTAssertGreaterThan(rows, 26)
            XCTAssertLessThanOrEqual(rows, 128)
            XCTAssertGreaterThan(maximumBytes, 0)
            XCTAssertLessThanOrEqual(maximumBytes, 8192)
            print("G6b actual schema26 catalog: rows=\(rows), maximumTextBytes=\(maximumBytes), bounds=128/8192")
            XCTAssertEqual(sqlite3_exec(db, "ROLLBACK", nil, nil, nil), SQLITE_OK)
        }
    }
}
