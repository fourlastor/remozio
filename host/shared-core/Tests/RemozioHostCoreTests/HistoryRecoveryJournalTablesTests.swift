import Foundation
import XCTest
import RemozioProtocol
import RemozioHostCore
#if os(Linux)
import CSQLite
#else
import SQLite3
#endif

final class HistoryRecoveryJournalTablesTests: XCTestCase {
    private enum Failure: Error { case injected }
    private func id(_ byte: UInt8) -> Data { Data(repeating: byte, count: 16) }

    private func intent(epoch: UInt8 = 9, ledger: UInt8 = 3) throws -> HistoryRecoveryIntent {
        let authority = Data(repeating: 1, count: 32)
        let committed = try ContinuityCheckpoint(generation: 10, authorityDigest: authority,
            ledgerDigest: Data(repeating: 2, count: 32), journalEpoch: id(4), journalHead: 12, authorityGeneration: 5)
        let pending = try committed.successor(authorityDigest: authority,
            ledgerDigest: Data(repeating: 5, count: 32), journalEpoch: id(4), journalHead: 13)
        return try HistoryRecoveryIntent(previous: ContinuityState(committed: committed, pending: pending, recoveryRequired: false),
            authorityDigest: authority, ledgerDigest: Data(repeating: ledger, count: 32), recoveryEpoch: id(epoch))
    }

    func testSchemaAndEvidenceShareOuterRollbackWithoutChangingOwnerVersion() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle), record = try intent()
        try db.exec("PRAGMA main.user_version=123")
        XCTAssertThrowsError(try db.write {
            try tables.createSchema()
            try tables.insert(record)
            throw Failure.injected
        })
        XCTAssertEqual(try db.integer("SELECT count(*) FROM main.sqlite_schema WHERE name='history_recoveries_v1'"), 0)
        XCTAssertEqual(try db.integer("PRAGMA main.user_version"), 123)

        try db.write { try tables.createSchema() }
        try db.exec("CREATE TABLE main.owner_marker(value INTEGER)")
        XCTAssertThrowsError(try db.write {
            try tables.insert(record)
            try db.exec("INSERT INTO main.owner_marker VALUES(1)")
            XCTAssertEqual(try tables.read(epoch: record.recoveryEpoch), record)
            throw Failure.injected
        })
        XCTAssertNil(try db.read { try tables.read(epoch: record.recoveryEpoch) })
        XCTAssertEqual(try db.integer("SELECT count(*) FROM main.owner_marker"), 0)
        XCTAssertEqual(try db.integer("PRAGMA main.user_version"), 123)
    }

    func testCanonicalEvidenceWithBothBoundariesSurvivesCloseAndReopen() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("journal.sqlite").path, record = try intent()
        do {
            let db = try DB(path), tables = HistoryRecoveryJournalTables(connection: db.handle)
            try db.exec("PRAGMA main.user_version=16")
            try db.write {
                try tables.createSchema()
                try tables.insert(record)
            }
            XCTAssertEqual(try db.blob("SELECT evidence FROM main.history_recoveries_v1"), try record.bytes)
        }
        let db = try DB(path), tables = HistoryRecoveryJournalTables(connection: db.handle)
        XCTAssertEqual(try db.read { try tables.read(epoch: record.recoveryEpoch) }, record)
        XCTAssertNotNil(try db.read { try tables.read(epoch: record.recoveryEpoch)?.previous.pending })
        XCTAssertNil(try db.read { try tables.read(epoch: id(10)) })
        XCTAssertEqual(try db.blob("SELECT evidence FROM main.history_recoveries_v1"), try record.bytes)
        XCTAssertEqual(try db.integer("PRAGMA main.user_version"), 16)
    }

    func testDuplicateEpochCannotReplaceEvidenceOrRecreateSchema() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle), record = try intent()
        try db.write {
            try tables.createSchema()
            try tables.insert(record)
        }
        for duplicate in [record, try intent(ledger: 7)] {
            XCTAssertThrowsError(try db.write { try tables.insert(duplicate) }) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .storage(SQLITE_CONSTRAINT))
            }
            XCTAssertEqual(try db.read { try tables.read(epoch: record.recoveryEpoch) }, record)
        }
        XCTAssertThrowsError(try db.write { try tables.createSchema() }) {
            XCTAssertEqual($0 as? HistoryRecoveryJournalError, .storage(SQLITE_ERROR))
        }
        XCTAssertEqual(try db.read { try tables.read(epoch: record.recoveryEpoch) }, record)
    }

    func testOperationsRequireExplicitTransactionsAndMainWrites() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle), record = try intent()
        XCTAssertThrowsError(try tables.createSchema()) {
            XCTAssertEqual($0 as? HistoryRecoveryJournalError, .transactionRequired)
        }
        XCTAssertThrowsError(try tables.insert(record)) {
            XCTAssertEqual($0 as? HistoryRecoveryJournalError, .transactionRequired)
        }
        XCTAssertThrowsError(try tables.read(epoch: record.recoveryEpoch)) {
            XCTAssertEqual($0 as? HistoryRecoveryJournalError, .transactionRequired)
        }
        try db.write { try tables.createSchema() }
        try db.read {
            XCTAssertThrowsError(try tables.createSchema()) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .writeTransactionRequired)
            }
            XCTAssertThrowsError(try tables.insert(record)) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .writeTransactionRequired)
            }
            XCTAssertNil(try tables.read(epoch: record.recoveryEpoch))
            XCTAssertThrowsError(try tables.insert(record)) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .writeTransactionRequired)
            }
        }
        try db.write { try tables.insert(record) }
        XCTAssertThrowsError(try tables.read(epoch: record.recoveryEpoch)) {
            XCTAssertEqual($0 as? HistoryRecoveryJournalError, .transactionRequired)
        }
    }

    func testAttachedDatabaseWriteDoesNotGrantMainWriteAccess() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle), record = try intent()
        try db.write { try tables.createSchema() }
        try db.exec("ATTACH DATABASE ':memory:' AS other")
        try db.read {
            try db.exec("CREATE TABLE other.marker(value INTEGER)")
            XCTAssertEqual(sqlite3_txn_state(db.handle, "other"), SQLITE_TXN_WRITE)
            XCTAssertNotEqual(sqlite3_txn_state(db.handle, "main"), SQLITE_TXN_WRITE)
            XCTAssertThrowsError(try tables.createSchema()) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .writeTransactionRequired)
            }
            XCTAssertThrowsError(try tables.insert(record)) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .writeTransactionRequired)
            }
        }
        XCTAssertNil(try db.read { try tables.read(epoch: record.recoveryEpoch) })
    }

    func testInvalidEpochPrecedesTransactionAndStorageErrors() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle)
        for length in [0, 15, 17, 1025] {
            let invalid = Data(repeating: 0, count: length)
            XCTAssertThrowsError(try tables.read(epoch: invalid)) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .invalidEpoch)
            }
            try db.read {
                XCTAssertThrowsError(try tables.read(epoch: invalid)) {
                    XCTAssertEqual($0 as? HistoryRecoveryJournalError, .invalidEpoch)
                }
            }
        }
        try db.read {
            XCTAssertThrowsError(try tables.read(epoch: id(9))) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .storage(SQLITE_ERROR))
            }
        }
    }

    func testReadsRejectWrongStoredTypeEmptyAndOversizedEvidence() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle)
        // A malformed legacy/replaced table must still fail closed at the read boundary.
        try db.exec("CREATE TABLE main.history_recoveries_v1(epoch BLOB PRIMARY KEY,evidence)")
        for value in ["NULL", "1", "'text'", "x''", "zeroblob(1025)"] {
            try db.exec("DELETE FROM main.history_recoveries_v1")
            try db.exec("INSERT INTO main.history_recoveries_v1 VALUES(\(hex(id(9))),\(value))")
            try db.read {
                XCTAssertThrowsError(try tables.read(epoch: id(9))) {
                    XCTAssertEqual($0 as? HistoryRecoveryJournalError, .corruptData)
                }
            }
        }
    }

    func testReadsRejectWrongEpochAndPreserveDecoderErrors() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle), record = try intent()
        try db.write { try tables.createSchema() }
        try db.exec("INSERT INTO main.history_recoveries_v1 VALUES(\(hex(id(10))),\(hex(try record.bytes)))")
        try db.read {
            XCTAssertThrowsError(try tables.read(epoch: id(10))) {
                XCTAssertEqual($0 as? HistoryRecoveryJournalError, .corruptData)
            }
        }
        let bytes = try record.bytes
        let malformed: [(Data, CBORError?)] = [(Data([0]), nil), (Data(bytes.dropLast()), .truncated),
            (bytes + Data([0]), .trailingBytes), (Data([0x18, 0x00]), .nonCanonical)]
        for (evidence, expectedCBOR) in malformed {
            try db.exec("DELETE FROM main.history_recoveries_v1")
            try db.exec("INSERT INTO main.history_recoveries_v1 VALUES(\(hex(id(9))),\(hex(evidence)))")
            try db.read {
                XCTAssertThrowsError(try tables.read(epoch: id(9))) {
                    if let expectedCBOR { XCTAssertEqual($0 as? CBORError, expectedCBOR) }
                    else { XCTAssertEqual($0 as? ContinuityStoreError, .invalidCheckpoint) }
                }
            }
        }
    }

    func testMainSchemaCannotBeShadowedByTemporaryTable() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle), record = try intent()
        try db.write {
            try tables.createSchema()
            try tables.insert(record)
        }
        try db.exec("CREATE TEMP TABLE history_recoveries_v1(epoch BLOB PRIMARY KEY,evidence BLOB)")
        try db.exec("INSERT INTO temp.history_recoveries_v1 VALUES(\(hex(record.recoveryEpoch)),x'00')")
        XCTAssertEqual(try db.read { try tables.read(epoch: record.recoveryEpoch) }, record)
        let second = try intent(epoch: 10)
        try db.write { try tables.insert(second) }
        XCTAssertEqual(try db.integer("SELECT count(*) FROM temp.history_recoveries_v1"), 1)
        XCTAssertEqual(try db.read { try tables.read(epoch: second.recoveryEpoch) }, second)
    }

    func testSchemaEnforcesBlobTypesAndEvidenceBounds() throws {
        let db = try DB(), tables = HistoryRecoveryJournalTables(connection: db.handle)
        try db.write { try tables.createSchema() }
        for values in ["zeroblob(15),x'00'", "zeroblob(17),x'00'", "zeroblob(16),x''",
                       "zeroblob(16),zeroblob(1025)", "zeroblob(16),NULL", "zeroblob(16),'text'",
                       "'1234567890123456',x'00'"] {
            XCTAssertThrowsError(try db.exec("INSERT INTO main.history_recoveries_v1 VALUES(\(values))"))
        }
        XCTAssertEqual(try db.integer("SELECT count(*) FROM main.history_recoveries_v1"), 0)
        try db.exec("INSERT INTO main.history_recoveries_v1 VALUES(zeroblob(16),zeroblob(1024))")
        try db.read {
            // The schema accepts its maximum length; the record decoder still rejects its invalid contents.
            XCTAssertThrowsError(try tables.read(epoch: Data(repeating: 0, count: 16))) {
                XCTAssertEqual($0 as? CBORError, .trailingBytes)
            }
        }
    }

    private func hex(_ data: Data) -> String { "x'" + data.map { String(format: "%02x", $0) }.joined() + "'" }

    private final class DB {
        enum Failure: Error, Equatable { case storage(Int32) }
        let handle: OpaquePointer
        init(_ path: String = ":memory:") throws {
            var connection: OpaquePointer?
            let result = sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
            guard result == SQLITE_OK, let connection else {
                if let connection { sqlite3_close(connection) }
                throw Failure.storage(result)
            }
            handle = connection
            try exec("PRAGMA trusted_schema=OFF")
        }
        deinit { sqlite3_close(handle) }
        func exec(_ sql: String) throws {
            let result = sqlite3_exec(handle, sql, nil, nil, nil)
            guard result == SQLITE_OK else { throw Failure.storage(result) }
        }
        func integer(_ sql: String) throws -> Int64 {
            try statement(sql) { sqlite3_column_int64($0, 0) }
        }
        func blob(_ sql: String) throws -> Data {
            try statement(sql) {
                guard let pointer = sqlite3_column_blob($0, 0) else { throw Failure.storage(SQLITE_MISMATCH) }
                return Data(bytes: pointer, count: Int(sqlite3_column_bytes($0, 0)))
            }
        }
        private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
            var value: OpaquePointer?
            let result = sqlite3_prepare_v2(handle, sql, -1, &value, nil)
            guard result == SQLITE_OK, let value else { throw Failure.storage(result) }
            defer { sqlite3_finalize(value) }
            let step = sqlite3_step(value)
            guard step == SQLITE_ROW else { throw Failure.storage(step) }
            return try body(value)
        }
        func write<T>(_ body: () throws -> T) throws -> T { try transaction("BEGIN IMMEDIATE", body) }
        func read<T>(_ body: () throws -> T) throws -> T { try transaction("BEGIN", body) }
        private func transaction<T>(_ begin: String, _ body: () throws -> T) throws -> T {
            try exec(begin)
            do {
                let result = try body()
                try exec("COMMIT")
                return result
            } catch {
                try? exec("ROLLBACK")
                throw error
            }
        }
    }
}
