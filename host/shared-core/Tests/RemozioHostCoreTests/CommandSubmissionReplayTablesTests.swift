#if os(Linux)
import CSQLite
#else
import SQLite3
#endif
import Foundation
import RemozioHostCore
import RemozioProtocol
import XCTest

final class CommandSubmissionReplayTablesTests: XCTestCase {
    private enum Failure: Error { case injected }
    private func bytes(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func value(_ id: UInt8 = 7, nonce: UInt8? = nil, mac: UInt8 = 1,
                       account: UInt8 = 2, caller: UInt8 = 8) throws -> CommandSubmissionReservation {
        try CommandSubmissionReservation(macID: bytes(mac), accountID: bytes(account),
            submission: CapturedSubmission(id: bytes(id), nonce: bytes(nonce ?? id, 32), callerBinding: bytes(caller)),
            captureDigest: bytes(9, 32))
    }
    private func tables(_ db: DB, maximum: Int = 10, mac: UInt8 = 1, account: UInt8 = 2,
                        initialize: Bool = true) throws -> CommandSubmissionReplayTables {
        let result = try CommandSubmissionReplayTables(connection: db.handle, macID: bytes(mac),
            accountID: bytes(account), maximumRows: maximum)
        if initialize { try db.write { try result.createSchema() } }
        return result
    }
    private func expect(_ error: CommandSubmissionReplayError, _ body: () throws -> Void,
                        file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? CommandSubmissionReplayError, error, file: file, line: line)
        }
    }

    func testInvalidScopeAndCapacityAreRejectedBeforeUse() throws {
        let db = try DB()
        for (mac, account, maximum) in [(Data(), bytes(2), 10), (bytes(1), Data(), 10),
                                      (bytes(1, 17), bytes(2), 10), (bytes(1), bytes(2, 17), 10),
                                      (bytes(1), bytes(2), 0), (bytes(1), bytes(2), -1),
                                      (bytes(1), bytes(2), Int(Int32.max) + 1)] {
            expect(.invalidConfiguration) {
                _ = try CommandSubmissionReplayTables(connection: db.handle, macID: mac, accountID: account, maximumRows: maximum)
            }
        }
    }

    func testInvalidReservationAndLookupSizesFailClosed() throws {
        let db = try DB(), table = try tables(db), valid = try value()
        for field in 0..<6 {
            var fields = [valid.macID, valid.accountID, valid.submission.id, valid.submission.nonce,
                          valid.submission.callerBinding, valid.captureDigest]
            fields[field] = Data([1])
            expect(.invalidConfiguration) {
                _ = try CommandSubmissionReservation(macID: fields[0], accountID: fields[1],
                    submission: CapturedSubmission(id: fields[2], nonce: fields[3], callerBinding: fields[4]), captureDigest: fields[5])
            }
        }
        try db.read {
            for bad in [Data(), bytes(7, 17)] {
                expect(.invalidConfiguration) { _ = try table.read(submissionID: bad) }
            }
            for invalid in [CapturedSubmission(id: Data(), nonce: bytes(7, 32), callerBinding: bytes(8)),
                            CapturedSubmission(id: bytes(7), nonce: Data(), callerBinding: bytes(8)),
                            CapturedSubmission(id: bytes(7), nonce: bytes(7, 32), callerBinding: Data())] {
                expect(.invalidConfiguration) { _ = try table.contains(invalid) }
            }
        }
    }

    func testExplicitTransactionsAndActualMainWriteLockAreRequired() throws {
        let db = try DB(), table = try tables(db), reservation = try value()
        expect(.transactionRequired) { try table.createSchema() }
        expect(.transactionRequired) { try table.validateSchema() }
        expect(.transactionRequired) { _ = try table.reserve(reservation) }
        expect(.transactionRequired) { _ = try table.read(submissionID: bytes(7)) }
        expect(.transactionRequired) { _ = try table.contains(reservation.submission) }
        try db.read {
            expect(.writeTransactionRequired) { _ = try table.reserve(reservation) }
            try table.validateSchema() // Opens a read snapshot of main.
            expect(.writeTransactionRequired) { try table.createSchema() }
            expect(.writeTransactionRequired) { _ = try table.reserve(reservation) }
        }
        try db.exec("ATTACH ':memory:' AS other")
        try db.read {
            try db.exec("CREATE TABLE other.unrelated(value INTEGER)")
            XCTAssertEqual(sqlite3_txn_state(db.handle, "other"), SQLITE_TXN_WRITE)
            XCTAssertNotEqual(sqlite3_txn_state(db.handle, "main"), SQLITE_TXN_WRITE)
            expect(.writeTransactionRequired) { _ = try table.reserve(reservation) }
        }
    }

    func testBothIdentifiersRemainReservedAcrossReopenAndChangedCaller() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("replay.sqlite").path, winner = try value()
        do {
            let db = try DB(path), table = try tables(db)
            XCTAssertEqual(try db.write { try table.reserve(winner) }, winner)
        }
        let db = try DB(path), table = try tables(db, initialize: false)
        try db.read {
            try table.validateSchema()
            XCTAssertEqual(try table.read(submissionID: winner.submission.id), winner)
            XCTAssertNil(try table.read(submissionID: bytes(10)))
            for duplicate in [try value(7, nonce: 10), try value(10, nonce: 7), try value(caller: 11)] {
                XCTAssertTrue(try table.contains(duplicate.submission))
            }
            XCTAssertFalse(try table.contains(value(10).submission))
        }
        try db.write {
            for duplicate in [try value(7, nonce: 10), try value(10, nonce: 7), try value(caller: 11)] {
                expect(.alreadyReserved) { _ = try table.reserve(duplicate) }
            }
        }
        XCTAssertEqual(try db.read { try table.read(submissionID: bytes(7)) }, winner)
    }

    func testScopeIsolationAndCapacityDoNotEvictEvidence() throws {
        let db = try DB(), first = try tables(db, maximum: 1)
        let otherAccount = try tables(db, maximum: 1, account: 3, initialize: false)
        let otherHost = try tables(db, maximum: 1, mac: 3, initialize: false)
        try db.write {
            _ = try first.reserve(value())
            expect(.alreadyReserved) { _ = try first.reserve(value()) }
            expect(.capacityExceeded) { _ = try first.reserve(value(10)) }
            for wrong in [try value(mac: 3), try value(account: 3)] {
                expect(.wrongScope) { _ = try first.reserve(wrong) }
            }
            XCTAssertFalse(try otherAccount.contains(value().submission))
            XCTAssertFalse(try otherHost.contains(value().submission))
            _ = try otherAccount.reserve(value(account: 3))
            _ = try otherHost.reserve(value(mac: 3))
        }
        let raised = try tables(db, maximum: 2, initialize: false)
        _ = try db.write { try raised.reserve(value(10)) }
        try db.read {
            XCTAssertEqual(try first.read(submissionID: bytes(7)), try value())
            XCTAssertEqual(try otherAccount.read(submissionID: bytes(7)), try value(account: 3))
            XCTAssertEqual(try otherHost.read(submissionID: bytes(7)), try value(mac: 3))
            XCTAssertEqual(try raised.read(submissionID: bytes(10)), try value(10))
        }
    }

    func testSchemaCreationRollsBackAndNeverReplacesOrChangesOwnerVersion() throws {
        let db = try DB(), table = try tables(db, initialize: false)
        try db.exec("PRAGMA main.user_version=42")
        XCTAssertThrowsError(try db.write { try table.createSchema(); throw Failure.injected })
        try db.read { expect(.storage(SQLITE_ERROR)) { try table.validateSchema() } }
        try db.write { try table.createSchema(); _ = try table.reserve(value()) }
        try db.write { expect(.storage(SQLITE_ERROR)) { try table.createSchema() } }
        try db.read {
            XCTAssertEqual(try table.read(submissionID: bytes(7)), try value())
            XCTAssertEqual(try db.integer("PRAGMA main.user_version"), 42)
        }
    }

    func testOwnerRollbackCoversReservationsAndOtherAdmissionWrites() throws {
        let db = try DB(), table = try tables(db)
        try db.exec("CREATE TABLE admission(value INTEGER)")
        XCTAssertThrowsError(try db.write {
            _ = try table.reserve(value())
            try db.exec("INSERT INTO admission VALUES(1)")
            _ = try table.reserve(value(10))
            throw Failure.injected
        })
        try db.read {
            XCTAssertFalse(try table.contains(value().submission))
            XCTAssertNil(try table.read(submissionID: bytes(10)))
            XCTAssertEqual(try db.integer("SELECT count(*) FROM admission"), 0)
        }
        _ = try db.write { try table.reserve(value()) }
    }

    func testCaughtDuplicateDoesNotReplaceWinnerOrPoisonBorrowedConnection() throws {
        // The protected owner decides whether to roll back the entire batch; the table does not commit or poison it.
        let db = try DB(), table = try tables(db)
        try db.write {
            _ = try table.reserve(value())
            expect(.alreadyReserved) { _ = try table.reserve(value(10, nonce: 7)) }
            XCTAssertNil(try table.read(submissionID: bytes(10)))
        }
        XCTAssertEqual(try db.read { try table.read(submissionID: bytes(7)) }, try value())
    }

    func testCompetingConnectionsCannotReserveSameIDOrNonce() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("replay.sqlite").path
        let one = try DB(path), first = try tables(one)
        let two = try DB(path), second = try tables(two, initialize: false)
        try one.exec("BEGIN IMMEDIATE")
        _ = try first.reserve(value())
        XCTAssertThrowsError(try two.exec("BEGIN IMMEDIATE")) { XCTAssertEqual($0 as? DB.Error, .storage(SQLITE_BUSY)) }
        try one.exec("COMMIT")
        try two.write {
            expect(.alreadyReserved) { _ = try second.reserve(value(10, nonce: 7)) }
            expect(.alreadyReserved) { _ = try second.reserve(value(7, nonce: 10)) }
            XCTAssertEqual(try second.read(submissionID: bytes(7)), try value())
        }
    }

    func testMalformedStoredBindingsFailClosed() throws {
        for (column, contents) in [("nonce", "x'00'"), ("caller", "x'00'"), ("capture", "x'00'"),
                                   ("nonce", "NULL"), ("caller", "'not a blob'"), ("capture", "1")] {
            let db = try DB(), table = try tables(db)
            _ = try db.write { try table.reserve(value()) }
            try db.exec("ALTER TABLE command_submissions_v1 RENAME TO saved")
            try db.exec("CREATE TABLE command_submissions_v1 AS SELECT * FROM saved")
            try db.exec("UPDATE command_submissions_v1 SET \(column)=\(contents)")
            try db.read { expect(.corruptData) { _ = try table.read(submissionID: bytes(7)) } }
        }
    }

    func testSQLiteWriteFailureCannotBecomeAReservation() throws {
        let db = try DB(), table = try tables(db)
        try db.exec("CREATE TRIGGER reject_replay BEFORE INSERT ON command_submissions_v1 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
        try db.write {
            expect(.storage(SQLITE_CONSTRAINT)) { _ = try table.reserve(value()) }
            XCTAssertFalse(try table.contains(value().submission))
            XCTAssertNil(try table.read(submissionID: bytes(7)))
        }
        try db.exec("DROP TRIGGER reject_replay")
        _ = try db.write { try table.reserve(value()) }
    }

    func testExistingMacTableLayoutIsReadableWithoutMigration() throws {
        let db = try DB(), table = try tables(db, initialize: false)
        // Original schema-15 table, independent of createSchema; the shared API must neither migrate nor clear it.
        try db.exec("""
            CREATE TABLE main.command_submissions_v1 (
                mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
                submission BLOB NOT NULL CHECK(length(submission)=16), nonce BLOB NOT NULL CHECK(length(nonce)=32),
                caller BLOB NOT NULL CHECK(length(caller)=16), capture BLOB NOT NULL CHECK(length(capture)=32),
                PRIMARY KEY(mac,account,submission), UNIQUE(mac,account,nonce)
            ) STRICT, WITHOUT ROWID;
            PRAGMA main.user_version=15;
            """)
        try db.write { _ = try table.reserve(value()) }
        try db.read {
            try table.validateSchema()
            XCTAssertEqual(try table.read(submissionID: bytes(7)), try value())
            XCTAssertEqual(try db.integer("SELECT count(*) FROM command_submissions_v1"), 1)
            XCTAssertEqual(try db.integer("PRAGMA main.user_version"), 15)
        }
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }
    private final class DB {
        enum Error: Swift.Error, Equatable { case storage(Int32) }
        let handle: OpaquePointer
        init(_ path: String = ":memory:") throws {
            var connection: OpaquePointer?
            let rc = sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
            guard rc == SQLITE_OK, let connection else {
                if let connection { sqlite3_close(connection) }
                throw Error.storage(rc)
            }
            handle = connection
        }
        deinit { sqlite3_close(handle) }
        func exec(_ sql: String) throws {
            let rc = sqlite3_exec(handle, sql, nil, nil, nil)
            guard rc == SQLITE_OK else { throw Error.storage(rc) }
        }
        func integer(_ sql: String) throws -> Int64 {
            var row: OpaquePointer?
            let rc = sqlite3_prepare_v2(handle, sql, -1, &row, nil)
            guard rc == SQLITE_OK, let row else { throw Error.storage(rc) }
            defer { sqlite3_finalize(row) }
            let result = sqlite3_step(row)
            guard result == SQLITE_ROW else { throw Error.storage(result) }
            return sqlite3_column_int64(row, 0)
        }
        func write<T>(_ body: () throws -> T) throws -> T { try transaction("BEGIN IMMEDIATE", body) }
        func read<T>(_ body: () throws -> T) throws -> T { try transaction("BEGIN", body) }
        private func transaction<T>(_ begin: String, _ body: () throws -> T) throws -> T {
            try exec(begin)
            do { let result = try body(); try exec("COMMIT"); return result }
            catch { try? exec("ROLLBACK"); throw error }
        }
    }
}
