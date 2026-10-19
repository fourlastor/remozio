import Foundation
import RemozioHostCore
import RemozioProtocol
#if os(Linux)
import CSQLite
#else
import SQLite3
#endif
import XCTest

final class AuditJournalTablesTests: XCTestCase {
    private var bound: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func descriptor(_ epoch: UInt8 = 3, account: UInt8 = 2) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(account)), 3: .bytes(id(epoch)),
            4: .unsigned(UInt64.max), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: bound), limits: bound)
    }
    private func record(_ sequence: UInt64, epoch: UInt8 = 3, account: UInt8 = 2, event: UInt8? = nil) throws -> Data {
        try AuditEventMetadata(eventID: id(event ?? UInt8(truncatingIfNeeded: sequence)), macID: id(1), accountID: id(account),
            journalEpoch: id(epoch), sequence: sequence, requestID: id(8), eventTimeMs: nil, authorityReceiptTimeMs: nil,
            kind: .consumed, category: .command, action: nil, decisionPhoneID: nil, authentication: .system,
            outcome: .accepted, reason: .none, droppedEventCount: nil, peerDeviceID: nil).encode(limits: bound)
    }
    private func tables(_ db: DB, account: UInt8 = 2) throws -> AuditJournalTables {
        try AuditJournalTables(connection: db.handle, macID: id(1), accountID: id(account), recordLimits: bound, descriptorLimits: bound)
    }
    private func initial(_ db: DB) throws -> (AuditJournalTables, AuditEpochWriter) {
        let table = try tables(db)
        try db.exec("BEGIN IMMEDIATE")
        try table.createSchema()
        let writer = try table.createEpoch(descriptor())
        try db.exec("COMMIT")
        return (table, writer)
    }
    private func page(_ table: AuditJournalTables, epoch: UInt8 = 3, after: UInt64 = 0,
                      count: Int = 10, bytes: Int = 16384) throws -> AuditJournalPage {
        try table.page(epoch: id(epoch), after: after, maximumRecords: count, maximumBytes: bytes)
    }

    func testConsumptionAndAuditCommitOrRollbackTogetherAndSurviveReopen() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("journal.sqlite").path
        do {
            let db = try DB(path), (table, writer) = try initial(db)
            try db.exec("CREATE TABLE consumptions (request INTEGER PRIMARY KEY)")
            try db.exec("BEGIN IMMEDIATE; INSERT INTO consumptions VALUES(1)")
            try table.append(record(1), writer: writer, expectedHead: 0)
            try db.exec("ROLLBACK; BEGIN")
            XCTAssertEqual(try db.scalar("SELECT count(*) FROM consumptions"), 0)
            XCTAssertEqual(try page(table).epoch.head, 0)
            try db.exec("COMMIT; BEGIN IMMEDIATE; INSERT INTO consumptions VALUES(1)")
            try table.append(record(1), writer: writer, expectedHead: 0)
            try db.exec("COMMIT")
        }
        let db = try DB(path), table = try tables(db)
        try db.exec("BEGIN")
        XCTAssertEqual(try db.scalar("SELECT count(*) FROM consumptions"), 1)
        XCTAssertEqual(try page(table).canonicalRecords, try [record(1)])
        try db.exec("COMMIT")
    }

    func testExplicitTransactionsAndFreshWriterOwnership() throws {
        let db = try DB(), (table, writer) = try initial(db)
        XCTAssertThrowsError(try page(table))
        XCTAssertThrowsError(try table.append(record(1), writer: writer, expectedHead: 0))
        try db.exec("BEGIN")
        XCTAssertThrowsError(try table.append(record(1), writer: writer, expectedHead: 0))
        try db.exec("ROLLBACK; BEGIN IMMEDIATE")
        let reopened = try tables(db)
        XCTAssertThrowsError(try reopened.append(record(1), writer: writer, expectedHead: 0))
        let newer = try table.createEpoch(descriptor(4))
        XCTAssertThrowsError(try table.append(record(1), writer: writer, expectedHead: 0))
        try table.append(record(1, epoch: 4), writer: newer, expectedHead: 0)
        XCTAssertEqual(try page(table).epoch.head, 0)
        XCTAssertEqual(try page(table, epoch: 4).epoch.head, 1)
        try db.exec("COMMIT")
    }

    func testFailedInsertRestoresHeadAndDoesNotCommitTheCallerTransaction() throws {
        let db = try DB(), (table, writer) = try initial(db)
        try db.exec("BEGIN IMMEDIATE")
        try table.append(record(1), writer: writer, expectedHead: 0)
        XCTAssertThrowsError(try table.append(record(2, event: 1), writer: writer, expectedHead: 1))
        XCTAssertEqual(try page(table).epoch.head, 1)
        XCTAssertEqual(sqlite3_get_autocommit(db.handle), 0)
        XCTAssertThrowsError(try table.append(record(3), writer: writer, expectedHead: 1))
        XCTAssertThrowsError(try table.append(record(1), writer: writer, expectedHead: 0))
        try table.append(record(2), writer: writer, expectedHead: 1)
        try db.exec("ROLLBACK; BEGIN")
        XCTAssertEqual(try page(table).epoch.head, 0)
        try db.exec("COMMIT")
    }

    func testSQLiteAbortAndAutomaticRollbackNeverLeaveAnAdvancedHead() throws {
        for action in ["ABORT", "ROLLBACK"] {
            let db = try DB(), (table, writer) = try initial(db)
            try db.exec("CREATE TABLE consumptions (request INTEGER PRIMARY KEY)")
            try db.exec("CREATE TRIGGER inject_failure BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(\(action),'test'); END")
            try db.exec("BEGIN IMMEDIATE; INSERT INTO consumptions VALUES(1)")
            XCTAssertThrowsError(try table.append(record(1), writer: writer, expectedHead: 0))
            if action == "ABORT" {
                XCTAssertEqual(sqlite3_get_autocommit(db.handle), 0)
                XCTAssertEqual(try page(table).epoch.head, 0)
                // The authority cancels the complete consumption transaction after any append failure.
                try db.exec("ROLLBACK")
            } else { XCTAssertNotEqual(sqlite3_get_autocommit(db.handle), 0) }
            try db.exec("BEGIN")
            XCTAssertEqual(try db.scalar("SELECT count(*) FROM consumptions"), 0)
            XCTAssertEqual(try page(table).epoch.head, 0)
            try db.exec("COMMIT")
        }
    }

    func testAccountIsolationAndWrongRecordScope() throws {
        let db = try DB(), (first, writer) = try initial(db), second = try tables(db, account: 9)
        try db.exec("BEGIN IMMEDIATE")
        XCTAssertNil(try second.epoch(id(3)))
        let secondWriter = try second.createEpoch(descriptor(account: 9))
        XCTAssertThrowsError(try first.append(record(1, account: 9), writer: writer, expectedHead: 0))
        try first.append(record(1), writer: writer, expectedHead: 0)
        try second.append(record(1, account: 9), writer: secondWriter, expectedHead: 0)
        XCTAssertEqual(try page(first).canonicalRecords, try [record(1)])
        XCTAssertEqual(try page(second).canonicalRecords, try [record(1, account: 9)])
        try db.exec("COMMIT")
    }

    func testBoundedPagesAndExplicitRetention() throws {
        let db = try DB(), (table, writer) = try initial(db)
        try db.exec("BEGIN IMMEDIATE")
        for n in 1...4 { try table.append(record(UInt64(n)), writer: writer, expectedHead: UInt64(n - 1)) }
        XCTAssertEqual(try page(table, count: 2).canonicalRecords, try [record(1), record(2)])
        XCTAssertEqual(try page(table, bytes: record(1).count).canonicalRecords, try [record(1)])
        XCTAssertThrowsError(try page(table, bytes: 1))
        XCTAssertThrowsError(try page(table, after: 5))
        XCTAssertThrowsError(try table.prune(epoch: id(3), through: 3, expectedHead: 3))
        try table.prune(epoch: id(3), through: 2, expectedHead: 4)
        let retained = try page(table)
        XCTAssertEqual(retained.epoch.retainedAfter, 2)
        XCTAssertEqual(retained.canonicalRecords, try [record(3), record(4)])
        try table.prune(epoch: id(3), through: 4, expectedHead: 4)
        XCTAssertTrue(try page(table).canonicalRecords.isEmpty)
        XCTAssertEqual(try page(table).epoch.retainedAfter, 4)
        XCTAssertThrowsError(try table.prune(epoch: id(3), through: 3, expectedHead: 4))
        try db.exec("COMMIT")
    }

    func testUnsignedOrderingAndExhaustion() throws {
        let db = try DB(), (table, writer) = try initial(db)
        try db.exec("BEGIN IMMEDIATE; UPDATE audit_epochs_v1 SET head=x'FFFFFFFFFFFFFFFD',retained=x'FFFFFFFFFFFFFFFD'")
        try table.append(record(.max - 1), writer: writer, expectedHead: .max - 2)
        try table.append(record(.max), writer: writer, expectedHead: .max - 1)
        XCTAssertEqual(try page(table).canonicalRecords, try [record(.max - 1), record(.max)])
        XCTAssertThrowsError(try table.append(record(1), writer: writer, expectedHead: .max))
        XCTAssertTrue(try page(table, after: .max).canonicalRecords.isEmpty)
        try db.exec("COMMIT")
    }

    func testMissingAlteredAndOversizedRowsFailInsteadOfSigningPartialHistory() throws {
        for mutation in ["DELETE FROM audit_records_v1 WHERE sequence=x'0000000000000002'",
                         "UPDATE audit_records_v1 SET body=x'01' WHERE sequence=x'0000000000000001'",
                         "UPDATE audit_records_v1 SET body=zeroblob(20000) WHERE sequence=x'0000000000000001'",
                         "UPDATE audit_records_v1 SET event=zeroblob(16) WHERE sequence=x'0000000000000001'"] {
            let db = try DB(), (table, writer) = try initial(db)
            try db.exec("BEGIN IMMEDIATE")
            try table.append(record(1), writer: writer, expectedHead: 0)
            try table.append(record(2), writer: writer, expectedHead: 1)
            try db.exec(mutation)
            XCTAssertThrowsError(try page(table), mutation)
            try db.exec("ROLLBACK")
        }
    }

    func testReadSnapshotDoesNotMixConcurrentCommittedHeads() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("journal.sqlite").path
        let db = try DB(path)
        try db.exec("PRAGMA journal_mode=WAL")
        let (table, writer) = try initial(db), reader = try DB(path), readTable = try tables(reader)
        try reader.exec("BEGIN")
        XCTAssertEqual(try readTable.epoch(id(3))?.head, 0)
        try db.exec("BEGIN IMMEDIATE")
        try table.append(record(1), writer: writer, expectedHead: 0)
        try db.exec("COMMIT")
        XCTAssertEqual(try page(readTable).epoch.head, 0)
        XCTAssertTrue(try page(readTable).canonicalRecords.isEmpty)
        try reader.exec("COMMIT; BEGIN")
        XCTAssertEqual(try page(readTable).canonicalRecords, try [record(1)])
        try reader.exec("COMMIT")
    }

    private final class DB {
        let handle: OpaquePointer
        init(_ path: String = ":memory:") throws {
            var value: OpaquePointer?
            let rc = sqlite3_open(path, &value)
            guard rc == SQLITE_OK, let value else { if let value { sqlite3_close(value) }; throw AuditJournalError.storage(rc) }
            handle = value
        }
        deinit { sqlite3_close(handle) }
        func exec(_ sql: String) throws {
            let rc = sqlite3_exec(handle, sql, nil, nil, nil)
            guard rc == SQLITE_OK else { throw AuditJournalError.storage(rc) }
        }
        func scalar(_ sql: String) throws -> Int64 {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw AuditJournalError.corruptData }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { throw AuditJournalError.corruptData }
            return sqlite3_column_int64(stmt, 0)
        }
    }
}
