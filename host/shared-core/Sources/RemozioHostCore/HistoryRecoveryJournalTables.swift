import Foundation
#if os(Linux)
import CSQLite
#else
import SQLite3
#endif

public enum HistoryRecoveryJournalError: Error, Equatable {
    case invalidEpoch, transactionRequired, writeTransactionRequired, corruptData, storage(Int32)
}

/// Retained history-gap evidence in the owner's existing journal connection.
/// The owner provides connection lifetime, serialized access, protected storage and outer transactions.
/// Schema versions, migrations, authority validation and connection retirement remain with that owner.
/// These records cannot authorize actions, restore pending requests or permit dispatch or replay.
public final class HistoryRecoveryJournalTables {
    private let db: OpaquePointer
    public init(connection: OpaquePointer) { db = connection }

    /// Run once inside the owner's main-database write transaction. Existing tables are never replaced.
    /// This installs only the table; it does not read or change the owner's schema version.
    public func createSchema() throws {
        try writeTransaction()
        try exec("""
            CREATE TABLE main.history_recoveries_v1(
                epoch BLOB PRIMARY KEY CHECK(length(epoch)=16),
                evidence BLOB NOT NULL CHECK(length(evidence) BETWEEN 1 AND 1024)
            ) STRICT, WITHOUT ROWID;
            """)
    }

    /// The explicit outer transaction supplies the snapshot. Missing evidence is distinct from malformed evidence.
    public func read(epoch: Data) throws -> HistoryRecoveryIntent? {
        guard epoch.count == 16 else { throw HistoryRecoveryJournalError.invalidEpoch }
        try transaction()
        return try statement("SELECT evidence FROM main.history_recoveries_v1 WHERE epoch=?", values: [epoch]) { row in
            let result = sqlite3_step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw HistoryRecoveryJournalError.storage(result) }
            let count = sqlite3_column_bytes(row, 0)
            guard sqlite3_column_type(row, 0) == SQLITE_BLOB, count > 0, count <= 1024,
                  let pointer = sqlite3_column_blob(row, 0) else { throw HistoryRecoveryJournalError.corruptData }
            let intent = try HistoryRecoveryIntent.decode(Data(bytes: pointer, count: Int(count)))
            guard intent.recoveryEpoch == epoch else { throw HistoryRecoveryJournalError.corruptData }
            return intent
        }
    }

    /// Commit this evidence with the fresh epoch and gap event in the same outer transaction.
    /// The validated value retains its canonical encoding. Duplicate epochs fail instead of replacing evidence.
    public func insert(_ intent: HistoryRecoveryIntent) throws {
        try writeTransaction()
        try statement("INSERT INTO main.history_recoveries_v1 VALUES(?,?)",
            values: [intent.recoveryEpoch, try intent.bytes]) { row in
            let result = sqlite3_step(row)
            guard result == SQLITE_DONE else { throw HistoryRecoveryJournalError.storage(result) }
        }
    }

    private func transaction() throws {
        guard sqlite3_get_autocommit(db) == 0 else { throw HistoryRecoveryJournalError.transactionRequired }
    }
    private func writeTransaction() throws {
        try transaction()
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else {
            throw HistoryRecoveryJournalError.writeTransactionRequired
        }
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw HistoryRecoveryJournalError.storage(result) }
    }
    private func statement<T>(_ sql: String, values: [Data], _ body: (OpaquePointer) throws -> T) throws -> T {
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw HistoryRecoveryJournalError.storage(result) }
        defer { sqlite3_finalize(row) }
        // Both inputs are bounded by their validated value: a 16-byte epoch and at most 1024 evidence bytes.
        for (index, value) in values.enumerated() {
            let result = value.withUnsafeBytes {
                sqlite3_bind_blob(row, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard result == SQLITE_OK else { throw HistoryRecoveryJournalError.storage(result) }
        }
        return try body(row)
    }
}
