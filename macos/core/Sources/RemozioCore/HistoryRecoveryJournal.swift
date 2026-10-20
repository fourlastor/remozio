import Foundation
import RemozioHostCore
import SQLite3

/// Retained gap evidence shares the journal transaction and ledger digest, never the authority digest.
/// The Mac owner retains schema migration, error mapping and failed-transaction handling.
final class HistoryRecoveryJournal {
    private let db: OpaquePointer
    private let tables: HistoryRecoveryJournalTables
    init(connection: OpaquePointer) {
        db = connection
        tables = HistoryRecoveryJournalTables(connection: connection)
    }

    func read(epoch: Data) throws -> HistoryRecoveryIntent? {
        guard epoch.count == 16 else { throw ContinuityStoreError.invalidCheckpoint }
        let version = try schemaVersion()
        guard (12...16).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        if version < 14 { return nil }
        return try adapt { try tables.read(epoch: epoch) }
    }

    func prepareSchema() throws {
        let version = try schemaVersion()
        guard (13...16).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        if version == 13 {
            try adapt { try tables.createSchema() }
            try exec("PRAGMA main.user_version=14;")
        }
    }

    func insert(_ intent: HistoryRecoveryIntent) throws {
        try prepareSchema()
        try adapt { try tables.insert(intent) }
    }

    private func schemaVersion() throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        return try statement("PRAGMA main.user_version") { row in
            let result = sqlite3_step(row)
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            return sqlite3_column_int64(row, 0)
        }
    }
    private func adapt<T>(_ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch let error as HistoryRecoveryJournalError {
            switch error {
            case .invalidEpoch: throw ContinuityStoreError.invalidCheckpoint
            case .transactionRequired: throw JournalDatabaseError.expiredTransaction
            case .writeTransactionRequired: throw JournalDatabaseError.readOnly
            case .corruptData: throw JournalDatabaseError.incompatibleStore
            case .storage(let code): throw JournalDatabaseError.storage(code)
            }
        }
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(row) }
        return try body(row)
    }
}
