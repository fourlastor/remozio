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
        let version = try AuthorityJournalSchema.featureTier(on: db)
        guard (12...18).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        if version < 14 { return nil }
        return try adapt { try tables.read(epoch: epoch) }
    }

    func prepareSchema() throws {
        let version = try AuthorityJournalSchema.featureTier(on: db)
        guard (13...18).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        if version == 13 {
            try adapt { try tables.createSchema() }
            try AuthorityJournalSchema.setFeatureTier(14, on: db)
        }
    }

    func insert(_ intent: HistoryRecoveryIntent) throws {
        try prepareSchema()
        try adapt { try tables.insert(intent) }
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
}
