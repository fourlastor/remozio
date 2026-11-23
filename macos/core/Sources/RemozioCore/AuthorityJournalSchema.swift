import SQLite3

/// Resolves the authority journal format and its installed feature tier.
enum AuthorityJournalSchema {
    static func formatVersion(on db: OpaquePointer) throws -> Int64 {
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, "PRAGMA main.user_version", -1, &statement, nil)
        guard result == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(statement) }
        let step = sqlite3_step(statement)
        guard step != SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore }
        guard step == SQLITE_ROW else { throw JournalDatabaseError.storage(step) }
        return sqlite3_column_int64(statement, 0)
    }

    static func featureTier(on db: OpaquePointer) throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        return try formatVersion(on: db)
    }

    static func setFeatureTier(_ tier: Int64, on db: OpaquePointer) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        guard (12...18).contains(tier) else { throw JournalDatabaseError.incompatibleStore }
        let result = sqlite3_exec(db, "PRAGMA main.user_version=\(tier)", nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
}
