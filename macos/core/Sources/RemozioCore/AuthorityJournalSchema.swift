import SQLite3

/// Resolves the authority journal format and its installed feature tier.
enum AuthorityJournalSchema {
    static let recoveryFormat: Int64 = 19
    static let tierTable = "authority_feature_tier_v1"
    static let supportedFormats: ClosedRange<Int64> = 12...recoveryFormat

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
        let format = try formatVersion(on: db)
        if format != recoveryFormat { return format }
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, "SELECT id,tier FROM main.\(tierTable)", -1, &statement, nil)
        guard result == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW,
              sqlite3_column_type(statement, 0) == SQLITE_INTEGER, sqlite3_column_int64(statement, 0) == 1,
              sqlite3_column_type(statement, 1) == SQLITE_INTEGER else { throw JournalDatabaseError.incompatibleStore }
        let tier = sqlite3_column_int64(statement, 1)
        guard (12...18).contains(tier), sqlite3_step(statement) == SQLITE_DONE else {
            throw JournalDatabaseError.incompatibleStore
        }
        return tier
    }

    static func featureTierInTransaction(on db: OpaquePointer) throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        return try featureTier(on: db)
    }

    static func recoveryFormatInstalled(on db: OpaquePointer) throws -> Bool {
        let format = try formatVersion(on: db)
        guard supportedFormats.contains(format) else { throw JournalDatabaseError.incompatibleStore }
        return format == recoveryFormat
    }

    static func setFeatureTier(_ tier: Int64, on db: OpaquePointer) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        guard (12...18).contains(tier) else { throw JournalDatabaseError.incompatibleStore }
        if try formatVersion(on: db) == recoveryFormat {
            _ = try featureTier(on: db)
            try execute("UPDATE main.\(tierTable) SET tier=\(tier) WHERE id=1", on: db)
            guard sqlite3_changes(db) == 1 else { throw JournalDatabaseError.incompatibleStore }
        } else {
            try execute("PRAGMA main.user_version=\(tier)", on: db)
        }
    }

    /// The first authorized stage and this format transition share the same checkpointed write.
    static func installRecoveryFormat(on db: OpaquePointer) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        let format = try formatVersion(on: db)
        if format == recoveryFormat { return }
        guard (12...18).contains(format) else { throw JournalDatabaseError.incompatibleStore }
        try execute("""
            CREATE TABLE main.\(tierTable) (
                id INTEGER PRIMARY KEY CHECK(id=1),
                tier INTEGER NOT NULL CHECK(tier BETWEEN 12 AND 18)
            ) STRICT;
            INSERT INTO main.\(tierTable) VALUES(1,\(format));
            """, on: db)
        try PairingRecoveryStageJournal.createStorage(on: db)
        try execute("PRAGMA main.user_version=\(recoveryFormat)", on: db)
    }

    private static func execute(_ sql: String, on db: OpaquePointer) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
}
