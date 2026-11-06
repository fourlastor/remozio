import CryptoKit
import Foundation
import SQLite3

/// Evidence from one journal transaction. These hashes do not grant admission or dispatch authority.
public struct JournalContinuityDigests: Equatable, Sendable {
    public let authority: Data
    public let ledger: Data
}

/// The catalog is part of the digest format. A schema change requires an explicit format review.
enum JournalContinuityDigest {
    private static let authorityTables = [
        "journal_identity_v1", "approval_authority_v1", "approval_enrollments_v1", "pairing_commits_v1",
        "routing_state_v1", "routing_operations_v1", "gateway_authority_v1", "gateway_outbox_v1",
        "gateway_root_candidates_v1", "gateway_desired_tokens_v1", "gateway_revocations_v1",
        "gateway_acknowledgment_v1", "gateway_reconciled_controls_v1", "gateway_recovered_revocations_v1",
        "gateway_trust_restrictions_v1",
    ]
    private static let ledgerTables = [
        "journal_identity_v1", "audit_epochs_v1", "audit_records_v1", "consumptions_v1", "consumption_outcomes_v1",
    ]

    static func read(_ db: OpaquePointer) throws -> JournalContinuityDigests {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        var tables = Set<String>()
        try rows(db, "SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name") { row in
            guard let name = sqlite3_column_text(row, 0) else { throw JournalDatabaseError.incompatibleStore }
            tables.insert(String(cString: name))
        }
        var version: Int64?
        try rows(db, "PRAGMA main.user_version") { version = sqlite3_column_int64($0, 0) }
        guard let version, (12...17).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        let authorityTables = Self.authorityTables + (version >= 13 ? ["authority_code_policy_v1"] : [])
            + (version >= 15 ? ["command_submissions_v1"] : [])
            + (version >= 16 ? ["gateway_submission_outbox_v1"] : [])
            + (version >= 17 ? ["update_scheduling_state_v1", "update_scheduling_operations_v1"] : [])
        let ledgerTables = Self.ledgerTables + (version >= 14 ? ["history_recoveries_v1"] : [])
        guard tables == Set(authorityTables + ledgerTables) else { throw JournalDatabaseError.incompatibleStore }
        return try JournalContinuityDigests(authority: digest(db, tables: authorityTables, domain: "authority", schema: version >= 17 ? 17 : (version >= 16 ? 16 : (version >= 15 ? 15 : min(version, 13)))),
                                            ledger: digest(db, tables: ledgerTables, domain: "ledger"))
    }

    private static func digest(_ db: OpaquePointer, tables: [String], domain: String, schema: Int64 = 12) throws -> Data {
        var hash = SHA256()
        field(Data("remozio/journal-continuity/v1/schema\(schema)/\(domain)".utf8), into: &hash)
        for table in tables.sorted() {
            field(Data(table.utf8), into: &hash)
            var columns = [String]()
            try rows(db, "PRAGMA main.table_info('\(table)')") { row in
                guard let name = sqlite3_column_text(row, 1) else { throw JournalDatabaseError.incompatibleStore }
                columns.append(String(cString: name))
            }
            guard !columns.isEmpty else { throw JournalDatabaseError.incompatibleStore }
            number(UInt64(columns.count), into: &hash)
            for column in columns { field(Data(column.utf8), into: &hash) }
            // Ordinals avoid interpreting column names as SQL. Sorting every value also handles composite keys.
            let order = (1...columns.count).map(String.init).joined(separator: ",")
            try rows(db, "SELECT * FROM main.\(table) ORDER BY \(order)") { row in
                hash.update(data: Data([1]))
                for index in columns.indices {
                    let column = Int32(index)
                    switch sqlite3_column_type(row, column) {
                    case SQLITE_NULL: hash.update(data: Data([0]))
                    case SQLITE_INTEGER:
                        hash.update(data: Data([1]))
                        number(UInt64(bitPattern: sqlite3_column_int64(row, column)), into: &hash)
                    case SQLITE_TEXT, SQLITE_BLOB:
                        let text = sqlite3_column_type(row, column) == SQLITE_TEXT
                        hash.update(data: Data([text ? 2 : 3]))
                        let pointer = text ? sqlite3_column_text(row, column).map(UnsafeRawPointer.init) : sqlite3_column_blob(row, column)
                        let size = Int(sqlite3_column_bytes(row, column))
                        guard size == 0 || pointer != nil else { throw JournalDatabaseError.storage(SQLITE_NOMEM) }
                        field(size == 0 ? Data() : Data(bytes: pointer!, count: size), into: &hash)
                    default: throw JournalDatabaseError.incompatibleStore
                    }
                }
            }
            hash.update(data: Data([0]))
        }
        return Data(hash.finalize())
    }

    private static func field(_ data: Data, into hash: inout SHA256) {
        number(UInt64(data.count), into: &hash)
        hash.update(data: data)
    }
    private static func number(_ value: UInt64, into hash: inout SHA256) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { hash.update(data: Data($0)) }
    }
    private static func rows(_ db: OpaquePointer, _ sql: String, _ body: (OpaquePointer) throws -> Void) throws {
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard result == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(statement) }
        while true {
            let result = sqlite3_step(statement)
            if result == SQLITE_DONE { return }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            try body(statement)
        }
    }
}
