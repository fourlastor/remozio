import Foundation
import RemozioProtocol
import SQLite3

/// Reads retained intent without enabling a scheduling policy or writing storage.
enum UpdateSchedulingStateStorage {
    static func read(connection: OpaquePointer) throws -> UpdateSchedulingIntent? {
        guard sqlite3_get_autocommit(connection) == 0 else { throw JournalDatabaseError.expiredTransaction }
        var statement: OpaquePointer?
        let prepared = sqlite3_prepare_v2(connection,
            "SELECT update_id,generation,revision,action FROM main.update_scheduling_state_v1 WHERE id=1", -1, &statement, nil)
        guard prepared == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(prepared) }
        defer { sqlite3_finalize(statement) }
        let stepped = sqlite3_step(statement)
        if stepped == SQLITE_DONE { return nil }
        guard stepped == SQLITE_ROW else { throw JournalDatabaseError.storage(stepped) }
        func bytes(_ column: Int32, count: Int) throws -> Data {
            guard sqlite3_column_type(statement, column) == SQLITE_BLOB,
                  sqlite3_column_bytes(statement, column) == count,
                  let value = sqlite3_column_blob(statement, column) else { throw UpdateSchedulingJournalError.corruptData }
            return Data(bytes: value, count: count)
        }
        func uint(_ column: Int32) throws -> UInt64 {
            try bytes(column, count: 8).reduce(0) { ($0 << 8) | UInt64($1) }
        }
        let update = try bytes(0, count: 32), generation = try uint(1), revision = try uint(2)
        guard generation > 0 else { throw UpdateSchedulingJournalError.corruptData }
        let action: UpdateSchedulingAction?
        if sqlite3_column_type(statement, 3) == SQLITE_NULL { action = nil }
        else {
            guard sqlite3_column_type(statement, 3) == SQLITE_INTEGER,
                  let code = UInt64(exactly: sqlite3_column_int64(statement, 3)),
                  let value = UpdateSchedulingAction(rawValue: code) else { throw UpdateSchedulingJournalError.corruptData }
            action = value
        }
        let result = try UpdateSchedulingIntent(snapshot: .init(updateID: update, generation: generation, revision: revision),
            requestedAction: action)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw UpdateSchedulingJournalError.corruptData }
        return result
    }
}
