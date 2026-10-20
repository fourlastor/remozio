import Foundation
import RemozioHostCore
import RemozioProtocol
import SQLite3

public typealias CommandSubmissionReplayError = RemozioHostCore.CommandSubmissionReplayError
public typealias CommandSubmissionReservation = RemozioHostCore.CommandSubmissionReservation

/// The Mac owner retains protected installation policy, schema versions and transaction failure handling.
final class CommandSubmissionReplayJournal {
    private let db: OpaquePointer
    private let tables: CommandSubmissionReplayTables

    init(connection: OpaquePointer, macID: Data, accountID: Data, maximumRows: Int) throws {
        db = connection
        tables = try CommandSubmissionReplayTables(connection: connection, macID: macID,
            accountID: accountID, maximumRows: maximumRows)
    }

    func install() throws {
        let version = try schemaVersion()
        guard (13...16).contains(version) else { throw CommandSubmissionReplayError.unavailable }
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        guard try CodePolicyJournal(connection: db).read() != nil else { throw CommandSubmissionReplayError.unavailable }
        if version < 15 {
            try HistoryRecoveryJournal(connection: db).prepareSchema()
            try adapt { try tables.createSchema() }
            try exec("PRAGMA main.user_version=15;")
        }
        try adapt { try tables.validateSchema() }
    }

    func reserve(_ value: CommandSubmissionReservation) throws -> CommandSubmissionReservation {
        try requireInstalled()
        return try adapt { try tables.reserve(value) }
    }
    func contains(_ submission: CapturedSubmission) throws -> Bool {
        try requireInstalled()
        return try adapt { try tables.contains(submission) }
    }
    func read(submissionID: Data) throws -> CommandSubmissionReservation? {
        try requireInstalled()
        return try adapt { try tables.read(submissionID: submissionID) }
    }

    private func requireInstalled() throws {
        let version = try schemaVersion()
        guard (12...16).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        guard version >= 15 else { throw CommandSubmissionReplayError.unavailable }
    }
    private func schemaVersion() throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        return try schemaStatement { row in
            guard try step(row) == SQLITE_ROW else { throw JournalDatabaseError.incompatibleStore }
            return sqlite3_column_int64(row, 0)
        }
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
    private func schemaStatement<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, "PRAGMA main.user_version", -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(row) }
        return try body(row)
    }
    private func step(_ row: OpaquePointer) throws -> Int32 {
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw JournalDatabaseError.storage(result) }
        return result
    }
    private func adapt<T>(_ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch CommandSubmissionReplayError.storage(let code) { throw JournalDatabaseError.storage(code) }
        catch CommandSubmissionReplayError.transactionRequired { throw JournalDatabaseError.expiredTransaction }
        catch CommandSubmissionReplayError.writeTransactionRequired { throw JournalDatabaseError.readOnly }
    }
}
