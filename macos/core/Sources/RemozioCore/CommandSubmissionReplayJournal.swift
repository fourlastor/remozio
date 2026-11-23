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
        let version = try AuthorityJournalSchema.featureTier(on: db)
        guard (13...18).contains(version) else { throw CommandSubmissionReplayError.unavailable }
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        guard try CodePolicyJournal(connection: db).read() != nil else { throw CommandSubmissionReplayError.unavailable }
        if version < 15 {
            try HistoryRecoveryJournal(connection: db).prepareSchema()
            try adapt { try tables.createSchema() }
            try AuthorityJournalSchema.setFeatureTier(15, on: db)
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
        let version = try AuthorityJournalSchema.featureTier(on: db)
        guard (12...18).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        guard version >= 15 else { throw CommandSubmissionReplayError.unavailable }
    }
    private func adapt<T>(_ operation: () throws -> T) throws -> T {
        do { return try operation() }
        catch CommandSubmissionReplayError.storage(let code) { throw JournalDatabaseError.storage(code) }
        catch CommandSubmissionReplayError.transactionRequired { throw JournalDatabaseError.expiredTransaction }
        catch CommandSubmissionReplayError.writeTransactionRequired { throw JournalDatabaseError.readOnly }
    }
}
