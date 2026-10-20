import Foundation
import RemozioProtocol
#if os(Linux)
import CSQLite
#else
import SQLite3
#endif

public enum CommandSubmissionReplayError: Error, Equatable {
    case invalidConfiguration, unavailable, wrongScope, alreadyReserved, capacityExceeded, corruptData
    case transactionRequired, writeTransactionRequired, storage(Int32)
}

/// Historical replay evidence. Construction and lookup grant no admission, retry, or execution authority.
public struct CommandSubmissionReservation: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let submission: CapturedSubmission
    public let captureDigest: Data

    /// The host supplies the scope and digest after authenticating and assembling the original capture.
    public init(macID: Data, accountID: Data, submission: CapturedSubmission, captureDigest: Data) throws {
        guard macID.count == 16, accountID.count == 16, captureDigest.count == 32,
              submission.id.count == 16, submission.nonce.count == 32, submission.callerBinding.count == 16 else {
            throw CommandSubmissionReplayError.invalidConfiguration
        }
        self.macID = macID; self.accountID = accountID; self.submission = submission; self.captureDigest = captureDigest
    }
}

/// Permanent replay evidence in the owner's existing SQLite connection, not an admission authority.
/// The caller owns connection lifetime, serialized access, schema migration, durability and recovery.
/// Publish reservations only after the owner's complete admission transaction and checkpoints commit.
public final class CommandSubmissionReplayTables {
    private let db: OpaquePointer
    private let macID: Data
    private let accountID: Data
    private let maximumRows: Int

    public init(connection: OpaquePointer, macID: Data, accountID: Data, maximumRows: Int) throws {
        guard macID.count == 16, accountID.count == 16, maximumRows > 0, maximumRows <= Int(Int32.max) else {
            throw CommandSubmissionReplayError.invalidConfiguration
        }
        db = connection; self.macID = macID; self.accountID = accountID; self.maximumRows = maximumRows
    }

    /// Run in the owner's schema migration transaction. Never replaces existing evidence or sets user_version.
    public func createSchema() throws {
        try writeTransaction()
        try exec("""
            CREATE TABLE main.command_submissions_v1 (
                mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
                submission BLOB NOT NULL CHECK(length(submission)=16), nonce BLOB NOT NULL CHECK(length(nonce)=32),
                caller BLOB NOT NULL CHECK(length(caller)=16), capture BLOB NOT NULL CHECK(length(capture)=32),
                PRIMARY KEY(mac,account,submission), UNIQUE(mac,account,nonce)
            ) STRICT, WITHOUT ROWID;
            """)
    }

    /// Presence/column probe only; the protected owner must separately validate its complete store schema.
    public func validateSchema() throws {
        try transaction()
        try statement("SELECT mac,account,submission,nonce,caller,capture FROM main.command_submissions_v1 LIMIT 0") {
            guard try step($0) == SQLITE_DONE else { throw CommandSubmissionReplayError.corruptData }
        }
    }

    /// No expiry, replacement or deletion. Failure does not poison the caller's outer transaction;
    /// the owner must roll back the entire admission batch when any required operation fails.
    public func reserve(_ value: CommandSubmissionReservation) throws -> CommandSubmissionReservation {
        try transaction()
        guard value.macID == macID, value.accountID == accountID else { throw CommandSubmissionReplayError.wrongScope }
        try writeTransaction()
        try statement("SELECT 1 FROM main.command_submissions_v1 WHERE mac=? AND account=? AND (submission=? OR nonce=?)",
            values: [macID, accountID, value.submission.id, value.submission.nonce]) {
            guard try step($0) == SQLITE_DONE else { throw CommandSubmissionReplayError.alreadyReserved }
        }
        try statement("SELECT count(*) FROM main.command_submissions_v1 WHERE mac=? AND account=?", values: [macID, accountID]) {
            guard try step($0) == SQLITE_ROW, sqlite3_column_type($0, 0) == SQLITE_INTEGER else {
                throw CommandSubmissionReplayError.corruptData
            }
            let count = sqlite3_column_int64($0, 0)
            guard count >= 0 else { throw CommandSubmissionReplayError.corruptData }
            guard count < Int64(maximumRows) else { throw CommandSubmissionReplayError.capacityExceeded }
        }
        try statement("INSERT INTO main.command_submissions_v1 VALUES(?,?,?,?,?,?)",
            values: [macID, accountID, value.submission.id, value.submission.nonce, value.submission.callerBinding, value.captureDigest]) {
            guard try step($0) == SQLITE_DONE else { throw CommandSubmissionReplayError.corruptData }
        }
        return value
    }

    /// A scoped absence observation covers both identifiers. It grants no retry authority by itself.
    public func contains(_ submission: CapturedSubmission) throws -> Bool {
        try transaction()
        guard submission.id.count == 16, submission.nonce.count == 32, submission.callerBinding.count == 16 else {
            throw CommandSubmissionReplayError.invalidConfiguration
        }
        return try statement("SELECT 1 FROM main.command_submissions_v1 WHERE mac=? AND account=? AND (submission=? OR nonce=?) LIMIT 1",
            values: [macID, accountID, submission.id, submission.nonce]) { try step($0) == SQLITE_ROW }
    }

    public func read(submissionID: Data) throws -> CommandSubmissionReservation? {
        try transaction()
        guard submissionID.count == 16 else { throw CommandSubmissionReplayError.invalidConfiguration }
        return try statement("SELECT mac,account,submission,nonce,caller,capture FROM main.command_submissions_v1 WHERE mac=? AND account=? AND submission=?",
            values: [macID, accountID, submissionID]) { row in
            if try step(row) == SQLITE_DONE { return nil }
            let mac = try blob(row, column: 0, count: 16), account = try blob(row, column: 1, count: 16)
            let id = try blob(row, column: 2, count: 16)
            guard mac == macID, account == accountID, id == submissionID else { throw CommandSubmissionReplayError.corruptData }
            let binding = try CapturedSubmission(id: id, nonce: blob(row, column: 3, count: 32), callerBinding: blob(row, column: 4, count: 16))
            return try CommandSubmissionReservation(macID: mac, accountID: account, submission: binding,
                captureDigest: blob(row, column: 5, count: 32))
        }
    }

    private func transaction() throws {
        guard sqlite3_get_autocommit(db) == 0 else { throw CommandSubmissionReplayError.transactionRequired }
    }
    private func writeTransaction() throws {
        try transaction()
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw CommandSubmissionReplayError.writeTransactionRequired }
    }
    private func blob(_ row: OpaquePointer, column: Int32, count: Int32) throws -> Data {
        guard sqlite3_column_type(row, column) == SQLITE_BLOB, sqlite3_column_bytes(row, column) == count,
              let bytes = sqlite3_column_blob(row, column) else { throw CommandSubmissionReplayError.corruptData }
        return Data(bytes: bytes, count: Int(count))
    }
    private func step(_ row: OpaquePointer) throws -> Int32 {
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw CommandSubmissionReplayError.storage(result) }
        return result
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw CommandSubmissionReplayError.storage(result) }
    }
    private func statement<T>(_ sql: String, values: [Data] = [], _ body: (OpaquePointer) throws -> T) throws -> T {
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw CommandSubmissionReplayError.storage(result) }
        defer { sqlite3_finalize(row) }
        for (index, value) in values.enumerated() {
            let result = value.withUnsafeBytes {
                sqlite3_bind_blob(row, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard result == SQLITE_OK else { throw CommandSubmissionReplayError.storage(result) }
        }
        return try body(row)
    }
}
