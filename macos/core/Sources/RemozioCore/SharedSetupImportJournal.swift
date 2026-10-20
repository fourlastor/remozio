import Darwin
import Foundation
import SQLite3

/// A separate Root journal allows import retention before runtime setup. It never executes an imported action.
final class SharedSetupImportJournal {
    static let formatName = "setup.shared-import-journal"
    static let supportedVersions: Set<UInt64> = [2]
    private static let applicationID: Int64 = 0x524D5349
    private let lease: ProtectedStorageLease
    private let owner: uid_t
    private let macID: Data
    private let installationID: Data
    private let maximumRecords: Int
    private let didCommit: (() throws -> Void)?
    private var db: OpaquePointer?
    private var active = false
    private var unavailable = false

    static func open(machineDirectory: String, macID: Data, installationID: Data, initialize: Bool) throws -> SharedSetupImportJournal {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard machineDirectory.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        guard macID.count == 16, installationID.count == 16 else { throw SharedSetupImportError.invalidRecord }
        let directory = machineDirectory + "/SharedSetupImport"
        if initialize { _ = try SetupDatabaseFileProvisioning.prepare(directoryPath: directory, kind: .sharedSetupImport) }
        let lease = try ProtectedStorageLease(anchor: "/", relativeDirectory: String(directory.dropFirst()),
            owner: 0, ancestorOwner: 0, databaseName: "setup-import.sqlite")
        return try .init(lease: lease, owner: 0, macID: macID, installationID: installationID, initialize: initialize)
    }
    static func withExisting<Value>(anchor: String, relativeMachineDirectory: String, owner: uid_t,
                                    macID: Data, installationID: Data,
                                    body: (SharedSetupImportJournal?) throws -> Value) throws -> Value {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let machine = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeMachineDirectory,
            owner: owner, createIfMissing: false)
        defer { machine.close() }
        return try machine.withPrivateDirectory { parent in
            var info = stat()
            if fstatat(parent, "SharedSetupImport", &info, AT_SYMLINK_NOFOLLOW) != 0 {
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                return try body(nil)
            }
            let lease = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeMachineDirectory + "/SharedSetupImport",
                owner: owner, ancestorOwner: owner, databaseName: "setup-import.sqlite")
            let journal = try Self(lease: lease, owner: owner, macID: macID, installationID: installationID, initialize: false)
            defer { try? journal.close() }
            return try body(journal)
        }
    }
    // Ordinary-owner fixtures use the same file, schema, transaction and scope checks. They prove no Root admission.
    init(lease: ProtectedStorageLease, owner: uid_t, macID: Data, installationID: Data,
         initialize: Bool, maximumRecords: Int = 64, didCommit: (() throws -> Void)? = nil) throws {
        self.lease = lease; self.owner = owner; self.macID = macID; self.installationID = installationID
        self.maximumRecords = maximumRecords; self.didCommit = didCommit
        do {
            guard macID.count == 16, installationID.count == 16, (1...64).contains(maximumRecords) else {
                throw SharedSetupImportError.invalidRecord
            }
            try validateLease()
            var connection: OpaquePointer?
            let result = sqlite3_open_v2(lease.databasePath, &connection,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard result == SQLITE_OK, let connection else { throw SharedSetupImportError.storage(result) }
            guard sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1,
                  sqlite3_busy_timeout(connection, 1000) == SQLITE_OK else { throw SharedSetupImportError.incompatibleStore }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, 131_072)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_SQL_LENGTH, 8192)
            try exec("PRAGMA trusted_schema=OFF")
            if initialize {
                guard try scalar("SELECT COUNT(*) FROM sqlite_master") == 0, try scalar("PRAGMA user_version") == 0,
                      try scalar("PRAGMA application_id") == 0 else { throw SharedSetupImportError.incompatibleStore }
            } else { try identity() }
            try exec("PRAGMA journal_mode=DELETE"); try exec("PRAGMA synchronous=EXTRA"); try exec("PRAGMA fullfsync=ON")
            guard try scalar("PRAGMA synchronous") == 3, try scalar("PRAGMA fullfsync") == 1,
                  try scalar("PRAGMA trusted_schema") == 0, try scalar("PRAGMA max_page_count=8192") <= 8192 else {
                throw SharedSetupImportError.incompatibleStore
            }
            let mode = try statement("PRAGMA journal_mode") { row in
                guard try step(row) == SQLITE_ROW, let text = sqlite3_column_text(row, 0) else { return false }
                return String(cString: text) == "delete"
            }
            guard mode else { throw SharedSetupImportError.incompatibleStore }
            if initialize {
                try transaction(write: true) {
                    try exec("CREATE TABLE import_destination_v2(id INTEGER PRIMARY KEY CHECK(id=1),mac BLOB NOT NULL CHECK(length(mac)=16),installation BLOB NOT NULL CHECK(length(installation)=16)) STRICT")
                    try exec("CREATE TABLE shared_setup_import_v2(account BLOB PRIMARY KEY CHECK(length(account)=16),operation BLOB NOT NULL UNIQUE CHECK(length(operation)=16),revision BLOB NOT NULL CHECK(length(revision)=16),digest BLOB NOT NULL CHECK(length(digest)=32),phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 4),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 70000)) STRICT, WITHOUT ROWID")
                    try statement("INSERT INTO import_destination_v2 VALUES(1,?,?)") { row in
                        try bind(macID, at: 1, to: row); try bind(installationID, at: 2, to: row)
                        guard try step(row) == SQLITE_DONE else { throw SharedSetupImportError.corruptRecord }
                    }
                    try exec("PRAGMA application_id=\(Self.applicationID)"); try exec("PRAGMA user_version=2")
                }
            }
            try identity(); _ = try records(); try validateLease()
        } catch { shutdown(); throw error }
    }
    deinit { shutdown() }
    func close() throws {
        guard !active else { throw SharedSetupImportError.transactionActive }
        shutdown()
    }
    func records() throws -> [SharedSetupImportIntent] {
        try transaction(write: false) { try identity(); return try loadAll() }
    }
    func current(scope: SharedSetupImportIntent.Scope) throws -> SharedSetupImportIntent? {
        try validateScope(scope)
        return try transaction(write: false) {
            try identity()
            let selected = try loadAll().first { $0.scope.accountID == scope.accountID }
            guard selected == nil || selected?.scope == scope else { throw SharedSetupImportError.wrongScope }
            return selected
        }
    }
    func begin(_ intent: SharedSetupImportIntent) throws {
        try validateScope(intent.scope)
        guard intent.phase == .retained else { throw SharedSetupImportError.invalidTransition }
        let bytes = try intent.bytes
        try transaction(write: true) {
            try identity(); let existing = try loadAll()
            if let current = existing.first(where: { $0.scope.accountID == intent.scope.accountID }) {
                guard current == intent else { throw SharedSetupImportError.conflict }; return
            }
            guard existing.count < maximumRecords else { throw SharedSetupImportError.capacity }
            guard !existing.contains(where: { $0.operationID == intent.operationID }) else { throw SharedSetupImportError.conflict }
            try statement("INSERT INTO shared_setup_import_v2 VALUES(?,?,?,?,?,?)") { row in
                try bind(intent.scope.accountID, at: 1, to: row); try bind(intent.operationID, at: 2, to: row)
                try bind(intent.revision, at: 3, to: row); try bind(intent.proposalDigest, at: 4, to: row)
                try bind(Int64(intent.phase.rawValue), at: 5, to: row); try bind(bytes, at: 6, to: row)
                guard try step(row) == SQLITE_DONE else { throw SharedSetupImportError.corruptRecord }
            }
        }
    }
    /// This compare-and-swap records verified outputs. The native controller owns verification and authorization.
    func advance(_ expected: SharedSetupImportIntent, to phase: SharedSetupImportIntent.Phase) throws -> SharedSetupImportIntent {
        try validateScope(expected.scope)
        let next = try expected.advanced(to: phase), bytes = try next.bytes
        return try transaction(write: true) {
            try identity()
            guard try loadAll().first(where: { $0.scope.accountID == expected.scope.accountID }) == expected else {
                throw SharedSetupImportError.staleRevision
            }
            try statement("UPDATE shared_setup_import_v2 SET revision=?,phase=?,record=? WHERE account=? AND revision=? AND digest=?") { row in
                try bind(next.revision, at: 1, to: row); try bind(Int64(phase.rawValue), at: 2, to: row); try bind(bytes, at: 3, to: row)
                try bind(expected.scope.accountID, at: 4, to: row); try bind(expected.revision, at: 5, to: row)
                try bind(expected.proposalDigest, at: 6, to: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw SharedSetupImportError.staleRevision }
            }
            return next
        }
    }
    private func validateScope(_ scope: SharedSetupImportIntent.Scope) throws {
        guard scope.macID == macID, scope.installationID == installationID else { throw SharedSetupImportError.wrongScope }
    }
    private func loadAll() throws -> [SharedSetupImportIntent] {
        try statement("SELECT account,operation,revision,digest,phase,record FROM shared_setup_import_v2 ORDER BY account LIMIT 65") { row in
            var records: [SharedSetupImportIntent] = [], accounts = Set<Data>(), operations = Set<Data>()
            while try step(row) == SQLITE_ROW {
                guard records.count < maximumRecords else { throw SharedSetupImportError.corruptRecord }
                let record: SharedSetupImportIntent
                do { record = try .decode(blob(row, at: 5, maximum: SharedSetupImportIntent.maximumBytes)) }
                catch { throw SharedSetupImportError.corruptRecord }
                guard record.scope.macID == macID, record.scope.installationID == installationID,
                      accounts.insert(record.scope.accountID).inserted, operations.insert(record.operationID).inserted,
                      try blob(row, at: 0, maximum: 16) == record.scope.accountID,
                      try blob(row, at: 1, maximum: 16) == record.operationID,
                      try blob(row, at: 2, maximum: 16) == record.revision,
                      try blob(row, at: 3, maximum: 32) == record.proposalDigest,
                      sqlite3_column_type(row, 4) == SQLITE_INTEGER, sqlite3_column_int64(row, 4) == Int64(record.phase.rawValue) else {
                    throw SharedSetupImportError.corruptRecord
                }
                records.append(record)
            }
            return records
        }
    }
    private func identity() throws {
        guard try scalar("PRAGMA application_id") == Self.applicationID, try scalar("PRAGMA user_version") == 2,
              try scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'") == 2,
              try scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('import_destination_v2','shared_setup_import_v2')") == 2 else {
            throw SharedSetupImportError.incompatibleStore
        }
        try statement("SELECT id,mac,installation FROM import_destination_v2") { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 1,
                  try blob(row, at: 1, maximum: 16) == macID, try blob(row, at: 2, maximum: 16) == installationID,
                  try step(row) == SQLITE_DONE else { throw SharedSetupImportError.wrongScope }
        }
    }
    private func validateLease() throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try lease.validate()
    }
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
        guard !unavailable else { throw SharedSetupImportError.unavailable }
        guard db != nil else { throw SharedSetupImportError.closed }
        guard !active else { throw SharedSetupImportError.transactionActive }
        do { try validateLease() } catch { unavailable = true; shutdown(); throw error }
        do { try exec(write ? "BEGIN IMMEDIATE" : "BEGIN") }
        catch { if Self.corruption(error) { unavailable = true; shutdown() }; throw error }
        active = true; defer { active = false }
        do {
            let value = try body(); try validateLease()
            do { try exec("COMMIT"); if write { try didCommit?() } }
            catch { unavailable = true; throw error }
            try validateLease(); return value
        } catch {
            if error as? SharedSetupImportError == .corruptRecord || error as? SharedSetupImportError == .incompatibleStore ||
                error is JournalLeaseError || Self.corruption(error) { unavailable = true }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            if unavailable { shutdown() }; throw error
        }
    }
    private static func corruption(_ error: any Error) -> Bool {
        guard case SharedSetupImportError.storage(let code) = error else { return false }
        return code & 0xff == SQLITE_CORRUPT || code & 0xff == SQLITE_NOTADB
    }
    private func bind(_ data: Data, at column: Int32, to row: OpaquePointer) throws {
        let result = data.withUnsafeBytes { sqlite3_bind_blob(row, column, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
        guard result == SQLITE_OK else { throw SharedSetupImportError.storage(result) }
    }
    private func bind(_ number: Int64, at column: Int32, to row: OpaquePointer) throws {
        let result = sqlite3_bind_int64(row, column, number)
        guard result == SQLITE_OK else { throw SharedSetupImportError.storage(result) }
    }
    private func blob(_ row: OpaquePointer, at column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(row, column))
        guard sqlite3_column_type(row, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let pointer = sqlite3_column_blob(row, column) else { throw SharedSetupImportError.corruptRecord }
        return Data(bytes: pointer, count: count)
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER else { throw SharedSetupImportError.incompatibleStore }
            let value = sqlite3_column_int64(row, 0)
            guard try step(row) == SQLITE_DONE else { throw SharedSetupImportError.incompatibleStore }; return value
        }
    }
    private func exec(_ sql: String) throws {
        guard let db else { throw SharedSetupImportError.closed }
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw SharedSetupImportError.storage(result) }
    }
    private func step(_ row: OpaquePointer) throws -> Int32 {
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw SharedSetupImportError.storage(result) }; return result
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        guard let db else { throw SharedSetupImportError.closed }
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw SharedSetupImportError.storage(result) }
        defer { sqlite3_finalize(row) }; return try body(row)
    }
    private func shutdown() {
        if let db { _ = sqlite3_close_v2(db) }; db = nil; lease.close()
    }
}
