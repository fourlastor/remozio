import Foundation
import SQLite3

/// Root-owned independent checkpoint storage. Serialize calls and close before releasing authority ownership.
/// This store neither executes journal mutations nor grants dispatch permission.
public final class ContinuityStore {
    func directoryIdentities() throws -> [ProtectedStorageLease.DirectoryIdentity] {
        try lease.directoryIdentities()
    }
    private let lease: ProtectedContinuityLease
    private var db: OpaquePointer?
    private var unavailable = false
    /// Negative connection state for serialized owner cleanup, not authority to resume work.
    var retired: Bool { db == nil || unavailable }
    private let macID: Data
    private let accountID: Data

    public static func open(directoryPath: String, macID: Data, accountID: Data,
                            initialize: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
        try ContinuityStore(lease: ProtectedContinuityLease.acquire(directoryPath: directoryPath),
                            macID: macID, accountID: accountID, initialize: initialize)
    }

    static func open(directoryPath: String, macID: Data, accountID: Data,
                     excludingDirectory: ProtectedStorageLease.DirectoryIdentity) throws -> ContinuityStore {
        try ContinuityStore(lease: ProtectedContinuityLease.acquire(directoryPath: directoryPath,
            excludingDirectory: excludingDirectory), macID: macID, accountID: accountID, initialize: nil)
    }

    init(lease: ProtectedContinuityLease, macID: Data, accountID: Data, initialize: ContinuityCheckpoint?) throws {
        self.lease = lease; self.macID = macID; self.accountID = accountID
        do {
            guard macID.count == 16, accountID.count == 16 else { throw ContinuityStoreError.wrongScope }
            try lease.validate()
            var connection: OpaquePointer?
            let result = sqlite3_open_v2(lease.databasePath, &connection,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard result == SQLITE_OK, let connection else { throw ContinuityStoreError.storage(result) }
            guard sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1,
                  sqlite3_busy_timeout(connection, 5000) == SQLITE_OK else { throw ContinuityStoreError.incompatibleStore }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, 8192)
            try exec("PRAGMA trusted_schema=OFF")
            if initialize != nil {
                try requireEmptyStore()
            } else {
                guard try scalar("PRAGMA application_id") == 0x524D5A43,
                      [1, 2, 3, 4].contains(try scalar("PRAGMA user_version")) else { throw ContinuityStoreError.incompatibleStore }
            }
            try exec("PRAGMA journal_mode=DELETE")
            try exec("PRAGMA synchronous=EXTRA")
            try exec("PRAGMA fullfsync=ON")
            guard try scalar("PRAGMA synchronous") == 3, try scalar("PRAGMA fullfsync") == 1,
                  try scalar("PRAGMA trusted_schema") == 0 else { throw ContinuityStoreError.incompatibleStore }
            try statement("PRAGMA journal_mode") {
                try self.row($0)
                guard let mode = sqlite3_column_text($0, 0),
                      String(cString: mode) == "delete" else { throw ContinuityStoreError.incompatibleStore }
            }
            if let initialize {
                try transaction(write: true) {
                    try self.requireEmptyStore()
                    try self.exec("CREATE TABLE continuity_v1(id INTEGER PRIMARY KEY CHECK(id=1), mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16), committed BLOB NOT NULL, pending BLOB, repair INTEGER NOT NULL CHECK(repair IN (0,1))) STRICT")
                    try self.statement("INSERT INTO continuity_v1 VALUES(1,?,?,?,NULL,0)", [macID, accountID, try initialize.bytes]) { try self.done($0) }
                    try self.exec("PRAGMA application_id=1380801091")
                    try self.exec("PRAGMA user_version=1")
                }
            }
            try transaction(write: false) {
                if try self.scalar("PRAGMA user_version") == 4 {
                    try self.exec("SELECT epoch,intent,candidate FROM history_attempts_v1 LIMIT 0")
                }
                let state = try self.load()
                _ = try self.loadHistoryRecovery(state: state)
            }
        } catch { close(); throw error }
    }
    deinit { close() }

    func requireInitializationScope(path: String, mac: Data, account: Data) throws {
        try lease.validate()
        guard lease.databasePath == path, macID == mac, accountID == account else {
            throw AuthorityInitializationError.conflictingIntent
        }
    }

    public func read() throws -> ContinuityState {
        try transaction(write: false) {
            let state = try self.load()
            try self.requireNoHistoryRecovery(state: state)
            return state
        }
    }

    /// Read retained recovery evidence without opening ordinary checkpoint operations.
    func historyRecovery() throws -> HistoryRecoveryIntent? {
        try transaction(write: false) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            return try self.loadHistoryRecovery(state: state)
        }
    }

    /// Persist recovery evidence before changing any journal bytes. Migration and preparation are atomic.
    func prepareHistoryRecovery(_ intent: HistoryRecoveryIntent) throws {
        try transaction(write: true) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            try self.requireNoHistoryRecovery(state: state)
            guard state == intent.previous else { throw ContinuityStoreError.staleState }
            guard try self.loadSupersededHistory(epoch: intent.recoveryEpoch) == nil else {
                throw ContinuityStoreError.staleState
            }
            if try self.scalar("PRAGMA user_version") == 1 {
                try self.exec("ALTER TABLE continuity_v1 ADD COLUMN history BLOB")
                try self.exec("PRAGMA user_version=2")
            }
            try self.statement("UPDATE continuity_v1 SET history=? WHERE id=1", [try intent.bytes]) { try self.done($0) }
        }
    }

    /// The exact proposed boundary survives a crash before or after the journal commit.
    func historyRecoveryCandidate() throws -> ContinuityCheckpoint? {
        try transaction(write: false) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            return try self.loadHistoryCandidate(intent: self.loadHistoryRecovery(state: state))
        }
    }

    /// Call inside the journal transaction, after its mutations and before its commit.
    /// A retained candidate can only be retried unchanged; it cannot be replaced with newly observed bytes.
    func prepareHistoryRecoveryCandidate(expected: HistoryRecoveryIntent, candidate: ContinuityCheckpoint) throws {
        try transaction(write: true) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard try self.loadHistoryRecovery(state: state) == expected else { throw ContinuityStoreError.staleState }
            try self.validateHistoryCandidate(candidate, intent: expected)
            if let retained = try self.loadHistoryCandidate(intent: expected) {
                guard retained == candidate else { throw ContinuityStoreError.staleState }
                return
            }
            if try self.scalar("PRAGMA user_version") == 2 {
                try self.exec("ALTER TABLE continuity_v1 ADD COLUMN history_candidate BLOB")
                try self.exec("PRAGMA user_version=3")
            }
            try self.statement("UPDATE continuity_v1 SET history_candidate=? WHERE id=1",
                [try candidate.bytes]) { try self.done($0) }
        }
    }

    /// Retained evidence is read by epoch so history growth does not require an unbounded allocation.
    func supersededHistoryRecovery(epoch: Data) throws -> (intent: HistoryRecoveryIntent, candidate: ContinuityCheckpoint?)? {
        try transaction(write: false) {
            _ = try self.load()
            return try self.loadSupersededHistory(epoch: epoch)
        }
    }

    /// The caller must prove further history loss with unchanged authority before replacing an attempt.
    /// Archive and replacement share one durable transaction; ordinary admission stays closed.
    func supersedeHistoryRecovery(expected: HistoryRecoveryIntent, expectedCandidate: ContinuityCheckpoint?,
                                  replacement: HistoryRecoveryIntent) throws {
        try transaction(write: true) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard try self.loadHistoryRecovery(state: state) == expected,
                  try self.loadHistoryCandidate(intent: expected) == expectedCandidate else {
                throw ContinuityStoreError.staleState
            }
            guard replacement.previous == expected.previous,
                  replacement.authorityDigest == expected.authorityDigest,
                  replacement.recoveryEpoch != expected.recoveryEpoch,
                  replacement.ledgerDigest != expected.ledgerDigest,
                  replacement.ledgerDigest != expectedCandidate?.ledgerDigest,
                  try self.loadSupersededHistory(epoch: replacement.recoveryEpoch) == nil else {
                throw ContinuityStoreError.invalidCheckpoint
            }
            if try self.scalar("PRAGMA user_version") == 2 {
                try self.exec("ALTER TABLE continuity_v1 ADD COLUMN history_candidate BLOB")
            }
            if try self.scalar("PRAGMA user_version") < 4 {
                try self.exec("CREATE TABLE history_attempts_v1(epoch BLOB PRIMARY KEY CHECK(length(epoch)=16), intent BLOB NOT NULL CHECK(length(intent) BETWEEN 1 AND 1024), candidate BLOB CHECK(candidate IS NULL OR length(candidate) BETWEEN 1 AND 256)) STRICT, WITHOUT ROWID")
                try self.exec("PRAGMA user_version=4")
            }
            try self.statement("INSERT INTO history_attempts_v1 SELECT ?,history,history_candidate FROM continuity_v1 WHERE id=1",
                [expected.recoveryEpoch]) { try self.done($0) }
            try self.statement("UPDATE continuity_v1 SET history=?,history_candidate=NULL WHERE id=1",
                [try replacement.bytes]) { try self.done($0) }
        }
    }

    private func loadSupersededHistory(epoch: Data) throws -> (intent: HistoryRecoveryIntent, candidate: ContinuityCheckpoint?)? {
        guard epoch.count == 16 else { throw ContinuityStoreError.invalidCheckpoint }
        guard try scalar("PRAGMA user_version") == 4 else { return nil }
        return try statement("SELECT intent,candidate FROM history_attempts_v1 WHERE epoch=?", [epoch]) { stmt in
            let result = sqlite3_step(stmt)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw ContinuityStoreError.storage(result) }
            let intent = try HistoryRecoveryIntent.decode(self.blob(stmt, 0, maximumBytes: 1024))
            guard intent.recoveryEpoch == epoch else { throw ContinuityStoreError.incompatibleStore }
            let candidate = sqlite3_column_type(stmt, 1) == SQLITE_NULL ? nil : try ContinuityCheckpoint.decode(self.blob(stmt, 1))
            if let candidate { try self.validateHistoryCandidate(candidate, intent: intent) }
            return (intent, candidate)
        }
    }

    /// Call only after verifying the durable journal contains the gap evidence at this exact candidate boundary.
    func finalizeHistoryRecovery(expected: HistoryRecoveryIntent, candidate: ContinuityCheckpoint) throws {
        try transaction(write: true) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard try self.loadHistoryRecovery(state: state) == expected else { throw ContinuityStoreError.staleState }
            guard try self.loadHistoryCandidate(intent: expected) == candidate else {
                throw ContinuityStoreError.invalidCheckpoint
            }
            try self.statement("UPDATE continuity_v1 SET committed=?,pending=NULL,history=NULL,history_candidate=NULL WHERE id=1",
                [try candidate.bytes]) { try self.done($0) }
        }
    }

    private func requireNoHistoryRecovery(state: ContinuityState) throws {
        guard try loadHistoryRecovery(state: state) == nil else { throw ContinuityStoreError.historyRecoveryPending }
    }

    private func loadHistoryRecovery(state: ContinuityState) throws -> HistoryRecoveryIntent? {
        let version = try scalar("PRAGMA user_version")
        if version == 1 { return nil }
        guard (2...4).contains(version) else { throw ContinuityStoreError.incompatibleStore }
        let intent: HistoryRecoveryIntent? = try statement("SELECT history FROM continuity_v1 WHERE id=1") { stmt in
            try self.row(stmt)
            if sqlite3_column_type(stmt, 0) == SQLITE_NULL { return nil }
            let intent = try HistoryRecoveryIntent.decode(self.blob(stmt, 0, maximumBytes: 1024))
            guard intent.previous.committed == state.committed, intent.previous.pending == state.pending else {
                throw ContinuityStoreError.incompatibleStore
            }
            return intent
        }
        _ = try loadHistoryCandidate(intent: intent)
        return intent
    }

    private func loadHistoryCandidate(intent: HistoryRecoveryIntent?) throws -> ContinuityCheckpoint? {
        guard try scalar("PRAGMA user_version") >= 3 else { return nil }
        return try statement("SELECT history_candidate FROM continuity_v1 WHERE id=1") { stmt in
            try self.row(stmt)
            if sqlite3_column_type(stmt, 0) == SQLITE_NULL { return nil }
            guard let intent else { throw ContinuityStoreError.incompatibleStore }
            let candidate = try ContinuityCheckpoint.decode(self.blob(stmt, 0))
            try self.validateHistoryCandidate(candidate, intent: intent)
            return candidate
        }
    }

    private func validateHistoryCandidate(_ candidate: ContinuityCheckpoint, intent: HistoryRecoveryIntent) throws {
        guard candidate.generation == intent.checkpointGeneration,
              candidate.authorityGeneration == intent.authorityGeneration,
              candidate.authorityDigest == intent.authorityDigest,
              candidate.journalEpoch == intent.recoveryEpoch else { throw ContinuityStoreError.invalidCheckpoint }
    }

    /// Persist both boundaries before changing the journal. A return is not permission to dispatch.
    public func prepare(expected: ContinuityCheckpoint, candidate: ContinuityCheckpoint) throws {
        try transaction(write: true) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            try self.requireNoHistoryRecovery(state: state)
            guard state.committed == expected, state.pending == nil else { throw ContinuityStoreError.staleState }
            _ = try ContinuityState(committed: expected, pending: candidate, recoveryRequired: false)
            try self.statement("UPDATE continuity_v1 SET pending=? WHERE id=1", [try candidate.bytes]) { try self.done($0) }
        }
    }

    /// Call only after the journal's candidate boundary is durably committed and independently verified.
    public func finalize(expected: ContinuityState) throws {
        try transaction(write: true) {
            guard !expected.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            try self.requireNoHistoryRecovery(state: self.load())
            guard let pending = expected.pending, try self.load() == expected else { throw ContinuityStoreError.staleState }
            try self.statement("UPDATE continuity_v1 SET committed=?,pending=NULL WHERE id=1", [try pending.bytes]) { try self.done($0) }
        }
    }

    /// Recovery may discard preparation only after proving the journal still matches the committed boundary.
    public func discardPreparation(expected: ContinuityState) throws {
        try transaction(write: true) {
            guard !expected.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            try self.requireNoHistoryRecovery(state: self.load())
            guard expected.pending != nil, try self.load() == expected else { throw ContinuityStoreError.staleState }
            try self.exec("UPDATE continuity_v1 SET pending=NULL WHERE id=1")
        }
    }

    /// Sticky across reopen. This API intentionally has no repair-clearing operation.
    public func requireRecovery() throws {
        try transaction(write: true) { _ = try self.load(); try self.exec("UPDATE continuity_v1 SET repair=1 WHERE id=1") }
    }

    public func close() {
        if let db { _ = sqlite3_close_v2(db); self.db = nil }
        lease.close()
    }

    private func load() throws -> ContinuityState {
        guard try scalar("SELECT count(*) FROM continuity_v1") == 1 else { throw ContinuityStoreError.incompatibleStore }
        return try statement("SELECT mac,account,committed,pending,repair FROM continuity_v1 WHERE id=1") { stmt in
            try self.row(stmt)
            guard try self.blob(stmt, 0) == macID, try self.blob(stmt, 1) == accountID else { throw ContinuityStoreError.wrongScope }
            let committed = try ContinuityCheckpoint.decode(self.blob(stmt, 2))
            let pending = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? nil : try ContinuityCheckpoint.decode(self.blob(stmt, 3))
            let repair = sqlite3_column_int64(stmt, 4)
            guard sqlite3_column_type(stmt, 4) == SQLITE_INTEGER, (0...1).contains(repair) else { throw ContinuityStoreError.incompatibleStore }
            return try ContinuityState(committed: committed, pending: pending, recoveryRequired: repair == 1)
        }
    }
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
        guard db != nil else { throw ContinuityStoreError.closed }
        guard !unavailable else { throw ContinuityStoreError.unavailable }
        do { try lease.validate() } catch { unavailable = true; throw error }
        try exec(write ? "BEGIN IMMEDIATE" : "BEGIN")
        do {
            let value = try body()
            try lease.validate()
            do { try exec("COMMIT") } catch { unavailable = true; throw error }
            do { try lease.validate() } catch { unavailable = true; throw error }
            return value
        } catch {
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            throw error
        }
    }
    private func requireEmptyStore() throws {
        guard try scalar("PRAGMA application_id") == 0, try scalar("PRAGMA user_version") == 0,
              try scalar("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'") == 0 else {
            throw ContinuityStoreError.incompatibleStore
        }
    }
    private func row(_ stmt: OpaquePointer) throws {
        let result = sqlite3_step(stmt)
        guard result != SQLITE_DONE else { throw ContinuityStoreError.incompatibleStore }
        guard result == SQLITE_ROW else { throw ContinuityStoreError.storage(result) }
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw ContinuityStoreError.storage(result) }
    }
    private func statement<T>(_ sql: String, _ values: [Data] = [], _ body: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard result == SQLITE_OK, let stmt else { throw ContinuityStoreError.storage(result) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in values.enumerated() {
            let bound = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress,
                Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard bound == SQLITE_OK else { throw ContinuityStoreError.storage(bound) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws {
        let result = sqlite3_step(stmt)
        guard result == SQLITE_DONE else { throw ContinuityStoreError.storage(result) }
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) {
            try self.row($0)
            return sqlite3_column_int64($0, 0)
        }
    }
    private func blob(_ stmt: OpaquePointer, _ column: Int32, maximumBytes: Int = 256) throws -> Data {
        let count = sqlite3_column_bytes(stmt, column)
        guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, count > 0, count <= maximumBytes,
              let bytes = sqlite3_column_blob(stmt, column) else { throw ContinuityStoreError.incompatibleStore }
        return Data(bytes: bytes, count: Int(count))
    }
}
