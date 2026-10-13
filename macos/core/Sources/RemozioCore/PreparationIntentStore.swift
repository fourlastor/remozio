import Foundation
import Darwin
import SQLite3

enum PreparationStoreError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongMac, closed, unavailable, transactionActive
    case capacity, notFound, staleRevision, invalidTransition, corruptRecord, inventoryNotEnabled, wrongInstallation
    case storage(Int32)
}

/// Serialized machine-scoped bookkeeping. Stored copy metadata grants no activation authority.
public final class PreparationIntentStore {
    private let lease: InstallationStorageLease
    private var db: OpaquePointer?
    private let maximumRecords: Int
    private let macID: Data
    private let didCommit: (() throws -> Void)?
    private var active = false
    private var unavailable = false
    private static let applicationID: Int64 = 0x524D4953

    public static func open(directoryPath: String, macID: Data, maximumRecords: Int = 64,
                     initialize: Bool = false) throws -> PreparationIntentStore {
        try .init(lease: InstallationStorageLease.acquire(directoryPath: directoryPath),
                  macID: macID, maximumRecords: maximumRecords, initialize: initialize)
    }
    // Internal fixture seam. The connection owns the lease even when initialization fails.
    init(lease: InstallationStorageLease, macID: Data, maximumRecords: Int, initialize: Bool,
         didCommit: (() throws -> Void)? = nil) throws {
        self.lease = lease; self.maximumRecords = maximumRecords; self.macID = macID; self.didCommit = didCommit
        do {
            guard macID.count == 16, (1...4096).contains(maximumRecords) else { throw PreparationStoreError.invalidConfiguration }
            try lease.validate()
            var connection: OpaquePointer?
            let result = sqlite3_open_v2(lease.databasePath, &connection,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard result == SQLITE_OK, let connection else { throw PreparationStoreError.storage(result) }
            try lease.validate()
            guard sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1,
                  sqlite3_busy_timeout(connection, 1000) == SQLITE_OK else { throw PreparationStoreError.invalidConfiguration }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, 32_768)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_SQL_LENGTH, 8192)
            try exec("PRAGMA trusted_schema=OFF")
            if initialize {
                guard try scalar("SELECT COUNT(*) FROM sqlite_master") == 0,
                      try scalar("PRAGMA user_version") == 0, try scalar("PRAGMA application_id") == 0 else {
                    throw PreparationStoreError.incompatibleStore
                }
            } else { try identity(macID) }
            try exec("PRAGMA journal_mode=DELETE")
            try exec("PRAGMA synchronous=EXTRA")
            try exec("PRAGMA fullfsync=ON")
            guard try scalar("PRAGMA synchronous") == 3, try scalar("PRAGMA fullfsync") == 1,
                  try scalar("PRAGMA trusted_schema") == 0,
                  try statement("PRAGMA journal_mode", { row in
                      guard try step(row) == SQLITE_ROW, let value = sqlite3_column_text(row, 0) else { return false }
                      return String(cString: value) == "delete"
                  }) else { throw PreparationStoreError.invalidConfiguration }
            if initialize {
                try transaction(write: true) {
                    try exec("CREATE TABLE installation_identity_v1(id INTEGER PRIMARY KEY CHECK(id=1),mac BLOB NOT NULL CHECK(length(mac)=16)) STRICT")
                    try exec("CREATE TABLE preparation_intents_v1(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384)) STRICT")
                    try statement("INSERT INTO installation_identity_v1 VALUES(1,?)") { row in
                        try bind(macID, column: 1, row: row)
                        guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
                    }
                    try exec("PRAGMA application_id=\(Self.applicationID)")
                    try exec("PRAGMA user_version=1")
                }
            }
            try identity(macID)
            if try scalar("PRAGMA user_version") == 2 { configureInventoryLimit() }
            try lease.validate()
        } catch { shutdown(); throw error }
    }
    deinit { shutdown() }
    public func close() throws {
        guard !active else { throw PreparationStoreError.transactionActive }
        shutdown()
    }
    /// Explicit storage upgrade only. It grants no service registration or update activation authority.
    public func enableInventoryStorage() throws {
        try requireRoot(); try upgradeInventoryStorage()
    }
    public func loadInventory() throws -> InstallationInventory? {
        try requireRoot(); return try inventory()
    }
    @discardableResult
    public func initializeInventory(_ value: InstallationInventory) throws -> InstallationInventory {
        try requireRoot(); return try writeInventory(value, expectedRevision: nil)
    }
    @discardableResult
    public func replaceInventory(_ value: InstallationInventory, expectedRevision: Data) throws -> InstallationInventory {
        try requireRoot(); return try writeInventory(value, expectedRevision: expectedRevision)
    }
    private func requireRoot() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
    }

    // Internal ordinary-owner seams retain the same lease, transaction and record checks.
    func upgradeInventoryStorage() throws {
        try transaction(write: true) {
            try identity(macID)
            if try scalar("PRAGMA user_version") == 2 { return }
            _ = try loadAll()
            try exec("CREATE TABLE installation_inventory_v1(id INTEGER PRIMARY KEY CHECK(id=1),installation BLOB NOT NULL CHECK(length(installation)=16),revision BLOB NOT NULL CHECK(length(revision)=16),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 65536)) STRICT")
            try exec("PRAGMA user_version=2")
            try identity(macID)
        }
        configureInventoryLimit()
    }
    func inventory() throws -> InstallationInventory? {
        try transaction(write: false) { try requireInventorySchema(); return try loadInventoryRecord() }
    }
    @discardableResult
    func writeInventory(_ value: InstallationInventory, expectedRevision: Data?) throws -> InstallationInventory {
        guard value.macID == macID, expectedRevision == nil || expectedRevision?.count == 16 else {
            throw PreparationStoreError.invalidConfiguration
        }
        return try transaction(write: true) {
            try requireInventorySchema()
            let previous = try loadInventoryRecord()
            var revision = bytes(UUID())
            while revision == value.revision || revision == previous?.revision { revision = bytes(UUID()) }
            let retained = try InstallationInventory(macID: value.macID, installationID: value.installationID,
                revision: revision, bundlePath: value.bundlePath, releaseDigest: value.releaseDigest,
                accounts: value.accounts, services: value.services)
            if let expectedRevision {
                guard let previous else { throw PreparationStoreError.notFound }
                guard previous.revision == expectedRevision else {
                    throw PreparationStoreError.staleRevision
                }
                guard previous.installationID == value.installationID else { throw PreparationStoreError.wrongInstallation }
                try statement("UPDATE installation_inventory_v1 SET revision=?,record=? WHERE id=1 AND installation=? AND revision=?") { row in
                    try bind(retained.revision, column: 1, row: row)
                    try bind(retained.canonicalBytes, column: 2, row: row)
                    try bind(value.installationID, column: 3, row: row)
                    try bind(expectedRevision, column: 4, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
                }
            } else {
                guard previous == nil else { throw PreparationStoreError.invalidTransition }
                try statement("INSERT INTO installation_inventory_v1 VALUES(1,?,?,?)") { row in
                    try bind(value.installationID, column: 1, row: row)
                    try bind(retained.revision, column: 2, row: row)
                    try bind(retained.canonicalBytes, column: 3, row: row)
                    guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.corruptRecord }
                }
            }
            return retained
        }
    }
    private func configureInventoryLimit() {
        if let db { _ = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 69_632) }
    }
    private func requireInventorySchema() throws {
        try identity(macID)
        guard try scalar("PRAGMA user_version") == 2 else { throw PreparationStoreError.inventoryNotEnabled }
    }
    private func loadInventoryRecord() throws -> InstallationInventory? {
        try statement("SELECT id,installation,revision,record FROM installation_inventory_v1 ORDER BY id") { row in
            let result = try step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER,
                  sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.corruptRecord }
            let value: InstallationInventory
            do { value = try .decode(blob(row, column: 3, maximum: 65_536), expectedMacID: macID) }
            catch { throw PreparationStoreError.corruptRecord }
            guard try blob(row, column: 1, maximum: 16) == value.installationID,
                  try blob(row, column: 2, maximum: 16) == value.revision, try step(row) == SQLITE_DONE else {
                throw PreparationStoreError.corruptRecord
            }
            return value
        }
    }
    func records() throws -> [PreparationIntentRecord] { try transaction(write: false) { try loadAll() } }
    func begin(parent: String, ancestry: [PreparationFileIdentity]) throws -> PreparationIntentRecord {
        try transaction(write: true) {
            let retained = try loadAll()
            guard retained.count < maximumRecords, retained.count < 4096 else { throw PreparationStoreError.capacity }
            let value = try PreparationIntentRecord(id: UUID(), revision: UUID(), parent: parent, ancestry: ancestry, phase: .intent)
            try statement("INSERT INTO preparation_intents_v1 VALUES(?,?,?)") { row in
                try bind(bytes(value.id), column: 1, row: row)
                try bind(bytes(value.revision), column: 2, row: row)
                try bind(value.encoded, column: 3, row: row)
                guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.corruptRecord }
            }
            return value
        }
    }
    func recordCopy(id: UUID, expectedRevision: UUID, identity: PreparationFileIdentity,
                    digest: Data) throws -> PreparationIntentRecord {
        try change(id: id, expectedRevision: expectedRevision, phase: .copyRecorded, identity: identity, digest: digest)
    }
    func abandon(id: UUID, expectedRevision: UUID) throws -> PreparationIntentRecord {
        try change(id: id, expectedRevision: expectedRevision, phase: .abandoned, identity: nil, digest: nil)
    }
    // Only the Core reconciler calls this after confirming copy absence under the bound destination lease.
    func forgetAbsentAbandoned(id: UUID, expectedRevision: UUID) throws {
        try transaction(write: true) {
            guard let previous = try loadAll().first(where: { $0.id == id }) else { throw PreparationStoreError.notFound }
            guard previous.revision == expectedRevision else { throw PreparationStoreError.staleRevision }
            guard previous.phase == .abandoned else { throw PreparationStoreError.invalidTransition }
            try statement("DELETE FROM preparation_intents_v1 WHERE id=? AND revision=?") { row in
                try bind(bytes(id), column: 1, row: row)
                try bind(bytes(expectedRevision), column: 2, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
        }
    }
    private func change(id: UUID, expectedRevision: UUID, phase: PreparationRecordPhase,
                        identity: PreparationFileIdentity?, digest: Data?) throws -> PreparationIntentRecord {
        try transaction(write: true) {
            guard let previous = try loadAll().first(where: { $0.id == id }) else { throw PreparationStoreError.notFound }
            guard previous.revision == expectedRevision else { throw PreparationStoreError.staleRevision }
            guard previous.phase != .abandoned,
                  phase == .abandoned || previous.phase == .intent else { throw PreparationStoreError.invalidTransition }
            let value = try PreparationIntentRecord(id: id, revision: UUID(), parent: previous.parent,
                ancestry: previous.ancestry, phase: phase, copyIdentity: identity ?? previous.copyIdentity,
                copyDigest: digest ?? previous.copyDigest)
            try statement("UPDATE preparation_intents_v1 SET revision=?,record=? WHERE id=? AND revision=?") { row in
                try bind(bytes(value.revision), column: 1, row: row)
                try bind(value.encoded, column: 2, row: row)
                try bind(bytes(id), column: 3, row: row)
                try bind(bytes(expectedRevision), column: 4, row: row)
                guard try step(row) == SQLITE_DONE, sqlite3_changes(db) == 1 else { throw PreparationStoreError.staleRevision }
            }
            return value
        }
    }
    private func identity(_ macID: Data) throws {
        let version = try scalar("PRAGMA user_version")
        guard try scalar("PRAGMA application_id") == Self.applicationID, [1, 2].contains(version),
              try scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'") == (version == 1 ? 2 : 3) else {
            throw PreparationStoreError.incompatibleStore
        }
        let names = try statement("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name") { row in
            var names: [String] = []
            while try step(row) == SQLITE_ROW {
                guard names.count < 3, sqlite3_column_type(row, 0) == SQLITE_TEXT,
                      let name = sqlite3_column_text(row, 0), let type = sqlite3_column_text(row, 1),
                      String(cString: type) == "table" else { throw PreparationStoreError.incompatibleStore }
                names.append(String(cString: name))
            }
            return names
        }
        let expected = version == 1 ? ["installation_identity_v1", "preparation_intents_v1"] :
            ["installation_identity_v1", "installation_inventory_v1", "preparation_intents_v1"]
        guard names == expected else { throw PreparationStoreError.incompatibleStore }
        try statement("SELECT id,mac FROM installation_identity_v1") { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 1 else { throw PreparationStoreError.incompatibleStore }
            guard try blob(row, column: 1, maximum: 16) == macID else { throw PreparationStoreError.wrongMac }
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.incompatibleStore }
        }
    }
    private func loadAll() throws -> [PreparationIntentRecord] {
        try statement("SELECT id,revision,record FROM preparation_intents_v1 ORDER BY id LIMIT 4097") { row in
            var result: [PreparationIntentRecord] = []
            while try step(row) == SQLITE_ROW {
                guard result.count < 4096 else { throw PreparationStoreError.corruptRecord }
                let value: PreparationIntentRecord
                do { value = try .decode(blob(row, column: 2, maximum: PreparationIntentRecord.maximumBytes)) }
                catch { throw PreparationStoreError.corruptRecord }
                guard try blob(row, column: 0, maximum: 16) == bytes(value.id),
                      try blob(row, column: 1, maximum: 16) == bytes(value.revision) else { throw PreparationStoreError.corruptRecord }
                result.append(value)
            }
            return result
        }
    }
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
        guard !unavailable else { throw PreparationStoreError.unavailable }
        guard db != nil else { throw PreparationStoreError.closed }
        guard !active else { throw PreparationStoreError.transactionActive }
        do { try lease.validate() } catch { unavailable = true; shutdown(); throw error }
        do { try exec(write ? "BEGIN IMMEDIATE" : "BEGIN") }
        catch {
            if Self.isSQLiteCorruption(error) { unavailable = true; shutdown() }
            throw error
        }
        active = true; defer { active = false }
        do {
            let value = try body()
            try lease.validate()
            do { try exec("COMMIT"); if write { try didCommit?() } } catch { unavailable = true; throw error }
            try lease.validate()
            return value
        } catch {
            if error as? PreparationStoreError == .corruptRecord || error as? PreparationStoreError == .incompatibleStore || error is JournalLeaseError || Self.isSQLiteCorruption(error) {
                unavailable = true
            }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            if unavailable { shutdown() }
            throw error
        }
    }
    private static func isSQLiteCorruption(_ error: any Error) -> Bool {
        guard case PreparationStoreError.storage(let code) = error else { return false }
        let primary = code & 0xff
        return primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB
    }
    private func bytes(_ id: UUID) -> Data {
        var value = id.uuid
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    private func bind(_ data: Data, column: Int32, row: OpaquePointer) throws {
        let result = data.withUnsafeBytes {
            sqlite3_bind_blob(row, column, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        guard result == SQLITE_OK else { throw PreparationStoreError.storage(result) }
    }
    private func blob(_ row: OpaquePointer, column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(row, column))
        guard sqlite3_column_type(row, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let pointer = sqlite3_column_blob(row, column) else { throw PreparationStoreError.corruptRecord }
        return Data(bytes: pointer, count: count)
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) { row in
            guard try step(row) == SQLITE_ROW, sqlite3_column_type(row, 0) == SQLITE_INTEGER else { throw PreparationStoreError.incompatibleStore }
            let result = sqlite3_column_int64(row, 0)
            guard try step(row) == SQLITE_DONE else { throw PreparationStoreError.incompatibleStore }
            return result
        }
    }
    private func exec(_ sql: String) throws {
        guard let db else { throw PreparationStoreError.closed }
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw PreparationStoreError.storage(result) }
    }
    private func step(_ row: OpaquePointer) throws -> Int32 {
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw PreparationStoreError.storage(result) }
        return result
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        guard let db else { throw PreparationStoreError.closed }
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw PreparationStoreError.storage(result) }
        defer { sqlite3_finalize(row) }
        return try body(row)
    }
    private func shutdown() {
        if let db { _ = sqlite3_close_v2(db) }
        db = nil; lease.close()
    }
}
