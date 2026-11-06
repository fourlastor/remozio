import Foundation
import SQLite3

/// Uses only the enclosing journal transaction. No connection or statement escapes this owner.
final class CodePolicyJournal {
    private let db: OpaquePointer
    init(connection: OpaquePointer) { db = connection }

    func read() throws -> AuthorityCodePolicySnapshot? {
        let version = try schemaVersion()
        guard (12...17).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        if version == 12 { return nil }
        return try statement("SELECT id,revision,policy FROM main.authority_code_policy_v1") { row in
            // Version 13 is committed only with a complete policy. An absent row is not first-time setup.
            guard try step(row) == SQLITE_ROW, sqlite3_column_int64(row, 0) == 1 else { throw AuthorityCodePolicyError.corruptData }
            let revisionBytes = try blob(row, column: 1, maximum: 16)
            guard revisionBytes.count == 16 else { throw AuthorityCodePolicyError.corruptData }
            let revision = revisionBytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
            let snapshot = try AuthorityCodePolicySnapshot.decodeStored(blob(row, column: 2, maximum: AuthorityCodePolicy.maximumBytes), revision: revision)
            guard try step(row) == SQLITE_DONE else { throw AuthorityCodePolicyError.corruptData }
            return snapshot
        }
    }

    func install(_ policy: AuthorityCodePolicy, expectedRevision: UUID?) throws -> AuthorityCodePolicySnapshot {
        let previous = try read()
        guard previous?.revision == expectedRevision else { throw AuthorityCodePolicyError.staleRevision }
        if let previous {
            try policy.requireSuccessor(of: previous.policy)
            if previous.policy == policy { return previous }
        } else {
            try exec("""
                CREATE TABLE main.authority_code_policy_v1(id INTEGER PRIMARY KEY CHECK(id=1),
                    revision BLOB NOT NULL CHECK(length(revision)=16),
                    policy BLOB NOT NULL CHECK(length(policy) BETWEEN 1 AND 8192)) STRICT;
                PRAGMA main.user_version=13;
                """)
        }
        let revision = UUID()
        var raw = revision.uuid
        let revisionBytes = withUnsafeBytes(of: &raw) { Data($0) }
        let revisions = Dictionary(uniqueKeysWithValues: policy.entries.map { entry -> (AuthorityCodeRole, UUID) in
            if let previous, previous.policy.entries.first(where: { $0.role == entry.role }) == entry,
               let revision = previous.roleRevisions[entry.role] { return (entry.role, revision) }
            return (entry.role, UUID())
        })
        let snapshot = AuthorityCodePolicySnapshot(revision: revision, policy: policy, roleRevisions: revisions)
        let bytes = try snapshot.storedBytes
        try statement("INSERT INTO main.authority_code_policy_v1 VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,policy=excluded.policy") { row in
            try bind(revisionBytes, column: 1, row: row)
            try bind(bytes, column: 2, row: row)
            guard try step(row) == SQLITE_DONE else { throw AuthorityCodePolicyError.corruptData }
        }
        return snapshot
    }

    private func schemaVersion() throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        return try statement("PRAGMA main.user_version") { row in
            guard try step(row) == SQLITE_ROW else { throw JournalDatabaseError.incompatibleStore }
            return sqlite3_column_int64(row, 0)
        }
    }
    private func blob(_ row: OpaquePointer, column: Int32, maximum: Int) throws -> Data {
        guard sqlite3_column_type(row, column) == SQLITE_BLOB else { throw AuthorityCodePolicyError.corruptData }
        let length = Int(sqlite3_column_bytes(row, column))
        guard length > 0, length <= maximum, let bytes = sqlite3_column_blob(row, column) else { throw AuthorityCodePolicyError.corruptData }
        return Data(bytes: bytes, count: length)
    }
    private func bind(_ value: Data, column: Int32, row: OpaquePointer) throws {
        let result = value.withUnsafeBytes {
            sqlite3_bind_blob(row, column, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
    private func step(_ row: OpaquePointer) throws -> Int32 {
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw JournalDatabaseError.storage(result) }
        return result
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(row) }
        return try body(row)
    }
}
