import Foundation
import RemozioProtocol
#if os(Linux)
import CSQLite
#else
import SQLite3
#endif

public enum AuditJournalError: Error, Equatable {
    case transactionRequired, writeTransactionRequired, invalidScope, invalidBounds
    case unavailableEpoch, headMismatch, invalidRecord, corruptData, storage(Int32)
}

/// An epoch created by this table owner. Persisted epochs cannot acquire a new writer through this API.
public final class AuditEpochWriter {
    fileprivate let owner: UUID
    public let epoch: Data
    fileprivate init(owner: UUID, epoch: Data) { self.owner = owner; self.epoch = epoch }
}

public struct AuditJournalPage {
    public let epoch: AuditEpochRead
    public let canonicalRecords: [Data]
}

/// Metadata tables in the authority's existing SQLite connection, not a separate execution ledger.
/// The caller owns connection lifetime, serial access, protected storage, recovery and outer transactions.
public final class AuditJournalTables {
    private let db: OpaquePointer
    private let owner = UUID()
    private var activeEpoch: Data?
    private let macID: Data
    private let accountID: Data
    private let recordLimits: CBORLimits
    private let descriptorLimits: CBORLimits

    public init(connection: OpaquePointer, macID: Data, accountID: Data,
                recordLimits: CBORLimits, descriptorLimits: CBORLimits) throws {
        guard macID.count == 16, accountID.count == 16 else { throw AuditJournalError.invalidScope }
        self.db = connection; self.macID = macID; self.accountID = accountID
        self.recordLimits = recordLimits; self.descriptorLimits = descriptorLimits
    }

    /// Run once in the owner's schema migration transaction. Existing tables are an error, never replaced.
    public func createSchema() throws {
        try writeTransaction()
        try atomic {
            try exec("""
                CREATE TABLE main.audit_epochs_v1 (
                    mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
                    epoch BLOB NOT NULL CHECK(length(epoch)=16), descriptor BLOB NOT NULL,
                    head BLOB NOT NULL CHECK(length(head)=8), retained BLOB NOT NULL CHECK(length(retained)=8),
                    PRIMARY KEY(mac,account,epoch), CHECK(retained<=head)
                ) STRICT, WITHOUT ROWID
                """)
            try exec("""
                CREATE TABLE main.audit_records_v1 (
                    mac BLOB NOT NULL, account BLOB NOT NULL, epoch BLOB NOT NULL,
                    sequence BLOB NOT NULL CHECK(length(sequence)=8), event BLOB NOT NULL CHECK(length(event)=16),
                    body BLOB NOT NULL, PRIMARY KEY(mac,account,epoch,sequence), UNIQUE(mac,account,epoch,event)
                ) STRICT, WITHOUT ROWID
                """)
        }
    }

    /// Call only after ownership and authority continuity validation. Supply a fresh random epoch per start.
    /// The returned handle grants no action authority and does not mean that the outer transaction committed.
    public func createEpoch(_ descriptor: AuditEpochDescriptor) throws -> AuditEpochWriter {
        try writeTransaction()
        guard descriptor.macID == macID, descriptor.accountID == accountID else { throw AuditJournalError.invalidScope }
        let body = try descriptor.encode(limits: descriptorLimits)
        try statement("INSERT INTO main.audit_epochs_v1 VALUES(?,?,?,?,?,?)",
                      scope(descriptor.epoch) + [body, uint(0), uint(0)]) { try done($0) }
        activeEpoch = descriptor.epoch
        return AuditEpochWriter(owner: owner, epoch: descriptor.epoch)
    }

    /// Commit this mutation with consumption in the same outer transaction. A return is not a dispatch permit.
    public func append(_ canonicalRecord: Data, writer: AuditEpochWriter, expectedHead: UInt64) throws {
        try writeTransaction()
        guard writer.owner == owner, writer.epoch == activeEpoch, expectedHead < UInt64.max else { throw AuditJournalError.headMismatch }
        let record = try AuditEventMetadata.decode(canonicalRecord, limits: recordLimits)
        guard record.macID == macID, record.accountID == accountID, record.journalEpoch == writer.epoch,
              record.sequence == expectedHead + 1 else { throw AuditJournalError.invalidRecord }
        try atomic {
            try statement("UPDATE main.audit_epochs_v1 SET head=? WHERE mac=? AND account=? AND epoch=? AND head=?",
                          [uint(record.sequence)] + scope(writer.epoch) + [uint(expectedHead)]) {
                try done($0)
                guard sqlite3_changes(db) == 1 else { throw AuditJournalError.headMismatch }
            }
            try statement("INSERT INTO main.audit_records_v1 VALUES(?,?,?,?,?,?)",
                          scope(writer.epoch) + [uint(record.sequence), record.eventID, canonicalRecord]) { try done($0) }
        }
    }

    public func epoch(_ id: Data) throws -> AuditEpochRead? {
        try transaction()
        guard id.count == 16 else { throw AuditJournalError.invalidScope }
        return try statement("SELECT descriptor,head,retained FROM main.audit_epochs_v1 WHERE mac=? AND account=? AND epoch=?", scope(id)) {
            let rc = sqlite3_step($0)
            if rc == SQLITE_DONE { return nil }
            try row(rc)
            let descriptor = try AuditEpochDescriptor.decode(blob($0, 0, maximum: descriptorLimits.maxBytes), limits: descriptorLimits)
            guard descriptor.macID == macID, descriptor.accountID == accountID, descriptor.epoch == id else {
                throw AuditJournalError.corruptData
            }
            return try AuditEpochRead(descriptor: descriptor, retainedAfter: number(blob($0, 2, maximum: 8)),
                                      head: number(blob($0, 1, maximum: 8)))
        }
    }

    /// The outer read transaction keeps the descriptor, boundaries and page in one snapshot.
    /// Byte exhaustion returns a shorter nonempty page. A record that cannot fit fails explicitly.
    public func page(epoch id: Data, after: UInt64, maximumRecords: Int, maximumBytes: Int) throws -> AuditJournalPage {
        try transaction()
        guard maximumRecords > 0, maximumRecords <= Int(Int32.max), maximumBytes > 0 else { throw AuditJournalError.invalidBounds }
        guard let epoch = try epoch(id) else { throw AuditJournalError.unavailableEpoch }
        guard after <= epoch.head else { throw AuditJournalError.headMismatch }
        let start = max(after, epoch.retainedAfter)
        var records: [Data] = [], bytes = 0, cursor = start
        var byteLimited = false
        try statement("SELECT sequence,event,body FROM main.audit_records_v1 WHERE mac=? AND account=? AND epoch=? AND sequence>? ORDER BY sequence LIMIT ?",
                      scope(id) + [uint(start)], integer: maximumRecords) { stmt in
            while true {
                let rc = sqlite3_step(stmt)
                if rc == SQLITE_DONE { break }
                try row(rc)
                let sequence = try number(blob(stmt, 0, maximum: 8))
                guard cursor < UInt64.max, sequence == cursor + 1, sequence <= epoch.head else { throw AuditJournalError.corruptData }
                let body = try blob(stmt, 2, maximum: recordLimits.maxBytes)
                let record = try AuditEventMetadata.decode(body, limits: recordLimits)
                guard record.macID == macID, record.accountID == accountID, record.journalEpoch == id,
                      record.sequence == sequence, record.eventID == (try blob(stmt, 1, maximum: 16)) else { throw AuditJournalError.corruptData }
                if body.count > maximumBytes - bytes {
                    guard !records.isEmpty else { throw AuditJournalError.invalidBounds }
                    byteLimited = true
                    break
                }
                records.append(body); bytes += body.count; cursor = sequence
            }
        }
        // An exhausted short page must reach the head; otherwise a retained record disappeared.
        if records.isEmpty && start < epoch.head { throw AuditJournalError.corruptData }
        if !byteLimited && records.count < maximumRecords && cursor < epoch.head { throw AuditJournalError.corruptData }
        return AuditJournalPage(epoch: epoch, canonicalRecords: records)
    }

    /// Explicit retention only. The owner selects the policy and keeps this transaction separate from admission.
    public func prune(epoch id: Data, through: UInt64, expectedHead: UInt64) throws {
        try writeTransaction()
        guard let read = try epoch(id), read.head == expectedHead,
              through >= read.retainedAfter, through <= read.head else { throw AuditJournalError.headMismatch }
        try atomic {
            try statement("DELETE FROM main.audit_records_v1 WHERE mac=? AND account=? AND epoch=? AND sequence<=?", scope(id) + [uint(through)]) { try done($0) }
            try statement("UPDATE main.audit_epochs_v1 SET retained=? WHERE mac=? AND account=? AND epoch=? AND head=?",
                          [uint(through)] + scope(id) + [uint(expectedHead)]) {
                try done($0)
                guard sqlite3_changes(db) == 1 else { throw AuditJournalError.headMismatch }
            }
        }
    }

    // Consumption must append through the exact same connection and scope before either table can commit.
    func matchesConsumptionContext(connection: OpaquePointer, macID: Data, accountID: Data) -> Bool {
        db == connection && self.macID == macID && self.accountID == accountID
    }

    private func transaction() throws {
        guard sqlite3_get_autocommit(db) == 0 else { throw AuditJournalError.transactionRequired }
    }
    private func writeTransaction() throws {
        try transaction()
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw AuditJournalError.writeTransactionRequired }
    }
    private func atomic<T>(_ operation: () throws -> T) throws -> T {
        try exec("SAVEPOINT remozio_audit_tables")
        do {
            let result = try operation()
            try exec("RELEASE remozio_audit_tables")
            return result
        } catch {
            // SQLite may already have rolled back the outer transaction after a storage error.
            if sqlite3_get_autocommit(db) == 0 {
                do { try exec("ROLLBACK TO remozio_audit_tables"); try exec("RELEASE remozio_audit_tables") }
                catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
            }
            throw error
        }
    }
    private func exec(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw AuditJournalError.storage(rc) }
    }
    private func statement<T>(_ sql: String, _ blobs: [Data], integer: Int? = nil, _ use: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw AuditJournalError.storage(rc) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in blobs.enumerated() {
            guard value.count <= Int(Int32.max) else { throw AuditJournalError.invalidBounds }
            let bound = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard bound == SQLITE_OK else { throw AuditJournalError.storage(bound) }
        }
        if let integer {
            let bound = sqlite3_bind_int64(stmt, Int32(blobs.count + 1), Int64(integer))
            guard bound == SQLITE_OK else { throw AuditJournalError.storage(bound) }
        }
        return try use(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws {
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else { throw AuditJournalError.storage(rc) }
    }
    private func row(_ rc: Int32) throws {
        guard rc == SQLITE_ROW else { throw rc == SQLITE_DONE ? AuditJournalError.corruptData : AuditJournalError.storage(rc) }
    }
    private func blob(_ stmt: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
        guard sqlite3_column_type(stmt, column) == SQLITE_BLOB else { throw AuditJournalError.corruptData }
        let count = Int(sqlite3_column_bytes(stmt, column))
        guard count > 0, count <= maximum, let pointer = sqlite3_column_blob(stmt, column) else { throw AuditJournalError.corruptData }
        return Data(bytes: pointer, count: count)
    }
    private func scope(_ epoch: Data) -> [Data] { [macID, accountID, epoch] }
    private func uint(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
    private func number(_ data: Data) throws -> UInt64 {
        guard data.count == 8 else { throw AuditJournalError.corruptData }
        return data.reduce(0) { ($0 << 8) | UInt64($1) }
    }
}
