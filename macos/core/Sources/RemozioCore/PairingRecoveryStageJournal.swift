import Foundation
import RemozioProtocol
import SQLite3

enum PairingRecoveryStageError: Error, Equatable {
    case pendingForIdentity, capacity, noPendingStage, notExpired
}

struct PairingRecoveryStage: Sendable {
    enum State: Int64, Sendable {
        case pending, committed, deadlineElapsed, retiredIncarnation, invalidated

        var expiryReason: PairingExpiryReason? {
            switch self {
            case .deadlineElapsed: .deadlineElapsed
            case .retiredIncarnation: .retiredIncarnation
            case .pending, .committed, .invalidated: nil
            }
        }
    }

    let transcript: PairingTranscript
    let proposalDigest: Data
    let transcriptDigest: Data
    let incarnation: UUID
    let started: UInt64
    let deadline: UInt64
    let state: State

    init(transcript: PairingTranscript, proposalDigest: Data, incarnation: UUID,
         started: UInt64, deadline: UInt64, state: State = .pending) throws {
        guard transcript.replacement?.phoneID == transcript.phone.scope.phoneID,
              proposalDigest.count == 32, started < deadline else { throw JournalDatabaseError.incompatibleStore }
        self.transcript = transcript
        self.proposalDigest = proposalDigest
        transcriptDigest = try transcript.digest()
        self.incarnation = incarnation
        self.started = started
        self.deadline = deadline
        self.state = state
    }
}

/// Uses the caller's authority journal transaction and inherits its owner and rollback boundary.
struct PairingRecoveryStageJournal {
    static let table = "pairing_recovery_stages_v1"
    private static let columns = "setup,phone,proposal,transcript,digest,incarnation,started,deadline,state"
    private static let maximumPending = 32
    let db: OpaquePointer

    static func createStorage(on db: OpaquePointer) throws {
        let result = sqlite3_exec(db, """
            CREATE TABLE main.\(table) (
                setup BLOB PRIMARY KEY CHECK(length(setup)=16),
                phone BLOB NOT NULL CHECK(length(phone)=16),
                proposal BLOB NOT NULL CHECK(length(proposal)=32),
                transcript BLOB NOT NULL CHECK(length(transcript) BETWEEN 1 AND 132000),
                digest BLOB NOT NULL CHECK(length(digest)=32),
                incarnation BLOB NOT NULL CHECK(length(incarnation)=16),
                started BLOB NOT NULL CHECK(length(started)=8),
                deadline BLOB NOT NULL CHECK(length(deadline)=8 AND started < deadline),
                state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 4)
            ) STRICT, WITHOUT ROWID;
            CREATE UNIQUE INDEX main.pairing_recovery_pending_phone_v1 ON \(table)(phone) WHERE state=0;
            """, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    static func validateStorage(on db: OpaquePointer) throws {
        try Self(db: db).statement("SELECT \(columns) FROM main.\(table) LIMIT 0", []) {
            guard sqlite3_step($0) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore }
        }
    }

    func stage(setupID: Data) throws -> PairingRecoveryStage? {
        try read("setup=?", [setupID])
    }

    func pending(phoneID: Data) throws -> PairingRecoveryStage? {
        try read("phone=? AND state=0", [phoneID])
    }

    func hasRetiredStages(incarnation: UUID) throws -> Bool {
        try statement("SELECT 1 FROM main.\(Self.table) WHERE state=0 AND incarnation<>? LIMIT 1",
                      [GatewayHostSnapshot.bytes(incarnation)]) {
            let step = sqlite3_step($0)
            guard step == SQLITE_ROW || step == SQLITE_DONE else { throw JournalDatabaseError.storage(step) }
            return step == SQLITE_ROW
        }
    }

    func reserve(_ stage: PairingRecoveryStage) throws {
        let scope = stage.transcript.phone.scope
        guard stage.state == .pending else { throw JournalDatabaseError.incompatibleStore }
        guard try pending(phoneID: scope.phoneID) == nil else { throw PairingRecoveryStageError.pendingForIdentity }
        try statement("SELECT count(*) FROM main.\(Self.table) WHERE state=0", []) {
            let step = sqlite3_step($0)
            guard step == SQLITE_ROW else { throw JournalDatabaseError.storage(step) }
            guard sqlite3_column_int64($0, 0) < Self.maximumPending else { throw PairingRecoveryStageError.capacity }
        }
        try mutate("INSERT INTO main.\(Self.table) (\(Self.columns)) VALUES(?,?,?,?,?,?,?,?,0)",
            [stage.transcript.setupID, scope.phoneID, stage.proposalDigest, try stage.transcript.encode(),
             stage.transcriptDigest, GatewayHostSnapshot.bytes(stage.incarnation), bytes(stage.started), bytes(stage.deadline)])
    }

    func finish(_ stage: PairingRecoveryStage, as state: PairingRecoveryStage.State) throws {
        guard stage.state == .pending, state != .pending else { throw PairingRecoveryStageError.noPendingStage }
        try mutate("UPDATE main.\(Self.table) SET state=\(state.rawValue) WHERE setup=? AND digest=? AND state=0",
                   [stage.transcript.setupID, stage.transcriptDigest])
        guard sqlite3_changes(db) == 1 else { throw PairingRecoveryStageError.noPendingStage }
    }

    func expireDueStages(now: AuthorityMoment) throws {
        try mutate("UPDATE main.\(Self.table) SET state=2 WHERE state=0 AND incarnation=? AND deadline<=?",
                   [GatewayHostSnapshot.bytes(now.epoch), bytes(now.milliseconds)])
    }

    func closeRetiredStages(incarnation: UUID) throws {
        try mutate("UPDATE main.\(Self.table) SET state=3 WHERE state=0 AND incarnation<>?", [GatewayHostSnapshot.bytes(incarnation)])
    }

    func invalidate(phoneID: Data) throws {
        try mutate("UPDATE main.\(Self.table) SET state=4 WHERE phone=? AND state=0", [phoneID])
    }

    func discardExpired(setupID: Data, digest: Data) throws {
        try mutate("DELETE FROM main.\(Self.table) WHERE setup=? AND digest=? AND state IN (2,3)", [setupID, digest])
        guard sqlite3_changes(db) == 1 else { throw PairingRecoveryStageError.notExpired }
    }

    private func read(_ predicate: String, _ values: [Data]) throws -> PairingRecoveryStage? {
        try statement("SELECT \(Self.columns) FROM main.\(Self.table) WHERE \(predicate)", values) { row in
            let step = sqlite3_step(row)
            if step == SQLITE_DONE { return nil }
            guard step == SQLITE_ROW else { throw JournalDatabaseError.storage(step) }
            let setup = try blob(row, 0, length: 16...16)
            let phone = try blob(row, 1, length: 16...16)
            let transcript = try PairingTranscript.decode(blob(row, 3, length: 1...132_000))
            guard transcript.setupID == setup, transcript.phone.scope.phoneID == phone,
                  sqlite3_column_type(row, 8) == SQLITE_INTEGER,
                  let state = PairingRecoveryStage.State(rawValue: sqlite3_column_int64(row, 8)) else {
                throw JournalDatabaseError.incompatibleStore
            }
            let stage = try PairingRecoveryStage(transcript: transcript, proposalDigest: blob(row, 2, length: 32...32),
                incarnation: GatewayHostSnapshot.uuid(blob(row, 5, length: 16...16)),
                started: number(row, 6), deadline: number(row, 7), state: state)
            guard try stage.transcriptDigest == blob(row, 4, length: 32...32),
                  sqlite3_step(row) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore }
            return stage
        }
    }

    private func mutate(_ sql: String, _ values: [Data]) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        try statement(sql, values) {
            let step = sqlite3_step($0)
            guard step == SQLITE_DONE else { throw JournalDatabaseError.storage(step) }
        }
    }

    private func statement<T>(_ sql: String, _ values: [Data], _ body: (OpaquePointer) throws -> T) throws -> T {
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard result == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(statement) }
        for (index, bytes) in values.enumerated() {
            let result = bytes.withUnsafeBytes {
                sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
        }
        return try body(statement)
    }

    private func blob(_ row: OpaquePointer, _ column: Int32, length: ClosedRange<Int>) throws -> Data {
        let count = Int(sqlite3_column_bytes(row, column))
        guard sqlite3_column_type(row, column) == SQLITE_BLOB, length.contains(count),
              let pointer = sqlite3_column_blob(row, column) else { throw JournalDatabaseError.incompatibleStore }
        return Data(bytes: pointer, count: count)
    }

    private func number(_ row: OpaquePointer, _ column: Int32) throws -> UInt64 {
        try blob(row, column, length: 8...8).withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self)) }
    }

    private func bytes(_ value: UInt64) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
