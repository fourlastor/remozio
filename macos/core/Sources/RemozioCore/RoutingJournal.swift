import Foundation
import RemozioProtocol
import Security
import SQLite3

public enum RoutingJournalError: Error, Equatable {
    case disabled, invalidConfiguration, corruptData, conflict, exhausted, capacityExceeded
    case invalidClock, expired, unavailableChallenge, wrongBinding, wrongKey, invalidSignature
}

public struct RoutingState: Equatable, Sendable {
    public let mode: RoutingMode
    public let revision: UInt64
}

public struct RoutingChange: Sendable {
    public let state: RoutingState
    public let inserted: Bool
}

public struct RoutingJournalPolicy: Sendable {
    public let clockEpoch: UUID
    public let challengeLifetimeMillis: UInt64
    public let maximumOperations: Int
    public let payloadLimits: CBORLimits
    public let signingLimits: CBORLimits
    public init(clockEpoch: UUID, challengeLifetimeMillis: UInt64, maximumOperations: Int,
                payloadLimits: CBORLimits, signingLimits: CBORLimits) throws {
        guard challengeLifetimeMillis > 0, challengeLifetimeMillis <= 86_400_000,
              maximumOperations > 0, maximumOperations <= 100_000,
              payloadLimits.maxBytes <= 65536, signingLimits.maxBytes <= 131072 else { throw RoutingJournalError.invalidConfiguration }
        self.clockEpoch = clockEpoch; self.challengeLifetimeMillis = challengeLifetimeMillis
        self.maximumOperations = maximumOperations; self.payloadLimits = payloadLimits; self.signingLimits = signingLimits
    }
}

/// Private storage owner. Calls run within the root journal transaction and never expose a raw connection.
final class RoutingJournal {
    private let db: OpaquePointer
    private let mac: Data
    private let account: Data
    private let policy: RoutingJournalPolicy
    private let run = UUID()
    private var lastMoment: UInt64?
    init(connection: OpaquePointer, macID: Data, accountID: Data, policy: RoutingJournalPolicy) {
        db = connection; mac = macID; account = accountID; self.policy = policy
    }
    static func createSchema(_ db: OpaquePointer) throws {
        let rc = sqlite3_exec(db, """
            CREATE TABLE main.routing_state_v1(id INTEGER PRIMARY KEY CHECK(id=1), mode INTEGER NOT NULL CHECK(mode IN (0,1,2)),
                revision BLOB NOT NULL CHECK(length(revision)=8)) STRICT;
            INSERT INTO main.routing_state_v1 VALUES(1,0,x'0000000000000000');
            CREATE TABLE main.routing_operations_v1(operation BLOB PRIMARY KEY CHECK(length(operation)=16), payload BLOB NOT NULL,
                run BLOB NOT NULL CHECK(length(run)=16), started BLOB NOT NULL CHECK(length(started)=8),
                deadline BLOB NOT NULL CHECK(length(deadline)=8), consumed BLOB CHECK(consumed IS NULL OR length(consumed)=8)) STRICT, WITHOUT ROWID;
            """, nil, nil, nil)
        guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
    }
    var scope: (macID: Data, accountID: Data) { (mac, account) }

    func state() throws -> RoutingState {
        try statement("SELECT mode,revision FROM main.routing_state_v1 WHERE id=1", []) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw RoutingJournalError.corruptData }
            let mode: RoutingMode
            switch sqlite3_column_int64($0, 0) { case 0: mode = .automatic; case 1: mode = .present; case 2: mode = .away
            default: throw RoutingJournalError.corruptData }
            return try RoutingState(mode: mode, revision: uint(blob($0, 1)))
        }
    }
    func setLocal(_ mode: RoutingMode, expected: UInt64) throws -> RoutingState {
        try advance(mode, expected: expected)
    }
    func issue(enrollment: StoredApprovalEnrollment, expected: UInt64, wall: UInt64, now: AuthorityMoment) throws -> RoutingAwayControl {
        try clock(now)
        guard try state().revision == expected else { throw RoutingJournalError.conflict }
        guard expected < UInt64.max else { throw RoutingJournalError.exhausted }
        guard let key = enrollment.approval.keys.first(where: { $0.keyClass == .decision }) else { throw RoutingJournalError.wrongKey }
        let expires = wall.addingReportingOverflow(policy.challengeLifetimeMillis)
        let deadline = now.milliseconds.addingReportingOverflow(policy.challengeLifetimeMillis)
        guard !expires.overflow, !deadline.overflow else { throw RoutingJournalError.invalidClock }
        try ensureOperationCapacity(now: now.milliseconds)
        var challenge = Data(count: 32)
        guard challenge.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw RoutingJournalError.unavailableChallenge
        }
        let control = try RoutingAwayControl(macID: mac, accountID: account, phoneID: enrollment.approval.phoneID,
            enrollmentEpoch: enrollment.epoch, operationID: bytes(UUID()), challenge: challenge, keyID: key.id,
            expectedRevision: expected, issuedAtUnixMillis: wall, expiresAtUnixMillis: expires.partialValue)
        try statement("INSERT INTO main.routing_operations_v1 VALUES(?,?,?,?,?,NULL)",
            [control.operationID, try control.encode(limits: policy.payloadLimits), bytes(run), uint(now.milliseconds), uint(deadline.partialValue)]) { try done($0) }
        return control
    }
    private func ensureOperationCapacity(now: UInt64) throws {
        let maximum = Int64(policy.maximumOperations)
        guard try operationCount() >= maximum else { return }
        let scope = [bytes(run), uint(now)]
        try statement("""
            DELETE FROM main.routing_operations_v1
            WHERE consumed IS NULL AND (run<>? OR deadline<=?)
            """, scope) { try done($0) }
        let remaining = try operationCount()
        guard remaining >= maximum else { return }

        // Keep current-run receipts through their original retry window.
        let needed = remaining - maximum + 1
        try statement("""
            DELETE FROM main.routing_operations_v1 WHERE operation IN (
                SELECT operation FROM main.routing_operations_v1
                WHERE consumed IS NOT NULL AND (run<>? OR deadline<=?)
                ORDER BY consumed, operation LIMIT \(needed)
            )
            """, scope) { try done($0) }
        guard try operationCount() < maximum else { throw RoutingJournalError.capacityExceeded }
    }
    private func operationCount() throws -> Int64 {
        try statement("SELECT count(*) FROM main.routing_operations_v1", []) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw RoutingJournalError.corruptData }
            return sqlite3_column_int64($0, 0)
        }
    }

    func apply(payload: Data, signature: Data, enrollment: StoredApprovalEnrollment, wall: UInt64, now: AuthorityMoment) throws -> RoutingChange {
        try clock(now)
        let control = try RoutingAwayControl.decode(payload, limits: policy.payloadLimits)
        guard control.macID == mac, control.accountID == account, control.phoneID == enrollment.approval.phoneID,
              control.enrollmentEpoch == enrollment.epoch else { throw RoutingJournalError.wrongBinding }
        guard let key = enrollment.approval.keys.first(where: { $0.id == control.keyID && $0.keyClass == .decision }) else {
            throw RoutingJournalError.wrongKey
        }
        guard try RoutingAwaySignature.verify(signature: signature, publicKey: key.publicKey, wireVersion: 1,
            canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else { throw RoutingJournalError.invalidSignature }
        let current = try state()
        return try statement("SELECT payload,run,started,deadline,consumed FROM main.routing_operations_v1 WHERE operation=?", [control.operationID]) { stmt in
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { throw RoutingJournalError.unavailableChallenge }
            guard rc == SQLITE_ROW else { throw JournalDatabaseError.storage(rc) }
            let retained = try blob(stmt, 0)
            guard retained == payload else { throw RoutingJournalError.wrongBinding }
            let storedRun = try blob(stmt, 1), started = try uint(blob(stmt, 2)), deadline = try uint(blob(stmt, 3))
            guard storedRun.count == 16, started < deadline,
                  deadline - started == control.expiresAtUnixMillis - control.issuedAtUnixMillis,
                  control.expectedRevision < UInt64.max else { throw RoutingJournalError.corruptData }
            if sqlite3_column_type(stmt, 4) != SQLITE_NULL {
                let consumed = try uint(blob(stmt, 4))
                guard consumed == control.expectedRevision + 1, consumed <= current.revision else { throw RoutingJournalError.corruptData }
                return RoutingChange(state: RoutingState(mode: .away, revision: consumed), inserted: false)
            }
            guard storedRun == bytes(run) else { throw RoutingJournalError.unavailableChallenge }
            guard now.milliseconds >= started else { throw RoutingJournalError.invalidClock }
            guard now.milliseconds < deadline, wall >= control.issuedAtUnixMillis, wall < control.expiresAtUnixMillis else {
                throw RoutingJournalError.expired
            }
            let next = try advance(.away, expected: control.expectedRevision)
            try statement("UPDATE main.routing_operations_v1 SET consumed=? WHERE operation=? AND consumed IS NULL", [uint(next.revision), control.operationID]) {
                try done($0); guard sqlite3_changes(db) == 1 else { throw RoutingJournalError.conflict }
            }
            return RoutingChange(state: next, inserted: true)
        }
    }
    private func advance(_ mode: RoutingMode, expected: UInt64) throws -> RoutingState {
        guard try state().revision == expected else { throw RoutingJournalError.conflict }
        guard expected < UInt64.max else { throw RoutingJournalError.exhausted }
        let code = mode == .automatic ? 0 : mode == .present ? 1 : 2
        try statement("UPDATE main.routing_state_v1 SET mode=\(code),revision=? WHERE id=1 AND revision=?", [uint(expected + 1), uint(expected)]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw RoutingJournalError.conflict }
        }
        return RoutingState(mode: mode, revision: expected + 1)
    }
    private func clock(_ now: AuthorityMoment) throws {
        guard now.epoch == policy.clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else { throw RoutingJournalError.invalidClock }
        lastMoment = now.milliseconds
    }
    private func statement<T>(_ sql: String, _ values: [Data], _ body: (OpaquePointer) throws -> T) throws -> T {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw JournalDatabaseError.storage(rc) }
        defer { sqlite3_finalize(stmt) }
        for (i, value) in values.enumerated() {
            let bound = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(i + 1), $0.baseAddress, Int32(value.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard bound == SQLITE_OK else { throw JournalDatabaseError.storage(bound) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws { guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) } }
    private func blob(_ stmt: OpaquePointer, _ column: Int32) throws -> Data {
        let count = Int(sqlite3_column_bytes(stmt, column))
        guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, count > 0, count <= max(policy.payloadLimits.maxBytes, 16),
              let pointer = sqlite3_column_blob(stmt, column) else { throw RoutingJournalError.corruptData }
        return Data(bytes: pointer, count: count)
    }
    private func uint(_ value: UInt64) -> Data { var value = value.bigEndian; return withUnsafeBytes(of: &value) { Data($0) } }
    private func uint(_ value: Data) throws -> UInt64 {
        guard value.count == 8 else { throw RoutingJournalError.corruptData }
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    private func bytes(_ value: UUID) -> Data { var value = value.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
}
