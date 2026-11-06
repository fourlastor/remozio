import Foundation
import RemozioProtocol
import Security
import SQLite3

enum UpdateSchedulingJournalError: Error, Equatable {
    case disabled, invalidConfiguration, unavailableSchema, corruptData, notOffered
    case conflict, exhausted, capacityExceeded, unavailableChallenge, alreadyConsumed, invalidClock
}

struct UpdateSchedulingIntent: Equatable, Sendable {
    let snapshot: UpdateSchedulingSnapshot
    let requestedAction: UpdateSchedulingAction?
}

struct UpdateSchedulingJournalPolicy: Sendable {
    let clockEpoch: UUID
    let challengeLifetimeMillis: UInt64
    let maximumOperations: Int
    let payloadLimits: CBORLimits
    let signingLimits: CBORLimits
    init(clockEpoch: UUID, challengeLifetimeMillis: UInt64, maximumOperations: Int,
         payloadLimits: CBORLimits, signingLimits: CBORLimits) throws {
        guard (1...86_400_000).contains(challengeLifetimeMillis), (1...100_000).contains(maximumOperations),
              payloadLimits.maxBytes <= 65536, signingLimits.maxBytes <= 131072 else {
            throw UpdateSchedulingJournalError.invalidConfiguration
        }
        self.clockEpoch = clockEpoch; self.challengeLifetimeMillis = challengeLifetimeMillis
        self.maximumOperations = maximumOperations; self.payloadLimits = payloadLimits; self.signingLimits = signingLimits
    }
}

/// Private intent storage. The authority serializes and checkpoints calls before publishing their results.
/// A stored intent does not close admission, establish quiescence, or grant installation authority.
final class UpdateSchedulingJournal {
    private let db: OpaquePointer
    private let mac: Data
    private let account: Data
    private let policy: UpdateSchedulingJournalPolicy
    private let run = UUID()
    private var lastMoment: UInt64?
    init(connection: OpaquePointer, macID: Data, accountID: Data, policy: UpdateSchedulingJournalPolicy) {
        db = connection; mac = macID; account = accountID; self.policy = policy
    }

    func install() throws {
        let version = try schema()
        guard (15...17).contains(version) else { throw UpdateSchedulingJournalError.unavailableSchema }
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        guard try CodePolicyJournal(connection: db).read() != nil else { throw UpdateSchedulingJournalError.invalidConfiguration }
        if version < 17 {
            if version == 15 { try GatewayAuthorityJournal.createSubmissionHistoryStorage(connection: db) }
            try exec("""
                CREATE TABLE main.update_scheduling_state_v1(id INTEGER PRIMARY KEY CHECK(id=1),
                    update_id BLOB NOT NULL CHECK(length(update_id)=32), generation BLOB NOT NULL CHECK(length(generation)=8),
                    revision BLOB NOT NULL CHECK(length(revision)=8), action INTEGER CHECK(action IN (0,1,2))) STRICT;
                CREATE TABLE main.update_scheduling_operations_v1(operation BLOB PRIMARY KEY CHECK(length(operation)=16),
                    payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 65536),
                    trust BLOB NOT NULL CHECK(length(trust)=16), run BLOB NOT NULL CHECK(length(run)=16),
                    started BLOB NOT NULL CHECK(length(started)=8), deadline BLOB NOT NULL CHECK(length(deadline)=8),
                    consumed BLOB CHECK(consumed IS NULL OR length(consumed)=8)) STRICT, WITHOUT ROWID;
                PRAGMA main.user_version=17;
                """)
        }
        try statement("SELECT update_id,generation,revision,action FROM main.update_scheduling_state_v1 LIMIT 0", []) { try complete($0) }
        try statement("SELECT operation,payload,trust,run,started,deadline,consumed FROM main.update_scheduling_operations_v1 LIMIT 0", []) { try complete($0) }
    }

    func state() throws -> UpdateSchedulingIntent? {
        try installed()
        return try UpdateSchedulingStateStorage.read(connection: db)
    }

    /// Only the live verified machine owner can bind an account offer to its current selection generation.
    func offer(candidate: LiveUpdateSchedulingCandidate, expected: UpdateSchedulingSnapshot?) throws -> UpdateSchedulingIntent {
        try candidate.requireCurrent(macID: mac, accountID: account)
        let previous = try state()
        guard previous?.snapshot == expected else { throw UpdateSchedulingJournalError.conflict }
        if let previous, previous.snapshot.generation == candidate.generation {
            guard previous.snapshot.updateID == candidate.updateID else { throw UpdateSchedulingJournalError.conflict }
            try candidate.requireCurrent(macID: mac, accountID: account)
            return previous
        }
        guard previous.map({ $0.snapshot.generation < candidate.generation }) ?? true else {
            throw UpdateSchedulingJournalError.conflict
        }
        try statement("INSERT INTO main.update_scheduling_state_v1 VALUES(1,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET update_id=excluded.update_id,generation=excluded.generation,revision=excluded.revision,action=NULL",
            [candidate.updateID, uint(candidate.generation), uint(0)]) { try complete($0) }
        try candidate.requireCurrent(macID: mac, accountID: account)
        return try .init(snapshot: .init(updateID: candidate.updateID, generation: candidate.generation, revision: 0), requestedAction: nil)
    }

    func issue(candidate: LiveUpdateSchedulingCandidate, action: UpdateSchedulingAction, expected: UpdateSchedulingSnapshot, binding: AuthorityPeerBinding,
               trust: RequestDeliveryTrust, wall: UInt64, now: AuthorityMoment) throws -> UpdateSchedulingControl {
        try candidate.requireAction(action, macID: mac, accountID: account)
        guard expected.updateID == candidate.updateID, expected.generation == candidate.generation else {
            throw UpdateSchedulingVerificationError.staleSchedulingState
        }
        try clock(now)
        guard let current = try state() else { throw UpdateSchedulingJournalError.notOffered }
        guard current.snapshot == expected else { throw UpdateSchedulingJournalError.conflict }
        guard expected.revision < UInt64.max else { throw UpdateSchedulingJournalError.exhausted }
        guard trust.approval.macID == mac, trust.approval.accountID == account,
              binding.scope.macID == mac, binding.scope.accountID == account, binding.revision == trust.approval.revision else {
            throw UpdateSchedulingVerificationError.wrongBinding
        }
        guard let enrollment = trust.enrollments.first(where: {
            $0.approval.phoneID == binding.scope.phoneID && $0.epoch == binding.scope.enrollmentEpoch && $0.approval.active
        }), let key = enrollment.approval.keys.first(where: { $0.keyClass == .decision }) else {
            throw UpdateSchedulingVerificationError.unavailableEnrollment
        }
        let expires = wall.addingReportingOverflow(policy.challengeLifetimeMillis)
        let deadline = now.milliseconds.addingReportingOverflow(policy.challengeLifetimeMillis)
        guard !expires.overflow, !deadline.overflow else { throw UpdateSchedulingJournalError.invalidClock }
        let count = try statement("SELECT count(*) FROM main.update_scheduling_operations_v1", []) { row -> Int64 in
            guard sqlite3_step(row) == SQLITE_ROW else { throw UpdateSchedulingJournalError.corruptData }
            return sqlite3_column_int64(row, 0)
        }
        guard count < policy.maximumOperations else { throw UpdateSchedulingJournalError.capacityExceeded }
        var challenge = Data(count: 32)
        guard challenge.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
            throw UpdateSchedulingJournalError.unavailableChallenge
        }
        let control = try UpdateSchedulingControl(macID: mac, accountID: account, phoneID: binding.scope.phoneID,
            enrollmentEpoch: binding.scope.enrollmentEpoch, operationID: bytes(UUID()), challenge: challenge, keyID: key.id,
            updateID: expected.updateID, expectedGeneration: expected.generation, expectedRevision: expected.revision,
            issuedAtUnixMillis: wall, expiresAtUnixMillis: expires.partialValue, action: action)
        try statement("INSERT INTO main.update_scheduling_operations_v1 VALUES(?,?,?,?,?,?,NULL)",
            [control.operationID, try control.encode(limits: policy.payloadLimits), bytes(trust.approval.revision), bytes(run),
             uint(now.milliseconds), uint(deadline.partialValue)]) { try complete($0) }
        try candidate.requireCurrent(macID: mac, accountID: account)
        return control
    }

    /// Recheck an unconsumed challenge before the Root publishes its endorsement.
    func issuedChallenge(candidate: LiveUpdateSchedulingCandidate, payload: Data, binding: AuthorityPeerBinding,
                         trust: RequestDeliveryTrust, wall: UInt64, now: AuthorityMoment) throws -> RetainedUpdateSchedulingChallenge {
        try candidate.requireCurrent(macID: mac, accountID: account)
        try clock(now); try installed()
        let control = try UpdateSchedulingControl.decode(payload, limits: policy.payloadLimits)
        try candidate.requireAction(control.action, macID: mac, accountID: account)
        let operation = try retained(control.operationID)
        guard operation.payload == payload else { throw UpdateSchedulingVerificationError.wrongChallenge }
        guard operation.consumed == nil else { throw UpdateSchedulingJournalError.alreadyConsumed }
        guard operation.run == bytes(run) else { throw UpdateSchedulingJournalError.unavailableChallenge }
        guard let current = try state(), current.snapshot.updateID == candidate.updateID,
              current.snapshot.generation == candidate.generation, control.updateID == candidate.updateID,
              control.expectedGeneration == candidate.generation, control.expectedRevision == current.snapshot.revision else {
            throw UpdateSchedulingVerificationError.staleSchedulingState
        }
        guard operation.trust == trust.approval.revision, binding.revision == trust.approval.revision else {
            throw UpdateSchedulingVerificationError.staleTrust
        }
        guard control.macID == mac, control.accountID == account, binding.scope.macID == mac,
              binding.scope.accountID == account, control.phoneID == binding.scope.phoneID,
              control.enrollmentEpoch == binding.scope.enrollmentEpoch,
              let enrollment = trust.enrollments.first(where: {
                  $0.approval.active && $0.approval.phoneID == control.phoneID && $0.epoch == control.enrollmentEpoch
              }), enrollment.approval.keys.contains(where: { $0.id == control.keyID && $0.keyClass == .decision }) else {
            throw UpdateSchedulingVerificationError.unavailableEnrollment
        }
        let retained = try RetainedUpdateSchedulingChallenge(control: control, trustRevision: operation.trust,
            issuedAt: .init(epoch: policy.clockEpoch, milliseconds: operation.started), deadlineMilliseconds: operation.deadline)
        try retained.requireLive(now: now, wall: wall)
        try candidate.requireCurrent(macID: mac, accountID: account)
        return retained
    }

    func verify(candidate: LiveUpdateSchedulingCandidate, payload: Data, signature: Data, binding: AuthorityPeerBinding, trust: RequestDeliveryTrust,
               wall: UInt64, now: AuthorityMoment) throws -> (control: UpdateSchedulingControl, current: UpdateSchedulingIntent) {
        try candidate.requireCurrent(macID: mac, accountID: account)
        let control = try UpdateSchedulingControl.decode(payload, limits: policy.payloadLimits)
        try candidate.requireAction(control.action, macID: mac, accountID: account)
        guard control.updateID == candidate.updateID, control.expectedGeneration == candidate.generation else {
            throw UpdateSchedulingVerificationError.staleSchedulingState
        }
        try clock(now); try installed()
        let operation = try retained(control.operationID)
        guard operation.payload == payload else { throw UpdateSchedulingVerificationError.wrongChallenge }
        guard operation.consumed == nil else { throw UpdateSchedulingJournalError.alreadyConsumed }
        guard operation.run == bytes(run) else { throw UpdateSchedulingJournalError.unavailableChallenge }
        guard let current = try state() else { throw UpdateSchedulingJournalError.notOffered }
        let challenge = try RetainedUpdateSchedulingChallenge(control: control, trustRevision: operation.trust,
            issuedAt: .init(epoch: policy.clockEpoch, milliseconds: operation.started), deadlineMilliseconds: operation.deadline)
        _ = try UpdateSchedulingVerifier.verify(canonicalControl: payload, signature: signature, retained: challenge,
            current: current.snapshot, binding: binding, trust: trust, now: now, nowUnixMillis: wall,
            payloadLimits: policy.payloadLimits, signingLimits: policy.signingLimits)
        guard current.snapshot.revision < UInt64.max else { throw UpdateSchedulingJournalError.exhausted }
        try candidate.requireCurrent(macID: mac, accountID: account)
        return (control, current)
    }

    func apply(candidate: LiveUpdateSchedulingCandidate, payload: Data, signature: Data, binding: AuthorityPeerBinding, trust: RequestDeliveryTrust,
               wall: UInt64, now: AuthorityMoment) throws -> UpdateSchedulingIntent {
        let (control, current) = try verify(candidate: candidate, payload: payload, signature: signature,
            binding: binding, trust: trust, wall: wall, now: now)
        let next = current.snapshot.revision + 1
        try statement("UPDATE main.update_scheduling_state_v1 SET revision=?,action=\(control.action.rawValue) WHERE id=1 AND update_id=? AND generation=? AND revision=?",
            [uint(next), current.snapshot.updateID, uint(current.snapshot.generation), uint(current.snapshot.revision)]) {
            try complete($0); guard sqlite3_changes(db) == 1 else { throw UpdateSchedulingJournalError.conflict }
        }
        try statement("UPDATE main.update_scheduling_operations_v1 SET consumed=? WHERE operation=? AND consumed IS NULL",
            [uint(next), control.operationID]) {
            try complete($0); guard sqlite3_changes(db) == 1 else { throw UpdateSchedulingJournalError.conflict }
        }
        try candidate.requireCurrent(macID: mac, accountID: account)
        return try .init(snapshot: .init(updateID: current.snapshot.updateID, generation: current.snapshot.generation, revision: next),
            requestedAction: control.action)
    }

    func consumedRevision(operationID: Data) throws -> UInt64? { try installed(); return try retained(operationID).consumed }
    private struct Operation {
        let payload: Data
        let trust: UUID
        let run: Data
        let started: UInt64
        let deadline: UInt64
        let consumed: UInt64?
    }
    private func retained(_ operationID: Data) throws -> Operation {
        guard operationID.count == 16 else { throw UpdateSchedulingJournalError.unavailableChallenge }
        return try statement("SELECT payload,trust,run,started,deadline,consumed FROM main.update_scheduling_operations_v1 WHERE operation=?", [operationID]) { row in
            let rc = sqlite3_step(row)
            if rc == SQLITE_DONE { throw UpdateSchedulingJournalError.unavailableChallenge }
            guard rc == SQLITE_ROW else { throw JournalDatabaseError.storage(rc) }
            let payload = try blob(row, 0, maximum: policy.payloadLimits.maxBytes)
            let control: UpdateSchedulingControl
            do { control = try UpdateSchedulingControl.decode(payload, limits: policy.payloadLimits) }
            catch { throw UpdateSchedulingJournalError.corruptData }
            let trust = try blob(row, 1, maximum: 16), run = try blob(row, 2, maximum: 16)
            let started = try uint(blob(row, 3, maximum: 8)), deadline = try uint(blob(row, 4, maximum: 8))
            let consumed = sqlite3_column_type(row, 5) == SQLITE_NULL ? nil : try uint(blob(row, 5, maximum: 8))
            guard control.operationID == operationID, control.macID == mac, control.accountID == account,
                  trust.count == 16, run.count == 16, started < deadline,
                  deadline - started == control.expiresAtUnixMillis - control.issuedAtUnixMillis,
                  control.expectedRevision < UInt64.max, consumed == nil || consumed == control.expectedRevision + 1 else {
                throw UpdateSchedulingJournalError.corruptData
            }
            return Operation(payload: payload, trust: trust.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) },
                run: run, started: started, deadline: deadline, consumed: consumed)
        }
    }
    private func installed() throws { guard try schema() == 17 else { throw UpdateSchedulingJournalError.unavailableSchema } }
    private func schema() throws -> Int64 {
        try statement("PRAGMA main.user_version", []) { row in
            guard sqlite3_step(row) == SQLITE_ROW else { throw JournalDatabaseError.incompatibleStore }
            return sqlite3_column_int64(row, 0)
        }
    }
    private func clock(_ now: AuthorityMoment) throws {
        guard now.epoch == policy.clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else {
            throw UpdateSchedulingJournalError.invalidClock
        }
        lastMoment = now.milliseconds
    }
    private func statement<T>(_ sql: String, _ values: [Data], _ body: (OpaquePointer) throws -> T) throws -> T {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        var row: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard rc == SQLITE_OK, let row else { throw JournalDatabaseError.storage(rc) }
        defer { sqlite3_finalize(row) }
        for (i, value) in values.enumerated() {
            let rc = value.withUnsafeBytes { sqlite3_bind_blob(row, Int32(i + 1), $0.baseAddress, Int32(value.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
        }
        return try body(row)
    }
    private func exec(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
    }
    private func complete(_ row: OpaquePointer) throws {
        guard sqlite3_step(row) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
    }
    private func blob(_ row: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(row, column))
        guard sqlite3_column_type(row, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let pointer = sqlite3_column_blob(row, column) else { throw UpdateSchedulingJournalError.corruptData }
        return Data(bytes: pointer, count: count)
    }
    private func uint(_ value: UInt64) -> Data { var n = value.bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    private func uint(_ value: Data) throws -> UInt64 {
        guard value.count == 8 else { throw UpdateSchedulingJournalError.corruptData }
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    private func bytes(_ value: UUID) -> Data { var n = value.uuid; return withUnsafeBytes(of: &n) { Data($0) } }
}

extension UpdateSchedulingJournalPolicy {
    func sameConfiguration(as other: Self) -> Bool {
        clockEpoch == other.clockEpoch && challengeLifetimeMillis == other.challengeLifetimeMillis &&
        maximumOperations == other.maximumOperations &&
        payloadLimits.maxBytes == other.payloadLimits.maxBytes && payloadLimits.maxDepth == other.payloadLimits.maxDepth &&
        payloadLimits.maxItems == other.payloadLimits.maxItems && signingLimits.maxBytes == other.signingLimits.maxBytes &&
        signingLimits.maxDepth == other.signingLimits.maxDepth && signingLimits.maxItems == other.signingLimits.maxItems
    }
}
