import Foundation
import FixtureSQLite
import RemozioHostCore
import RemozioProtocol

/// Deliberately tiny fixture ledger, NOT the production consumption/continuity authority.
/// One owner, one request, disposable user-owned storage. No protected installation or power-loss claim.
final class FixtureStore {
    private let db: OpaquePointer
    private let audit: AuditJournalTables
    private let checkpointURL: URL
    private let authorityURL: URL
    private var writer: AuditEpochWriter?
    private var state: ContinuityState!
    private(set) var checkpointAction = "unchanged"

    init(directory: String, reopening: Bool) throws {
        checkpointURL = URL(fileURLWithPath: directory + "/checkpoint.cbor")
        authorityURL = URL(fileURLWithPath: directory + "/fixture-authority.cbor")
        let database = directory + "/fixture.sqlite"
        try require(FileManager.default.fileExists(atPath: database) == reopening, "databasePresence")
        var connection: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | (reopening ? 0 : SQLITE_OPEN_CREATE)
        try require(sqlite3_open_v2(database, &connection, flags, nil) == SQLITE_OK && connection != nil, "databaseOpen")
        db = connection!
        audit = try AuditJournalTables(connection: db, macID: FixtureProtocol.macID,
            accountID: FixtureProtocol.accountID, recordLimits: FixtureProtocol.limits, descriptorLimits: FixtureProtocol.limits)
        try execute("PRAGMA journal_mode=DELETE")
        try execute("PRAGMA synchronous=FULL")
        try execute("PRAGMA foreign_keys=ON")
        if reopening {
            state = try readState()
            try reconcile()
        } else {
            let authority = try DeterministicCBOR.encode(.map([0: .text("disposable fixture configuration"),
                1: .bytes(FixtureProtocol.macID), 2: .bytes(FixtureProtocol.accountID)]), limits: FixtureProtocol.limits)
            try authority.write(to: authorityURL, options: .atomic)
            try transaction {
                try execute("CREATE TABLE fixture_consumptions (request BLOB PRIMARY KEY CHECK(length(request)=16), phase TEXT NOT NULL) STRICT, WITHOUT ROWID")
                try audit.createSchema()
                writer = try audit.createEpoch(descriptor(previous: nil))
                let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: authorityDigest(),
                    ledgerDigest: ledgerDigest(), journalEpoch: writer!.epoch, journalHead: 0, authorityGeneration: 1)
                state = try ContinuityState(committed: checkpoint, pending: nil, recoveryRequired: false)
            }
            try writeState(state)
        }
    }

    deinit { sqlite3_close(db) }

    /// The check is repeated under the same write transaction as the unique row and audit append.
    /// This returns only a fixture token; it grants no production execution authority.
    func consume(_ material: FixtureApprovalMaterial, command: OwnedCommand, now: () throws -> AuthorityMoment,
                 leavePending: Bool = false) throws -> FixtureDispatchToken? {
        var dispatch = false
        try mutate(leavePending: leavePending) {
            // A completed request owns no live pipe descriptors; reject its authenticated replay before inspecting them.
            _ = try material.verify(now: now())
            try require(try scalar("SELECT count(*) FROM fixture_consumptions") == 0, "fixtureReplay")
            let capture = try LinuxCommandCapture(canonicalBytes: material.request.canonicalCapture,
                limits: FixtureProtocol.limits, expectedSchemaVersion: material.request.contract.schemaVersion)
            try command.validate(capture)
            let verified = try material.verify(now: now())
            let declined = verified.decision.action.choice == .decline
            try require(declined || (verified.decision.action.choice == .execute && verified.requirement.effect == .dispatchTarget), "executeOnly")
            try require(!declined || verified.requirement.effect == .resolveRequest, "declineEffect")
            let phase = try RequestLifecycle.transition(from: .presented, event: declined ? .decline : .authorize)
            try statement("INSERT INTO fixture_consumptions VALUES(?,?)", blobs: [material.request.requestID], text: phase.rawValue) { statement in
                try require(sqlite3_step(statement) == SQLITE_DONE, "fixtureReplay")
            }
            try append(request: material.request.requestID, kind: .consumed,
                outcome: declined ? .noDispatch : .accepted, reason: declined ? .userDeclined : .none,
                action: verified.decision.action, phone: verified.decision.phoneID,
                authentication: declined ? .decisionKey : .biometricKey)
            dispatch = !declined
        }
        return dispatch ? FixtureDispatchToken() : nil
    }

    func dispatched(_ token: FixtureDispatchToken) throws {
        try token.take()
        try transition(.beginDispatch, kind: .dispatched, outcome: .attempted, reason: .none)
    }
    func succeeded() throws { try transition(.verifySuccess, kind: .verifiedResult, outcome: .verifiedSuccess, reason: .none) }

    func injectAuditFailure() throws {
        try execute("CREATE TEMP TRIGGER fixture_fail_audit BEFORE INSERT ON main.audit_records_v1 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
    }

    /// No retained request, software key or live dispatch token is restored on reopening.
    func retireUncertainOutcome() throws {
        let old = try snapshot()
        guard let phase = RequestPhase(rawValue: old.phase), !phase.isTerminal else { return }
        try mutate {
            writer = try audit.createEpoch(descriptor(previous: state.committed))
            try changePhase(.restartAuthority)
            try append(request: requestID(), kind: .unknownOutcome, outcome: .unresolved,
                reason: .authorityRestarted, action: nil, phone: nil, authentication: .system)
        }
    }

    func snapshot() throws -> (phase: String, rows: Int, records: Int) {
        try transaction(write: false) {
            let rows = try scalar("SELECT count(*) FROM fixture_consumptions")
            try require(rows <= 1, "fixtureRowCount")
            let phase = rows == 0 ? "none" : try phase().rawValue
            var records = 0
            try statement("SELECT epoch FROM audit_epochs_v1", blobs: []) { statement in
                while sqlite3_step(statement) == SQLITE_ROW {
                    let epoch = try blob(statement, 0)
                    let page = try audit.page(epoch: epoch, after: 0, maximumRecords: 16, maximumBytes: 32768)
                    try require(page.canonicalRecords.count == Int(page.epoch.head), "auditPageCompleteness")
                    records += page.canonicalRecords.count
                }
            }
            try require(records == scalar("SELECT count(*) FROM audit_records_v1"), "auditCount")
            return (phase, rows, records)
        }
    }

    func checkpointMatches() throws -> Bool {
        try transaction(write: false) { try matches(state.committed) && state.pending == nil }
    }

    private func transition(_ event: RequestEvent, kind: AuditEventKind, outcome: AuditOutcome, reason: AuditReason) throws {
        try mutate {
            try changePhase(event)
            try append(request: requestID(), kind: kind, outcome: outcome, reason: reason,
                action: nil, phone: nil, authentication: .system)
        }
    }
    private func changePhase(_ event: RequestEvent) throws {
        let next = try RequestLifecycle.transition(from: phase(), event: event)
        try statement("UPDATE fixture_consumptions SET phase=?", blobs: [], text: next.rawValue) { statement in
            try require(sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(db) == 1, "phaseUpdate")
        }
    }
    private func append(request: Data, kind: AuditEventKind, outcome: AuditOutcome, reason: AuditReason,
                        action: CapturedAction?, phone: Data?, authentication: AuditAuthentication) throws {
        guard let writer, let epoch = try audit.epoch(writer.epoch) else { throw FixtureError.failed("noLiveAuditWriter") }
        let record = try AuditEventMetadata(eventID: randomBytes(16), macID: FixtureProtocol.macID,
            accountID: FixtureProtocol.accountID, journalEpoch: writer.epoch, sequence: epoch.head + 1,
            requestID: request, eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: kind, category: .command,
            action: action.map { AuditActionMetadata(action: $0) }, decisionPhoneID: phone,
            authentication: authentication, outcome: outcome, reason: reason, droppedEventCount: nil, peerDeviceID: nil)
        try audit.append(record.encode(limits: FixtureProtocol.limits), writer: writer, expectedHead: epoch.head)
    }
    private func descriptor(previous: ContinuityCheckpoint?) throws -> AuditEpochDescriptor {
        var last: CBORValue = .null
        if let previous, previous.journalHead > 0 {
            let page = try audit.page(epoch: previous.journalEpoch, after: previous.journalHead - 1,
                maximumRecords: 1, maximumBytes: 32768)
            try require(page.canonicalRecords.count == 1, "previousHead")
            last = .bytes(digest(page.canonicalRecords[0]))
        }
        let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(FixtureProtocol.macID),
            2: .bytes(FixtureProtocol.accountID), 3: .bytes(randomBytes(16)),
            4: .unsigned(previous == nil ? 1 : 2), 5: .unsigned(previous == nil ? 0 : 1),
            6: previous.map { .bytes($0.journalEpoch) } ?? .null,
            7: previous.map { .unsigned($0.journalHead) } ?? .null, 8: last]), limits: FixtureProtocol.limits)
        return try AuditEpochDescriptor.decode(bytes, limits: FixtureProtocol.limits)
    }

    private func mutate(leavePending: Bool = false, _ body: () throws -> Void) throws {
        let baseline = state!
        do {
            try transaction {
                try body()
                guard let writer, let epoch = try audit.epoch(writer.epoch) else { throw FixtureError.failed("epoch") }
                let next = try baseline.committed.successor(authorityDigest: authorityDigest(), ledgerDigest: ledgerDigest(),
                    journalEpoch: writer.epoch, journalHead: epoch.head)
                state = try ContinuityState(committed: baseline.committed, pending: next, recoveryRequired: false)
                try writeState(state)
            }
        } catch {
            state = baseline
            try writeState(baseline)
            throw error
        }
        if !leavePending {
            state = try ContinuityState(committed: state.pending!, pending: nil, recoveryRequired: false)
            try writeState(state)
        }
    }
    private func reconcile() throws {
        let selection = try transaction(write: false) {
            let pendingMatches = try state.pending.map { try matches($0) } ?? false
            let committedMatches = try !pendingMatches && matches(state.committed)
            return JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: try authorityDigest(),
                pendingMatches: pendingMatches, committedMatches: committedMatches)
        }
        let checkpoint: ContinuityCheckpoint
        switch selection {
        case .unchanged(let value): checkpoint = value
        case .finalizePending(let value): checkpoint = value; checkpointAction = "finalizePending"
        case .discardPending(let value): checkpoint = value; checkpointAction = "discardPending"
        case .historyDiscontinuity, .requireRepair: throw FixtureError.failed("checkpointRepairRequired")
        }
        state = try ContinuityState(committed: checkpoint, pending: nil, recoveryRequired: false)
        try writeState(state)
    }
    private func matches(_ checkpoint: ContinuityCheckpoint) throws -> Bool {
        guard checkpoint.authorityDigest == (try authorityDigest()), checkpoint.ledgerDigest == (try ledgerDigest()),
              let epoch = try audit.epoch(checkpoint.journalEpoch) else { return false }
        return epoch.head == checkpoint.journalHead
    }
    private func authorityDigest() throws -> Data {
        let bytes = try Data(contentsOf: authorityURL)
        try require(bytes.count <= 1024, "authoritySize")
        _ = try DeterministicCBOR.decode(bytes, limits: FixtureProtocol.limits)
        return digest(bytes)
    }
    private func ledgerDigest() throws -> Data {
        var values: [CBORValue] = []
        try statement("SELECT request,phase FROM fixture_consumptions ORDER BY request", blobs: []) { statement in
            while sqlite3_step(statement) == SQLITE_ROW {
                try require(values.isEmpty, "fixtureRowCount")
                values.append(.array([.bytes(try blob(statement, 0)), .text(try text(statement, 1))]))
            }
        }
        return digest(try DeterministicCBOR.encode(.array(values), limits: FixtureProtocol.limits))
    }
    private func writeState(_ state: ContinuityState) throws {
        let bytes = try DeterministicCBOR.encode(.map([0: .bytes(state.committed.bytes),
            1: try state.pending.map { .bytes(try $0.bytes) } ?? .null]), limits: FixtureProtocol.limits)
        try bytes.write(to: checkpointURL, options: .atomic)
    }
    private func readState() throws -> ContinuityState {
        let bytes = try Data(contentsOf: checkpointURL)
        try require(bytes.count <= 1024, "checkpointSize")
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: FixtureProtocol.limits),
              Set(fields.keys) == [0, 1], case .bytes(let committed) = fields[0] else { throw FixtureError.failed("checkpointFields") }
        let pending: ContinuityCheckpoint?
        if fields[1] == .null { pending = nil }
        else if case .bytes(let bytes) = fields[1] { pending = try ContinuityCheckpoint.decode(bytes) }
        else { throw FixtureError.failed("checkpointPending") }
        return try ContinuityState(committed: ContinuityCheckpoint.decode(committed), pending: pending, recoveryRequired: false)
    }

    private func requestID() throws -> Data {
        try statement("SELECT request FROM fixture_consumptions", blobs: []) { statement in
            try require(sqlite3_step(statement) == SQLITE_ROW, "requestRow")
            return try blob(statement, 0)
        }
    }
    private func phase() throws -> RequestPhase {
        try statement("SELECT phase FROM fixture_consumptions", blobs: []) { statement in
            try require(sqlite3_step(statement) == SQLITE_ROW, "phaseRow")
            guard let value = RequestPhase(rawValue: try text(statement, 0)) else { throw FixtureError.failed("phaseValue") }
            return value
        }
    }
    private func transaction<T>(write: Bool = true, _ body: () throws -> T) throws -> T {
        try execute(write ? "BEGIN IMMEDIATE" : "BEGIN")
        do { let value = try body(); try execute("COMMIT"); return value }
        catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }
    private func execute(_ sql: String) throws { try require(sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK, "fixtureSQL") }
    private func statement<T>(_ sql: String, blobs: [Data], text: String? = nil, _ use: (OpaquePointer) throws -> T) throws -> T {
        var prepared: OpaquePointer?
        try require(sqlite3_prepare_v2(db, sql, -1, &prepared, nil) == SQLITE_OK && prepared != nil, "fixturePrepare")
        let statement = prepared!
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (index, bytes) in blobs.enumerated() {
            let result = bytes.withUnsafeBytes { sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count), transient) }
            try require(result == SQLITE_OK, "fixtureBind")
        }
        if let text { try require(sqlite3_bind_text(statement, Int32(blobs.count + 1), text, -1, transient) == SQLITE_OK, "fixtureBind") }
        return try use(statement)
    }
    private func scalar(_ sql: String) throws -> Int {
        try statement(sql, blobs: []) { statement in
            try require(sqlite3_step(statement) == SQLITE_ROW, "fixtureScalar")
            return Int(sqlite3_column_int64(statement, 0))
        }
    }
    private func blob(_ statement: OpaquePointer, _ column: Int32) throws -> Data {
        let count = Int(sqlite3_column_bytes(statement, column))
        try require(sqlite3_column_type(statement, column) == SQLITE_BLOB && count == 16, "fixtureBlob")
        return Data(bytes: sqlite3_column_blob(statement, column)!, count: count)
    }
    private func text(_ statement: OpaquePointer, _ column: Int32) throws -> String {
        try require(sqlite3_column_type(statement, column) == SQLITE_TEXT && sqlite3_column_bytes(statement, column) <= 32, "fixtureText")
        return String(cString: sqlite3_column_text(statement, column)!)
    }
}

/// In-memory, one-use fixture capability; intentionally never serialized or restored.
final class FixtureDispatchToken {
    private var used = false
    fileprivate init() {}
    fileprivate func take() throws { try require(!used, "fixtureTokenReplay"); used = true }
}
