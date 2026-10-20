import Foundation
import FixtureSQLite
import RemozioHostCore
import RemozioProtocol

/// Disposable connection/checkpoint owner around the shared consumption, replay and audit tables.
/// One owner, one request, disposable user-owned storage. No protected installation or power-loss claim.
final class FixtureStore {
    private let db: OpaquePointer
    private let consumption: ConsumptionJournalTables
    private let replay: CommandSubmissionReplayTables
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
        consumption = try ConsumptionJournalTables(connection: db, macID: FixtureProtocol.macID,
            accountID: FixtureProtocol.accountID, decisionLimits: FixtureProtocol.limits,
            recordLimits: FixtureProtocol.limits, maximumRows: 1)
        replay = try CommandSubmissionReplayTables(connection: db, macID: FixtureProtocol.macID,
            accountID: FixtureProtocol.accountID, maximumRows: 1)
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
                try consumption.createSchema()
                try consumption.createOutcomeSchema()
                try replay.createSchema()
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
            let verified = try material.verify(now: now())
            guard try consumption.receipt(requestID: material.request.requestID) == nil else {
                throw ConsumptionJournalError.alreadyConsumed
            }
            let capture = try LinuxCommandCapture(canonicalBytes: material.request.canonicalCapture,
                limits: FixtureProtocol.limits, expectedSchemaVersion: material.request.contract.schemaVersion)
            guard try !replay.contains(capture.submission) else { throw CommandSubmissionReplayError.alreadyReserved }
            try command.validate(capture)
            _ = try replay.reserve(CommandSubmissionReservation(macID: FixtureProtocol.macID,
                accountID: FixtureProtocol.accountID, submission: capture.submission,
                captureDigest: digest(capture.canonicalBytes)))
            let (writer, head) = try liveAudit()
            let receipt = try consumption.consume(canonicalDecision: material.decisionBytes, signature: material.signature,
                retained: material.retained, trust: material.trust, now: now(), eventID: randomBytes(16),
                receiptTimeMs: nil, writer: writer, expectedHead: head, audit: audit,
                requestLimits: FixtureProtocol.limits, signingLimits: FixtureProtocol.limits)
            let declined = receipt.event.outcome == .noDispatch
            try require(declined || (receipt.decision.action.choice == .execute && verified.requirement.effect == .dispatchTarget), "executeOnly")
            try require(!declined || verified.requirement.effect == .resolveRequest, "declineEffect")
            dispatch = !declined
        }
        return dispatch ? FixtureDispatchToken() : nil
    }

    func dispatched(_ token: FixtureDispatchToken) throws {
        try token.take()
        try transition(.beginDispatch)
    }
    func succeeded() throws { try transition(.verifySuccess) }

    func injectAuditFailure() throws {
        try execute("CREATE TEMP TRIGGER fixture_fail_audit BEFORE INSERT ON main.audit_records_v1 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
    }

    /// No retained request, software key or live dispatch token is restored on reopening.
    func retireUncertainOutcome() throws {
        let old = try snapshot()
        guard let phase = RequestPhase(rawValue: old.phase), !phase.isTerminal else { return }
        try mutate {
            writer = try audit.createEpoch(descriptor(previous: state.committed))
            try changeOutcome(.restartAuthority)
        }
    }

    func snapshot() throws -> (phase: String, rows: Int, records: Int, reservations: Int) {
        try transaction(write: false) {
            let rows = try scalar("SELECT count(*) FROM consumptions_v1")
            let reservations = try scalar("SELECT count(*) FROM command_submissions_v1")
            let outcomes = try consumption.outcomePage(after: nil, maximumRecords: 2, maximumBytes: 32768)
            try require(rows <= 1 && outcomes.outcomes.count == rows && reservations == rows, "fixtureRowCount")
            let phase = outcomes.outcomes.first?.phase.rawValue ?? "none"
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
            return (phase, rows, records, reservations)
        }
    }

    func checkpointMatches() throws -> Bool {
        try transaction(write: false) { try matches(state.committed) && state.pending == nil }
    }

    /// Historical replay metadata is used only to construct fresh refusal controls on reopen.
    func reservation() throws -> CommandSubmissionReservation {
        try transaction(write: false) {
            try statement("SELECT submission FROM command_submissions_v1", blobs: []) { row in
                try require(sqlite3_step(row) == SQLITE_ROW, "reservationRow")
                guard let value = try replay.read(submissionID: blob(row, 0)) else { throw FixtureError.failed("reservationMissing") }
                return value
            }
        }
    }

    private func transition(_ event: RequestEvent) throws { try mutate { try changeOutcome(event) } }
    private func changeOutcome(_ event: RequestEvent) throws {
        let outcomes = try consumption.outcomePage(after: nil, maximumRecords: 2, maximumBytes: 32768)
        guard outcomes.outcomes.count == 1, let current = outcomes.outcomes.first else { throw FixtureError.failed("outcomeRow") }
        let (writer, head) = try liveAudit()
        _ = try consumption.transition(requestID: current.receipt.decision.requestID, expectedRevision: current.revision,
            event: event, eventID: randomBytes(16), receiptTimeMs: nil, writer: writer, expectedHead: head, audit: audit)
    }
    private func liveAudit() throws -> (AuditEpochWriter, UInt64) {
        guard let writer, let epoch = try audit.epoch(writer.epoch) else { throw FixtureError.failed("noLiveAuditWriter") }
        return (writer, epoch.head)
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
        return digest(try DeterministicCBOR.encode(.array([.bytes(bytes),
            tableEvidence("command_submissions_v1", columns: 6)]), limits: FixtureProtocol.limits))
    }
    private func ledgerDigest() throws -> Data {
        let values = try [("consumptions_v1", 5), ("consumption_outcomes_v1", 5),
                          ("audit_epochs_v1", 6), ("audit_records_v1", 6)].map { table, columns in
            try tableEvidence(table, columns: columns)
        }
        return digest(try DeterministicCBOR.encode(.array(values), limits: FixtureProtocol.limits))
    }
    /// A bounded fixture checksum, not the protected Mac journal continuity format or a Linux owner policy.
    private func tableEvidence(_ table: String, columns: Int) throws -> CBORValue {
        let order = (1...columns).map(String.init).joined(separator: ",")
        return try statement("SELECT * FROM main.\(table) ORDER BY \(order)", blobs: []) { row in
            var rows: [CBORValue] = []
            while true {
                let result = sqlite3_step(row)
                if result == SQLITE_DONE { break }
                try require(result == SQLITE_ROW && rows.count < 16 && sqlite3_column_count(row) == columns, "evidenceRows")
                var values: [CBORValue] = []
                for column in 0..<Int32(columns) {
                    if sqlite3_column_type(row, column) == SQLITE_INTEGER {
                        let value = sqlite3_column_int64(row, column)
                        try require(value >= 0, "evidenceInteger")
                        values.append(.unsigned(UInt64(value)))
                    } else {
                        let size = Int(sqlite3_column_bytes(row, column))
                        try require(sqlite3_column_type(row, column) == SQLITE_BLOB && size > 0 && size <= 32768, "evidenceBlob")
                        guard let pointer = sqlite3_column_blob(row, column) else { throw FixtureError.failed("evidencePointer") }
                        values.append(.bytes(Data(bytes: pointer, count: size)))
                    }
                }
                rows.append(.array(values))
            }
            return .array([.text(table), .array(rows)])
        }
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

    private func transaction<T>(write: Bool = true, _ body: () throws -> T) throws -> T {
        try execute(write ? "BEGIN IMMEDIATE" : "BEGIN")
        do { let value = try body(); try execute("COMMIT"); return value }
        catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }
    private func execute(_ sql: String) throws { try require(sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK, "fixtureSQL") }
    private func statement<T>(_ sql: String, blobs: [Data], _ use: (OpaquePointer) throws -> T) throws -> T {
        var prepared: OpaquePointer?
        try require(sqlite3_prepare_v2(db, sql, -1, &prepared, nil) == SQLITE_OK && prepared != nil, "fixturePrepare")
        let statement = prepared!
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (index, bytes) in blobs.enumerated() {
            let result = bytes.withUnsafeBytes { sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count), transient) }
            try require(result == SQLITE_OK, "fixtureBind")
        }
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
}

/// In-memory, one-use fixture capability; intentionally never serialized or restored.
final class FixtureDispatchToken {
    private var used = false
    fileprivate init() {}
    fileprivate func take() throws { try require(!used, "fixtureTokenReplay"); used = true }
}
