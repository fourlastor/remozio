import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3

public enum GatewayDatabaseError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongScope, closed, unavailable, transactionActive
    case headMismatch, operationConflict, capacityExceeded, invalidClock, corruptData, readOnly
    case revokedEnrollment, unavailableCandidate, retiredCredential, revokedCredential
    case updateHealthRecoveryRequired
    case storage(Int32)
}

/// Historical signed control, never a probe permit or proof of current enrollment.
public struct GatewayCandidateReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let candidate: GatewayTokenCandidate
    public let canonicalPayload: Data
    public let signature: Data
    public var description: String { "GatewayCandidateReceipt(redacted)" }
    public var debugDescription: String { description }
}

public struct GatewayCandidateAdmission: Sendable {
    public let receipt: GatewayCandidateReceipt
    public let inserted: Bool
}

/// Owns one registration's private connection. Serialize calls with current gateway trust and enrollment changes.
/// Candidate admission and recipient changes share one durable revision. No method grants provider dispatch authority.
public final class GatewayDatabase {
    private static let applicationID: Int64 = 0x524D5A47
    private let lease: ProtectedGatewayLease
    private let readOnlyForUpdateHealth: Bool
    private let identity: GatewayRegistrationIdentity
    private let payloadLimits: CBORLimits
    private let signingLimits: CBORLimits
    private let maximumOperations: Int
    private let maximumPendingPerEnrollment: Int
    private let maximumLifetimeMillis: UInt64
    private let probePolicy: GatewayProbePolicy?
    private let clockEpoch: UUID
    private let runID = UUID()
    private var lastMoment: UInt64?
    private var db: OpaquePointer?
    private var active = false
    private var unavailable = false

    /// Initialize only during protected setup on an empty, pre-provisioned file. Never initialize as recovery.
    public static func open(directoryPath: String, serviceUID: uid_t, identity: GatewayRegistrationIdentity,
                            payloadLimits: CBORLimits, signingLimits: CBORLimits, maximumOperations: Int,
                            maximumPendingPerEnrollment: Int, maximumLifetimeMillis: UInt64, clockEpoch: UUID,
                            busyMilliseconds: UInt32, initialize: Bool = false, migrateLegacyStore: Bool = false, probePolicy: GatewayProbePolicy? = nil) throws -> GatewayDatabase {
        try GatewayDatabase(lease: ProtectedGatewayLease.acquire(directoryPath: directoryPath, serviceUID: serviceUID),
            identity: identity, payloadLimits: payloadLimits, signingLimits: signingLimits, maximumOperations: maximumOperations,
            maximumPendingPerEnrollment: maximumPendingPerEnrollment, maximumLifetimeMillis: maximumLifetimeMillis,
            clockEpoch: clockEpoch, busyMilliseconds: busyMilliseconds, initialize: initialize, migrateLegacyStore: migrateLegacyStore, probePolicy: probePolicy)
    }

    /// Opens retained health state only. The caller must authenticate current code, the Root peer and closed admission first.
    static func openForUpdateHealth(configuration: GatewayServiceConfiguration, clockEpoch: UUID) throws -> GatewayDatabase {
        try configuration.requireNativeProcess()
        let settings = configuration.settings
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 8, maxItems: 256)
        return try GatewayDatabase(lease: ProtectedGatewayLease.acquire(directoryPath: configuration.directoryPath,
            serviceUID: configuration.serviceUID), identity: configuration.registration,
            payloadLimits: limits, signingLimits: limits, maximumOperations: settings.maximumStoredControls,
            maximumPendingPerEnrollment: settings.maximumPendingPerEnrollment,
            maximumLifetimeMillis: settings.maximumCandidateLifetimeMillis, clockEpoch: clockEpoch,
            busyMilliseconds: settings.databaseBusyMillis, initialize: false, migrateLegacyStore: false,
            probePolicy: settings.probe, readOnlyForUpdateHealth: true)
    }

    /// Internal fixture entry point. Ownership of the lease transfers even if opening fails.
    init(lease: ProtectedGatewayLease, identity: GatewayRegistrationIdentity, payloadLimits: CBORLimits,
         signingLimits: CBORLimits, maximumOperations: Int, maximumPendingPerEnrollment: Int,
         maximumLifetimeMillis: UInt64, clockEpoch: UUID, busyMilliseconds: UInt32, initialize: Bool, migrateLegacyStore: Bool = false, probePolicy: GatewayProbePolicy? = nil,
         readOnlyForUpdateHealth: Bool = false) throws {
        self.readOnlyForUpdateHealth = readOnlyForUpdateHealth
        self.lease = lease; self.identity = identity; self.payloadLimits = payloadLimits; self.signingLimits = signingLimits
        self.maximumOperations = maximumOperations; self.maximumPendingPerEnrollment = maximumPendingPerEnrollment
        self.maximumLifetimeMillis = maximumLifetimeMillis; self.clockEpoch = clockEpoch; self.probePolicy = probePolicy
        do {
            guard maximumOperations > 0, maximumOperations <= 1_000_000,
                  maximumPendingPerEnrollment > 0, maximumPendingPerEnrollment <= maximumOperations,
                  maximumLifetimeMillis > 0, busyMilliseconds <= 60_000,
                  payloadLimits.maxBytes <= Int(Int32.max) - 32768 else { throw GatewayDatabaseError.invalidConfiguration }
            guard !readOnlyForUpdateHealth || (!initialize && !migrateLegacyStore) else { throw GatewayDatabaseError.invalidConfiguration }
            try lease.validate()
            var connection: OpaquePointer?
            let access = readOnlyForUpdateHealth ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE
            let rc = sqlite3_open_v2(lease.databasePath, &connection, access | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard rc == SQLITE_OK, let connection else { throw GatewayDatabaseError.storage(rc) }
            try lease.validate()
            guard sqlite3_busy_timeout(connection, Int32(busyMilliseconds)) == SQLITE_OK,
                  sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1 else { throw GatewayDatabaseError.invalidConfiguration }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, Int32(payloadLimits.maxBytes + 32768))
            try exec("PRAGMA trusted_schema=OFF"); try exec("PRAGMA foreign_keys=ON")
            if initialize { try requireEmpty() } else { try validateIdentity(allowLegacy: migrateLegacyStore) }
            if !readOnlyForUpdateHealth { try exec("PRAGMA journal_mode=DELETE") }
            try exec("PRAGMA synchronous=EXTRA"); try exec("PRAGMA fullfsync=ON")
            if readOnlyForUpdateHealth { try exec("PRAGMA query_only=ON") }
            guard try scalarText("PRAGMA journal_mode") == "delete", try scalar("PRAGMA synchronous") == 3,
                  try scalar("PRAGMA fullfsync") == 1, try scalar("PRAGMA foreign_keys") == 1,
                  try scalar("PRAGMA trusted_schema") == 0 else { throw GatewayDatabaseError.invalidConfiguration }
            if initialize { try transaction(write: true) { try create() } }
            else if try !readOnlyForUpdateHealth && scalar("PRAGMA user_version") < 4 {
                try transaction(write: true) {
                    try validateIdentity(allowLegacy: true)
                    if try scalar("PRAGMA user_version") == 1 { try createRecipientTables() }
                    if try scalar("PRAGMA user_version") < 3 { try createProbeTable() }
                    try createSubmissionTable()
                    try exec("PRAGMA user_version=4")
                }
            }
            try validateIdentity()
            // A restart cannot restore a process-local deadline or turn an old receipt into another probe.
            if !readOnlyForUpdateHealth {
                try transaction(write: true) {
                    try exec("UPDATE gateway_candidates_v1 SET token=NULL WHERE token IS NOT NULL")
                    try exec("UPDATE gateway_probes_v3 SET status=5,retry=NULL WHERE status IN (1,2,4)")
                }
            }
        } catch {
            // SQLite's extended SQLITE_READONLY_ROLLBACK code. Leave recovery to the ordinary writer.
            let hotJournal = SQLITE_READONLY | (3 << 8)
            let recoveryRequired = readOnlyForUpdateHealth && db.map { sqlite3_extended_errcode($0) == hotJournal } == true
            shutdown()
            if recoveryRequired { throw GatewayDatabaseError.updateHealthRecoveryRequired }
            throw error
        }
    }
    deinit { shutdown() }

    public func head() throws -> UInt64 { try transaction(write: false) { try storedHead() } }

    /// Retained store evidence only. This read grants no provider dispatch, enrollment or update completion authority.
    func updateHealthEvidence() throws -> GatewayHeadEvidence {
        guard readOnlyForUpdateHealth else { throw GatewayDatabaseError.invalidConfiguration }
        try transaction(write: false) {
            try validateIdentity()
            guard try scalar("PRAGMA query_only") == 1, try scalarText("PRAGMA quick_check") == "ok" else {
                throw GatewayDatabaseError.corruptData
            }
        }
        let evidence = try headEvidence()
        try transaction(write: false) {
            try validateIdentity()
            guard try storedHead() == evidence.revision else { throw GatewayDatabaseError.headMismatch }
        }
        return evidence
    }
    /// Reads the counter and latest signed receipt in one transaction. The service must authenticate any network response separately.
    public func headEvidence() throws -> GatewayHeadEvidence {
        try transaction(write: false) {
            let head = try storedHead()
            let latest: [(Int64, Data, UInt64)] = try statement("""
                SELECT source,operation,revision FROM (
                    SELECT 1 AS source,operation,revision FROM gateway_candidates_v1
                    UNION ALL
                    SELECT 2 AS source,operation,revision FROM gateway_recipients_v2
                    UNION ALL SELECT 3 AS source,operation,revision FROM gateway_submission_controls_v4
                ) ORDER BY revision DESC LIMIT 2
                """) { stmt in
                var rows: [(Int64, Data, UInt64)] = []
                while true {
                    let rc = sqlite3_step(stmt)
                    if rc == SQLITE_DONE { return rows }
                    guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
                    rows.append((sqlite3_column_int64(stmt, 0), try blob(stmt, 1, maximum: 16),
                                 try unsigned(blob(stmt, 2, maximum: 8))))
                }
            }
            guard let row = latest.first else {
                guard head == 0 else { throw GatewayDatabaseError.corruptData }
                return GatewayHeadEvidence(registration: identity, revision: 0, receipt: nil)
            }
            guard head > 0, row.2 == head, latest.count == 1 || latest[1].2 < head else {
                throw GatewayDatabaseError.corruptData
            }
            let receipt = try storedControl(source: row.0, operationID: row.1)
            guard receipt.revision == head else { throw GatewayDatabaseError.corruptData }
            return GatewayHeadEvidence(registration: identity, revision: head, receipt: receipt)
        }
    }

    /// Historical controls only. The caller must authenticate any network reply and inspect missing revisions.
    public func controlHistory(afterRevision: UInt64, throughRevision: UInt64, maximumRecords: Int) throws -> GatewayControlHistoryPage {
        guard afterRevision < throughRevision, (1...16).contains(maximumRecords) else { throw GatewayDatabaseError.invalidConfiguration }
        return try transaction(write: false) {
            guard try throughRevision <= storedHead() else { throw GatewayDatabaseError.headMismatch }
            let rows: [(Int64, Data, UInt64)] = try statement("""
                SELECT source,operation,revision FROM (
                    SELECT 1 AS source,operation,revision FROM gateway_candidates_v1
                    UNION ALL SELECT 2 AS source,operation,revision FROM gateway_recipients_v2
                    UNION ALL SELECT 3 AS source,operation,revision FROM gateway_submission_controls_v4
                ) WHERE revision>? AND revision<=? ORDER BY revision LIMIT \(maximumRecords + 1)
                """, [uint(afterRevision), uint(throughRevision)]) { stmt in
                var result: [(Int64, Data, UInt64)] = []
                while true {
                    let code = sqlite3_step(stmt)
                    if code == SQLITE_DONE { return result }
                    guard code == SQLITE_ROW else { throw GatewayDatabaseError.storage(code) }
                    result.append((sqlite3_column_int64(stmt, 0), try blob(stmt, 1, maximum: 16), try unsigned(blob(stmt, 2, maximum: 8))))
                }
            }
            var previous = afterRevision
            var receipts: [GatewayControlReceipt] = []
            for row in rows {
                guard row.2 > previous else { throw GatewayDatabaseError.corruptData }
                let receipt = try storedControl(source: row.0, operationID: row.1)
                guard receipt.revision == row.2 else { throw GatewayDatabaseError.corruptData }
                receipts.append(receipt); previous = row.2
            }
            return GatewayControlHistoryPage(registration: identity, afterRevision: afterRevision, throughRevision: throughRevision,
                records: Array(receipts.prefix(maximumRecords)), hasMore: receipts.count > maximumRecords)
        }
    }

    public func receipt(operationID: Data) throws -> GatewayCandidateReceipt? {
        guard operationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: false) { try storedReceipt(operationID: operationID) }
    }

    /// The caller supplies a consistent current trust snapshot. A successful return means the transaction committed, not that a probe may run.
    public func admitCandidate(canonicalPayload: Data, signature: Data, wireVersion: UInt64, registrationToken: String,
                               trust: GatewayCandidateTrust, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayCandidateAdmission {
        try transaction(write: true) {
            try checkClock(now)
            guard identity.matches(trust) else { throw GatewayDatabaseError.wrongScope }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            let candidate = try GatewayCandidateVerifier.authenticate(canonicalCandidate: canonicalPayload, signature: signature,
                wireVersion: wireVersion, registrationToken: registrationToken, trust: trust, payloadLimits: payloadLimits, signingLimits: signingLimits)
            if let previous = try storedReceipt(operationID: candidate.operationID) {
                guard previous.canonicalPayload == canonicalPayload else { throw GatewayDatabaseError.operationConflict }
                return GatewayCandidateAdmission(receipt: previous, inserted: false)
            }
            guard try storedRecipient(operationID: candidate.operationID) == nil,
                  try storedSubmission(operationID: candidate.operationID) == nil else { throw GatewayDatabaseError.operationConflict }
            guard try !isRevoked(phone: candidate.binding.phoneID, enrollment: candidate.binding.enrollmentEpoch) else {
                throw GatewayDatabaseError.revokedEnrollment
            }
            let verified = try GatewayCandidateVerifier.verify(canonicalCandidate: canonicalPayload, signature: signature,
                wireVersion: wireVersion, registrationToken: registrationToken, trust: trust, nowUnixMillis: nowUnixMillis,
                now: now, maximumLifetimeMillis: maximumLifetimeMillis, payloadLimits: payloadLimits, signingLimits: signingLimits)
            try expire(now)
            try requireCapacity()
            let pending = try statement("SELECT count(*) FROM gateway_candidates_v1 WHERE phone=? AND enrollment=? AND token IS NOT NULL",
                [candidate.binding.phoneID, candidate.binding.enrollmentEpoch]) { stmt in
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
                return sqlite3_column_int64(stmt, 0)
            }
            guard pending < maximumPendingPerEnrollment else { throw GatewayDatabaseError.capacityExceeded }
            let duplicate = try statement("SELECT count(*) FROM gateway_candidates_v1 WHERE candidate=? OR challenge=?",
                [candidate.binding.candidateID, candidate.binding.challenge]) { stmt in
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
                return sqlite3_column_int64(stmt, 0)
            }
            guard duplicate == 0 else { throw GatewayDatabaseError.operationConflict }
            try statement("INSERT INTO gateway_candidates_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)", [candidate.operationID,
                candidate.binding.candidateID, candidate.binding.challenge, candidate.binding.phoneID, candidate.binding.enrollmentEpoch,
                canonicalPayload, signature, uint(candidate.revision), uuid(runID), uint(verified.deadlineMilliseconds), Data(registrationToken.utf8)]) {
                try done($0)
            }
            try advanceHead(candidate.revision, from: trust.appliedControlRevision)
            return GatewayCandidateAdmission(receipt: GatewayCandidateReceipt(candidate: candidate, canonicalPayload: canonicalPayload, signature: signature), inserted: true)
        }
    }

    public func recipientReceipt(operationID: Data) throws -> GatewayRecipientReceipt? {
        guard operationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: false) { try storedRecipient(operationID: operationID) }
    }

    public func isPhoneRevoked(phoneID: Data, enrollmentEpoch: Data) throws -> Bool {
        guard phoneID.count == 16, enrollmentEpoch.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: false) { try isRevoked(phone: phoneID, enrollment: enrollmentEpoch) }
    }

    /// Applies a current root claim atomically. Historical retries return the original receipt without restoring state.
    public func applyRecipient(canonicalPayload: Data, signature: Data, wireVersion: UInt64, kind: GatewayRecipientKind,
                               trust: GatewayCandidateTrust, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayRecipientApplication {
        try transaction(write: true) {
            try checkClock(now)
            guard identity.matches(trust), trust.active else { throw GatewayDatabaseError.wrongScope }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            let control = try GatewayStoredRecipient.decode(canonicalPayload, kind: kind, limits: payloadLimits)
            guard control.matches(identity), control.phoneID == trust.enrollment.phoneID,
                  control.enrollmentEpoch == trust.enrollment.epoch else { throw GatewayDatabaseError.wrongScope }
            guard try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: wireVersion,
                kind: kind, canonicalPayload: canonicalPayload, payloadLimits: payloadLimits, inputLimits: signingLimits) else {
                throw GatewayCandidateVerificationError.invalidSignature
            }
            if let previous = try storedRecipient(operationID: control.operationID) {
                guard previous.kind == kind, previous.canonicalPayload == canonicalPayload else { throw GatewayDatabaseError.operationConflict }
                return GatewayRecipientApplication(receipt: previous, inserted: false)
            }
            guard try storedReceipt(operationID: control.operationID) == nil,
                  try storedSubmission(operationID: control.operationID) == nil else { throw GatewayDatabaseError.operationConflict }
            guard control.revision > trust.appliedControlRevision else { throw GatewayCandidateVerificationError.staleRevision }
            guard control.issued <= nowUnixMillis else { throw GatewayCandidateVerificationError.futureIssue }
            guard nowUnixMillis < control.expires else { throw GatewayCandidateVerificationError.expired }
            guard control.expires - control.issued <= maximumLifetimeMillis else { throw GatewayCandidateVerificationError.excessiveLifetime }
            try requireCapacity()
            let token: Data?
            switch control {
            case .activation(let activation):
                guard trust.enrollment.active, activation.binding.enrollmentTag == trust.enrollment.tag else {
                    throw GatewayCandidateVerificationError.unavailableEnrollment
                }
                guard try !isRevoked(phone: control.phoneID, enrollment: control.enrollmentEpoch) else { throw GatewayDatabaseError.revokedEnrollment }
                token = try pendingToken(for: activation, nowUnixMillis: nowUnixMillis, now: now)
            case .revocation: token = nil
            }
            try statement("INSERT INTO gateway_recipients_v2 VALUES(?,?,?,?,?,?,?)", [control.operationID, uint(kind.rawValue),
                control.phoneID, control.enrollmentEpoch, canonicalPayload, signature, uint(control.revision)]) { try done($0) }
            switch control {
            case .activation(let activation):
                guard let token else { throw GatewayDatabaseError.corruptData }
                let candidate = try candidateReceipt(for: activation).candidate
                try statement("UPDATE gateway_candidates_v1 SET token=NULL WHERE phone=? AND revision<=?", [control.phoneID, uint(candidate.revision)]) { try done($0) }
                try statement("""
                    INSERT INTO gateway_mappings_v2 VALUES(?,?,?,?)
                    ON CONFLICT(phone) DO UPDATE SET enrollment=excluded.enrollment,operation=excluded.operation,token=excluded.token
                    """, [control.phoneID, control.enrollmentEpoch, control.operationID, token]) { try done($0) }
            case .revocation:
                try statement("UPDATE gateway_candidates_v1 SET token=NULL WHERE phone=? AND enrollment=?", [control.phoneID, control.enrollmentEpoch]) { try done($0) }
                try statement("DELETE FROM gateway_mappings_v2 WHERE phone=? AND enrollment=?", [control.phoneID, control.enrollmentEpoch]) { try done($0) }
            }
            try advanceHead(control.revision, from: trust.appliedControlRevision)
            return GatewayRecipientApplication(receipt: GatewayRecipientReceipt(control: control, canonicalPayload: canonicalPayload, signature: signature), inserted: true)
        }
    }

    /// Commits a Root credential control and the shared head together. A historical retry cannot restore credential state.
    public func applySubmission(canonicalPayload: Data, signature: Data, wireVersion: UInt64,
                                trust: GatewaySubmissionTrust, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewaySubmissionApplication {
        try transaction(write: true) {
            try checkClock(now)
            guard trust.registration == identity, trust.active else { throw GatewayDatabaseError.wrongScope }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            let control = try GatewaySubmissionVerifier.authenticate(canonicalPayload: canonicalPayload, signature: signature,
                wireVersion: wireVersion, registration: identity, payloadLimits: payloadLimits, signingLimits: signingLimits)
            guard try storedReceipt(operationID: control.operationID) == nil,
                  try storedRecipient(operationID: control.operationID) == nil else { throw GatewayDatabaseError.operationConflict }
            if let previous = try storedSubmission(operationID: control.operationID) {
                guard previous.canonicalPayload == canonicalPayload else { throw GatewayDatabaseError.operationConflict }
                return GatewaySubmissionApplication(receipt: previous, inserted: false)
            }
            _ = try GatewaySubmissionVerifier.verify(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
                trust: trust, nowUnixMillis: nowUnixMillis, now: now, maximumLifetimeMillis: maximumLifetimeMillis,
                payloadLimits: payloadLimits, signingLimits: signingLimits)
            if control.kind == .rotation {
                if try submissionReceipt(credential: control.credentialID, kind: .revocation) != nil { throw GatewayDatabaseError.revokedCredential }
                if try submissionReceipt(credential: control.credentialID, kind: .rotation) != nil { throw GatewayDatabaseError.retiredCredential }
            }
            try requireCapacity()
            try statement("INSERT INTO gateway_submission_controls_v4 VALUES(?,?,?,?,?,?)",
                [control.operationID, uint(control.kind.rawValue), control.credentialID, canonicalPayload, signature, uint(control.revision)]) { try done($0) }
            try advanceHead(control.revision, from: trust.appliedControlRevision)
            return GatewaySubmissionApplication(receipt: GatewaySubmissionReceipt(control: control, canonicalPayload: canonicalPayload, signature: signature), inserted: true)
        }
    }

    public func submissionReceipt(operationID: Data) throws -> GatewaySubmissionReceipt? {
        guard operationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: false) { try storedSubmission(operationID: operationID) }
    }

    /// Reads current credential evidence under current registration trust. This does not grant provider dispatch authority.
    public func activeSubmissionCredential(trust: GatewaySubmissionTrust) throws -> GatewayActiveSubmissionCredential? {
        try transaction(write: false) {
            guard trust.registration == identity, trust.active else { throw GatewayDatabaseError.wrongScope }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            guard let latest = try submissionReceipt(credential: nil, kind: .rotation) else { return nil }
            if try submissionReceipt(credential: latest.control.credentialID, kind: .revocation) != nil { return nil }
            return GatewayActiveSubmissionCredential(receipt: latest)
        }
    }

    private func storedControl(source: Int64, operationID: Data) throws -> GatewayControlReceipt {
        let candidate = try storedReceipt(operationID: operationID), recipient = try storedRecipient(operationID: operationID)
        let submission = try storedSubmission(operationID: operationID)
        switch (source, candidate, recipient, submission) {
        case (1, let value?, nil, nil): return .candidate(value)
        case (2, nil, let value?, nil): return .recipient(value)
        case (3, nil, nil, let value?): return .submission(value)
        default: throw GatewayDatabaseError.corruptData
        }
    }

    private func storedSubmission(operationID: Data) throws -> GatewaySubmissionReceipt? {
        try statement("SELECT kind,credential,payload,signature,revision FROM gateway_submission_controls_v4 WHERE operation=?", [operationID]) { stmt in
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            let payload = try blob(stmt, 2, maximum: payloadLimits.maxBytes), signature = try blob(stmt, 3, maximum: 64)
            let control: GatewaySubmissionControl
            do {
                control = try GatewaySubmissionVerifier.authenticate(canonicalPayload: payload, signature: signature, wireVersion: 1,
                    registration: identity, payloadLimits: payloadLimits, signingLimits: signingLimits)
            } catch { throw GatewayDatabaseError.corruptData }
            guard control.operationID == operationID, control.kind.rawValue == (try unsigned(blob(stmt, 0, maximum: 8))),
                  control.credentialID == (try blob(stmt, 1, maximum: 16)), control.revision == (try unsigned(blob(stmt, 4, maximum: 8))),
                  control.revision <= (try storedHead()) else { throw GatewayDatabaseError.corruptData }
            return GatewaySubmissionReceipt(control: control, canonicalPayload: payload, signature: signature)
        }
    }

    private func submissionReceipt(credential: Data?, kind: GatewaySubmissionKind) throws -> GatewaySubmissionReceipt? {
        // Authenticate every retained row before filtering. Unsigned columns cannot hide an older revocation.
        let operations: [Data] = try statement("SELECT operation FROM gateway_submission_controls_v4 ORDER BY revision DESC") {
            var result: [Data] = []
            while true {
                let rc = sqlite3_step($0)
                if rc == SQLITE_DONE { return result }
                guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
                guard result.count < maximumOperations else { throw GatewayDatabaseError.capacityExceeded }
                result.append(try blob($0, 0, maximum: 16))
            }
        }
        var match: GatewaySubmissionReceipt?
        for operation in operations {
            guard let receipt = try storedSubmission(operationID: operation) else { throw GatewayDatabaseError.corruptData }
            if match == nil, receipt.control.kind == kind, credential == nil || receipt.control.credentialID == credential { match = receipt }
        }
        return match
    }

    private func createSubmissionTable() throws {
        try exec("""
            CREATE TABLE gateway_submission_controls_v4 (
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), kind BLOB NOT NULL CHECK(length(kind)=8),
                credential BLOB NOT NULL CHECK(length(credential)=16), payload BLOB NOT NULL,
                signature BLOB NOT NULL CHECK(length(signature)=64), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8)
            ) STRICT, WITHOUT ROWID
            """)
        try exec("CREATE INDEX gateway_submission_identity_v4 ON gateway_submission_controls_v4(credential,kind,revision)")
        try exec("CREATE INDEX gateway_submission_kind_v4 ON gateway_submission_controls_v4(kind,revision)")
    }

    /// Returns stored mapping evidence only for the caller's current active enrollment. It does not authorize a send.
    public func activeMapping(trust: GatewayCandidateTrust) throws -> GatewayActiveMapping? {
        try transaction(write: false) {
            guard identity.matches(trust), trust.active else { throw GatewayDatabaseError.wrongScope }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            guard trust.enrollment.active else { return nil }
            if try isRevoked(phone: trust.enrollment.phoneID, enrollment: trust.enrollment.epoch) { return nil }
            return try statement("SELECT enrollment,operation,token FROM gateway_mappings_v2 WHERE phone=?", [trust.enrollment.phoneID]) { stmt in
                let rc = sqlite3_step(stmt)
                if rc == SQLITE_DONE { return nil }
                guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
                let enrollment = try blob(stmt, 0, maximum: 16), operation = try blob(stmt, 1, maximum: 16)
                let token = try blob(stmt, 2, maximum: 16384)
                guard let receipt = try storedRecipient(operationID: operation), case .activation(let activation) = receipt.control,
                      activation.binding.phoneID == trust.enrollment.phoneID, activation.binding.enrollmentEpoch == enrollment else {
                    throw GatewayDatabaseError.corruptData
                }
                guard enrollment == trust.enrollment.epoch, activation.binding.enrollmentTag == trust.enrollment.tag else { return nil }
                let latest = try recipientOperation(phone: trust.enrollment.phoneID, enrollment: nil, kind: .activation)
                guard latest == operation else { throw GatewayDatabaseError.corruptData }
                do { _ = try candidateReceipt(for: activation) }
                catch GatewayDatabaseError.unavailableCandidate { throw GatewayDatabaseError.corruptData }
                let string = try checkedToken(token, binding: activation.binding)
                return GatewayActiveMapping(activation: activation, receipt: receipt, registrationToken: string)
            }
        }
    }

    /// Remove only the exact mapping rejected as UNREGISTERED by the provider. A late result cannot remove a rotated token.
    /// This changes delivery state only; retain enrollment authority, signed receipts, and the control counter.
    public func invalidateMapping(_ rejected: GatewayActiveMapping, trust: GatewayCandidateTrust) throws -> Bool {
        try transaction(write: true) {
            let binding = rejected.activation.binding
            guard identity.matches(trust), trust.active, identity.matches(binding),
                  binding.phoneID == trust.enrollment.phoneID, binding.enrollmentEpoch == trust.enrollment.epoch else {
                throw GatewayDatabaseError.wrongScope
            }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            try statement("DELETE FROM gateway_mappings_v2 WHERE phone=? AND enrollment=? AND operation=?",
                [binding.phoneID, binding.enrollmentEpoch, rejected.activation.operationID]) { try done($0) }
            return sqlite3_changes(db) == 1
        }
    }

    private func candidateReceipt(for activation: GatewayMappingActivation) throws -> GatewayCandidateReceipt {
        let operation: Data? = try statement("SELECT operation FROM gateway_candidates_v1 WHERE candidate=?", [activation.binding.candidateID]) {
            let rc = sqlite3_step($0)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            return try blob($0, 0, maximum: 16)
        }
        guard let operation, let receipt = try storedReceipt(operationID: operation) else { throw GatewayDatabaseError.unavailableCandidate }
        guard receipt.candidate.binding == activation.binding, receipt.candidate.revision < activation.revision else {
            throw GatewayDatabaseError.unavailableCandidate
        }
        return receipt
    }
    private func pendingToken(for activation: GatewayMappingActivation, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> Data {
        let receipt = try candidateReceipt(for: activation)
        guard nowUnixMillis < receipt.candidate.expiresAtUnixMillis else { throw GatewayDatabaseError.unavailableCandidate }
        if let operation = try recipientOperation(phone: activation.binding.phoneID, enrollment: nil, kind: .activation) {
            guard let previous = try storedRecipient(operationID: operation), case .activation(let prior) = previous.control else {
                throw GatewayDatabaseError.corruptData
            }
            let priorCandidate: GatewayCandidateReceipt
            do { priorCandidate = try candidateReceipt(for: prior) }
            catch GatewayDatabaseError.unavailableCandidate { throw GatewayDatabaseError.corruptData }
            guard receipt.candidate.revision > priorCandidate.candidate.revision else { throw GatewayDatabaseError.unavailableCandidate }
        }
        return try statement("SELECT run,deadline,token FROM gateway_candidates_v1 WHERE operation=?", [receipt.candidate.operationID]) { stmt in
            guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.corruptData }
            guard try blob(stmt, 0, maximum: 16) == uuid(runID), try unsigned(blob(stmt, 1, maximum: 8)) > now.milliseconds,
                  sqlite3_column_type(stmt, 2) != SQLITE_NULL else { throw GatewayDatabaseError.unavailableCandidate }
            let token = try blob(stmt, 2, maximum: 16384)
            _ = try checkedToken(token, binding: activation.binding)
            return token
        }
    }
    private func checkedToken(_ token: Data, binding: GatewayTokenBinding) throws -> String {
        guard !token.isEmpty, token.count <= 16384, token.allSatisfy({ (33...126).contains($0) }),
              Data(SHA256.hash(data: token)) == binding.tokenDigest, let string = String(data: token, encoding: .utf8) else {
            throw GatewayDatabaseError.corruptData
        }
        return string
    }
    private func storedRecipient(operationID: Data) throws -> GatewayRecipientReceipt? {
        try statement("SELECT kind,phone,enrollment,payload,signature,revision FROM gateway_recipients_v2 WHERE operation=?", [operationID]) { stmt in
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            guard let kind = try GatewayRecipientKind(rawValue: unsigned(blob(stmt, 0, maximum: 8))) else { throw GatewayDatabaseError.corruptData }
            let payload = try blob(stmt, 3, maximum: payloadLimits.maxBytes), signature = try blob(stmt, 4, maximum: 64)
            let control: GatewayStoredRecipient
            do { control = try GatewayStoredRecipient.decode(payload, kind: kind, limits: payloadLimits) }
            catch { throw GatewayDatabaseError.corruptData }
            guard control.operationID == operationID, control.matches(identity),
                  control.phoneID == (try blob(stmt, 1, maximum: 16)), control.enrollmentEpoch == (try blob(stmt, 2, maximum: 16)),
                  control.revision == (try unsigned(blob(stmt, 5, maximum: 8))), control.revision <= (try storedHead()),
                  try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1, kind: kind,
                    canonicalPayload: payload, payloadLimits: payloadLimits, inputLimits: signingLimits) else { throw GatewayDatabaseError.corruptData }
            return GatewayRecipientReceipt(control: control, canonicalPayload: payload, signature: signature)
        }
    }
    private func recipientOperation(phone: Data, enrollment: Data?, kind: GatewayRecipientKind) throws -> Data? {
        let predicate = enrollment == nil ? "phone=? AND kind=?" : "phone=? AND kind=? AND enrollment=?"
        var values = [phone, uint(kind.rawValue)]
        if let enrollment { values.append(enrollment) }
        return try statement("SELECT operation FROM gateway_recipients_v2 WHERE \(predicate) ORDER BY revision DESC LIMIT 1", values) {
            let rc = sqlite3_step($0)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            return try blob($0, 0, maximum: 16)
        }
    }
    private func isRevoked(phone: Data, enrollment: Data) throws -> Bool {
        guard let operation = try recipientOperation(phone: phone, enrollment: enrollment, kind: .phoneRevocation) else { return false }
        guard let receipt = try storedRecipient(operationID: operation), receipt.kind == .phoneRevocation,
              receipt.phoneID == phone, receipt.enrollmentEpoch == enrollment else { throw GatewayDatabaseError.corruptData }
        return true
    }
    private func operationCount(includeSubmission: Bool = true) throws -> Int64 {
        let extra = includeSubmission ? "+(SELECT count(*) FROM gateway_submission_controls_v4)" : ""
        return try scalar("SELECT (SELECT count(*) FROM gateway_candidates_v1)+(SELECT count(*) FROM gateway_recipients_v2)" + extra)
    }
    private func requireCapacity() throws {
        guard try operationCount() < maximumOperations else { throw GatewayDatabaseError.capacityExceeded }
    }
    private func advanceHead(_ revision: UInt64, from previous: UInt64) throws {
        try statement("UPDATE gateway_identity_v1 SET head=? WHERE id=1 AND head=?", [uint(revision), uint(previous)]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayDatabaseError.headMismatch }
        }
    }
    private func createRecipientTables() throws {
        try exec("""
            CREATE TABLE gateway_recipients_v2 (
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), kind BLOB NOT NULL CHECK(length(kind)=8),
                phone BLOB NOT NULL CHECK(length(phone)=16), enrollment BLOB NOT NULL CHECK(length(enrollment)=16),
                payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
                revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8)
            ) STRICT, WITHOUT ROWID
            """)
        try exec("CREATE INDEX gateway_phone_controls_v2 ON gateway_recipients_v2(phone,kind,enrollment,revision)")
        try exec("""
            CREATE TABLE gateway_mappings_v2 (
                phone BLOB PRIMARY KEY CHECK(length(phone)=16), enrollment BLOB NOT NULL CHECK(length(enrollment)=16),
                operation BLOB NOT NULL UNIQUE REFERENCES gateway_recipients_v2(operation),
                token BLOB NOT NULL CHECK(length(token)>0 AND length(token)<=16384)
            ) STRICT, WITHOUT ROWID
            """)
    }

    /// Reserve before transport. This commits the attempt count but does not expose a provider message.
    /// Check before OAuth or pacing without consuming an attempt or exposing the registration token.
    func checkProbeCandidate(candidateOperationID: Data, trust: GatewayCandidateTrust,
                             nowUnixMillis: UInt64, now: AuthorityMoment) throws {
        guard probePolicy != nil else { throw GatewayProbeError.disabled }
        guard candidateOperationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        try transaction(write: true) {
            try checkClock(now)
            _ = try probeMaterial(operation: candidateOperationID, trust: trust, wall: nowUnixMillis, now: now)
        }
    }

    public func reserveProbe(candidateOperationID: Data, trust: GatewayCandidateTrust,
                             nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayProbeReservation {
        guard let policy = probePolicy else { throw GatewayProbeError.disabled }
        guard candidateOperationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: true) {
            try checkClock(now)
            _ = try probeMaterial(operation: candidateOperationID, trust: trust, wall: nowUnixMillis, now: now)
            let previous = try probeRow(operation: candidateOperationID)
            if let previous {
                guard previous.run == uuid(runID) else { throw GatewayDatabaseError.corruptData }
                switch previous.status {
                case .reserved, .dispatched: throw GatewayProbeError.attemptInFlight
                case .accepted, .terminal: throw GatewayProbeError.finished
                case .retryable:
                    guard let retry = previous.retry, now.milliseconds >= retry else { throw GatewayProbeError.retryNotDue }
                }
            }
            let number = (previous?.number ?? 0) + 1
            guard number <= policy.maximumAttempts else { throw GatewayProbeError.attemptsExhausted }
            let identifier = UUID()
            try statement("""
                INSERT INTO gateway_probes_v3(operation,attempt,number,status,run,trust,started,retry) VALUES(?,?,?,1,?,?,?,NULL)
                ON CONFLICT(operation) DO UPDATE SET attempt=excluded.attempt,number=excluded.number,status=1,
                    run=excluded.run,trust=excluded.trust,started=excluded.started,retry=NULL
                """, [candidateOperationID, uuid(identifier), uint(UInt64(number)), uuid(runID), uuid(trust.revision), uint(now.milliseconds)]) { try done($0) }
            return GatewayProbeReservation(owner: runID, operationID: candidateOperationID, identifier: identifier,
                trustRevision: trust.revision, number: number)
        }
    }

    /// Consume exactly once immediately before sending. The service must serialize this handoff with trust changes.
    public func takeProbe(_ reservation: GatewayProbeReservation, trust: GatewayCandidateTrust,
                          nowUnixMillis: UInt64, now: AuthorityMoment) throws -> FCMTokenProbe {
        guard let policy = probePolicy else { throw GatewayProbeError.disabled }
        guard reservation.owner == runID else { throw GatewayProbeError.staleReservation }
        return try transaction(write: true) {
            try checkClock(now)
            guard trust.revision == reservation.trustRevision,
                  let row = try probeRow(operation: reservation.operationID), matches(row, reservation), row.status == .reserved else {
                throw GatewayProbeError.staleReservation
            }
            let material = try probeMaterial(operation: reservation.operationID, trust: trust, wall: nowUnixMillis, now: now)
            let probe = try FCMTokenProbe(candidate: material.receipt.candidate, registrationToken: material.token,
                admittedAt: AuthorityMoment(epoch: clockEpoch, milliseconds: row.started), deadlineMilliseconds: material.deadline,
                nowUnixMillis: nowUnixMillis, now: now, maximumTTLSeconds: policy.maximumTTLSeconds)
            try statement("UPDATE gateway_probes_v3 SET status=2 WHERE operation=? AND attempt=? AND status=1",
                [reservation.operationID, uuid(reservation.identifier)]) {
                try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayProbeError.staleReservation }
            }
            return probe
        }
    }

    /// First outcome wins. A stale callback cannot change a newer attempt, a mapping or enrollment authority.
    /// A reserved attempt can be cancelled with terminal; accepted and retry outcomes require a dispatch.
    @discardableResult public func finishProbe(_ reservation: GatewayProbeReservation, outcome: GatewayProbeOutcome,
                                               now: AuthorityMoment) throws -> Bool {
        guard let policy = probePolicy else { throw GatewayProbeError.disabled }
        guard reservation.owner == runID else { throw GatewayProbeError.staleReservation }
        return try transaction(write: true) {
            try checkClock(now)
            guard let row = try probeRow(operation: reservation.operationID), matches(row, reservation) else { return false }
            if row.status != .reserved && row.status != .dispatched { return false }
            if row.status == .reserved {
                guard case .terminal = outcome else { throw GatewayProbeError.staleReservation }
            }
            let status: GatewayProbeStatus, retry: UInt64?
            switch outcome {
            case .accepted: status = .accepted; retry = nil
            case .terminal: status = .terminal; retry = nil
            case .retry(let requested):
                let (next, overflow) = now.milliseconds.addingReportingOverflow(max(requested, policy.minimumRetryDelayMillis))
                let available: Bool = try statement("SELECT run,deadline,token FROM gateway_candidates_v1 WHERE operation=?", [reservation.operationID]) {
                    guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayDatabaseError.corruptData }
                    return try blob($0, 0, maximum: 16) == uuid(runID) && unsigned(blob($0, 1, maximum: 8)) > next && sqlite3_column_type($0, 2) != SQLITE_NULL
                }
                if overflow || !available || row.number >= policy.maximumAttempts { status = .terminal; retry = nil }
                else { status = .retryable; retry = next }
            }
            if let retry {
                try statement("UPDATE gateway_probes_v3 SET status=4,retry=? WHERE operation=? AND attempt=?",
                    [uint(retry), reservation.operationID, uuid(reservation.identifier)]) { try done($0) }
            } else {
                try statement("UPDATE gateway_probes_v3 SET status=\(status.rawValue),retry=NULL WHERE operation=? AND attempt=?",
                    [reservation.operationID, uuid(reservation.identifier)]) { try done($0) }
            }
            return true
        }
    }

    public func probeProgress(candidateOperationID: Data) throws -> GatewayProbeProgress? {
        guard candidateOperationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: false) {
            guard let row = try probeRow(operation: candidateOperationID) else { return nil }
            guard try storedReceipt(operationID: candidateOperationID) != nil else { throw GatewayDatabaseError.corruptData }
            return GatewayProbeProgress(number: row.number, status: row.status, retryAtMilliseconds: row.run == uuid(runID) ? row.retry : nil)
        }
    }

    private struct ProbeRow {
        let attempt: Data
        let number: Int
        let status: GatewayProbeStatus
        let run: Data
        let trust: Data
        let started: UInt64
        let retry: UInt64?
    }
    private func matches(_ row: ProbeRow, _ reservation: GatewayProbeReservation) -> Bool {
        row.attempt == uuid(reservation.identifier) && row.number == reservation.number && row.run == uuid(runID) && row.trust == uuid(reservation.trustRevision)
    }
    private func probeRow(operation: Data) throws -> ProbeRow? {
        try statement("SELECT attempt,number,status,run,trust,started,retry FROM gateway_probes_v3 WHERE operation=?", [operation]) { stmt in
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            let number = try unsigned(blob(stmt, 1, maximum: 8))
            guard (1...32).contains(number), sqlite3_column_type(stmt, 2) == SQLITE_INTEGER,
                  let status = GatewayProbeStatus(rawValue: Int(sqlite3_column_int64(stmt, 2))) else { throw GatewayDatabaseError.corruptData }
            let attempt = try blob(stmt, 0, maximum: 16), run = try blob(stmt, 3, maximum: 16), trust = try blob(stmt, 4, maximum: 16)
            let started = try unsigned(blob(stmt, 5, maximum: 8))
            let retry = sqlite3_column_type(stmt, 6) == SQLITE_NULL ? nil : try unsigned(blob(stmt, 6, maximum: 8))
            guard attempt.count == 16, run.count == 16, trust.count == 16, (status == .retryable) == (retry != nil),
                  retry.map({ $0 > started }) ?? true else { throw GatewayDatabaseError.corruptData }
            return ProbeRow(attempt: attempt, number: Int(number), status: status, run: run, trust: trust, started: started, retry: retry)
        }
    }
    private func probeMaterial(operation: Data, trust: GatewayCandidateTrust, wall: UInt64, now: AuthorityMoment) throws -> (receipt: GatewayCandidateReceipt, token: String, deadline: UInt64) {
        guard identity.matches(trust) else { throw GatewayDatabaseError.wrongScope }
        guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
        guard let receipt = try storedReceipt(operationID: operation) else { throw GatewayDatabaseError.unavailableCandidate }
        let candidate = receipt.candidate
        guard try !isRevoked(phone: candidate.binding.phoneID, enrollment: candidate.binding.enrollmentEpoch) else { throw GatewayDatabaseError.revokedEnrollment }
        let material = try statement("SELECT run,deadline,token FROM gateway_candidates_v1 WHERE operation=?", [operation]) { stmt -> (String, UInt64) in
            guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.corruptData }
            let deadline = try unsigned(blob(stmt, 1, maximum: 8))
            guard try blob(stmt, 0, maximum: 16) == uuid(runID), deadline > now.milliseconds, sqlite3_column_type(stmt, 2) != SQLITE_NULL,
                  candidate.issuedAtUnixMillis <= wall, wall < candidate.expiresAtUnixMillis else { throw GatewayDatabaseError.unavailableCandidate }
            return (try checkedToken(blob(stmt, 2, maximum: 16384), binding: candidate.binding), deadline)
        }
        _ = try GatewayCandidateVerifier.authenticate(canonicalCandidate: receipt.canonicalPayload, signature: receipt.signature,
            wireVersion: 1, registrationToken: material.0, trust: trust, payloadLimits: payloadLimits, signingLimits: signingLimits)
        return (receipt, material.0, material.1)
    }
    private func createProbeTable() throws {
        try exec("""
            CREATE TABLE gateway_probes_v3 (
                operation BLOB PRIMARY KEY REFERENCES gateway_candidates_v1(operation), attempt BLOB NOT NULL CHECK(length(attempt)=16),
                number BLOB NOT NULL CHECK(length(number)=8), status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 5),
                run BLOB NOT NULL CHECK(length(run)=16), trust BLOB NOT NULL CHECK(length(trust)=16),
                started BLOB NOT NULL CHECK(length(started)=8), retry BLOB CHECK(retry IS NULL OR length(retry)=8)
            ) STRICT, WITHOUT ROWID
            """)
    }

    /// Reclaim expired token material without deleting the signed operation receipts or rewinding the head.
    public func expireCandidates(now: AuthorityMoment) throws {
        try transaction(write: true) { try checkClock(now); try expire(now) }
    }
    public func close() throws {
        guard !active else { throw GatewayDatabaseError.transactionActive }
        shutdown()
    }

    private func checkClock(_ now: AuthorityMoment) throws {
        guard now.epoch == clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else {
            unavailable = true
            throw GatewayDatabaseError.invalidClock
        }
        lastMoment = now.milliseconds
    }
    private func expire(_ now: AuthorityMoment) throws {
        try statement("UPDATE gateway_candidates_v1 SET token=NULL WHERE token IS NOT NULL AND (run<>? OR deadline<=?)", [uuid(runID), uint(now.milliseconds)]) { try done($0) }
    }
    private func storedHead() throws -> UInt64 {
        try statement("SELECT head FROM gateway_identity_v1 WHERE id=1") {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayDatabaseError.corruptData }
            return try unsigned(blob($0, 0, maximum: 8))
        }
    }
    private func storedReceipt(operationID: Data) throws -> GatewayCandidateReceipt? {
        try statement("SELECT candidate,challenge,phone,enrollment,payload,signature,revision FROM gateway_candidates_v1 WHERE operation=?", [operationID]) { stmt in
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            let payload = try blob(stmt, 4, maximum: payloadLimits.maxBytes), signature = try blob(stmt, 5, maximum: 64)
            let candidate: GatewayTokenCandidate
            do { candidate = try GatewayTokenCandidate.decode(payload, limits: payloadLimits) }
            catch { throw GatewayDatabaseError.corruptData }
            guard candidate.operationID == operationID, identity.matches(candidate.binding),
                  candidate.binding.candidateID == (try blob(stmt, 0, maximum: 16)), candidate.binding.challenge == (try blob(stmt, 1, maximum: 32)),
                  candidate.binding.phoneID == (try blob(stmt, 2, maximum: 16)), candidate.binding.enrollmentEpoch == (try blob(stmt, 3, maximum: 16)),
                  candidate.revision == (try unsigned(blob(stmt, 6, maximum: 8))), candidate.revision <= (try storedHead()),
                  try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                    canonicalPayload: payload, payloadLimits: payloadLimits, inputLimits: signingLimits) else { throw GatewayDatabaseError.corruptData }
            return GatewayCandidateReceipt(candidate: candidate, canonicalPayload: payload, signature: signature)
        }
    }
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
        guard db != nil else { throw GatewayDatabaseError.closed }
        guard !unavailable else { throw GatewayDatabaseError.unavailable }
        guard !write || !readOnlyForUpdateHealth else { throw GatewayDatabaseError.readOnly }
        guard !active else { throw GatewayDatabaseError.transactionActive }
        try validateLease()
        try exec(write ? "BEGIN IMMEDIATE" : "BEGIN")
        active = true; defer { active = false }
        do {
            let result = try body()
            try validateLease()
            do { try exec("COMMIT") } catch { unavailable = true; throw error }
            try validateLease()
            return result
        } catch {
            if error as? GatewayDatabaseError == .corruptData { unavailable = true }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            throw error
        }
    }
    private func validateLease() throws {
        do { try lease.validate() } catch { unavailable = true; throw error }
    }
    private func requireEmpty() throws {
        guard try scalar("PRAGMA application_id") == 0, try scalar("PRAGMA user_version") == 0,
              try scalar("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'") == 0 else { throw GatewayDatabaseError.incompatibleStore }
    }
    private func create() throws {
        try requireEmpty()
        try exec("CREATE TABLE gateway_identity_v1(id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, head BLOB NOT NULL CHECK(length(head)=8)) STRICT")
        try statement("INSERT INTO gateway_identity_v1 VALUES(1,?,?)", [identity.encode(), uint(0)]) { try done($0) }
        try exec("""
            CREATE TABLE gateway_candidates_v1 (
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), candidate BLOB NOT NULL UNIQUE CHECK(length(candidate)=16),
                challenge BLOB NOT NULL UNIQUE CHECK(length(challenge)=32), phone BLOB NOT NULL CHECK(length(phone)=16),
                enrollment BLOB NOT NULL CHECK(length(enrollment)=16), payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
                revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8), run BLOB NOT NULL CHECK(length(run)=16),
                deadline BLOB NOT NULL CHECK(length(deadline)=8), token BLOB CHECK(token IS NULL OR (length(token)>0 AND length(token)<=16384))
            ) STRICT, WITHOUT ROWID
            """)
        try exec("CREATE INDEX gateway_pending_v1 ON gateway_candidates_v1(phone,enrollment) WHERE token IS NOT NULL")
        try createRecipientTables(); try createProbeTable(); try createSubmissionTable()
        try exec("PRAGMA application_id=\(Self.applicationID)"); try exec("PRAGMA user_version=4")
    }
    private func validateIdentity(allowLegacy: Bool = false) throws {
        let version = try scalar("PRAGMA user_version")
        guard try scalar("PRAGMA application_id") == Self.applicationID, version == 4 || (allowLegacy && (1...3).contains(version)) else {
            throw GatewayDatabaseError.incompatibleStore
        }
        try statement("SELECT id,identity,head FROM gateway_identity_v1") {
            guard sqlite3_step($0) == SQLITE_ROW, sqlite3_column_int64($0, 0) == 1 else { throw GatewayDatabaseError.incompatibleStore }
            guard try blob($0, 1, maximum: 512) == identity.encode() else { throw GatewayDatabaseError.wrongScope }
            _ = try unsigned(blob($0, 2, maximum: 8))
            guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore }
        }
        try statement("SELECT operation,candidate,challenge,phone,enrollment,payload,signature,revision,run,deadline,token FROM gateway_candidates_v1 LIMIT 0") {
            guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore }
        }
        if version >= 2 {
            for sql in ["SELECT operation,kind,phone,enrollment,payload,signature,revision FROM gateway_recipients_v2 LIMIT 0",
                        "SELECT phone,enrollment,operation,token FROM gateway_mappings_v2 LIMIT 0"] {
                try statement(sql) { guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore } }
            }
            if version >= 3 {
                try statement("SELECT operation,attempt,number,status,run,trust,started,retry FROM gateway_probes_v3 LIMIT 0") {
                    guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore }
                }
                guard try scalar("SELECT count(*) FROM gateway_probes_v3") <= scalar("SELECT count(*) FROM gateway_candidates_v1") else {
                    throw GatewayDatabaseError.corruptData
                }
            }
            if version >= 4 {
                try statement("SELECT operation,kind,credential,payload,signature,revision FROM gateway_submission_controls_v4 LIMIT 0") {
                    guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore }
                }
            }
            guard try operationCount(includeSubmission: version >= 4) <= maximumOperations else { throw GatewayDatabaseError.capacityExceeded }
        } else {
            guard try scalar("SELECT count(*) FROM gateway_candidates_v1") <= maximumOperations else { throw GatewayDatabaseError.capacityExceeded }
        }
    }
    private func shutdown() {
        if let db { precondition(sqlite3_close(db) == SQLITE_OK, "Gateway retained a private SQLite resource"); self.db = nil }
        lease.close()
    }
    private func exec(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw GatewayDatabaseError.storage(rc) }
    }
    private func statement<T>(_ sql: String, _ values: [Data] = [], _ body: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw GatewayDatabaseError.storage(rc) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in values.enumerated() {
            guard value.count <= Int(Int32.max) else { throw GatewayDatabaseError.invalidConfiguration }
            let rc = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard rc == SQLITE_OK else { throw GatewayDatabaseError.storage(rc) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws {
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else { throw GatewayDatabaseError.storage(rc) }
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) { guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }; return sqlite3_column_int64($0, 0) }
    }
    private func scalarText(_ sql: String) throws -> String {
        try statement(sql) {
            guard sqlite3_step($0) == SQLITE_ROW, let value = sqlite3_column_text($0, 0) else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
            return String(cString: value)
        }
    }
    private func blob(_ stmt: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(stmt, column))
        guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let value = sqlite3_column_blob(stmt, column) else { throw GatewayDatabaseError.corruptData }
        return Data(bytes: value, count: count)
    }
    private func uint(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
    private func unsigned(_ data: Data) throws -> UInt64 {
        guard data.count == 8 else { throw GatewayDatabaseError.corruptData }
        return data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
    private func uuid(_ value: UUID) -> Data { withUnsafeBytes(of: value.uuid) { Data($0) } }
}
